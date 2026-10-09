use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row, postgres::PgRow};

use crate::{
    AuthError, AuthResult,
    saml::request_store::{PendingSamlRequest, SamlRequestStore, ensure_unexpired},
};

/// PostgreSQL-backed store for pending SAML requests and the assertion replay cache.
pub struct PostgresSamlRequestStore {
    pool: PgPool,
}

impl PostgresSamlRequestStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create the pending-request and replay-cache tables and their cleanup indexes.
    pub async fn init(&self) -> AuthResult<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS saml_pending_request (
                request_id TEXT PRIMARY KEY,
                realm_id   TEXT NOT NULL,
                return_url TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Generic(format!("Failed to create saml_pending_request table: {e}"))
        })?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_saml_pending_expires_at ON saml_pending_request(expires_at)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Generic(format!("Failed to create saml_pending_request index: {e}"))
        })?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS saml_seen_assertion (
                assertion_id TEXT PRIMARY KEY,
                expires_at   BIGINT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Generic(format!("Failed to create saml_seen_assertion table: {e}"))
        })?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_saml_seen_expires_at ON saml_seen_assertion(expires_at)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Generic(format!("Failed to create saml_seen_assertion index: {e}"))
        })?;

        Ok(())
    }
}

fn row_to_pending(row: PgRow) -> AuthResult<PendingSamlRequest> {
    Ok(PendingSamlRequest {
        request_id: row
            .try_get("request_id")
            .map_err(|e| AuthError::Generic(format!("bad request_id column: {e}")))?,
        realm_id: row
            .try_get("realm_id")
            .map_err(|e| AuthError::Generic(format!("bad realm_id column: {e}")))?,
        return_url: row
            .try_get("return_url")
            .map_err(|e| AuthError::Generic(format!("bad return_url column: {e}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| AuthError::Generic(format!("bad created_at column: {e}")))?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|e| AuthError::Generic(format!("bad expires_at column: {e}")))?,
    })
}

#[async_trait]
impl SamlRequestStore for PostgresSamlRequestStore {
    async fn store_pending_request(&self, request: &PendingSamlRequest) -> AuthResult<()> {
        ensure_unexpired(request.expires_at, "SAML pending request")?;
        sqlx::query(
            r#"
            INSERT INTO saml_pending_request (request_id, realm_id, return_url, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(&request.request_id)
        .bind(&request.realm_id)
        .bind(&request.return_url)
        .bind(request.created_at)
        .bind(request.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to store SAML pending request: {e}")))?;
        Ok(())
    }

    async fn take_pending_request(
        &self,
        request_id: &str,
        realm_id: &str,
    ) -> AuthResult<Option<PendingSamlRequest>> {
        let now = Utc::now().timestamp();
        // DELETE ... RETURNING is atomic fetch-and-delete: single-use, so a replayed
        // `InResponseTo` can't correlate twice.
        let row = sqlx::query(
            r#"
            DELETE FROM saml_pending_request
            WHERE request_id = $1 AND realm_id = $2 AND expires_at > $3
            RETURNING request_id, realm_id, return_url, created_at, expires_at
            "#,
        )
        .bind(request_id)
        .bind(realm_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to take SAML pending request: {e}")))?;

        row.map(row_to_pending).transpose()
    }

    async fn record_assertion_id(&self, assertion_id: &str, expires_at: i64) -> AuthResult<bool> {
        ensure_unexpired(expires_at, "SAML assertion id")?;
        // ON CONFLICT DO NOTHING: the first insert for an assertion id wins (1 row affected);
        // a replay conflicts and affects 0 rows.
        let result = sqlx::query(
            "INSERT INTO saml_seen_assertion (assertion_id, expires_at) VALUES ($1, $2) ON CONFLICT (assertion_id) DO NOTHING",
        )
        .bind(assertion_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to record SAML assertion id: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_expired(&self) -> AuthResult<()> {
        let now = Utc::now().timestamp();
        sqlx::query("DELETE FROM saml_pending_request WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Generic(format!(
                    "Failed to delete expired SAML pending requests: {e}"
                ))
            })?;
        sqlx::query("DELETE FROM saml_seen_assertion WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Generic(format!("Failed to delete expired SAML assertion ids: {e}"))
            })?;
        Ok(())
    }
}
