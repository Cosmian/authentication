use async_trait::async_trait;
use chrono::Utc;
use sqlx::{MySqlPool, Row, mysql::MySqlRow};

use crate::{
    AuthError, AuthResult,
    saml::request_store::{PendingSamlRequest, SamlRequestStore},
};

/// MySQL-backed store for pending SAML requests and the assertion replay cache.
pub struct MySqlSamlRequestStore {
    pool: MySqlPool,
}

impl MySqlSamlRequestStore {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    /// Create the pending-request and replay-cache tables (indexes declared inline, MySQL-style).
    pub async fn init(&self) -> AuthResult<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS saml_pending_request (
                request_id VARCHAR(255) PRIMARY KEY,
                realm_id   VARCHAR(255) NOT NULL,
                return_url TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                INDEX idx_saml_pending_expires_at (expires_at)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Generic(format!("Failed to create saml_pending_request table: {e}"))
        })?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS saml_seen_assertion (
                assertion_id VARCHAR(255) PRIMARY KEY,
                expires_at   BIGINT NOT NULL,
                INDEX idx_saml_seen_expires_at (expires_at)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Generic(format!("Failed to create saml_seen_assertion table: {e}"))
        })?;

        Ok(())
    }
}

fn row_to_pending(row: MySqlRow) -> AuthResult<PendingSamlRequest> {
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
impl SamlRequestStore for MySqlSamlRequestStore {
    async fn store_pending_request(&self, request: &PendingSamlRequest) -> AuthResult<()> {
        sqlx::query(
            r#"
            INSERT INTO saml_pending_request (request_id, realm_id, return_url, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
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

        // MySQL has no `DELETE ... RETURNING`, so `SELECT ... FOR UPDATE` then `DELETE` inside a
        // single transaction gives the same atomic single-use guarantee: the row lock prevents a
        // concurrent ACS post from also reading it before the delete commits.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to begin transaction: {e}")))?;

        let row = sqlx::query(
            r#"
            SELECT request_id, realm_id, return_url, created_at, expires_at
            FROM saml_pending_request
            WHERE request_id = ? AND realm_id = ? AND expires_at > ?
            FOR UPDATE
            "#,
        )
        .bind(request_id)
        .bind(realm_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to select SAML pending request: {e}")))?;

        let result = match row {
            None => None,
            Some(row) => {
                sqlx::query("DELETE FROM saml_pending_request WHERE request_id = ?")
                    .bind(request_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        AuthError::Generic(format!("Failed to delete SAML pending request: {e}"))
                    })?;
                Some(row_to_pending(row)?)
            }
        };

        tx.commit()
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to commit transaction: {e}")))?;

        Ok(result)
    }

    async fn record_assertion_id(&self, assertion_id: &str, expires_at: i64) -> AuthResult<bool> {
        // INSERT IGNORE: the first insert for an assertion id wins (1 row affected); a replay
        // collides on the primary key and affects 0 rows.
        let result = sqlx::query(
            "INSERT IGNORE INTO saml_seen_assertion (assertion_id, expires_at) VALUES (?, ?)",
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
        sqlx::query("DELETE FROM saml_pending_request WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Generic(format!("Failed to delete expired SAML pending requests: {e}"))
            })?;
        sqlx::query("DELETE FROM saml_seen_assertion WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Generic(format!("Failed to delete expired SAML assertion ids: {e}"))
            })?;
        Ok(())
    }
}
