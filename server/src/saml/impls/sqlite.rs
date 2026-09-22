use async_trait::async_trait;
use chrono::Utc;
use sqlx::{Row, SqlitePool};

use crate::{
    AuthError, AuthResult,
    saml::request_store::{PendingSamlRequest, SamlRequestStore},
};

/// SQLite-backed store for pending SAML `AuthnRequest`s and the assertion replay cache.
pub struct SqliteSamlRequestStore {
    pool: SqlitePool,
}

impl SqliteSamlRequestStore {
    pub fn new(pool: SqlitePool) -> Self {
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
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
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
                expires_at   INTEGER NOT NULL
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

#[async_trait]
impl SamlRequestStore for SqliteSamlRequestStore {
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

        // DELETE ... RETURNING makes fetch-and-delete a single atomic statement, so a request
        // is consumed at most once even under concurrent ACS posts — this single-use property
        // is what makes a replayed `InResponseTo` fail to correlate a second time.
        let row = sqlx::query(
            r#"
            DELETE FROM saml_pending_request
            WHERE request_id = ? AND realm_id = ? AND expires_at > ?
            RETURNING request_id, realm_id, return_url, created_at, expires_at
            "#,
        )
        .bind(request_id)
        .bind(realm_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to take SAML pending request: {e}")))?;

        row.map(|row| {
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
        })
        .transpose()
    }

    async fn record_assertion_id(&self, assertion_id: &str, expires_at: i64) -> AuthResult<bool> {
        // INSERT OR IGNORE relies on the PRIMARY KEY: the first insert for an assertion id wins
        // (1 row affected); a replay collides and affects 0 rows. `rows_affected` therefore
        // distinguishes a newly-recorded id from a replay without a separate read.
        let result = sqlx::query(
            "INSERT OR IGNORE INTO saml_seen_assertion (assertion_id, expires_at) VALUES (?, ?)",
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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn store() -> SqliteSamlRequestStore {
        // max_connections(1) keeps the single in-memory database alive across queries — each
        // `sqlite::memory:` connection is otherwise its own separate database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite pool");
        let store = SqliteSamlRequestStore::new(pool);
        store.init().await.expect("init schema");
        store
    }

    fn sample(request_id: &str, realm_id: &str, expires_at: i64) -> PendingSamlRequest {
        PendingSamlRequest {
            request_id: request_id.to_string(),
            realm_id: realm_id.to_string(),
            return_url: "https://app.example.com/home".to_string(),
            created_at: 1_000,
            expires_at,
        }
    }

    #[tokio::test]
    async fn take_returns_the_stored_request_then_consumes_it() {
        let store = store().await;
        let future = Utc::now().timestamp() + 300;
        store
            .store_pending_request(&sample("id-1", "realm-a", future))
            .await
            .unwrap();

        let taken = store.take_pending_request("id-1", "realm-a").await.unwrap();
        assert_eq!(taken, Some(sample("id-1", "realm-a", future)));

        // Single-use: a second take of the same request id finds nothing.
        let again = store.take_pending_request("id-1", "realm-a").await.unwrap();
        assert_eq!(again, None);
    }

    #[tokio::test]
    async fn take_rejects_a_wrong_realm() {
        let store = store().await;
        let future = Utc::now().timestamp() + 300;
        store
            .store_pending_request(&sample("id-1", "realm-a", future))
            .await
            .unwrap();

        // A request initiated by realm-a must not be consumable by realm-b's ACS.
        let taken = store.take_pending_request("id-1", "realm-b").await.unwrap();
        assert_eq!(taken, None);
        // And it remains available to its own realm (was not consumed by the wrong-realm attempt).
        assert!(store.take_pending_request("id-1", "realm-a").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn take_rejects_an_expired_request() {
        let store = store().await;
        let past = Utc::now().timestamp() - 1;
        store
            .store_pending_request(&sample("id-old", "realm-a", past))
            .await
            .unwrap();

        let taken = store.take_pending_request("id-old", "realm-a").await.unwrap();
        assert_eq!(taken, None);
    }

    #[tokio::test]
    async fn record_assertion_id_detects_replay() {
        let store = store().await;
        let future = Utc::now().timestamp() + 300;

        assert!(store.record_assertion_id("assertion-1", future).await.unwrap());
        // Second time the same id is seen → replay.
        assert!(!store.record_assertion_id("assertion-1", future).await.unwrap());
        // A different id is still accepted.
        assert!(store.record_assertion_id("assertion-2", future).await.unwrap());
    }

    #[tokio::test]
    async fn delete_expired_purges_only_expired_entries() {
        let store = store().await;
        let now = Utc::now().timestamp();
        store
            .store_pending_request(&sample("fresh", "realm-a", now + 300))
            .await
            .unwrap();
        store
            .store_pending_request(&sample("stale", "realm-a", now - 1))
            .await
            .unwrap();
        store.record_assertion_id("assertion-fresh", now + 300).await.unwrap();
        store.record_assertion_id("assertion-stale", now - 1).await.unwrap();

        store.delete_expired().await.unwrap();

        // The fresh pending request survives; the stale one is gone.
        assert!(store.take_pending_request("fresh", "realm-a").await.unwrap().is_some());
        assert!(store.take_pending_request("stale", "realm-a").await.unwrap().is_none());
        // The stale assertion id was purged, so it is accepted again (no longer a known replay);
        // the fresh one is still remembered.
        assert!(store.record_assertion_id("assertion-stale", now + 300).await.unwrap());
        assert!(!store.record_assertion_id("assertion-fresh", now + 300).await.unwrap());
    }
}
