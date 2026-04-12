use crate::{
    AuthError, AuthResult, AuthenticatedClientScheme, Realm, models::SessionData,
    session::SessionStore,
};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row};

/// PostgreSQL session store implementation
#[allow(dead_code)]
pub struct PostgresSessionStore {
    pool: PgPool,
}

impl PostgresSessionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[allow(dead_code)]
    /// Create a new PostgresSessionStore from a connection string
    pub async fn from_url(url: &str) -> AuthResult<Self> {
        let pool = PgPool::connect(url)
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to connect to PostgreSQL: {e}")))?;
        Ok(Self::new(pool))
    }

    /// Initialize the sessions table
    pub async fn init(&self) -> AuthResult<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS session (
                session_id TEXT PRIMARY KEY,
                realm_id TEXT NOT NULL,
                username TEXT NOT NULL,
                auth_scheme TEXT NOT NULL,
                cookie_string TEXT NOT NULL,
                stale_at BIGINT NOT NULL,
                max_stale_age_seconds BIGINT NOT NULL,
                max_age_seconds BIGINT NOT NULL,
                created_at BIGINT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to create session table: {e}")))?;

        // Create index on stale_at for efficient cleanup
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_session_stale_at ON session(stale_at)
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to create session index: {e}")))?;

        // Create index on realm_id, username, and auth_scheme for efficient user session lookups
        // username and auth_scheme together form the AuthenticatedUser tuple
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_session_realm_user ON session(realm_id, username, auth_scheme)
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to create session index: {e}")))?;

        Ok(())
    }
}

#[async_trait]
impl SessionStore for PostgresSessionStore {
    async fn upsert_session(
        &self,
        session_id: &str,
        realm: &Realm,
        authenticated_client: &AuthenticatedClientScheme,
        session_value: &str,
    ) -> AuthResult<()> {
        let now = Utc::now().timestamp();
        let stale_at = now + realm.session_max_stale_age_seconds;
        let auth_scheme_str = serde_json::to_string(&authenticated_client.auth_scheme)
            .map_err(|e| AuthError::Generic(format!("Failed to serialize auth_scheme: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO session (session_id, realm_id, username, auth_scheme, cookie_string, stale_at, max_stale_age_seconds, max_age_seconds, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(session_id)
        .bind(&realm.id)
        .bind(&authenticated_client.username)
        .bind(&auth_scheme_str)
        .bind(session_value)
        .bind(stale_at)
        .bind(realm.session_max_stale_age_seconds)
        .bind(realm.session_max_age_seconds)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to insert session: {e}")))?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> AuthResult<Option<SessionData>> {
        let now = Utc::now().timestamp();

        // First, check if session exists and is not stale or expired
        let row = sqlx::query(
            r#"
            SELECT realm_id, username, auth_scheme, cookie_string, created_at, stale_at, max_stale_age_seconds, max_age_seconds
            FROM session
            WHERE session_id = $1
            "#,
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to fetch session: {e}")))?;

        match row {
            Some(row) => {
                let stale_at: i64 = row
                    .try_get("stale_at")
                    .map_err(|e| AuthError::Generic(format!("Failed to get stale_at: {e}")))?;
                let created_at: i64 = row
                    .try_get("created_at")
                    .map_err(|e| AuthError::Generic(format!("Failed to get created_at: {e}")))?;
                let max_age_seconds: i64 = row.try_get("max_age_seconds").map_err(|e| {
                    AuthError::Generic(format!("Failed to get max_age_seconds: {e}"))
                })?;

                // Check if session is stale or exceeded absolute maximum age
                if now > stale_at || now > (created_at + max_age_seconds) {
                    // Session is stale or expired, delete it and return None
                    sqlx::query("DELETE FROM session WHERE session_id = $1")
                        .bind(session_id)
                        .execute(&self.pool)
                        .await
                        .map_err(|e| {
                            AuthError::Generic(format!("Failed to delete expired session: {e}"))
                        })?;
                    return Ok(None);
                }

                let realm_id: String = row
                    .try_get("realm_id")
                    .map_err(|e| AuthError::Generic(format!("Failed to get realm_id: {e}")))?;
                let username: String = row
                    .try_get("username")
                    .map_err(|e| AuthError::Generic(format!("Failed to get username: {e}")))?;
                let auth_scheme: String = row
                    .try_get("auth_scheme")
                    .map_err(|e| AuthError::Generic(format!("Failed to get auth_scheme: {e}")))?;
                let cookie_string: String = row
                    .try_get("cookie_string")
                    .map_err(|e| AuthError::Generic(format!("Failed to get cookie_string: {e}")))?;
                let max_stale_age_seconds: i64 =
                    row.try_get("max_stale_age_seconds").map_err(|e| {
                        AuthError::Generic(format!("Failed to get max_stale_age_seconds: {e}"))
                    })?;

                // Calculate new stale_at, capped by absolute expiration
                let absolute_expiry = created_at + max_age_seconds;
                let time_until_absolute_expiry = absolute_expiry - now;
                let stale_duration =
                    std::cmp::min(max_stale_age_seconds, time_until_absolute_expiry);
                let new_stale_at = now + stale_duration;

                sqlx::query(
                    r#"
                    UPDATE session
                    SET stale_at = $1
                    WHERE session_id = $2
                    "#,
                )
                .bind(new_stale_at)
                .bind(session_id)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    AuthError::Generic(format!("Failed to update session stale_at: {e}"))
                })?;

                Ok(Some(SessionData {
                    session_id: session_id.to_string(),
                    realm_id,
                    username,
                    auth_scheme,
                    cookie_string,
                    max_stale_age_seconds,
                    max_age_seconds,
                    created_at,
                }))
            }
            None => Ok(None),
        }
    }

    async fn get_sessions_for_clients(
        &self,
        realm_id: &str,
        authenticated_users: &[&AuthenticatedClientScheme],
    ) -> AuthResult<Vec<SessionData>> {
        if authenticated_users.is_empty() {
            return Ok(vec![]);
        }

        let now = Utc::now().timestamp();

        // Serialize auth_schemes for all users upfront
        let auth_scheme_strs: Vec<String> = authenticated_users
            .iter()
            .map(|u| {
                serde_json::to_string(&u.auth_scheme).map_err(|e| {
                    AuthError::Generic(format!("Failed to serialize auth_scheme: {e}"))
                })
            })
            .collect::<AuthResult<Vec<String>>>()?;

        // Build OR conditions for each (username, auth_scheme) tuple
        // Each AuthenticatedUser is uniquely identified by both username AND auth_scheme
        let user_conditions = authenticated_users
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let base = 4 + (i * 2);
                format!("(username = ${} AND auth_scheme = ${})", base, base + 1)
            })
            .collect::<Vec<_>>()
            .join(" OR ");

        let query_str = format!(
            r#"
            SELECT session_id, realm_id, username, auth_scheme, cookie_string, max_stale_age_seconds, max_age_seconds, created_at
            FROM session
            WHERE realm_id = $1 AND stale_at > $2 AND (created_at + max_age_seconds) > $3
            AND ({})
            "#,
            user_conditions
        );

        let mut query = sqlx::query(&query_str).bind(realm_id).bind(now).bind(now);

        // Bind each username and auth_scheme pair
        for (i, user) in authenticated_users.iter().enumerate() {
            query = query.bind(&user.username).bind(&auth_scheme_strs[i]);
        }

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to fetch sessions: {e}")))?;

        let mut sessions = Vec::new();
        for row in rows {
            let session_id: String = row
                .try_get("session_id")
                .map_err(|e| AuthError::Generic(format!("Failed to get session_id: {e}")))?;
            let realm_id: String = row
                .try_get("realm_id")
                .map_err(|e| AuthError::Generic(format!("Failed to get realm_id: {e}")))?;
            let username: String = row
                .try_get("username")
                .map_err(|e| AuthError::Generic(format!("Failed to get username: {e}")))?;
            let auth_scheme: String = row
                .try_get("auth_scheme")
                .map_err(|e| AuthError::Generic(format!("Failed to get auth_scheme: {e}")))?;
            let cookie_string: String = row
                .try_get("cookie_string")
                .map_err(|e| AuthError::Generic(format!("Failed to get cookie_string: {e}")))?;
            let max_stale_age_seconds: i64 = row.try_get("max_stale_age_seconds").map_err(|e| {
                AuthError::Generic(format!("Failed to get max_stale_age_seconds: {e}"))
            })?;
            let max_age_seconds: i64 = row
                .try_get("max_age_seconds")
                .map_err(|e| AuthError::Generic(format!("Failed to get max_age_seconds: {e}")))?;
            let created_at: i64 = row
                .try_get("created_at")
                .map_err(|e| AuthError::Generic(format!("Failed to get created_at: {e}")))?;
            sessions.push(SessionData {
                session_id,
                realm_id,
                username,
                auth_scheme,
                cookie_string,
                max_stale_age_seconds,
                max_age_seconds,
                created_at,
            });
        }

        Ok(sessions)
    }

    async fn delete_sessions(&self, session_ids: &[&str]) -> AuthResult<()> {
        if session_ids.is_empty() {
            return Ok(());
        }

        // Convert &[&str] to Vec<String> for PostgreSQL binding
        let session_ids_vec: Vec<String> = session_ids.iter().map(|s| s.to_string()).collect();

        sqlx::query(
            r#"
            DELETE FROM session
            WHERE session_id = ANY($1)
            "#,
        )
        .bind(&session_ids_vec)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to delete sessions: {e}")))?;

        Ok(())
    }

    async fn delete_expired_sessions(&self) -> AuthResult<()> {
        let now = Utc::now().timestamp();

        sqlx::query(
            r#"
            DELETE FROM session
            WHERE stale_at <= $1 OR (created_at + max_age_seconds) <= $2
            "#,
        )
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to delete expired sessions: {e}")))?;

        Ok(())
    }
    async fn delete_sessions_for_realm(&self, realm_id: &str) -> AuthResult<()> {
        sqlx::query(
            r#"
            DELETE FROM session
            WHERE realm_id = $1
            "#,
        )
        .bind(realm_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Generic(format!("Failed to delete sessions for realm: {e}")))?;

        Ok(())
    }
}
