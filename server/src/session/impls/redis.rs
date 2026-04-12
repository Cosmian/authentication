use crate::{
    AuthError, AuthResult, AuthenticatedClientScheme, Realm, models::SessionData,
    session::SessionStore,
};
use async_trait::async_trait;
use chrono::Utc;
use redis::{AsyncCommands, Client};
use std::sync::Arc;

/// Redis/ValKey session store implementation
///
/// Uses the following Redis key patterns:
/// - `session:{session_id}` -> SessionData (with TTL for automatic expiration)
/// - `user_sessions:{realm_id}:{username}` -> Set of session_ids (without TTL)
///
/// **Note:** This implementation uses Redis TTL for automatic expiration.
/// Sessions automatically expire after `max_stale_age_seconds` of inactivity.
/// The TTL is refreshed on every access (get_session), providing true access-based expiration.
///
/// **Lazy Cleanup:** When a session expires via TTL, it is automatically removed from Redis,
/// but the session ID may remain in the user_sessions set. This is cleaned up lazily when
/// `get_sessions_for_user()` is called - it checks for expired sessions and removes their IDs
/// from the set. This approach is simple and efficient for typical usage patterns.
#[allow(dead_code)]
pub struct RedisSessionStore {
    client: Arc<Client>,
}

impl RedisSessionStore {
    /// Create a new RedisSessionStore with the given client
    ///
    /// # Arguments
    /// * `client` - Redis client
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    #[allow(dead_code)]
    /// Create a new RedisSessionStore from a connection string
    pub async fn from_url(url: &str) -> AuthResult<Self> {
        let client = Client::open(url)
            .map_err(|e| AuthError::Generic(format!("Failed to connect to Redis: {e}")))?;
        Ok(Self::new(client))
    }

    /// Generate session key for Redis
    fn session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }

    /// Generate user sessions set key for Redis
    /// username and auth_scheme together form the AuthenticatedUser tuple
    fn user_sessions_key(realm_id: &str, username: &str, auth_scheme: &str) -> String {
        format!("user_sessions:{}:{}:{}", realm_id, username, auth_scheme)
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn upsert_session(
        &self,
        session_id: &str,
        realm: &Realm,
        authenticated_client: &AuthenticatedClientScheme,
        session_value: &str,
    ) -> AuthResult<()> {
        let now = Utc::now().timestamp();
        let auth_scheme_str = serde_json::to_string(&authenticated_client.auth_scheme)
            .map_err(|e| AuthError::Generic(format!("Failed to serialize auth_scheme: {e}")))?;

        let session_data = SessionData {
            session_id: session_id.to_string(),
            realm_id: realm.id.clone(),
            username: authenticated_client.username.clone(),
            auth_scheme: auth_scheme_str.clone(),
            cookie_string: session_value.to_string(),
            max_stale_age_seconds: realm.session_max_stale_age_seconds,
            max_age_seconds: realm.session_max_age_seconds,
            created_at: now,
        };

        let session_json = serde_json::to_string(&session_data)
            .map_err(|e| AuthError::Generic(format!("Failed to serialize session data: {e}")))?;

        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to get Redis connection: {e}")))?;

        let session_key = Self::session_key(session_id);
        let user_sessions_key =
            Self::user_sessions_key(&realm.id, &authenticated_client.username, &auth_scheme_str);

        // Calculate TTL: minimum of max_stale_age and remaining time until absolute expiration
        let time_until_absolute_expiry = realm.session_max_age_seconds;
        let ttl = std::cmp::min(
            realm.session_max_stale_age_seconds,
            time_until_absolute_expiry,
        );

        // Redis requires TTL >= 1. If TTL is 0 or negative, use 1 second (session will be expired immediately on first access)
        let ttl = std::cmp::max(1, ttl);

        // Store session data with TTL for automatic expiration
        let _: () = conn
            .set_ex(&session_key, &session_json, ttl as u64)
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to set session in Redis: {e}")))?;

        // Add session ID to user's session set
        let _: () = conn
            .sadd(&user_sessions_key, session_id)
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to add session to user set: {e}")))?;

        // Set TTL on user sessions set to match session TTL
        let _: () = conn.expire(&user_sessions_key, ttl).await.map_err(|e| {
            AuthError::Generic(format!("Failed to set TTL on user sessions set: {e}"))
        })?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> AuthResult<Option<SessionData>> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to get Redis connection: {e}")))?;

        let session_key = Self::session_key(session_id);

        // Get the session data
        let session_json: Option<String> = conn
            .get(&session_key)
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to get session from Redis: {e}")))?;

        match session_json {
            Some(json) => {
                let session_data: SessionData = serde_json::from_str(&json).map_err(|e| {
                    AuthError::Generic(format!("Failed to deserialize session data: {e}"))
                })?;

                let now = Utc::now().timestamp();
                let absolute_expiry = session_data.created_at + session_data.max_age_seconds;

                // Check if session exceeded absolute maximum age
                if now > absolute_expiry {
                    // Session exceeded absolute max age, delete it and return None
                    let _: () = conn.del(&session_key).await.map_err(|e| {
                        AuthError::Generic(format!("Failed to delete expired session: {e}"))
                    })?;

                    // Also remove from user's sessions set
                    let user_sessions_key = Self::user_sessions_key(
                        &session_data.realm_id,
                        &session_data.username,
                        &session_data.auth_scheme,
                    );
                    let _: () = conn
                        .srem(&user_sessions_key, session_id)
                        .await
                        .map_err(|e| {
                            AuthError::Generic(format!(
                                "Failed to remove session from user set: {e}"
                            ))
                        })?;

                    return Ok(None);
                }

                // Calculate TTL: minimum of max_stale_age and remaining time until absolute expiration
                let time_until_absolute_expiry = absolute_expiry - now;
                let ttl = std::cmp::min(
                    session_data.max_stale_age_seconds,
                    time_until_absolute_expiry,
                );

                // Redis requires TTL >= 1. If we're at or past expiry, delete the session
                if ttl <= 0 {
                    let _: () = conn.del(&session_key).await.map_err(|e| {
                        AuthError::Generic(format!("Failed to delete expired session: {e}"))
                    })?;
                    let user_sessions_key = Self::user_sessions_key(
                        &session_data.realm_id,
                        &session_data.username,
                        &session_data.auth_scheme,
                    );
                    let _: () = conn
                        .srem(&user_sessions_key, session_id)
                        .await
                        .map_err(|e| {
                            AuthError::Generic(format!(
                                "Failed to remove session from user set: {e}"
                            ))
                        })?;
                    return Ok(None);
                }

                // Refresh the TTL to reset the expiration timer (access-based expiration)
                let _: () = conn.expire(&session_key, ttl).await.map_err(|e| {
                    AuthError::Generic(format!("Failed to refresh TTL in Redis: {e}"))
                })?;

                Ok(Some(session_data))
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

        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to get Redis connection: {e}")))?;

        let mut all_valid_sessions = Vec::new();
        let now = Utc::now().timestamp();

        // Iterate through each user and get their sessions
        for authenticated_user in authenticated_users {
            let auth_scheme_str = serde_json::to_string(&authenticated_user.auth_scheme)
                .map_err(|e| AuthError::Generic(format!("Failed to serialize auth_scheme: {e}")))?;
            let user_sessions_key =
                Self::user_sessions_key(realm_id, &authenticated_user.username, &auth_scheme_str);

            // Get all session IDs for this user
            let session_ids: Vec<String> =
                conn.smembers(&user_sessions_key).await.map_err(|e| {
                    AuthError::Generic(format!("Failed to get user sessions from Redis: {e}"))
                })?;

            // Lazy cleanup: Check each session and remove expired ones from the set
            for session_id_str in session_ids {
                let session_key = Self::session_key(&session_id_str);

                // Get the session data to check absolute expiration
                let session_json: Option<String> = conn.get(&session_key).await.map_err(|e| {
                    AuthError::Generic(format!("Failed to get session from Redis: {e}"))
                })?;

                if let Some(json) = session_json {
                    let session_data: SessionData = serde_json::from_str(&json).map_err(|e| {
                        AuthError::Generic(format!("Failed to deserialize session data: {e}"))
                    })?;

                    let absolute_expiry = session_data.created_at + session_data.max_age_seconds;

                    // Check if session exceeded absolute maximum age
                    if now > absolute_expiry {
                        // Session expired - delete it and remove from user's set
                        let _: () = conn.del(&session_key).await.map_err(|e| {
                            AuthError::Generic(format!("Failed to delete expired session: {e}"))
                        })?;

                        let _: () = conn
                            .srem(&user_sessions_key, &session_id_str)
                            .await
                            .map_err(|e| {
                                AuthError::Generic(format!(
                                    "Failed to remove expired session from user set: {e}"
                                ))
                            })?;
                    } else {
                        // Session is valid
                        all_valid_sessions.push(session_data);
                    }
                } else {
                    // Session expired via TTL - remove its ID from user's set (lazy cleanup)
                    let _: () = conn
                        .srem(&user_sessions_key, &session_id_str)
                        .await
                        .map_err(|e| {
                            AuthError::Generic(format!(
                                "Failed to remove non-existent session from user set: {e}"
                            ))
                        })?;
                }
            }
        }

        Ok(all_valid_sessions)
    }

    async fn delete_sessions(&self, session_ids: &[&str]) -> AuthResult<()> {
        if session_ids.is_empty() {
            return Ok(());
        }

        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to get Redis connection: {e}")))?;

        for session_id in session_ids {
            let session_key = Self::session_key(session_id);

            // Get session data first to remove from user's set
            let session_json: Option<String> = conn.get(&session_key).await.map_err(|e| {
                AuthError::Generic(format!("Failed to get session from Redis: {e}"))
            })?;

            if let Some(json) = session_json {
                let session_data: SessionData = serde_json::from_str(&json).map_err(|e| {
                    AuthError::Generic(format!("Failed to deserialize session data: {e}"))
                })?;

                let user_sessions_key = Self::user_sessions_key(
                    &session_data.realm_id,
                    &session_data.username,
                    &session_data.auth_scheme,
                );

                // Remove from user's sessions set
                let _: () = conn
                    .srem(&user_sessions_key, *session_id)
                    .await
                    .map_err(|e| {
                        AuthError::Generic(format!("Failed to remove session from user set: {e}"))
                    })?;
            }

            // Delete the session
            let _: () = conn.del(&session_key).await.map_err(|e| {
                AuthError::Generic(format!("Failed to delete session from Redis: {e}"))
            })?;
        }

        Ok(())
    }

    async fn delete_expired_sessions(&self) -> AuthResult<()> {
        // Redis automatically handles expiration via TTL.
        // Expired sessions are automatically removed by Redis, so this is a no-op.
        // The max_stale_age_seconds from the Realm is used when setting TTLs on upsert
        // and refreshing them on access.
        Ok(())
    }

    async fn delete_sessions_for_realm(&self, realm_id: &str) -> AuthResult<()> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to get Redis connection: {e}")))?;

        // Scan for all session keys and collect them first
        let pattern = "session:*";
        let keys = {
            let mut scan = conn
                .scan_match::<&str, String>(pattern)
                .await
                .map_err(|e| AuthError::Generic(format!("Failed to start Redis scan: {e}")))?;

            let mut keys = Vec::new();
            while let Some(key) = scan.next_item().await {
                keys.push(key);
            }
            keys
        }; // scan is dropped here, releasing the borrow on conn

        // Now process each key (scan is complete, conn is available again)
        for session_key in keys {
            let session_json: Option<String> = conn.get(&session_key).await.map_err(|e| {
                AuthError::Generic(format!("Failed to get session from Redis: {e}"))
            })?;

            if let Some(json) = session_json
                && let Ok(session_data) = serde_json::from_str::<SessionData>(&json)
                && session_data.realm_id == realm_id
            {
                // Extract session_id from key (remove "session:" prefix)
                let session_id = session_key.strip_prefix("session:").unwrap_or(&session_key);

                // Remove from user's sessions set
                let user_sessions_key = Self::user_sessions_key(
                    &session_data.realm_id,
                    &session_data.username,
                    &session_data.auth_scheme,
                );
                let _: () = conn
                    .srem(&user_sessions_key, session_id)
                    .await
                    .map_err(|e| {
                        AuthError::Generic(format!("Failed to remove session from user set: {e}"))
                    })?;

                // Delete the session
                let _: () = conn.del(&session_key).await.map_err(|e| {
                    AuthError::Generic(format!("Failed to delete session from Redis: {e}"))
                })?;
            }
        }

        Ok(())
    }
}
