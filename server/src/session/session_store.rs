use async_trait::async_trait;

use crate::{AuthResult, AuthenticatedClientScheme, Realm, models::SessionData};

#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Create or update a session for the given client in the specified realm.
    async fn upsert_session(
        &self,
        session_id: &str,
        realm: &Realm,
        authenticated_client: &AuthenticatedClientScheme,
        session_value: &str,
    ) -> AuthResult<()>;

    /// Retrieve the session value by session ID.
    /// Returns None if the session does not exist or is expired.
    async fn get_session(&self, session_id: &str) -> AuthResult<Option<SessionData>>;

    /// Retrieve all sessions for a given client in a realm.
    /// This can be used to implement "logout from all devices" functionality.
    async fn get_sessions_for_clients(
        &self,
        realm_id: &str,
        authenticated_clients: &[&AuthenticatedClientScheme],
    ) -> AuthResult<Vec<SessionData>>;

    /// Deletes sessions by their session IDs.
    /// This can be used to implement "logout from this device" or "logout from all devices" functionality.
    async fn delete_sessions(&self, session_ids: &[&str]) -> AuthResult<()>;

    /// Delete all expired sessions.
    /// This can be called periodically (e.g., via a background task) to clean up old sessions.
    async fn delete_expired_sessions(&self) -> AuthResult<()>;

    /// Delete all sessions for a given realm.
    /// This can be used when a realm is deleted to clean up associated sessions,
    /// or to "kick all users out" of a realm when critical changes are made.
    async fn delete_sessions_for_realm(&self, realm_id: &str) -> AuthResult<()>;
}
