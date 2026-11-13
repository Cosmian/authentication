use crate::{AuthenticatedClientScheme, SessionData};
use serde::{Deserialize, Serialize};

/// A session as returned by the `/sessions` API: the stored [`SessionData`] without its
/// `cookie_string`, which is the session credential and is never sent back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub realm_id: String,
    pub username: String,
    pub auth_scheme: String,
    pub max_stale_age_seconds: i64,
    pub max_age_seconds: i64,
    pub created_at: i64,
}

impl From<SessionData> for SessionInfo {
    fn from(session: SessionData) -> Self {
        Self {
            session_id: session.session_id,
            realm_id: session.realm_id,
            username: session.username,
            auth_scheme: session.auth_scheme,
            max_stale_age_seconds: session.max_stale_age_seconds,
            max_age_seconds: session.max_age_seconds,
            created_at: session.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionsAction {
    LogoutOtherSessions,
    LogoutAllSessions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSessionRequest {
    /// Others potential client sessions to consider when retrieving the session information.
    /// The action to take on the session will depend on the `sessions_action` field.
    pub authenticated_clients: Vec<AuthenticatedClientScheme>,

    /// The action to take on the client's sessions based on the presence of other authenticated clients.
    pub sessions_action: Option<SessionsAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSessionsForClientsRequest {
    pub authenticated_clients: Vec<AuthenticatedClientScheme>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSessionsForClientsResponse {
    pub session_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteSessionsRequest {
    pub session_ids: Vec<String>,
}
