use crate::{AuthenticatedClientScheme, Realm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertSessionRequest {
    pub session_id: String,
    pub realm: Realm,
    pub authenticated_client: AuthenticatedClientScheme,
    pub session_value: String,
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
