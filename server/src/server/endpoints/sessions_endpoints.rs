use std::{collections::HashSet, sync::Arc};

use crate::{
    AuthError, AuthenticatedClientScheme,
    session::{self},
};
use actix_web::{
    HttpResponse, delete, get, post,
    web::{Data, Json, Path},
};
use auth_client::{
    DeleteSessionsRequest, GetSessionRequest, GetSessionsForClientsRequest,
    GetSessionsForClientsResponse, SessionsAction, UpsertSessionRequest,
};

/// Create or update a session.
#[post("")]
pub async fn upsert_session(
    payload: Json<UpsertSessionRequest>,
    session_store: Data<Arc<dyn session::SessionStore>>,
) -> Result<HttpResponse, AuthError> {
    let payload = payload.into_inner();

    session_store
        .upsert_session(
            &payload.session_id,
            &payload.realm,
            &payload.authenticated_client,
            &payload.session_value,
        )
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

/// Retrieve session information by session ID (simple GET, no session actions).
/// Returns `null` (HTTP 200) when the session does not exist or has expired.
#[get("/{session_id}")]
pub async fn get_session_by_id(
    session_id: Path<String>,
    session_store: Data<Arc<dyn session::SessionStore>>,
) -> Result<HttpResponse, AuthError> {
    let session_id = session_id.into_inner();
    let session_data = session_store.get_session(&session_id).await?;
    Ok(HttpResponse::Ok().json(session_data))
}

/// Retrieve session information by session ID.
/// Optionally perform session actions (logout other sessions, logout all sessions)
/// based on the presence of other authenticated clients in the request payload.
#[post("/{session_id}")]
pub async fn get_session(
    session_id: Path<String>,
    payload: Json<GetSessionRequest>,
    session_store: Data<Arc<dyn session::SessionStore>>,
) -> Result<HttpResponse, AuthError> {
    let session_id = session_id.into_inner();
    let Some(session_data) = session_store.get_session(&session_id).await? else {
        return Err(AuthError::SessionNotFound);
    };

    if let Some(action) = &payload.sessions_action {
        let existing_sessions = session_store
            .get_sessions_for_clients(
                &session_data.realm_id,
                &payload
                    .authenticated_clients
                    .iter()
                    .collect::<Vec<&AuthenticatedClientScheme>>(),
            )
            .await?;
        // logout these sessions by deleting them from the session store
        match action {
            SessionsAction::LogoutOtherSessions => {
                let sessions_to_logout: Vec<&str> = existing_sessions
                    .iter()
                    .filter(|s| s.session_id != session_id)
                    .map(|s| s.session_id.as_str())
                    .collect();
                session_store.delete_sessions(&sessions_to_logout).await?;
            }
            SessionsAction::LogoutAllSessions => {
                let mut sessions_to_logout: HashSet<&str> = existing_sessions
                    .iter()
                    .map(|s| s.session_id.as_str())
                    .collect();
                sessions_to_logout.insert(session_id.as_str());
                session_store
                    .delete_sessions(&sessions_to_logout.into_iter().collect::<Vec<&str>>())
                    .await?;
            }
        }
    }

    Ok(HttpResponse::Ok().json(session_data))
}

/// Retrieve all sessions for a list of clients in a realm.
#[post("/realms/{realm_id}/clients")]
pub async fn get_sessions_for_clients(
    realm_id: Path<String>,
    payload: Json<GetSessionsForClientsRequest>,
    session_store: Data<Arc<dyn session::SessionStore>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm_id.into_inner();
    let payload = payload.into_inner();

    let user_refs: Vec<&AuthenticatedClientScheme> = payload.authenticated_clients.iter().collect();
    let sessions = session_store
        .get_sessions_for_clients(&realm_id, &user_refs)
        .await?;

    Ok(HttpResponse::Ok().json(GetSessionsForClientsResponse {
        session_ids: sessions.iter().map(|s| s.session_id.clone()).collect(),
    }))
}

/// Delete sessions by session IDs.
#[delete("")]
pub async fn delete_sessions(
    payload: Json<DeleteSessionsRequest>,
    session_store: Data<Arc<dyn session::SessionStore>>,
) -> Result<HttpResponse, AuthError> {
    let payload = payload.into_inner();
    let session_id_refs: Vec<&str> = payload.session_ids.iter().map(String::as_str).collect();

    session_store.delete_sessions(&session_id_refs).await?;

    Ok(HttpResponse::NoContent().finish())
}

/// Delete all expired sessions.
#[delete("/expired")]
pub async fn delete_expired_sessions(
    session_store: Data<Arc<dyn session::SessionStore>>,
) -> Result<HttpResponse, AuthError> {
    session_store.delete_expired_sessions().await?;
    Ok(HttpResponse::NoContent().finish())
}

/// Delete all sessions for a given realm.
#[delete("/realms/{realm_id}")]
pub async fn delete_sessions_for_realm(
    realm_id: Path<String>,
    session_store: Data<Arc<dyn session::SessionStore>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm_id.into_inner();
    session_store.delete_sessions_for_realm(&realm_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
