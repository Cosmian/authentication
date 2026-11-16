//! Session endpoints exposed under `/sessions`.
//!
//! Every call needs a valid session cookie, and what it may touch depends on who the caller is:
//!
//! - any client acts on its **own** sessions: same realm and username, whatever the login scheme;
//! - an admin (session opened on the admin realm) also acts on the sessions of every realm it may
//!   manage, i.e. [`can_manage_realm`]: its own realms, and, for a super admin, the realms that
//!   have no admin of their own yet;
//! - purging expired sessions is reserved to super admins.
//!
//! A session the caller may not access looks like a missing one. The stored cookie value is a live
//! credential and is never returned.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    AuthError, AuthResult, AuthenticatedClientScheme,
    database::Database,
    middleware::find_admin_for_claims,
    models::{Admin, ClientClaims, SessionData},
    server::endpoints::can_manage_realm,
    session::{self},
};
use actix_web::{
    HttpMessage, HttpRequest, HttpResponse, delete, get, post,
    web::{Data, Json, Path},
};
use auth_client::{
    DeleteSessionsRequest, GetSessionRequest, GetSessionsForClientsRequest,
    GetSessionsForClientsResponse, SessionInfo, SessionsAction,
};

/// The principal behind a `/sessions` call, taken from its session cookie.
struct Caller {
    realm_id: String,
    username: String,
    /// Set when the session was opened on the admin realm by an admin.
    admin: Option<Admin>,
}

impl Caller {
    async fn from_request(
        req: &HttpRequest,
        database: &Data<Arc<dyn Database>>,
    ) -> AuthResult<Self> {
        let claims = req
            .extensions()
            .get::<ClientClaims>()
            .cloned()
            .ok_or_else(|| AuthError::Session("no client claims found in request".to_string()))?;
        let realm_id =
            claims.private.realm_id.clone().ok_or_else(|| {
                AuthError::Session("no realm found in session claims".to_string())
            })?;
        let username =
            claims.registered.sub.clone().ok_or_else(|| {
                AuthError::Session("no subject found in session claims".to_string())
            })?;
        let admin = find_admin_for_claims(database.get_ref().as_ref(), &claims).await?;
        Ok(Self {
            realm_id,
            username,
            admin,
        })
    }

    fn owns(&self, session: &SessionData) -> bool {
        session.realm_id == self.realm_id && session.username == self.username
    }

    async fn manages_realm(
        &self,
        realm_id: &str,
        database: &Data<Arc<dyn Database>>,
    ) -> AuthResult<bool> {
        match &self.admin {
            Some(admin) => can_manage_realm(admin, realm_id, database).await,
            None => Ok(false),
        }
    }

    async fn may_access(
        &self,
        session: &SessionData,
        database: &Data<Arc<dyn Database>>,
    ) -> AuthResult<bool> {
        Ok(self.owns(session) || self.manages_realm(&session.realm_id, database).await?)
    }

    /// The session `session_id`, or `None` if it does not exist or the caller may not access it.
    async fn accessible_session(
        &self,
        session_id: &str,
        session_store: &Data<Arc<dyn session::SessionStore>>,
        database: &Data<Arc<dyn Database>>,
    ) -> AuthResult<Option<SessionData>> {
        let Some(session) = session_store.get_session(session_id).await? else {
            return Ok(None);
        };
        Ok(self
            .may_access(&session, database)
            .await?
            .then_some(session))
    }

    /// Checks that the caller may look up or log out the sessions of `clients` in `realm_id`:
    /// admins of the realm any client, everybody else only themselves.
    async fn require_clients(
        &self,
        realm_id: &str,
        clients: &[AuthenticatedClientScheme],
        database: &Data<Arc<dyn Database>>,
    ) -> AuthResult<()> {
        let only_self =
            realm_id == self.realm_id && clients.iter().all(|c| c.username == self.username);
        if only_self || self.manages_realm(realm_id, database).await? {
            Ok(())
        } else {
            Err(AuthError::Forbidden(format!(
                "You may only manage your own sessions, or those of a realm you administer ('{realm_id}')"
            )))
        }
    }
}

/// Retrieve session information by session ID (simple GET, no session actions).
/// Returns `null` (HTTP 200) when the session does not exist, has expired, or belongs to
/// someone the caller may not manage.
#[get("/{session_id}")]
pub async fn get_session_by_id(
    req: HttpRequest,
    session_id: Path<String>,
    session_store: Data<Arc<dyn session::SessionStore>>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let caller = Caller::from_request(&req, &database).await?;
    let session = caller
        .accessible_session(&session_id.into_inner(), &session_store, &database)
        .await?;
    Ok(HttpResponse::Ok().json(session.map(SessionInfo::from)))
}

/// Retrieve session information by session ID.
/// Optionally perform session actions (logout other sessions, logout all sessions)
/// based on the presence of other authenticated clients in the request payload.
#[post("/{session_id}")]
pub async fn get_session(
    req: HttpRequest,
    session_id: Path<String>,
    payload: Json<GetSessionRequest>,
    session_store: Data<Arc<dyn session::SessionStore>>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let session_id = session_id.into_inner();
    let caller = Caller::from_request(&req, &database).await?;
    let Some(session_data) = caller
        .accessible_session(&session_id, &session_store, &database)
        .await?
    else {
        return Err(AuthError::SessionNotFound);
    };

    if let Some(action) = &payload.sessions_action {
        caller
            .require_clients(
                &session_data.realm_id,
                &payload.authenticated_clients,
                &database,
            )
            .await?;
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

    Ok(HttpResponse::Ok().json(SessionInfo::from(session_data)))
}

/// Retrieve all sessions for a list of clients in a realm.
#[post("/realms/{realm_id}/clients")]
pub async fn get_sessions_for_clients(
    req: HttpRequest,
    realm_id: Path<String>,
    payload: Json<GetSessionsForClientsRequest>,
    session_store: Data<Arc<dyn session::SessionStore>>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm_id.into_inner();
    let payload = payload.into_inner();
    let caller = Caller::from_request(&req, &database).await?;
    caller
        .require_clients(&realm_id, &payload.authenticated_clients, &database)
        .await?;

    let user_refs: Vec<&AuthenticatedClientScheme> = payload.authenticated_clients.iter().collect();
    let sessions = session_store
        .get_sessions_for_clients(&realm_id, &user_refs)
        .await?;

    Ok(HttpResponse::Ok().json(GetSessionsForClientsResponse {
        session_ids: sessions.iter().map(|s| s.session_id.clone()).collect(),
    }))
}

/// Delete sessions by session IDs. Sessions the caller may not access are skipped, like missing
/// ones.
#[delete("")]
pub async fn delete_sessions(
    req: HttpRequest,
    payload: Json<DeleteSessionsRequest>,
    session_store: Data<Arc<dyn session::SessionStore>>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let payload = payload.into_inner();
    let caller = Caller::from_request(&req, &database).await?;
    let mut managed_realms: HashMap<String, bool> = HashMap::new();
    let mut deletable: Vec<&str> = Vec::new();
    for session_id in &payload.session_ids {
        let Some(session) = session_store.get_session(session_id).await? else {
            continue;
        };
        let allowed = if caller.owns(&session) {
            true
        } else if let Some(&managed) = managed_realms.get(&session.realm_id) {
            managed
        } else {
            let managed = caller.manages_realm(&session.realm_id, &database).await?;
            managed_realms.insert(session.realm_id.clone(), managed);
            managed
        };
        if allowed {
            deletable.push(session_id);
        }
    }

    session_store.delete_sessions(&deletable).await?;

    Ok(HttpResponse::NoContent().finish())
}

/// Delete all expired sessions. Super admins only.
#[delete("/expired")]
pub async fn delete_expired_sessions(
    req: HttpRequest,
    session_store: Data<Arc<dyn session::SessionStore>>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let caller = Caller::from_request(&req, &database).await?;
    if !caller.admin.as_ref().is_some_and(Admin::is_super_admin) {
        return Err(AuthError::Forbidden(
            "Only super admins can purge expired sessions".to_string(),
        ));
    }
    session_store.delete_expired_sessions().await?;
    Ok(HttpResponse::NoContent().finish())
}

/// Delete all sessions for a given realm. Admins of that realm only.
#[delete("/realms/{realm_id}")]
pub async fn delete_sessions_for_realm(
    req: HttpRequest,
    realm_id: Path<String>,
    session_store: Data<Arc<dyn session::SessionStore>>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm_id.into_inner();
    let caller = Caller::from_request(&req, &database).await?;
    if !caller.manages_realm(&realm_id, &database).await? {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{realm_id}' can revoke all its sessions"
        )));
    }
    session_store.delete_sessions_for_realm(&realm_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
