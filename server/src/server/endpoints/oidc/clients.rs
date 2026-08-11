//! Admin CRUD endpoints for provisioning OIDC/OAuth 2.0 clients.
//!
//! Mounted under the realm admin scope (`/realms/{realm_id}/clients`), so the
//! existing `ExtractRealm` → `CookieAuthSameServer` → `AdminAuth` middleware
//! stack applies. Authorization is enforced per-realm via
//! [`Admin::can_administer_realm`].

use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_logger::info;

use crate::database::{Database, OAuthClient};
use crate::oidc::tokens::generate_opaque_token;
use crate::server::endpoints::admin_from_request;
use crate::server::endpoints::oidc::common::hash_secret;
use crate::{AuthError, OAuthClientRequest, OAuthClientResponse};

/// Ensure the requester may administer `realm_id`, returning `Forbidden` otherwise.
fn ensure_realm_admin(req: &HttpRequest, realm_id: &str) -> Result<(), AuthError> {
    let admin = admin_from_request(req)?;
    if !admin.can_administer_realm(realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{realm_id}' can manage its OAuth clients"
        )));
    }
    Ok(())
}

/// Map a stored [`OAuthClient`] to a response (never exposes the secret hash).
fn to_response(client: OAuthClient, secret: Option<String>) -> OAuthClientResponse {
    OAuthClientResponse {
        client_id: client.client_id,
        client_secret: secret,
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        response_types: client.response_types,
        scopes: client.scopes,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        realm: client.realm,
        created_at: client.created_at,
    }
}

/// Validate a client-registration request, returning `BadRequest` on invalid input.
fn validate_request(body: &OAuthClientRequest) -> Result<(), AuthError> {
    if body.redirect_uris.is_empty() && body.grant_types.iter().any(|g| g == "authorization_code") {
        return Err(AuthError::BadRequest(
            "authorization_code clients require at least one redirect_uri".to_string(),
        ));
    }
    for uri in &body.redirect_uris {
        if !(uri.starts_with("https://")
            || uri.starts_with("http://localhost")
            || uri.starts_with("http://127.0.0.1"))
        {
            return Err(AuthError::BadRequest(format!(
                "redirect_uri must be https (or http on localhost): {uri}"
            )));
        }
    }
    if body.response_types.iter().any(|r| r != "code") {
        return Err(AuthError::BadRequest(
            "only the 'code' response_type is supported".to_string(),
        ));
    }
    let valid_auth = ["client_secret_basic", "client_secret_post", "none"];
    if !valid_auth.contains(&body.token_endpoint_auth_method.as_str()) {
        return Err(AuthError::BadRequest(format!(
            "unsupported token_endpoint_auth_method: {}",
            body.token_endpoint_auth_method
        )));
    }
    Ok(())
}

/// Create a new OAuth client in the realm.
#[post("/{realm_id}/clients")]
pub async fn create_oauth_client(
    req: HttpRequest,
    realm: Path<String>,
    body: Json<OAuthClientRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm.into_inner();
    ensure_realm_admin(&req, &realm_id)?;
    let body = body.into_inner();
    validate_request(&body)?;

    // Generate a client_id and (for confidential clients) a client_secret.
    let (client_id, _) = generate_opaque_token("client-");
    let is_public = body.token_endpoint_auth_method == "none";
    let (secret_plain, secret_hash) = if is_public {
        (None, None)
    } else {
        let (raw, _) = generate_opaque_token("");
        let hash = hash_secret(&raw);
        (Some(raw), Some(hash))
    };

    let record = OAuthClient {
        client_id: client_id.clone(),
        client_secret_hash: secret_hash,
        client_name: body.client_name,
        redirect_uris: body.redirect_uris,
        grant_types: body.grant_types,
        response_types: body.response_types,
        scopes: body.scopes,
        token_endpoint_auth_method: body.token_endpoint_auth_method,
        realm: realm_id.clone(),
        created_at: chrono::Utc::now().timestamp(),
    };
    database.create_oauth_client(&record).await?;

    let requester = admin_from_request(&req)?;
    info!(
        "create_oauth_client: '{}' created client '{}' in realm '{}'",
        requester.id, client_id, realm_id
    );
    Ok(HttpResponse::Created().json(to_response(record, secret_plain)))
}

/// List all OAuth clients in the realm.
#[get("/{realm_id}/clients")]
pub async fn list_oauth_clients(
    req: HttpRequest,
    realm: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm.into_inner();
    ensure_realm_admin(&req, &realm_id)?;
    let clients = database.list_oauth_clients_by_realm(&realm_id).await?;
    let out: Vec<OAuthClientResponse> = clients.into_iter().map(|c| to_response(c, None)).collect();
    Ok(HttpResponse::Ok().json(out))
}

/// Get a single OAuth client.
#[get("/{realm_id}/clients/{client_id}")]
pub async fn get_oauth_client(
    req: HttpRequest,
    path: Path<(String, String)>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (realm_id, client_id) = path.into_inner();
    ensure_realm_admin(&req, &realm_id)?;
    let client = database
        .get_oauth_client(&client_id)
        .await?
        .filter(|c| c.realm == realm_id)
        .ok_or(AuthError::SessionNotFound)?;
    Ok(HttpResponse::Ok().json(to_response(client, None)))
}

/// Update an OAuth client. A new secret is issued when the client is confidential
/// and `token_endpoint_auth_method` remains secret-based.
#[put("/{realm_id}/clients/{client_id}")]
pub async fn update_oauth_client(
    req: HttpRequest,
    path: Path<(String, String)>,
    body: Json<OAuthClientRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (realm_id, client_id) = path.into_inner();
    ensure_realm_admin(&req, &realm_id)?;
    let body = body.into_inner();
    validate_request(&body)?;

    let existing = database
        .get_oauth_client(&client_id)
        .await?
        .filter(|c| c.realm == realm_id)
        .ok_or(AuthError::SessionNotFound)?;

    // Preserve the existing secret unless the auth method changes to/from `none`.
    let is_public = body.token_endpoint_auth_method == "none";
    let (secret_plain, secret_hash) = if is_public {
        (None, None)
    } else if existing.client_secret_hash.is_some() {
        (None, existing.client_secret_hash.clone())
    } else {
        let (raw, _) = generate_opaque_token("");
        let hash = hash_secret(&raw);
        (Some(raw), Some(hash))
    };

    let record = OAuthClient {
        client_id: client_id.clone(),
        client_secret_hash: secret_hash,
        client_name: body.client_name,
        redirect_uris: body.redirect_uris,
        grant_types: body.grant_types,
        response_types: body.response_types,
        scopes: body.scopes,
        token_endpoint_auth_method: body.token_endpoint_auth_method,
        realm: realm_id,
        created_at: existing.created_at,
    };
    database.update_oauth_client(&record).await?;
    Ok(HttpResponse::Ok().json(to_response(record, secret_plain)))
}

/// Delete an OAuth client.
#[delete("/{realm_id}/clients/{client_id}")]
pub async fn delete_oauth_client(
    req: HttpRequest,
    path: Path<(String, String)>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (realm_id, client_id) = path.into_inner();
    ensure_realm_admin(&req, &realm_id)?;
    // Ensure the client belongs to this realm before deleting.
    let _ = database
        .get_oauth_client(&client_id)
        .await?
        .filter(|c| c.realm == realm_id)
        .ok_or(AuthError::SessionNotFound)?;
    database.delete_oauth_client(&client_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
