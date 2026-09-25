use crate::server::endpoints::{admin_from_request, can_manage_realm};
use crate::server::parameters::ServerParams;
use crate::{AuthError, database::Database, models::Realm};
use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_logger::info;
use std::sync::Arc;

/// Validate a realm's SAML settings and fill in the IdP fields from its metadata. SAML
/// realms need the server's SP signing key, so they are refused while none is configured.
#[cfg(feature = "saml")]
fn check_saml_params(realm: &mut Realm, server_params: &ServerParams) -> Result<(), AuthError> {
    let Some(params) = realm.auth_params.saml_params.as_mut() else {
        return Ok(());
    };
    if server_params.saml_sp_params.is_none() {
        return Err(AuthError::BadRequest(
            "SAML needs a server signing key: set `saml_sp_params` in the server configuration"
                .to_string(),
        ));
    }
    crate::saml::validate_saml_params(params, &realm.id)
}

/// Without the `saml` feature there are no SAML endpoints and no way to validate SAML
/// settings, so they are refused instead of being stored unvalidated.
#[cfg(not(feature = "saml"))]
fn check_saml_params(realm: &mut Realm, _server_params: &ServerParams) -> Result<(), AuthError> {
    if realm.auth_params.saml_params.is_some() {
        return Err(AuthError::BadRequest(
            "SAML is not enabled on this server (built without the `saml` feature)".to_string(),
        ));
    }
    Ok(())
}

/// Create a new realm
///
/// # Arguments
/// * `realm` - The realm data to create
/// * `database` - Shared database connection
///
/// # Errors
/// Returns an error if the realm creation fails
#[post("")]
pub async fn create_realm(
    req: HttpRequest,
    realm: Json<Realm>,
    database: Data<Arc<dyn Database>>,
    server_params: Data<Arc<ServerParams>>,
) -> Result<HttpResponse, AuthError> {
    let mut realm = realm.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.is_super_admin() {
        return Err(AuthError::Forbidden(
            "Only super admins can create realms".to_string(),
        ));
    }

    check_saml_params(&mut realm, &server_params)?;

    info!(
        "create_realm: authenticated admin '{}' is creating realm '{}'",
        requester.id, realm.id
    );

    database.create_realm(&realm).await?;

    Ok(HttpResponse::Created().json(realm))
}

/// Get a realm by ID
///
/// # Arguments
/// * `id` - The realm ID to retrieve
/// * `database` - Shared database connection
///
/// # Errors
/// Returns an error if the realm is not found or retrieval fails
#[get("/{realm_id}")]
pub async fn get_realm(
    req: HttpRequest,
    id: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = id.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(
            "Admin does not have permission to retrieve this realm".to_string(),
        ));
    }

    match database.get_realm(&realm_id).await? {
        Some(realm) => Ok(HttpResponse::Ok().json(realm)),
        None => Err(AuthError::BadRequest(format!(
            "Realm '{}' not found",
            realm_id
        ))),
    }
}

/// Update an existing realm
///
/// The requester must administer the realm: either be a direct member, or be
/// a super admin acting on a realm that has no admin of its own yet. Once a
/// realm has ≥1 admin, only that realm's own admins may update its config.
///
/// # Arguments
/// * `id` - The realm ID to update
/// * `realm` - The updated realm data
/// * `database` - Shared database connection
///
/// # Errors
/// Returns an error if the realm update fails
#[put("/{realm_id}")]
pub async fn update_realm(
    req: HttpRequest,
    id: Path<String>,
    realm: Json<Realm>,
    database: Data<Arc<dyn Database>>,
    server_params: Data<Arc<ServerParams>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = id.into_inner();
    let requester = admin_from_request(&req)?;

    if !can_manage_realm(&requester, &realm_id, &database).await? {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can update it",
            realm_id
        )));
    }

    let mut realm = realm.into_inner();
    // Ensure the ID in the path matches the ID in the payload
    realm.id = realm_id;

    check_saml_params(&mut realm, &server_params)?;

    info!(
        "update_realm: '{}' is updating realm '{}'",
        requester.id, realm.id
    );
    database.update_realm(&realm).await?;

    Ok(HttpResponse::Ok().json(realm))
}

/// Delete a realm by ID
///
/// Unlike [`update_realm`], deletion is always available to a super admin,
/// regardless of whether the realm already has its own admin(s) — this is the
/// safety net that lets an abandoned realm be cleaned up even if its admins
/// never do it themselves. The realm's own admins may also delete it.
///
/// # Arguments
/// * `id` - The realm ID to delete
/// * `database` - Shared database connection
///
/// # Errors
/// Returns an error if the realm deletion fails
#[delete("/{realm_id}")]
pub async fn delete_realm(
    req: HttpRequest,
    id: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = id.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' (or a super admin) can delete it",
            realm_id
        )));
    }

    info!(
        "delete_realm: '{}' is deleting realm '{}'",
        requester.id, realm_id
    );
    database.delete_realm(&realm_id).await?;

    Ok(HttpResponse::NoContent().finish())
}

/// List all realms
///
/// # Arguments
/// * `database` - Shared database connection
///
/// # Errors
/// Returns an error if listing realms fails
#[get("")]
pub async fn list_realms(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let requester = admin_from_request(&req)?;
    let realms = database.list_realms().await?;

    let visible: Vec<_> = if requester.is_super_admin() {
        realms
    } else {
        realms
            .into_iter()
            .filter(|r| requester.can_administer_realm(&r.id))
            .collect()
    };

    Ok(HttpResponse::Ok().json(visible))
}
