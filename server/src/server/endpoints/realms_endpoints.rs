use crate::{
    AuthError, database::Database, models::UserPass, server::endpoints::admin_from_request,
};
use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_logger::info;
use std::sync::Arc;

/// Create a new user password entry.
///
/// The requester must administer the realm specified in the path.
#[post("/{realm_id}/userpass")]
pub async fn create_userpass(
    req: HttpRequest,
    realm: Path<String>,
    userpass: Json<UserPass>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can manage its credentials",
            realm_id
        )));
    }

    let mut userpass = userpass.into_inner();
    userpass.realm = realm_id.clone();

    database.create_userpass(&userpass).await?;
    info!(
        "create_userpass: '{}' created credentials for '{}' in realm '{}'",
        requester.id, userpass.username, realm_id
    );

    Ok(HttpResponse::Created().json(userpass))
}

/// Get a user password entry by realm and username.
///
/// The requester must administer the realm specified in the path.
#[get("/{realm_id}/userpass/{username}")]
pub async fn get_userpass(
    req: HttpRequest,
    params: Path<(String, String)>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (realm, username) = params.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.can_administer_realm(&realm) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can manage its credentials",
            realm
        )));
    }

    match database.get_userpass(&realm, &username).await? {
        Some(mut userpass) => {
            // Never return the stored password hash to callers.
            userpass.password = Vec::new();
            Ok(HttpResponse::Ok().json(userpass))
        }
        None => Err(AuthError::BadRequest(format!(
            "User password entry for '{}' in realm '{}' not found",
            username, realm
        ))),
    }
}

/// Update an existing user password entry.
///
/// The requester must administer the realm specified in the path.
#[put("/{realm_id}/userpass/{username}")]
pub async fn update_userpass(
    req: HttpRequest,
    params: Path<(String, String)>,
    userpass: Json<UserPass>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (realm, username) = params.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.can_administer_realm(&realm) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can manage its credentials",
            realm
        )));
    }

    let mut userpass = userpass.into_inner();
    userpass.realm = realm.clone();
    userpass.username = username.clone();

    database.update_userpass(&userpass).await?;
    info!(
        "update_userpass: '{}' updated credentials for '{}' in realm '{}'",
        requester.id, username, realm
    );

    Ok(HttpResponse::Ok().json(userpass))
}

/// Delete a user password entry by realm and username.
///
/// The requester must administer the realm specified in the path.
#[delete("/{realm_id}/userpass/{username}")]
pub async fn delete_userpass(
    req: HttpRequest,
    params: Path<(String, String)>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (realm, username) = params.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.can_administer_realm(&realm) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can manage its credentials",
            realm
        )));
    }

    database.delete_userpass(&realm, &username).await?;
    info!(
        "delete_userpass: '{}' deleted credentials for '{}' in realm '{}'",
        requester.id, username, realm
    );

    Ok(HttpResponse::NoContent().finish())
}

/// List all user password entries for a specific realm.
///
/// The requester must administer the realm specified in the path.
#[get("/{realm_id}/userpass")]
pub async fn list_userpass_by_realm(
    req: HttpRequest,
    realm: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can manage its credentials",
            realm_id
        )));
    }

    let userpass_list = database.list_userpass_by_realm(&realm_id).await?;

    Ok(HttpResponse::Ok().json(userpass_list))
}

/// List all user password entries across all realms. Super admins only.
#[get("/userpass")]
pub async fn list_all_userpass(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let requester = admin_from_request(&req)?;

    if !requester.is_super_admin() {
        return Err(AuthError::Forbidden(
            "Only super admins can list all credentials".to_string(),
        ));
    }

    let userpass_list = database.list_all_userpass().await?;

    Ok(HttpResponse::Ok().json(userpass_list))
}
