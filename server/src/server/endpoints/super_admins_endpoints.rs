use crate::server::endpoints::admin_from_request;
use crate::{AuthError, database::Database, models::Realm};
use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_logger::info;
use std::sync::Arc;

/// Create a new realm
///
/// # Arguments
/// * `realm` - The realm data to create
/// * `database` - Shared database connection
///
/// # Errors
/// Returns an error if the realm creation fails
#[post("/realm")]
pub async fn create_realm(
    req: HttpRequest,
    realm: Json<Realm>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm = realm.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.is_super_admin() {
        return Err(AuthError::Forbidden(
            "Only super admins can create realms".to_string(),
        ));
    }

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
#[get("/realm/{id}")]
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
/// # Arguments
/// * `id` - The realm ID to update
/// * `realm` - The updated realm data
/// * `database` - Shared database connection
///
/// # Errors
/// Returns an error if the realm update fails
#[put("/realm/{id}")]
pub async fn update_realm(
    req: HttpRequest,
    id: Path<String>,
    realm: Json<Realm>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = id.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.is_super_admin() {
        return Err(AuthError::Forbidden(
            "Only super admins can update realms".to_string(),
        ));
    }

    let mut realm = realm.into_inner();
    // Ensure the ID in the path matches the ID in the payload
    realm.id = realm_id;

    info!(
        "update_realm: '{}' is updating realm '{}'",
        requester.id, realm.id
    );
    database.update_realm(&realm).await?;

    Ok(HttpResponse::Ok().json(realm))
}

/// Delete a realm by ID
///
/// # Arguments
/// * `id` - The realm ID to delete
/// * `database` - Shared database connection
///
/// # Errors
/// Returns an error if the realm deletion fails
#[delete("/realm/{id}")]
pub async fn delete_realm(
    req: HttpRequest,
    id: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = id.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.is_super_admin() {
        return Err(AuthError::Forbidden(
            "Only super admins can delete realms".to_string(),
        ));
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
#[get("/realms")]
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
