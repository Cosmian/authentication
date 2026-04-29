//! Admin CRUD endpoints exposed under the `/admins` scope.
//!
//! Every operation reads the authenticated [`crate::models::Admin`] from the request
//! extensions (injected by the `AdminAuth` middleware) and enforces the following
//! authorization rules:
//!
//! | Endpoint | Who may call it |
//! |---|---|
//! | `POST /admins` | Super admin **or** realm admin (exclusive ownership) |
//! | `GET /admins/{id}` | Super admin **or** realm admin (exclusive ownership) |
//! | `PUT /admins/{id}` | Super admin **or** realm admin (exclusive ownership) |
//! | `DELETE /admins/{id}` | Super admin **or** realm admin (exclusive ownership) |
//! | `GET /admins` | Super admin |
//! | `PUT /admins/{id}/realms/{realm_id}` | Admin of `realm_id` **or** super admin |
//! | `DELETE /admins/{id}/realms/{realm_id}` | Admin of `realm_id` **or** super admin |

use crate::{AuthError, database::Database, models::Admin, server::endpoints::admin_from_request};
use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_logger::info;
use std::sync::Arc;

/// Create a new admin.
///
/// Super admins may create any admin.  Realm admins may create an admin only if
/// the admin's `realms` list is non-empty and every realm it contains is
/// administered by the requester.
#[post("")]
pub async fn create_admin(
    req: HttpRequest,
    created_admin: Json<Admin>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let admin = created_admin.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.is_super_admin()
        && (admin.realms.is_empty()
            || !admin
                .realms
                .iter()
                .all(|r| requester.can_administer_realm(r)))
    {
        return Err(AuthError::Forbidden(
                "Realm admins can only create admins that belong exclusively to their administered realms"
                    .to_string(),
            ));
    }

    database.create_admin(&admin).await?;
    info!(
        "create_admin: '{}' created admin '{}'",
        requester.id, admin.id
    );

    Ok(HttpResponse::Created().json(admin))
}

/// Retrieve an admin by ID.
///
/// Super admins may retrieve any admin.  Realm admins may retrieve an admin only
/// if the admin's `realms` list is non-empty and every realm it contains is
/// administered by the requester (i.e. the admin belongs exclusively to the
/// requester's realm(s)).
#[get("/{id}")]
pub async fn get_admin(
    req: HttpRequest,
    id: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let admin_id = id.into_inner();
    let requester = admin_from_request(&req)?;

    let target = database
        .get_admin(&admin_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("Admin '{}' not found", admin_id)))?;

    if !requester.is_super_admin()
        && (target.realms.is_empty()
            || !target
                .realms
                .iter()
                .all(|r| requester.can_administer_realm(r)))
    {
        return Err(AuthError::Forbidden(format!(
            "Access denied: admin '{}' does not belong exclusively to your administered realm(s)",
            admin_id
        )));
    }

    Ok(HttpResponse::Ok().json(target))
}

/// Update an existing admin.
///
/// Super admins may update any admin.  Realm admins may update an admin only if
/// the admin's `realms` list is non-empty and every realm it contains is
/// administered by the requester (exclusive-ownership rule).
///
/// The `id` path parameter is authoritative — the `id` field in the JSON body
/// is overwritten to keep them consistent.
#[put("/{id}")]
pub async fn update_admin(
    req: HttpRequest,
    id: Path<String>,
    updated_admin: Json<Admin>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let admin_id = id.into_inner();
    let mut admin = updated_admin.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.is_super_admin() {
        let target = database
            .get_admin(&admin_id)
            .await?
            .ok_or_else(|| AuthError::BadRequest(format!("Admin '{}' not found", admin_id)))?;

        // Check: requester must own the current state of the target admin.
        if target.realms.is_empty()
            || !target
                .realms
                .iter()
                .all(|r| requester.can_administer_realm(r))
        {
            return Err(AuthError::Forbidden(format!(
                "Access denied: admin '{}' does not belong exclusively to your administered realm(s)",
                admin_id
            )));
        }

        // Check: the new realm list in the body must also be exclusively within
        // the requester's authority.  This prevents privilege escalation via a
        // crafted body (e.g. adding `"_"` or a foreign realm to the admin's realms).
        if admin.realms.is_empty()
            || !admin
                .realms
                .iter()
                .all(|r| requester.can_administer_realm(r))
        {
            return Err(AuthError::Forbidden(
                "Realm admins can only assign admins to realms they administer".to_string(),
            ));
        }
    }

    info!(
        "update_admin: '{}' is updating admin '{}'",
        requester.id, admin_id
    );

    admin.id = admin_id;
    database.update_admin(&admin).await?;

    Ok(HttpResponse::Ok().json(admin))
}

/// Delete an admin by ID.
///
/// Super admins may delete any admin.  Realm admins may delete an admin only if
/// the admin's `realms` list is non-empty and every realm it contains is
/// administered by the requester (i.e. the admin belongs exclusively to the
/// requester's realm(s)).
///
/// Associated `userpass` credentials (if any) are cascade-deleted so that no
/// orphaned entries remain in the `userpass` table.
#[delete("/{id}")]
pub async fn delete_admin(
    req: HttpRequest,
    id: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let admin_id = id.into_inner();
    let requester = admin_from_request(&req)?;

    // Fetch the target once — used for both the authorization check and the
    // cascade-delete of associated credentials.
    let target = database.get_admin(&admin_id).await?;

    if !requester.is_super_admin() {
        let target = target
            .as_ref()
            .ok_or_else(|| AuthError::BadRequest(format!("Admin '{}' not found", admin_id)))?;

        if target.realms.is_empty()
            || !target
                .realms
                .iter()
                .all(|r| requester.can_administer_realm(r))
        {
            return Err(AuthError::Forbidden(format!(
                "Access denied: admin '{}' does not belong exclusively to your administered realm(s)",
                admin_id
            )));
        }
    }

    info!(
        "delete_admin: '{}' is deleting admin '{}'",
        requester.id, admin_id
    );

    database.delete_admin(&admin_id).await?;

    // Cascade-delete associated userpass credentials.
    if let Some(username) = target.as_ref().and_then(|u| u.userpass.as_deref()) {
        database.delete_userpass_by_username(username).await?;
    }

    Ok(HttpResponse::NoContent().finish())
}

/// List all admins. Super admins only.
///
/// Mapped to the scope root so the full URL is `GET /admins`.
#[get("")]
pub async fn list_admins(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let requester = admin_from_request(&req)?;

    if !requester.is_super_admin() {
        return Err(AuthError::Forbidden(
            "Only super admins can list admins".to_string(),
        ));
    }

    let admins = database.list_admins().await?;
    Ok(HttpResponse::Ok().json(admins))
}

/// Grant an admin membership in a realm.
///
/// The requester must be an administrator of `realm_id` (or a super admin).
/// If the admin is already a member, the request is a no-op.
///
/// Full URL: `PUT /admins/{id}/realms/{realm_id}`
#[put("/{admin_id}/realms/{realm_id}")]
pub async fn add_admin_to_realm(
    req: HttpRequest,
    path: Path<(String, String)>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (admin_id, realm_id) = path.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can add admins to it",
            realm_id
        )));
    }

    let mut admin = database
        .get_admin(&admin_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("Admin '{}' not found", admin_id)))?;

    if !admin.realms.contains(&realm_id) {
        admin.realms.push(realm_id.clone());
        database.update_admin(&admin).await?;
        info!(
            "add_admin_to_realm: '{}' added admin '{}' to realm '{}'",
            requester.id, admin_id, realm_id
        );
    }

    Ok(HttpResponse::Ok().json(admin))
}

/// Revoke an admin's membership in a realm.
///
/// The requester must be an administrator of `realm_id` (or a super admin).
/// If the admin is not a member, the request is a no-op.
///
/// Full URL: `DELETE /admins/{id}/realms/{realm_id}`
#[delete("/{admin_id}/realms/{realm_id}")]
pub async fn remove_admin_from_realm(
    req: HttpRequest,
    path: Path<(String, String)>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (admin_id, realm_id) = path.into_inner();
    let requester = admin_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can remove admins from it",
            realm_id
        )));
    }

    let mut admin = database
        .get_admin(&admin_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("Admin '{}' not found", admin_id)))?;

    let before = admin.realms.len();
    admin.realms.retain(|r| r != &realm_id);
    if admin.realms.len() < before {
        database.update_admin(&admin).await?;
        info!(
            "remove_admin_from_realm: '{}' removed admin '{}' from realm '{}'",
            requester.id, admin_id, realm_id
        );
    }

    Ok(HttpResponse::Ok().json(admin))
}
