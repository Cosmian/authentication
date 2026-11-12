//! Admin CRUD endpoints exposed under the `/admins` scope.
//!
//! Every operation reads the authenticated [`crate::models::Admin`] from the request
//! extensions (injected by the `AdminAuth` middleware) and enforces the following
//! authorization rules:
//!
//! | Endpoint | Who may call it |
//! |---|---|
//! | `POST /admins` | Realm admin (exclusive ownership) **or** super admin, but only for realms that don't have an admin of their own yet |
//! | `GET /admins/{id}` | Super admin (any admin, read-only, to contact the admins of a claimed realm) **or** realm admin (exclusive ownership) |
//! | `PUT /admins/{id}` | Realm admin (exclusive ownership) **or** super admin, but only while the target's realm(s) have no admin of their own; applied to both the current and the new realm list |
//! | `DELETE /admins/{id}` | Same as `PUT /admins/{id}` |
//! | `GET /admins` | Super admin, all admins |
//! | `PUT /admins/{id}/realms/{realm_id}` | Admin of `realm_id` **or** super admin, but only while `realm_id` has no admin of its own yet |
//! | `DELETE /admins/{id}/realms/{realm_id}` | Same as above |
//!
//! An admin with an empty `realms` list is "unaffiliated" and can only be managed by a
//! super admin, unaffected by realm-claim status.

use crate::{
    AuthError,
    database::Database,
    models::{ADMIN_REALM, Admin},
    server::endpoints::{
        admin_from_request, admins_using_login, can_manage_admin_realms, can_manage_realm,
    },
};
use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_logger::info;
use std::sync::Arc;

/// Checks that `requester` may point the admin `admin_id` at the `_` login `userpass`: it must
/// manage every other record using that login (a super admin when none does), and no other record
/// may be linked to it already.
async fn validate_login_link(
    requester: &Admin,
    admin_id: &str,
    userpass: &str,
    database: &Data<Arc<dyn Database>>,
) -> Result<(), AuthError> {
    let others: Vec<Admin> = admins_using_login(database, userpass)
        .await?
        .into_iter()
        .filter(|a| a.id != admin_id)
        .collect();
    let mut allowed = !others.is_empty() || requester.is_super_admin();
    for other in &others {
        allowed &= can_manage_admin_realms(requester, &other.realms, database).await?;
    }
    if !allowed {
        return Err(AuthError::Forbidden(format!(
            "You may only link an admin to the login '{userpass}' if you manage every admin using it"
        )));
    }
    if others
        .iter()
        .any(|a| a.userpass.as_deref() == Some(userpass))
    {
        return Err(AuthError::Conflict(format!(
            "The login '{userpass}' is already linked to another admin"
        )));
    }
    Ok(())
}

/// Create a new admin.
///
/// Realm admins may create an admin only if the admin's `realms` list is
/// non-empty and every realm it contains is administered by the requester.
/// Super admins may do the same, but only for realms that have no admin of
/// their own yet (once a realm has ≥1 admin, only that realm's own admins may
/// add more). An admin with an empty `realms` list may only be created by a
/// super admin.
///
/// `userpass`, the `_` login of the admin, is checked by [`validate_login_link`].
#[post("")]
pub async fn create_admin(
    req: HttpRequest,
    created_admin: Json<Admin>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let admin = created_admin.into_inner();
    let requester = admin_from_request(&req)?;

    if !can_manage_admin_realms(&requester, &admin.realms, &database).await? {
        return Err(AuthError::Forbidden(
                "Realm admins can only create admins that belong exclusively to their administered realms, and super admins can only do so for realms that have no admin of their own yet"
                    .to_string(),
            ));
    }

    if let Some(userpass) = admin.userpass.as_deref() {
        validate_login_link(&requester, &admin.id, userpass, &database).await?;
    }

    database.create_admin(&admin).await?;
    info!(
        "create_admin: '{}' created admin '{}'",
        requester.id, admin.id
    );

    let created = database.get_admin(&admin.id).await?.unwrap_or(admin);
    Ok(HttpResponse::Created().json(created))
}

/// Retrieve an admin by ID.
///
/// Super admins may read any admin, including those of claimed realms, to be able to contact
/// them. Realm admins may retrieve an admin only if the admin's `realms` list is non-empty and
/// every realm it contains is administered by the requester (i.e. the admin belongs exclusively
/// to the requester's realm(s)).
#[get("/{admin_id}")]
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
        && !can_manage_admin_realms(&requester, &target.realms, &database).await?
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
/// The exclusive-ownership rule (every realm of the admin must be one the requester manages)
/// applies to the admin's current `realms` list, plus a second check applying the same rule to the
/// new `realms` list in the request body (privilege-escalation guard).
///
/// The `id` path parameter is authoritative — the `id` field in the JSON body
/// is overwritten to keep them consistent.
///
/// A changed `userpass` is checked by [`validate_login_link`].
#[put("/{admin_id}")]
pub async fn update_admin(
    req: HttpRequest,
    id: Path<String>,
    updated_admin: Json<Admin>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let admin_id = id.into_inner();
    let mut admin = updated_admin.into_inner();
    let requester = admin_from_request(&req)?;

    // Check: requester must own the current state of the target admin.
    let target = database
        .get_admin(&admin_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("Admin '{}' not found", admin_id)))?;

    if !can_manage_admin_realms(&requester, &target.realms, &database).await? {
        return Err(AuthError::Forbidden(format!(
            "Access denied: admin '{}' does not belong exclusively to your administered realm(s)",
            admin_id
        )));
    }

    // Check: the new realm list in the body must also be exclusively within
    // the requester's authority.  This prevents privilege escalation via a
    // crafted body (e.g. adding `"_"` or a foreign/already-claimed realm to
    // the admin's realms).
    if !can_manage_admin_realms(&requester, &admin.realms, &database).await? {
        return Err(AuthError::Forbidden(
            "Realm admins can only assign admins to realms they administer".to_string(),
        ));
    }

    info!(
        "update_admin: '{}' is updating admin '{}'",
        requester.id, admin_id
    );

    if admin.userpass != target.userpass
        && let Some(userpass) = admin.userpass.as_deref()
    {
        validate_login_link(&requester, &admin_id, userpass, &database).await?;
    }

    admin.id = admin_id;
    database.update_admin(&admin).await?;

    let updated = database.get_admin(&admin.id).await?.unwrap_or(admin);
    Ok(HttpResponse::Ok().json(updated))
}

/// Delete an admin by ID.
///
/// The exclusive-ownership rule applies when the admin exists (see [`update_admin`]). Deleting a
/// nonexistent admin is a super-admin-only idempotent no-op (mirrors the
/// nonexistent-admin behavior of the pre-claim-aware authorization rules);
/// a realm admin gets a "not found" error either way.
///
/// The admin's own `_` login is deleted with it, unless another admin record still uses it.
/// Credentials of the same name in other realms are never touched.
#[delete("/{admin_id}")]
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

    match target.as_ref() {
        Some(target) => {
            if !can_manage_admin_realms(&requester, &target.realms, &database).await? {
                return Err(AuthError::Forbidden(format!(
                    "Access denied: admin '{}' does not belong exclusively to your administered realm(s)",
                    admin_id
                )));
            }
        }
        None if !requester.is_super_admin() => {
            return Err(AuthError::BadRequest(format!(
                "Admin '{}' not found",
                admin_id
            )));
        }
        None => {}
    }

    info!(
        "delete_admin: '{}' is deleting admin '{}'",
        requester.id, admin_id
    );

    database.delete_admin(&admin_id).await?;

    // Delete the admin's own `_` login, unless another record uses it.
    if let Some(username) = target.as_ref().and_then(|u| u.userpass.as_deref())
        && admins_using_login(&database, username).await?.is_empty()
    {
        database.delete_userpass(ADMIN_REALM, username).await?;
    }

    Ok(HttpResponse::NoContent().finish())
}

/// List all admins. Super admins only. A super admin sees every admin, including those of claimed
/// realms, to be able to contact them; it still cannot change them (see [`update_admin`]).
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

    Ok(HttpResponse::Ok().json(database.list_admins().await?))
}

/// Grant an admin membership in a realm.
///
/// The requester must be an administrator of `realm_id`, or a super admin
/// acting on a realm that has no admin of its own yet. The target admin must
/// also be one the requester already exclusively owns — i.e. either
/// unaffiliated (empty `realms`, onboarding an admin nobody has claimed yet)
/// or every realm it currently belongs to must itself be one the requester
/// administers. This prevents a realm admin from unilaterally handing their
/// realm to an admin who also serves a foreign realm they don't control.
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

    if !can_manage_realm(&requester, &realm_id, &database).await? {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can add admins to it",
            realm_id
        )));
    }

    let mut admin = database
        .get_admin(&admin_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("Admin '{}' not found", admin_id)))?;

    if !admin.realms.is_empty()
        && !can_manage_admin_realms(&requester, &admin.realms, &database).await?
    {
        return Err(AuthError::Forbidden(format!(
            "Cannot modify admin '{}': it belongs to a realm you don't administer",
            admin_id
        )));
    }

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
/// The requester must be an administrator of `realm_id`, or a super admin
/// acting on a realm that has no admin of its own yet. The target admin must
/// also be one the requester already exclusively owns — every realm it
/// currently belongs to must itself be one the requester administers (see
/// [`add_admin_to_realm`]). This prevents a realm admin from modifying the
/// membership of an admin who also serves a foreign realm they don't
/// control.
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

    if !can_manage_realm(&requester, &realm_id, &database).await? {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can remove admins from it",
            realm_id
        )));
    }

    let mut admin = database
        .get_admin(&admin_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("Admin '{}' not found", admin_id)))?;

    if !can_manage_admin_realms(&requester, &admin.realms, &database).await? {
        return Err(AuthError::Forbidden(format!(
            "Cannot modify admin '{}': it belongs to a realm you don't administer",
            admin_id
        )));
    }

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
