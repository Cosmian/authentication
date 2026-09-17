//! Admin CRUD endpoints exposed under the `/admins` scope.
//!
//! Every operation reads the authenticated [`crate::models::Admin`] from the request
//! extensions (injected by the `AdminAuth` middleware) and enforces the following
//! authorization rules:
//!
//! | Endpoint | Who may call it |
//! |---|---|
//! | `POST /admins` | Realm admin (exclusive ownership) **or** super admin, but only for realms that don't have an admin of their own yet |
//! | `GET /admins/{id}` | Realm admin (exclusive ownership) **or** super admin, but only while the target's realm(s) have no admin of their own |
//! | `PUT /admins/{id}` | Same as `GET /admins/{id}`, applied to both the current and the new realm list |
//! | `DELETE /admins/{id}` | Same as `GET /admins/{id}` |
//! | `GET /admins` | Super admin (results filtered to admins the requester may still see) |
//! | `PUT /admins/{id}/realms/{realm_id}` | Admin of `realm_id` **or** super admin, but only while `realm_id` has no admin of its own yet |
//! | `DELETE /admins/{id}/realms/{realm_id}` | Same as above |
//!
//! An admin with an empty `realms` list is "unaffiliated" and can only be managed by a
//! super admin, unaffected by realm-claim status.

use crate::{
    AuthError,
    database::Database,
    models::Admin,
    server::endpoints::{
        admin_from_request, can_manage_admin_realms, can_manage_realm, realm_manageable_given_claims,
    },
};
use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_logger::info;
use std::collections::HashSet;
use std::sync::Arc;

/// Create a new admin.
///
/// Realm admins may create an admin only if the admin's `realms` list is
/// non-empty and every realm it contains is administered by the requester.
/// Super admins may do the same, but only for realms that have no admin of
/// their own yet (once a realm has ≥1 admin, only that realm's own admins may
/// add more). An admin with an empty `realms` list may only be created by a
/// super admin.
///
/// # TODO — should we enforce `userpass` FK convention
/// The `userpass` field is intended to reference a `UserPass` entry whose
/// `username` matches `admin.id` in the `_` realm.  Currently the server
/// accepts any arbitrary string (or `null`), which means a caller can point one
/// admin at another admin's credentials.  This should be validated:
///   - if `admin.userpass` is `Some`, assert `admin.userpass == admin.id`
///   - ideally create/update the corresponding `_`-realm `UserPass` record
///     atomically in the same request rather than requiring a separate call.
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

    database.create_admin(&admin).await?;
    info!(
        "create_admin: '{}' created admin '{}'",
        requester.id, admin.id
    );

    Ok(HttpResponse::Created().json(admin))
}

/// Retrieve an admin by ID.
///
/// Realm admins may retrieve an admin only if the admin's `realms` list is
/// non-empty and every realm it contains is administered by the requester
/// (i.e. the admin belongs exclusively to the requester's realm(s)). Super
/// admins may do the same, but only while those realm(s) have no admin of
/// their own — since the target here already is one, that only ever holds for
/// an unaffiliated (empty `realms`) admin.
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

    if !can_manage_admin_realms(&requester, &target.realms, &database).await? {
        return Err(AuthError::Forbidden(format!(
            "Access denied: admin '{}' does not belong exclusively to your administered realm(s)",
            admin_id
        )));
    }

    Ok(HttpResponse::Ok().json(target))
}

/// Update an existing admin.
///
/// Same authorization as [`get_admin`], applied to the admin's current
/// `realms` list, plus a second check applying the same rule to the new
/// `realms` list in the request body (privilege-escalation guard).
///
/// The `id` path parameter is authoritative — the `id` field in the JSON body
/// is overwritten to keep them consistent.
///
/// # TODO — enforce `userpass` FK convention
/// See the same note on `create_admin`: `userpass` should equal `admin.id` when
/// set, and the `_`-realm credential should be managed atomically.
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

    admin.id = admin_id;
    database.update_admin(&admin).await?;

    Ok(HttpResponse::Ok().json(admin))
}

/// Delete an admin by ID.
///
/// Same authorization as [`get_admin`] when the admin exists. Deleting a
/// nonexistent admin is a super-admin-only idempotent no-op (mirrors the
/// nonexistent-admin behavior of the pre-claim-aware authorization rules);
/// a realm admin gets a "not found" error either way.
///
/// Associated `userpass` credentials (if any) are cascade-deleted so that no
/// orphaned entries remain in the `userpass` table.
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

    // Cascade-delete associated userpass credentials.
    if let Some(username) = target.as_ref().and_then(|u| u.userpass.as_deref()) {
        database.delete_userpass_by_username(username).await?;
    }

    Ok(HttpResponse::NoContent().finish())
}

/// List all admins. Super admins only, and the result is filtered to the
/// admins the requester may still see (see [`get_admin`]).
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

    // Compute the claimed-realm set once from the list already fetched above,
    // instead of calling `database.list_admins()` again for every admin in
    // it (each of which could itself re-scan every realm it has).
    let claimed_realms: HashSet<String> = admins
        .iter()
        .flat_map(|a| a.realms.iter().cloned())
        .collect();

    let visible: Vec<_> = admins
        .into_iter()
        .filter(|admin| {
            if admin.realms.is_empty() {
                requester.is_super_admin()
            } else {
                admin
                    .realms
                    .iter()
                    .all(|r| realm_manageable_given_claims(&requester, r, &claimed_realms))
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(visible))
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

    if !admin.realms.is_empty() && !can_manage_admin_realms(&requester, &admin.realms, &database).await? {
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
