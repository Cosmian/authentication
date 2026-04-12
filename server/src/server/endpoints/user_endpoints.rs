//! User CRUD endpoints exposed under the `/users` scope.
//!
//! Every operation reads the authenticated [`crate::models::User`] from the request
//! extensions (injected by the `UserAuth` middleware) and enforces the following
//! authorization rules:
//!
//! | Endpoint | Who may call it |
//! |---|---|
//! | `POST /users/user` | Super admin **or** realm admin (exclusive ownership) |
//! | `GET /users/user/{id}` | Super admin **or** realm admin (exclusive ownership) |
//! | `PUT /users/user/{id}` | Super admin **or** realm admin (exclusive ownership) |
//! | `DELETE /users/user/{id}` | Super admin **or** realm admin (exclusive ownership) |
//! | `GET /users` | Super admin |
//! | `PUT /users/user/{id}/realm/{realm_id}` | Admin of `realm_id` **or** super admin |
//! | `DELETE /users/user/{id}/realm/{realm_id}` | Admin of `realm_id` **or** super admin |

use crate::{AuthError, database::Database, models::User, server::endpoints::user_from_request};
use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_logger::info;
use std::sync::Arc;

/// Create a new user.
///
/// Super admins may create any user.  Realm admins may create a user only if
/// the user's `realms` list is non-empty and every realm it contains is
/// administered by the requester.
#[post("/user")]
pub async fn create_user(
    req: HttpRequest,
    created_user: Json<User>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let user = created_user.into_inner();
    let requester = user_from_request(&req)?;

    if !requester.is_super_admin()
        && (user.realms.is_empty()
            || !user
                .realms
                .iter()
                .all(|r| requester.can_administer_realm(r)))
    {
        return Err(AuthError::Forbidden(
                "Realm admins can only create users that belong exclusively to their administered realms"
                    .to_string(),
            ));
    }

    database.create_user(&user).await?;
    info!("create_user: '{}' created user '{}'", requester.id, user.id);

    Ok(HttpResponse::Created().json(user))
}

/// Retrieve a user by ID.
///
/// Super admins may retrieve any user.  Realm admins may retrieve a user only
/// if the user's `realms` list is non-empty and every realm it contains is
/// administered by the requester (i.e. the user belongs exclusively to the
/// requester's realm(s)).
#[get("/user/{id}")]
pub async fn get_user(
    req: HttpRequest,
    id: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let user_id = id.into_inner();
    let requester = user_from_request(&req)?;

    let target = database
        .get_user(&user_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("User '{}' not found", user_id)))?;

    if !requester.is_super_admin()
        && (target.realms.is_empty()
            || !target
                .realms
                .iter()
                .all(|r| requester.can_administer_realm(r)))
    {
        return Err(AuthError::Forbidden(format!(
            "Access denied: user '{}' does not belong exclusively to your administered realm(s)",
            user_id
        )));
    }

    Ok(HttpResponse::Ok().json(target))
}

/// Update an existing user.
///
/// Super admins may update any user.  Realm admins may update a user only if
/// the user's `realms` list is non-empty and every realm it contains is
/// administered by the requester (exclusive-ownership rule).
///
/// The `id` path parameter is authoritative — the `id` field in the JSON body
/// is overwritten to keep them consistent.
#[put("/user/{id}")]
pub async fn update_user(
    req: HttpRequest,
    id: Path<String>,
    updated_user: Json<User>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let user_id = id.into_inner();
    let mut user = updated_user.into_inner();
    let requester = user_from_request(&req)?;

    if !requester.is_super_admin() {
        let target = database
            .get_user(&user_id)
            .await?
            .ok_or_else(|| AuthError::BadRequest(format!("User '{}' not found", user_id)))?;

        // Check: requester must own the current state of the target user.
        if target.realms.is_empty()
            || !target
                .realms
                .iter()
                .all(|r| requester.can_administer_realm(r))
        {
            return Err(AuthError::Forbidden(format!(
                "Access denied: user '{}' does not belong exclusively to your administered realm(s)",
                user_id
            )));
        }

        // Check: the new realm list in the body must also be exclusively within
        // the requester's authority.  This prevents privilege escalation via a
        // crafted body (e.g. adding `"_"` or a foreign realm to the user's realms).
        if user.realms.is_empty()
            || !user
                .realms
                .iter()
                .all(|r| requester.can_administer_realm(r))
        {
            return Err(AuthError::Forbidden(
                "Realm admins can only assign users to realms they administer".to_string(),
            ));
        }
    }

    info!(
        "update_user: '{}' is updating user '{}'",
        requester.id, user_id
    );

    user.id = user_id;
    database.update_user(&user).await?;

    Ok(HttpResponse::Ok().json(user))
}

/// Delete a user by ID.
///
/// Super admins may delete any user.  Realm admins may delete a user only if
/// the user's `realms` list is non-empty and every realm it contains is
/// administered by the requester (i.e. the user belongs exclusively to the
/// requester's realm(s)).
///
/// Associated `userpass` credentials (if any) are cascade-deleted so that no
/// orphaned entries remain in the `userpass` table.
#[delete("/user/{id}")]
pub async fn delete_user(
    req: HttpRequest,
    id: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let user_id = id.into_inner();
    let requester = user_from_request(&req)?;

    // Fetch the target once — used for both the authorization check and the
    // cascade-delete of associated credentials.
    let target = database.get_user(&user_id).await?;

    if !requester.is_super_admin() {
        let target = target
            .as_ref()
            .ok_or_else(|| AuthError::BadRequest(format!("User '{}' not found", user_id)))?;

        if target.realms.is_empty()
            || !target
                .realms
                .iter()
                .all(|r| requester.can_administer_realm(r))
        {
            return Err(AuthError::Forbidden(format!(
                "Access denied: user '{}' does not belong exclusively to your administered realm(s)",
                user_id
            )));
        }
    }

    info!(
        "delete_user: '{}' is deleting user '{}'",
        requester.id, user_id
    );

    database.delete_user(&user_id).await?;

    // Cascade-delete associated userpass credentials.
    if let Some(username) = target.as_ref().and_then(|u| u.userpass.as_deref()) {
        database.delete_userpass_by_username(username).await?;
    }

    Ok(HttpResponse::NoContent().finish())
}

/// List all users. Super admins only.
///
/// Mapped to the scope root so the full URL is `GET /users`.
#[get("")]
pub async fn list_users(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let requester = user_from_request(&req)?;

    if !requester.is_super_admin() {
        return Err(AuthError::Forbidden(
            "Only super admins can list users".to_string(),
        ));
    }

    let users = database.list_users().await?;
    Ok(HttpResponse::Ok().json(users))
}

/// Grant a user membership in a realm.
///
/// The requester must be an administrator of `realm_id` (or a super admin).
/// If the user is already a member, the request is a no-op.
///
/// Full URL: `PUT /users/user/{id}/realm/{realm_id}`
#[put("/user/{user_id}/realm/{realm_id}")]
pub async fn add_user_to_realm(
    req: HttpRequest,
    path: Path<(String, String)>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (user_id, realm_id) = path.into_inner();
    let requester = user_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can add users to it",
            realm_id
        )));
    }

    let mut user = database
        .get_user(&user_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("User '{}' not found", user_id)))?;

    if !user.realms.contains(&realm_id) {
        user.realms.push(realm_id.clone());
        database.update_user(&user).await?;
        info!(
            "add_user_to_realm: '{}' added user '{}' to realm '{}'",
            requester.id, user_id, realm_id
        );
    }

    Ok(HttpResponse::Ok().json(user))
}

/// Revoke a user's membership in a realm.
///
/// The requester must be an administrator of `realm_id` (or a super admin).
/// If the user is not a member, the request is a no-op.
///
/// Full URL: `DELETE /users/user/{id}/realm/{realm_id}`
#[delete("/user/{user_id}/realm/{realm_id}")]
pub async fn remove_user_from_realm(
    req: HttpRequest,
    path: Path<(String, String)>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (user_id, realm_id) = path.into_inner();
    let requester = user_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can remove users from it",
            realm_id
        )));
    }

    let mut user = database
        .get_user(&user_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("User '{}' not found", user_id)))?;

    let before = user.realms.len();
    user.realms.retain(|r| r != &realm_id);
    if user.realms.len() < before {
        database.update_user(&user).await?;
        info!(
            "remove_user_from_realm: '{}' removed user '{}' from realm '{}'",
            requester.id, user_id, realm_id
        );
    }

    Ok(HttpResponse::Ok().json(user))
}
