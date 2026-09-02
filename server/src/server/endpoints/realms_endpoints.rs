use crate::{
    AuthError,
    database::{AuthDbError, Database, hash_password_with_argon2, validate_argon2_phc_string},
    models::{ADMIN_REALM, UserPass, reject_reserved_claim_names, validate_extra_claims_size},
    server::endpoints::admin_from_request,
};
use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_logger::info;
use std::sync::Arc;
use zeroize::Zeroizing;

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

    if let Some(extra_claims) = &userpass.extra_claims {
        reject_reserved_claim_names(extra_claims.keys())?;
        validate_extra_claims_size(extra_claims)?;
    }

    // Exactly one of `password` (plaintext, hashed below) / `hashed_password` (a
    // pre-computed Argon2 PHC string, stored as-is — e.g. migrating credentials already
    // hashed by another Argon2-based system) must be provided.
    match (
        userpass.password.is_empty(),
        userpass.hashed_password.take(),
    ) {
        (false, None) => {
            let plaintext =
                Zeroizing::new(String::from_utf8(userpass.password).map_err(|e| {
                    AuthError::BadRequest(format!("Password is not valid UTF-8: {e}"))
                })?);
            userpass.password = hash_password_with_argon2(&plaintext)
                .map_err(|e| AuthError::Unexpected(format!("Failed to hash password: {e}")))?;
        }
        (true, Some(hashed)) => {
            validate_argon2_phc_string(&hashed)?;
            userpass.password = hashed.into_bytes();
        }
        (true, None) => {
            return Err(AuthError::BadRequest(
                "either 'password' or 'hashed_password' must be provided".to_string(),
            ));
        }
        (false, Some(_)) => {
            return Err(AuthError::BadRequest(
                "'password' and 'hashed_password' are mutually exclusive".to_string(),
            ));
        }
    };

    match database.create_userpass(&userpass).await {
        Ok(()) => {}
        // A conflicting (realm, username) is always rejected, even on a byte-for-byte
        // resubmission: telling the two cases apart requires verifying the submitted
        // password against the stored hash, which turns this admin-authenticated,
        // unrate-limited endpoint into a password-guessing oracle. Clients that need
        // idempotent provisioning should use PUT instead.
        Err(AuthDbError::Conflict(_)) => {
            return Err(AuthError::Conflict(format!(
                "credentials for '{}' already exist in realm '{}' — use PUT to update them",
                userpass.username, realm_id
            )));
        }
        Err(e) => return Err(e.into()),
    }

    // Auto-link: when creating a credential in the admin realm, if an admin
    // exists with a matching id, set its `userpass` field to enable login.
    if realm_id == ADMIN_REALM
        && let Some(mut admin) = database.get_admin(&userpass.username).await?
        && admin.userpass.as_deref() != Some(&userpass.username)
    {
        admin.userpass = Some(userpass.username.clone());
        database.update_admin(&admin).await?;
    }

    info!(
        "create_userpass: '{}' created credentials for '{}' in realm '{}'",
        requester.id, userpass.username, realm_id
    );

    // Never return the stored password hash to callers — matches get_userpass.
    userpass.password = Vec::new();
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

    if let Some(extra_claims) = &userpass.extra_claims {
        reject_reserved_claim_names(extra_claims.keys())?;
        validate_extra_claims_size(extra_claims)?;
    }

    // Hash the new plaintext password / validate-and-store the new pre-hashed password if
    // either was provided; otherwise preserve the existing hash by only updating the
    // metadata fields (roles, change_password). Clients send password: [] and no
    // hashed_password when only updating roles/flags (GET always returns password: []).
    match (
        userpass.password.is_empty(),
        userpass.hashed_password.take(),
    ) {
        (true, None) => {
            // `update_userpass_metadata` only persists roles/change_password — it has no
            // column to write extra_claims through. Silently dropping a genuine change
            // there would report success while not applying it, so only allow this path
            // when extra_claims is absent or unchanged from what's already stored.
            if let Some(requested) = &userpass.extra_claims {
                let existing = database.get_userpass(&realm, &username).await?;
                let unchanged =
                    existing.is_some_and(|e| e.extra_claims.as_ref() == Some(requested));
                if !unchanged {
                    return Err(AuthError::BadRequest(
                        "extra_claims cannot be changed without also providing 'password' or 'hashed_password' in the same request".to_string(),
                    ));
                }
            }
            database
                .update_userpass_metadata(
                    &realm,
                    &username,
                    userpass.change_password,
                    &userpass.roles,
                )
                .await?;
        }
        (false, None) => {
            let plaintext_password =
                Zeroizing::new(String::from_utf8(userpass.password).map_err(|e| {
                    AuthError::BadRequest(format!("Password is not valid UTF-8: {e}"))
                })?);
            userpass.password = hash_password_with_argon2(&plaintext_password)?;
            database.update_userpass(&userpass).await?;
        }
        (true, Some(hashed)) => {
            validate_argon2_phc_string(&hashed)?;
            userpass.password = hashed.into_bytes();
            database.update_userpass(&userpass).await?;
        }
        (false, Some(_)) => {
            return Err(AuthError::BadRequest(
                "'password' and 'hashed_password' are mutually exclusive".to_string(),
            ));
        }
    }
    info!(
        "update_userpass: '{}' updated credentials for '{}' in realm '{}'",
        requester.id, username, realm
    );

    // Never return the stored password hash to callers — matches get_userpass.
    userpass.password = Vec::new();
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

    // Auto-unlink: when deleting a credential in the admin realm, clear the
    // admin's `userpass` field if it referenced this username.
    if realm == ADMIN_REALM
        && let Some(mut admin) = database.get_admin(&username).await?
        && admin.userpass.as_deref() == Some(&username)
    {
        admin.userpass = None;
        database.update_admin(&admin).await?;
    }

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
