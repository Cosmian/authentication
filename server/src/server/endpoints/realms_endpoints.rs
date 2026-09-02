use crate::{
    AuthError,
    database::{AuthDbError, Database, hash_password_with_argon2, validate_argon2_phc_string},
    models::{ADMIN_REALM, UserPass},
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

    // Exactly one of `password` (plaintext, hashed below) / `hashed_password` (a
    // pre-computed Argon2 PHC string, stored as-is — e.g. migrating credentials already
    // hashed by another Argon2-based system) must be provided.
    //
    // `plaintext_password` is kept around (zeroized on drop, not persisted) only in the
    // plaintext case, so a conflict can be re-checked against it below — Argon2 hashes
    // are salted, so a stored hash can never be compared for equality directly.
    let plaintext_password = match (
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
            Some(plaintext)
        }
        (true, Some(hashed)) => {
            validate_argon2_phc_string(&hashed)?;
            userpass.password = hashed.into_bytes();
            None
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
        Err(AuthDbError::Conflict(_)) => {
            // Re-provisioning with byte-for-byte identical data is a common retry
            // pattern (e.g. a client that doesn't know whether its previous call
            // landed) — treat it as a no-op success rather than a conflict. Anything
            // else about the existing entry differing is a genuine conflict: someone
            // else already owns this username with different credentials/roles/claims.
            let data_matches = match &plaintext_password {
                Some(plaintext) => {
                    let password_matches = database
                        .validate_userpass(&realm_id, &userpass.username, plaintext)
                        .await
                        .is_ok();
                    let existing = database.get_userpass(&realm_id, &userpass.username).await?;
                    password_matches
                        && existing.is_some_and(|e| {
                            e.change_password == userpass.change_password
                                && e.roles == userpass.roles
                                && e.extra_claims == userpass.extra_claims
                        })
                }
                // A pre-hashed submission can't be re-verified without exposing the
                // stored hash — get_userpass deliberately never returns it — so this is
                // always treated as a genuine conflict.
                None => false,
            };

            if data_matches {
                info!(
                    "create_userpass: '{}' re-submitted identical credentials for '{}' in realm '{}' — idempotent no-op",
                    requester.id, userpass.username, realm_id
                );
                userpass.password = Vec::new();
                return Ok(HttpResponse::Ok().json(userpass));
            }

            return Err(AuthError::Conflict(format!(
                "credentials for '{}' already exist in realm '{}' with different data",
                userpass.username, realm_id
            )));
        }
        Err(e) => return Err(e.into()),
    }

    // TODO: This code is never executed in case of conflict. Is this normal?

    // Auto-link: when creating a credential in the admin realm, if an admin
    // exists with a matching id, set its `userpass` field to enable login.
    if realm_id == ADMIN_REALM
        && let Some(mut admin) = database.get_admin(&userpass.username).await?
    // TODO: why comparing a userpass with a username? those do not seem to be
    // homogeneous.
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
    // TODO: if I understand correctly, even a realm admin cannot modify the
    // userpass of another user? However, it can delete then create another
    // userpass... which seems to be another way to modify it.
    userpass.username = username.clone();

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
            // TODO: Why not changing the `userpass.password` field to make it a
            // `Zeroizing<String>` instead?
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
