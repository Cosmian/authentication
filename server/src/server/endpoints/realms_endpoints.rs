use crate::{
    AuthError,
    database::{AuthDbError, Database, hash_password_with_argon2, validate_argon2_phc_string},
    models::{
        ADMIN_REALM, Admin, PasswordInput, UserPass, reject_reserved_claim_names,
        validate_extra_claims_size,
    },
    server::endpoints::{
        admin_from_request, admins_using_login, can_manage_credentials, can_manage_realm,
        login_manageable_given_claims, realm_manageable_given_claims,
    },
};
use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_logger::info;
use std::{collections::HashSet, sync::Arc};
use zeroize::Zeroizing;

fn credentials_forbidden(realm_id: &str, username: &str) -> AuthError {
    if realm_id == ADMIN_REALM {
        AuthError::Forbidden(format!(
            "You may only manage the admin login '{username}' if you manage every admin using it"
        ))
    } else {
        AuthError::Forbidden(format!(
            "Only administrators of realm '{realm_id}' can manage its credentials"
        ))
    }
}

/// The credentials `requester` may see, without their password hashes. In the admin realm that is
/// the logins it manages (see [`login_manageable_given_claims`]); elsewhere the realm rule.
fn visible_credentials(
    requester: &Admin,
    entries: Vec<UserPass>,
    admins: &[Admin],
) -> Vec<UserPass> {
    let claimed_realms: HashSet<String> = admins
        .iter()
        .flat_map(|a| a.realms.iter().cloned())
        .collect();
    entries
        .into_iter()
        .filter(|entry| {
            if entry.realm == ADMIN_REALM {
                login_manageable_given_claims(requester, &entry.username, admins, &claimed_realms)
            } else {
                realm_manageable_given_claims(requester, &entry.realm, &claimed_realms)
            }
        })
        .map(|mut entry| {
            entry.password_hash.clear();
            entry
        })
        .collect()
}

/// Create a new user password entry.
///
/// The requester must administer the realm specified in the path; in the admin realm `_`, it must
/// manage the admin login being created (see [`can_manage_credentials`]).
#[post("/{realm_id}/userpass")]
pub async fn create_userpass(
    req: HttpRequest,
    realm: Path<String>,
    userpass: Json<UserPass>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm.into_inner();
    let requester = admin_from_request(&req)?;
    let mut userpass = userpass.into_inner();

    if !can_manage_credentials(&requester, &realm_id, &userpass.username, &database).await? {
        return Err(credentials_forbidden(&realm_id, &userpass.username));
    }

    userpass.realm = realm_id.clone();

    if let Some(extra_claims) = &userpass.extra_claims {
        reject_reserved_claim_names(extra_claims.keys())?;
        validate_extra_claims_size(extra_claims)?;
    }

    match userpass.password_input.take() {
        Some(PasswordInput::Plaintext(plaintext)) => {
            userpass.password_hash = hash_password_with_argon2(&Zeroizing::new(plaintext))
                .map_err(|e| AuthError::Unexpected(format!("Failed to hash password: {e}")))?;
        }
        Some(PasswordInput::Hashed(hashed)) => {
            validate_argon2_phc_string(&hashed)?;
            userpass.password_hash = hashed;
        }
        None => {
            return Err(AuthError::BadRequest(
                "'password_input' must be provided".to_string(),
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

    // Auto-link: a credential created in the admin realm links to the admin record of the same
    // id, unless that record already has a login.
    if realm_id == ADMIN_REALM
        && let Some(mut admin) = database.get_admin(&userpass.username).await?
        && admin.userpass.is_none()
    {
        admin.userpass = Some(userpass.username.clone());
        database.update_admin(&admin).await?;
    }

    info!(
        "create_userpass: '{}' created credentials for '{}' in realm '{}'",
        requester.id, userpass.username, realm_id
    );

    // Never return the stored password hash to callers — matches get_userpass.
    userpass.password_hash = String::new();
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

    if !can_manage_credentials(&requester, &realm, &username, &database).await? {
        return Err(credentials_forbidden(&realm, &username));
    }

    match database.get_userpass(&realm, &username).await? {
        Some(mut userpass) => {
            // Never return the stored password hash to callers.
            userpass.password_hash = String::new();
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

    if !can_manage_credentials(&requester, &realm, &username, &database).await? {
        return Err(credentials_forbidden(&realm, &username));
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
    // metadata fields (roles, change_password). Clients omit `password_input` when only
    // updating roles/flags.
    match userpass.password_input.take() {
        None => {
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
                        "extra_claims cannot be changed without also providing 'password_input' in the same request".to_string(),
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
        Some(PasswordInput::Plaintext(plaintext_password)) => {
            userpass.password_hash =
                hash_password_with_argon2(&Zeroizing::new(plaintext_password))?;
            database.update_userpass(&userpass).await?;
        }
        Some(PasswordInput::Hashed(hashed)) => {
            validate_argon2_phc_string(&hashed)?;
            userpass.password_hash = hashed;
            database.update_userpass(&userpass).await?;
        }
    }
    info!(
        "update_userpass: '{}' updated credentials for '{}' in realm '{}'",
        requester.id, username, realm
    );

    // Never return the stored password hash to callers — matches get_userpass.
    userpass.password_hash = String::new();
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

    if !can_manage_credentials(&requester, &realm, &username, &database).await? {
        return Err(credentials_forbidden(&realm, &username));
    }

    database.delete_userpass(&realm, &username).await?;

    // Auto-unlink: deleting a credential of the admin realm clears the login of every admin
    // record that referenced it.
    if realm == ADMIN_REALM {
        for mut admin in admins_using_login(&database, &username).await? {
            if admin.userpass.as_deref() == Some(&username) {
                admin.userpass = None;
                database.update_admin(&admin).await?;
            }
        }
    }

    info!(
        "delete_userpass: '{}' deleted credentials for '{}' in realm '{}'",
        requester.id, username, realm
    );

    Ok(HttpResponse::NoContent().finish())
}

/// List the user password entries of a specific realm.
///
/// In a regular realm the requester must administer it. In the admin realm `_` any admin may
/// call it and sees only the logins it manages.
#[get("/{realm_id}/userpass")]
pub async fn list_userpass_by_realm(
    req: HttpRequest,
    realm: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm.into_inner();
    let requester = admin_from_request(&req)?;

    if realm_id != ADMIN_REALM && !can_manage_realm(&requester, &realm_id, &database).await? {
        return Err(credentials_forbidden(&realm_id, ""));
    }

    let userpass_list = database.list_userpass_by_realm(&realm_id).await?;
    let admins = database.list_admins().await?;

    Ok(HttpResponse::Ok().json(visible_credentials(&requester, userpass_list, &admins)))
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
    let admins = database.list_admins().await?;

    Ok(HttpResponse::Ok().json(visible_credentials(&requester, userpass_list, &admins)))
}
