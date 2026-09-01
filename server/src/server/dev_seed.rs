use crate::{
    AuthResult,
    database::{Database, OAuthClient, hash_password_with_argon2},
    models::{ADMIN_REALM, Admin, Realm, UserPass},
    server::parameters::{DevSeedParams, DevSeedUser},
    {RealmAuthParams, UsernamePasswordParams},
};
use cosmian_logger::info;
use sha2::{Digest, Sha256};

/// SHA-256 hash of a client secret — mirrors the production implementation in
/// `server::endpoints::oidc::common::hash_secret` without requiring a public export.
fn hash_client_secret(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// Seeds a realm and a realm-scoped admin account for development use.
/// All operations are idempotent — nothing is overwritten if it already exists.
pub(super) async fn seed_dev_realm_admin(
    db: &dyn Database,
    seed: &DevSeedParams,
) -> AuthResult<()> {
    // 1. Create the realm if it does not exist.
    if db.get_realm(&seed.realm_id).await?.is_none() {
        let realm = Realm {
            id: seed.realm_id.clone(),
            auth_params: RealmAuthParams {
                username_password_params: Some(UsernamePasswordParams {
                    allow_expired_passwords: false,
                }),
                ..Default::default()
            },
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
        };
        db.create_realm(&realm).await.map_err(|e| {
            crate::AuthError::Init(format!(
                "dev_seed: failed to create realm '{}': {e}",
                seed.realm_id
            ))
        })?;
        info!("dev_seed: created realm '{}'", seed.realm_id);
    }

    // 2. Create the credential in the admin realm if it does not exist.
    if db
        .get_userpass(ADMIN_REALM, &seed.admin_username)
        .await?
        .is_none()
    {
        let admin_password = seed.resolve_admin_password()?;
        let hashed = hash_password_with_argon2(&admin_password).map_err(|e| {
            crate::AuthError::Init(format!(
                "dev_seed: failed to hash password for '{}': {e}",
                seed.admin_username
            ))
        })?;
        let userpass = UserPass {
            realm: ADMIN_REALM.to_string(),
            username: seed.admin_username.clone(),
            password: hashed,
            change_password: true,
            roles: Vec::new(),
        };
        db.create_userpass(&userpass).await.map_err(|e| {
            crate::AuthError::Init(format!(
                "dev_seed: failed to create credential for '{}': {e}",
                seed.admin_username
            ))
        })?;
        info!("dev_seed: created credential for '{}'", seed.admin_username);
    }

    // 3. Create the admin record if it does not exist.
    if db.get_admin(&seed.admin_username).await?.is_none() {
        let admin = Admin {
            id: seed.admin_username.clone(),
            realms: vec![seed.realm_id.clone()],
            userpass: Some(seed.admin_username.clone()),
            jwt: None,
            fido2: None,
            digital_credentials: None,
            client_certificate: None,
            totp_enabled: None,
            totp_secret: None,
            totp_auth_url: None,
        };
        db.create_admin(&admin).await.map_err(|e| {
            crate::AuthError::Init(format!(
                "dev_seed: failed to create admin '{}': {e}",
                seed.admin_username
            ))
        })?;
        info!(
            "dev_seed: created realm-admin '{}' for realm '{}'",
            seed.admin_username, seed.realm_id
        );
    }

    // 4. Optionally create a TOTP-enabled user in the seeded realm.
    if let (Some(totp_username), Some(totp_password)) = (&seed.totp_username, &seed.totp_password) {
        if db
            .get_userpass(&seed.realm_id, totp_username)
            .await?
            .is_none()
        {
            let hashed = hash_password_with_argon2(totp_password).map_err(|e| {
                crate::AuthError::Init(format!(
                    "dev_seed: failed to hash password for TOTP user '{}': {e}",
                    totp_username
                ))
            })?;
            let userpass = UserPass {
                realm: seed.realm_id.clone(),
                username: totp_username.clone(),
                password: hashed,
                change_password: false,
                roles: Vec::new(),
            };
            db.create_userpass(&userpass).await.map_err(|e| {
                crate::AuthError::Init(format!(
                    "dev_seed: failed to create TOTP user '{}': {e}",
                    totp_username
                ))
            })?;
            info!(
                "dev_seed: created TOTP user '{}' in realm '{}'",
                totp_username, seed.realm_id
            );
        }

        // Create the admin record for the TOTP user if it does not exist (required for TOTP fields in DB).
        if db.get_admin(totp_username).await?.is_none() {
            let admin = Admin {
                id: totp_username.clone(),
                realms: Vec::new(), // not an admin of any realms
                userpass: Some(totp_username.clone()),
                jwt: None,
                fido2: None,
                digital_credentials: None,
                client_certificate: None,
                totp_enabled: None,
                totp_secret: None,
                totp_auth_url: None,
            };
            db.create_admin(&admin).await.map_err(|e| {
                crate::AuthError::Init(format!(
                    "dev_seed: failed to create admin record for TOTP user '{}': {e}",
                    totp_username
                ))
            })?;
            info!(
                "dev_seed: created admin record for TOTP user '{}'",
                totp_username
            );
        }

        // Enable TOTP for the user (idempotent: skip if already enabled).
        let already_enabled = db
            .is_totp_enabled(&seed.realm_id, totp_username)
            .await?
            .unwrap_or(false);
        if !already_enabled {
            let secret = if let Some(s) = &seed.totp_secret {
                s.clone()
            } else {
                let generated = crate::totp::Totps::new()
                    .map_err(|e| {
                        crate::AuthError::Init(format!(
                            "dev_seed: failed to generate TOTP secret: {e}"
                        ))
                    })?
                    .generate_secret();
                info!(
                    "dev_seed: generated TOTP secret for '{}': {}",
                    totp_username, generated
                );
                generated
            };
            db.enable_totp(&seed.realm_id, totp_username, &secret, &seed.realm_id)
                .await
                .map_err(|e| {
                    crate::AuthError::Init(format!(
                        "dev_seed: failed to enable TOTP for '{}': {e}",
                        totp_username
                    ))
                })?;
            info!(
                "dev_seed: TOTP enabled for user '{}' in realm '{}'",
                totp_username, seed.realm_id
            );
        }
    }

    // 5. Optionally seed a pre-registered OIDC client with stable credentials.
    if let Some(ref oidc) = seed.oidc_client
        && db.get_oauth_client(&oidc.client_id).await?.is_none()
    {
            let record = OAuthClient {
                client_id: oidc.client_id.clone(),
                client_secret_hash: Some(hash_client_secret(&oidc.client_secret)),
                client_name: oidc.client_name.clone(),
                redirect_uris: oidc.redirect_uris.clone(),
                grant_types: oidc.grant_types.clone(),
                response_types: vec!["code".to_owned()],
                scopes: oidc.scopes.clone(),
                token_endpoint_auth_method: "client_secret_basic".to_owned(),
                realm: seed.realm_id.clone(),
                created_at: chrono::Utc::now().timestamp(),
            };
            db.create_oauth_client(&record).await.map_err(|e| {
                crate::AuthError::Init(format!(
                    "dev_seed: failed to create OIDC client '{}': {e}",
                    oidc.client_id
                ))
            })?;
            info!(
                "dev_seed: created OIDC client '{}' ('{}') in realm '{}'",
                oidc.client_id, oidc.client_name, seed.realm_id
            );
    }

    // 6. Optionally seed plain test users in the realm.
    for DevSeedUser { username, password } in &seed.users {
        if db.get_userpass(&seed.realm_id, username).await?.is_none() {
            let hashed = hash_password_with_argon2(password).map_err(|e| {
                crate::AuthError::Init(format!(
                    "dev_seed: failed to hash password for user '{username}': {e}"
                ))
            })?;
            let userpass = UserPass {
                realm: seed.realm_id.clone(),
                username: username.clone(),
                password: hashed,
                change_password: false,
                roles: Vec::new(),
            };
            db.create_userpass(&userpass).await.map_err(|e| {
                crate::AuthError::Init(format!(
                    "dev_seed: failed to create user '{username}': {e}"
                ))
            })?;
            info!("dev_seed: created user '{username}' in realm '{}'", seed.realm_id);
        }
    }

    Ok(())
}
