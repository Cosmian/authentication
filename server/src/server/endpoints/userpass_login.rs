//! Vault-compatible userpass login: `POST/PUT /v1/auth/userpass/login/{username}`
//! (`bao login -method=userpass`), backed by the Auth Verifier userpass store.

use crate::{
    AuthError,
    database::{AuthDbError, Database},
    models::ADMIN_REALM,
    server::parameters::ServerParams,
};
use actix_web::{
    HttpResponse, route,
    web::{Bytes, Data, Path},
};
use auth_client::{AppAuth, AppAuthResponse};
use cosmian_logger::info;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
struct VaultUserpassLoginRequest {
    password: String,
}

/// Log in a userpass account of `vault_userpass_realm` and issue a Vault-style app token.
#[route("/{username}", method = "POST", method = "PUT")]
pub async fn vault_userpass_login(
    username: Path<String>,
    body: Bytes,
    database: Data<Arc<dyn Database>>,
    server_params: Data<Arc<ServerParams>>,
) -> Result<HttpResponse, AuthError> {
    let username = username.into_inner();
    let realm_id = server_params
        .vault_userpass_realm
        .as_deref()
        .ok_or_else(|| {
            AuthError::Forbidden(
                "Vault userpass login is disabled: set vault_userpass_realm".to_owned(),
            )
        })?;
    if realm_id == ADMIN_REALM {
        return Err(AuthError::Forbidden(
            "vault_userpass_realm must not be the admin realm".to_owned(),
        ));
    }
    let payload: VaultUserpassLoginRequest = serde_json::from_slice(&body)
        .map_err(|e| AuthError::BadRequest(format!("invalid userpass login body: {e}")))?;

    match database
        .validate_userpass(realm_id, &username, &payload.password)
        .await
    {
        Err(AuthDbError::InvalidCredentials) => {
            return Err(AuthError::Forbidden(
                "invalid username or password".to_owned(),
            ));
        }
        Err(e) => return Err(e.into()),
        Ok(true) => {
            return Err(AuthError::Forbidden(
                "password change required: log in to the Auth Verifier first".to_owned(),
            ));
        }
        Ok(false) => {}
    }
    if database
        .is_totp_enabled(realm_id, &username)
        .await?
        .unwrap_or(false)
    {
        return Err(AuthError::Forbidden(
            "TOTP-enabled accounts cannot use Vault userpass login".to_owned(),
        ));
    }
    let policies = database
        .get_userpass(realm_id, &username)
        .await?
        .map(|u| u.roles)
        .unwrap_or_default();
    let realm = database.get_realm(realm_id).await?.ok_or_else(|| {
        AuthError::Forbidden(format!("vault_userpass_realm '{realm_id}' does not exist"))
    })?;
    let ttl = realm.session_max_age_seconds;

    let token = super::issue_app_token(
        &database,
        &format!("userpass:{realm_id}:{username}"),
        &policies,
        ttl,
        true,
    )
    .await?;

    info!(
        event = "auth.vault_userpass.login.success",
        realm = %realm_id,
        username = %username,
        "Vault userpass login"
    );

    Ok(HttpResponse::Ok().json(AppAuthResponse {
        auth: AppAuth {
            client_token: token,
            renewable: true,
            lease_duration: ttl,
            policies,
            metadata: std::collections::HashMap::from([
                ("username".to_owned(), username),
                ("realm".to_owned(), realm_id.to_owned()),
            ]),
        },
    }))
}
