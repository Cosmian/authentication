//! 2FA (TOTP) management for admin logins.
//!
//! 2FA exists only for the logins of admins, in the admin realm `_`, and is stored on the admin
//! record that uses the login. Managing it follows the rule for `_` logins (see
//! `can_manage_admin_login`): the requester must manage every admin using the login. In any other
//! realm the endpoints answer `400`: ordinary realm users have no 2FA, and pretending to enrol
//! them silently left them unprotected.

use crate::{
    AuthError, AuthScheme,
    database::Database,
    models::{ADMIN_REALM, Admin},
    server::endpoints::{admin_from_request, can_manage_credentials},
    totp::{create_totp_secret, realm_params_to_totp_params},
};
use actix_web::{
    HttpRequest, HttpResponse, delete, post,
    web::{Data, Json, Path},
};
use auth_client::{TotpGenerateRequest, TotpGenerateResponse, TotpVerifyRequest};
use cosmian_logger::info;
use std::sync::Arc;

/// Checks that `requester` may manage the 2FA of `username` in `realm_id`, and that 2FA exists
/// there at all.
async fn authorize_totp(
    requester: &Admin,
    realm_id: &str,
    username: &str,
    database: &Data<Arc<dyn Database>>,
) -> Result<(), AuthError> {
    if !can_manage_credentials(requester, realm_id, username, database).await? {
        return Err(AuthError::Forbidden(format!(
            "You may not manage the 2FA of '{username}' in realm '{realm_id}'"
        )));
    }
    if realm_id != ADMIN_REALM {
        return Err(AuthError::BadRequest(format!(
            "Two-factor authentication is only available for admin logins, in realm '{ADMIN_REALM}'"
        )));
    }
    Ok(())
}

/// The admin record holding the 2FA of the `_` login `username`: the one linked to it through
/// `userpass`, else the one named like it.
async fn totp_admin(
    database: &Data<Arc<dyn Database>>,
    username: &str,
) -> Result<Admin, AuthError> {
    let mut linked = database
        .find_admins_by_auth_scheme(AuthScheme::UsernamePassword, username)
        .await?;
    if linked.len() > 1 {
        return Err(AuthError::Conflict(format!(
            "Several admins use the login '{username}'"
        )));
    }
    let admin = match linked.pop() {
        Some(admin) => Some(admin),
        None => database.get_admin(username).await?,
    }
    .ok_or_else(|| AuthError::BadRequest(format!("No admin uses the login '{username}'")))?;
    if admin.userpass.is_none() && admin.jwt.is_none() {
        return Err(AuthError::BadRequest(format!(
            "Admin '{}' has no login to protect with 2FA",
            admin.id
        )));
    }
    Ok(admin)
}

/// Generate a new TOTP secret for an admin login.
///
/// The secret is returned to the caller but NOT stored yet.
/// The caller must call the verify endpoint to confirm the token
/// and enable TOTP for the login.
#[post("/{realm_id}/totp/generate")]
pub async fn totp_generate(
    req: HttpRequest,
    realm: Path<String>,
    body: Json<TotpGenerateRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm.into_inner();
    let requester = admin_from_request(&req)?;
    authorize_totp(&requester, &realm_id, &body.username, &database).await?;

    let body = body.into_inner();
    let issuer = body.issuer.unwrap_or_else(|| realm_id.clone());

    // Fetch realm-level TOTP params (algorithm, step) if configured
    let realm_record = database
        .get_realm(&realm_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("Realm '{}' not found", realm_id)))?;

    let totp_params = realm_record
        .auth_params
        .totp_params
        .as_ref()
        .map(realm_params_to_totp_params)
        .transpose()?;

    let (totps, secret_base32) = create_totp_secret(&issuer, &body.username, totp_params)?;
    let otpauth_url = totps.get_otpauth_url();

    info!(
        "totp_generate: '{}' generated TOTP secret for '{}' in realm '{}'",
        requester.id, body.username, realm_id
    );

    Ok(HttpResponse::Ok().json(TotpGenerateResponse {
        secret_base32,
        otpauth_url,
    }))
}

/// Verify a TOTP token against a given secret and — if valid — enable TOTP for the login.
///
/// This combines verification and enrollment in one step: the client generates a new
/// secret via the generate endpoint, displays the QR code to the user, the user enters
/// the code from their authenticator app, and then calls this endpoint. If the code is
/// valid the secret is stored and TOTP is activated for the admin using the login.
#[post("/{realm_id}/totp/verify")]
pub async fn totp_verify(
    req: HttpRequest,
    realm: Path<String>,
    body: Json<TotpVerifyRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm.into_inner();
    let requester = admin_from_request(&req)?;
    authorize_totp(&requester, &realm_id, &body.username, &database).await?;
    let admin = totp_admin(&database, &body.username).await?;

    let body = body.into_inner();
    let issuer = body.issuer.unwrap_or_else(|| realm_id.clone());

    // Fetch realm-level TOTP params so validation uses the same algorithm/step
    let realm_record = database
        .get_realm(&realm_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("Realm '{}' not found", realm_id)))?;

    let totp_params = realm_record
        .auth_params
        .totp_params
        .as_ref()
        .map(realm_params_to_totp_params)
        .transpose()?;

    let totps = crate::totp::Totps::from_secret(
        &body.secret,
        Some(issuer),
        body.username.clone(),
        totp_params,
    )?;

    if !totps.validate_token(&body.token)? {
        return Err(AuthError::Forbidden(
            "Invalid TOTP token; code did not match the provided secret".to_string(),
        ));
    }

    // Token is valid — persist the secret and enable TOTP for the admin
    database
        .enable_totp(&realm_id, &admin.id, &body.secret, &realm_id)
        .await?;

    info!(
        "totp_verify: '{}' enabled TOTP for '{}' (admin '{}')",
        requester.id, body.username, admin.id
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "ok"})))
}

/// Disable TOTP for an admin login, removing the stored secret.
#[delete("/{realm_id}/totp/{username}")]
pub async fn totp_disable(
    req: HttpRequest,
    params: Path<(String, String)>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (realm_id, username) = params.into_inner();
    let requester = admin_from_request(&req)?;
    authorize_totp(&requester, &realm_id, &username, &database).await?;
    let admin = totp_admin(&database, &username).await?;

    database.disable_totp(&realm_id, &admin.id).await?;

    info!(
        "totp_disable: '{}' disabled TOTP for '{}' (admin '{}')",
        requester.id, username, admin.id
    );

    Ok(HttpResponse::NoContent().finish())
}
