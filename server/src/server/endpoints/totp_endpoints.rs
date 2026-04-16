use crate::{
    AuthError,
    database::Database,
    server::endpoints::user_from_request,
    totp::{create_totp_secret, realm_params_to_totp_params},
};
use actix_web::{
    HttpRequest, HttpResponse, delete, post,
    web::{Data, Json, Path},
};
use auth_client::{TotpGenerateRequest, TotpGenerateResponse, TotpVerifyRequest};
use cosmian_logger::info;
use std::sync::Arc;

/// Generate a new TOTP secret for a user.
///
/// The secret is returned to the caller but NOT stored yet.
/// The caller must call the verify endpoint to confirm the token
/// and enable TOTP for the user.
///
/// The requester must administer the realm specified in the path.
#[post("/{realm}/totp/generate")]
pub async fn totp_generate(
    req: HttpRequest,
    realm: Path<String>,
    body: Json<TotpGenerateRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm.into_inner();
    let requester = user_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can manage its TOTP settings",
            realm_id
        )));
    }

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

/// Verify a TOTP token against a given secret and — if valid — enable TOTP for the user.
///
/// This combines verification and enrollment in one step: the client generates a new
/// secret via the generate endpoint, displays the QR code to the user, the user enters
/// the code from their authenticator app, and then calls this endpoint. If the code is
/// valid the secret is stored and TOTP is activated for the user.
///
/// The requester must administer the realm specified in the path.
#[post("/{realm}/totp/verify")]
pub async fn totp_verify(
    req: HttpRequest,
    realm: Path<String>,
    body: Json<TotpVerifyRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let realm_id = realm.into_inner();
    let requester = user_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can manage its TOTP settings",
            realm_id
        )));
    }

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

    // Token is valid — persist the secret and enable TOTP for the user
    database
        .enable_totp(&realm_id, &body.username, &body.secret, &realm_id)
        .await?;

    info!(
        "totp_verify: '{}' enabled TOTP for '{}' in realm '{}'",
        requester.id, body.username, realm_id
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "ok"})))
}

/// Disable TOTP for a user, removing their stored secret.
///
/// The requester must administer the realm specified in the path.
#[delete("/{realm}/totp/{username}")]
pub async fn totp_disable(
    req: HttpRequest,
    params: Path<(String, String)>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let (realm_id, username) = params.into_inner();
    let requester = user_from_request(&req)?;

    if !requester.can_administer_realm(&realm_id) {
        return Err(AuthError::Forbidden(format!(
            "Only administrators of realm '{}' can manage its TOTP settings",
            realm_id
        )));
    }

    database.disable_totp(&realm_id, &username).await?;

    info!(
        "totp_disable: '{}' disabled TOTP for '{}' in realm '{}'",
        requester.id, username, realm_id
    );

    Ok(HttpResponse::NoContent().finish())
}
