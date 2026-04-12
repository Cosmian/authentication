use crate::models::ClientClaims;
use crate::models::LoginRequest;
use crate::session::{self, issue_token, session_id_from_cookie_value};
use crate::{AuthError, AuthenticatedClientScheme, server::Version};
use crate::{AuthenticationNextStep, AuthenticationResult, Realm, build_cookie};
use actix_web::HttpMessage;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use cosmian_logger::debug;
use std::sync::Arc;

pub async fn login(
    jwt_token_config: Data<Arc<session::JwtTokenConfig>>,
    session_store: Data<Arc<dyn session::SessionStore>>,
    database: Data<Arc<dyn crate::database::Database>>,
    req: HttpRequest,
    login_request: Json<LoginRequest>,
) -> Result<HttpResponse, AuthError> {
    let realm = req
        .extensions()
        .get::<Realm>()
        .ok_or_else(|| AuthError::Session("no realm found in request".to_string()))?
        .clone();
    let authenticated_client = req
        .extensions()
        .get::<AuthenticatedClientScheme>()
        .ok_or_else(|| AuthError::Session("no authenticated client found in request".to_string()))?
        .clone();

    // --- TOTP check ---
    let totp_enabled = database
        .is_totp_enabled(&realm.id, &authenticated_client.username)
        .await
        .map_err(|e| AuthError::Session(format!("Failed to check TOTP status: {e}")))?
        .unwrap_or(false);

    if totp_enabled {
        match login_request.totp_code.as_deref() {
            None => {
                // Credentials are valid but TOTP code is still required
                return Ok(HttpResponse::Ok().json(AuthenticationResult {
                    session_id: None,
                    next_step: AuthenticationNextStep::TotpRequired,
                }));
            }
            Some(code) => {
                let secret = database
                    .get_totp_secret(&realm.id, &authenticated_client.username)
                    .await
                    .map_err(|e| {
                        AuthError::Session(format!("Failed to retrieve TOTP secret: {e}"))
                    })?
                    .ok_or_else(|| {
                        AuthError::Session("TOTP is enabled but no secret is stored".to_string())
                    })?;

                let totp_params = realm
                    .auth_params
                    .totp_params
                    .as_ref()
                    .map(crate::totp::realm_params_to_totp_params)
                    .transpose()?;

                let totps = crate::totp::Totps::from_secret(
                    &secret,
                    None,
                    authenticated_client.username.clone(),
                    totp_params,
                )?;

                if !totps.validate_token(code)? {
                    return Ok(HttpResponse::Unauthorized().json("Invalid TOTP code"));
                }
            }
        }
    }
    // --- end TOTP check ---

    let token = issue_token(
        &authenticated_client.username,
        authenticated_client.auth_scheme,
        &realm.id,
        login_request.public_key_pem.clone(),
        jwt_token_config.algorithm,
        jwt_token_config.encoding_key.clone(),
        realm.session_max_age_seconds,
    )?;

    let cookie = build_cookie(&token, realm.session_max_age_seconds)?;
    let session_id = session_id_from_cookie_value(cookie.value().as_bytes())?;
    let cookie_string = cookie.to_string();

    // Store session in the session store
    session_store
        .upsert_session(&session_id, &realm, &authenticated_client, &cookie_string)
        .await?;

    debug!(
        "successfully authenticated user '{}' and created session with ID '{}'",
        authenticated_client.username, session_id
    );

    // Build the response with the session cookie set in the Set-Cookie header
    let mut response = HttpResponse::Ok().json(AuthenticationResult {
        session_id: Some(session_id),
        next_step: AuthenticationNextStep::Authenticated,
    });
    response
        .add_cookie(&cookie)
        .map_err(|e| AuthError::Unexpected(format!("failed adding cookie to the response: {e}")))?;

    Ok(response)
}

/// Endpoint to return the authenticated user's claims
pub async fn whoami(req: HttpRequest) -> Result<HttpResponse, AuthError> {
    let user_claims = req
        .extensions()
        .get::<ClientClaims>()
        .ok_or_else(|| AuthError::Session("no user claims found in request".to_string()))?
        .clone();

    Ok(HttpResponse::Ok().json(user_claims))
}

pub async fn version_endpoint(_req: HttpRequest) -> Result<HttpResponse, AuthError> {
    let version = env!("CARGO_PKG_VERSION");
    let version = Version {
        version: version.to_string(),
    };
    Ok(HttpResponse::Ok().json(version))
}
