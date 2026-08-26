use crate::models::{CertificateClaims, ClientClaims, LoginRequest};
use crate::server::parameters::ServerParams;
use crate::session::{self, JwksData, JwtTokenConfig, issue_token, session_id_from_cookie_value};
use crate::{AuthError, AuthenticatedClientScheme, server::Version};
use crate::{AuthenticationNextStep, AuthenticationResult, Realm, build_cookie};
use actix_web::HttpMessage;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use cosmian_logger::{debug, info};
use jsonwebtoken::{Algorithm, Header, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn login(
    jwt_token_config: Data<Arc<session::JwtTokenConfig>>,
    session_store: Data<Arc<dyn session::SessionStore>>,
    database: Data<Arc<dyn crate::database::Database>>,
    server_params: Data<Arc<ServerParams>>,
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
                    // TODO : Shouldn't issuer be the realm ?
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

    // Fetch roles from userpass record (if authenticated via username/password).
    // For non-userpass auth schemes (JWT, mTLS), roles=[] (fail-closed).
    let roles = if authenticated_client.auth_scheme == crate::AuthScheme::UsernamePassword {
        match database
            .get_userpass(&realm.id, &authenticated_client.username)
            .await?
        {
            Some(up) => up.roles,
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };

    let token = issue_token(
        &authenticated_client.username,
        authenticated_client.auth_scheme,
        &realm.id,
        roles,
        &jwt_token_config,
        realm.session_max_age_seconds,
    )?;

    let is_https = server_params.tls_params.is_some();
    let cookie = build_cookie(&token, realm.session_max_age_seconds, is_https)?;
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
    // Structured audit event — consumed by log shippers and SIEM tooling.
    info!(
        event = "auth.login.success",
        realm = %realm.id,
        username = %authenticated_client.username,
        auth_scheme = ?authenticated_client.auth_scheme,
        session_id = %session_id,
        "login successful"
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

/// Request body for `POST /certify`.
#[derive(Debug, Clone, Deserialize)]
pub struct CertifyRequest {
    /// PEM-encoded public key to certify.
    pub verification_key: String,
}

/// Response body for `POST /certify`.
#[derive(Debug, Clone, Serialize)]
pub struct CertifyResponse {
    /// Compact JWS (`alg: ES256`) whose payload is a [`CertificateClaims`] object, signed
    /// with the certificate signing key.
    pub certificate: String,
}

/// Certifies a verification key under the identity of the currently authenticated session.
///
/// The certificate binds `realm_id`/`sub`/`auth_scheme` — taken from the session's own
/// claims, never from the request body — to the caller-supplied key, and is signed with a
/// certificate signing key entirely separate from the session JWT key so it can never be
/// presented back as a session cookie/token.
/// Maximum accepted length (bytes) for `verification_key`. Generous enough for any real
/// public key or certificate chain PEM (even RSA-4096), while bounding the cost of embedding
/// caller-supplied input into a signed certificate.
const MAX_VERIFICATION_KEY_LEN: usize = 8192;

pub async fn certify(
    cert_jwt_config: Data<Option<Arc<JwtTokenConfig>>>,
    database: Data<Arc<dyn crate::database::Database>>,
    req: HttpRequest,
    body: Json<CertifyRequest>,
) -> Result<HttpResponse, AuthError> {
    let verification_key = body.verification_key.trim();
    if verification_key.is_empty() {
        return Err(AuthError::BadRequest(
            "verification_key must not be empty".to_string(),
        ));
    }
    if verification_key.len() > MAX_VERIFICATION_KEY_LEN {
        return Err(AuthError::BadRequest(format!(
            "verification_key must not exceed {MAX_VERIFICATION_KEY_LEN} bytes"
        )));
    }
    if !verification_key.starts_with("-----BEGIN ") || !verification_key.contains("-----END ") {
        return Err(AuthError::BadRequest(
            "verification_key must be a PEM-encoded key or certificate".to_string(),
        ));
    }

    let cert_jwt_config = cert_jwt_config.get_ref().as_ref().ok_or_else(|| {
        AuthError::Config("certificate signing is not configured on this server".to_string())
    })?;

    let claims = req
        .extensions()
        .get::<ClientClaims>()
        .ok_or_else(|| AuthError::Session("no user claims found in request".to_string()))?
        .clone();

    let sub = claims
        .registered
        .sub
        .ok_or_else(|| AuthError::Session("no subject in session claims".to_string()))?;
    let auth_scheme = claims
        .private
        .auth_scheme
        .ok_or_else(|| AuthError::Session("no auth scheme in session claims".to_string()))?;
    let realm_id = claims
        .private
        .realm_id
        .ok_or_else(|| AuthError::Session("no realm ID in session claims".to_string()))?;

    // Look up the certificate TTL policy for the realm the session actually authenticated to.
    // `/certify` has no `?realm=` query parameter, realm_id always comes from the session's own claims.
    let realm = database
        .get_realm(&realm_id)
        .await?
        .ok_or_else(|| AuthError::Session(format!("realm '{realm_id}' no longer exists")))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            AuthError::Unexpected(format!("System time error when issuing certificate: {e}"))
        })?
        .as_secs() as i64;

    let cert_claims = CertificateClaims {
        realm_id,
        sub,
        auth_scheme,
        verification_key: verification_key.to_string(),
        iat: now,
        exp: now + realm.certificate_max_age_seconds,
    };

    let header = Header::new(Algorithm::ES256);
    let certificate = encode(&header, &cert_claims, &cert_jwt_config.encoding_key)
        .map_err(|e| AuthError::Unexpected(format!("Failed to issue certificate: {e}")))?;

    Ok(HttpResponse::Ok().json(CertifyResponse { certificate }))
}

pub async fn version_endpoint(_req: HttpRequest) -> Result<HttpResponse, AuthError> {
    let version = env!("CARGO_PKG_VERSION");
    let version = Version {
        version: version.to_string(),
    };
    Ok(HttpResponse::Ok().json(version))
}

/// Returns the list of available RBAC roles configured on this server.
pub async fn roles_endpoint(
    server_params: Data<Arc<crate::server::parameters::ServerParams>>,
) -> Result<HttpResponse, AuthError> {
    Ok(HttpResponse::Ok().json(&server_params.roles))
}

/// Returns the JWKS (JSON Web Key Set) document containing the server's EC signing
/// public key. Served at `/.well-known/jwks.json` per OIDC / RFC 8414.
pub async fn jwks_well_known(jwks: Data<Arc<JwksData>>) -> Result<HttpResponse, AuthError> {
    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "public, max-age=3600"))
        .json(&jwks.0))
}

/// Returns the JWKS (JSON Web Key Set) for the certificate signing key used by `POST /certify`.
/// Deliberately a separate document from `/.well-known/jwks.json` — see [`certify`].
/// Served at `/.well-known/certificate-jwks.json`.
pub async fn certificate_jwks_well_known(
    cert_jwks: Data<Option<Arc<JwksData>>>,
) -> Result<HttpResponse, AuthError> {
    match cert_jwks.get_ref() {
        Some(jwks) => Ok(HttpResponse::Ok()
            .insert_header(("Cache-Control", "public, max-age=3600"))
            .json(&jwks.0)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "errors": ["certificate signing is not configured on this server"]
        }))),
    }
}

/// Serve the raw OpenAPI 3.1 schema (YAML), embedded at compile time.
#[cfg(feature = "swagger-ui")]
pub async fn openapi_yaml_endpoint(_req: HttpRequest) -> Result<HttpResponse, AuthError> {
    const SCHEMA: &str = include_str!("../../../documentation/openapi.yaml");
    Ok(HttpResponse::Ok()
        .content_type("application/yaml")
        .body(SCHEMA))
}

/// Serve a Swagger UI HTML page that loads the schema from `/public/openapi.yaml`.
///
/// Assets are pinned to swagger-ui-dist 5.18.2 with Subresource Integrity (SRI) hashes.
/// A strict Content-Security-Policy header restricts script/style sources to the CDN.
#[cfg(feature = "swagger-ui")]
pub async fn swagger_ui_endpoint(_req: HttpRequest) -> Result<HttpResponse, AuthError> {
    let version = env!("CARGO_PKG_VERSION");
    let html = format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head>\n\
           <meta charset=\"UTF-8\" />\n\
           <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n\
           <title>Cosmian Authentication Verifier {version} \u{2014} API</title>\n\
           <link rel=\"stylesheet\" \
                 href=\"https://unpkg.com/swagger-ui-dist@5.18.2/swagger-ui.css\" \
                 integrity=\"sha384-rcbEi6xgdPk0iWkAQzT2F3FeBJXdG+ydrawGlfHAFIZG7wU6aKbQaRewysYpmrlW\" \
                 crossorigin=\"anonymous\" />\n\
         </head>\n\
         <body>\n\
           <div id=\"swagger-ui\"></div>\n\
           <script src=\"https://unpkg.com/swagger-ui-dist@5.18.2/swagger-ui-bundle.js\" \
                   integrity=\"sha384-NXtFPpN61oWCuN4D42K6Zd5Rt2+uxeIT36R7kpXBuY9tLnZorzrJ4ykpqwJfgjpZ\" \
                   crossorigin=\"anonymous\"></script>\n\
           <script>\n\
             SwaggerUIBundle({{\n\
               url: \"/public/openapi.yaml\",\n\
               dom_id: \"#swagger-ui\",\n\
               presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],\n\
               layout: \"BaseLayout\",\n\
               deepLinking: true,\n\
               displayRequestDuration: true,\n\
               filter: true,\n\
             }});\n\
           </script>\n\
         </body>\n\
         </html>"
    );
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; \
             script-src https://unpkg.com 'unsafe-inline'; \
             style-src https://unpkg.com 'unsafe-inline'; \
             img-src data: https://unpkg.com; \
             connect-src 'self'",
        ))
        .body(html))
}
