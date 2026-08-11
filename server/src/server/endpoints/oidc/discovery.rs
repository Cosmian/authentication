//! OIDC discovery: `/.well-known/openid-configuration` (RFC 8414 / OpenID
//! Connect Discovery 1.0) and the combined JWKS endpoint.

use std::sync::Arc;

use actix_web::{HttpResponse, web::Data};

use crate::AuthError;
use crate::oidc::OidcState;

/// Serve the OpenID Provider metadata document.
pub async fn openid_configuration(state: Data<Arc<OidcState>>) -> Result<HttpResponse, AuthError> {
    let metadata = serde_json::json!({
        "issuer": state.issuer,
        "authorization_endpoint": state.endpoint("oidc/authorize"),
        "token_endpoint": state.endpoint("oidc/token"),
        "userinfo_endpoint": state.endpoint("oidc/userinfo"),
        "introspection_endpoint": state.endpoint("oidc/introspect"),
        "revocation_endpoint": state.endpoint("oidc/revoke"),
        "jwks_uri": state.endpoint("oidc/jwks"),
        "scopes_supported": state.supported_scopes,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none"
        ],
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "revocation_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
            "at_hash", "azp", "name", "preferred_username", "email", "roles"
        ],
        "claims_parameter_supported": false,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
    });

    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "public, max-age=3600"))
        .json(metadata))
}

/// Serve the combined JWKS (OIDC signing key + session key).
pub async fn oidc_jwks(state: Data<Arc<OidcState>>) -> Result<HttpResponse, AuthError> {
    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "public, max-age=3600"))
        .json(&state.jwks.0))
}
