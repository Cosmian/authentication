//! Shared helpers for OIDC/OAuth 2.0 endpoint handlers.

use actix_web::{HttpResponse, http::StatusCode};

/// Build an OAuth 2.0 error response (RFC 6749 §5.2) with the standard
/// `{"error": ..., "error_description": ...}` JSON body.
pub fn oauth_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    HttpResponse::build(status).json(serde_json::json!({
        "error": error,
        "error_description": description,
    }))
}

/// `400 invalid_request`.
pub fn invalid_request(description: &str) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_request", description)
}

/// `400 invalid_grant`.
pub fn invalid_grant(description: &str) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

/// `400 unsupported_grant_type`.
pub fn unsupported_grant_type(description: &str) -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "unsupported_grant_type",
        description,
    )
}

/// `400 invalid_scope`.
pub fn invalid_scope(description: &str) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_scope", description)
}

/// `401 invalid_client` with a `WWW-Authenticate: Basic` challenge.
pub fn invalid_client(description: &str) -> HttpResponse {
    HttpResponse::Unauthorized()
        .insert_header(("WWW-Authenticate", "Basic realm=\"oidc\""))
        .json(serde_json::json!({
            "error": "invalid_client",
            "error_description": description,
        }))
}
