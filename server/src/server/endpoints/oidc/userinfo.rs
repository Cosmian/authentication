//! OIDC UserInfo endpoint (`GET`/`POST /oidc/userinfo`).
//!
//! Requires a valid Bearer access token (RFC 6750). Returns the scope-gated
//! claims for the token's subject.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, http::StatusCode, web::Data};

use crate::AuthError;
use crate::database::Database;
use crate::oidc::OidcState;
use crate::oidc::tokens::{self, AccessTokenClaims};

/// Extract a Bearer token from the `Authorization` header.
fn bearer_token(req: &HttpRequest) -> Option<String> {
    let value = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(|s| s.trim().to_string())
}

/// `401` with an RFC 6750 `WWW-Authenticate: Bearer` challenge.
fn unauthorized(description: &str) -> HttpResponse {
    HttpResponse::build(StatusCode::UNAUTHORIZED)
        .insert_header((
            "WWW-Authenticate",
            format!("Bearer error=\"invalid_token\", error_description=\"{description}\""),
        ))
        .finish()
}

/// Return the UserInfo claims for the presented access token.
pub async fn userinfo(
    req: HttpRequest,
    state: Data<Arc<OidcState>>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let Some(token) = bearer_token(&req) else {
        return Ok(unauthorized("missing bearer access token"));
    };
    let claims: AccessTokenClaims = match tokens::validate_access_token(&state, &token) {
        Ok(c) => c,
        Err(_) => return Ok(unauthorized("invalid or expired access token")),
    };

    let realm = claims.realm.clone().unwrap_or_default();
    let roles = match database.get_userpass(&realm, &claims.sub).await {
        Ok(Some(up)) => up.roles,
        _ => Vec::new(),
    };

    // Always include `sub`; other claims are gated by the token's scope.
    let mut out = serde_json::json!({ "sub": claims.sub });
    if tokens::scope_contains(&claims.scope, "profile") {
        out["preferred_username"] = serde_json::Value::String(claims.sub.clone());
    }
    if tokens::scope_contains(&claims.scope, "email") && claims.sub.contains('@') {
        out["email"] = serde_json::Value::String(claims.sub.clone());
        out["email_verified"] = serde_json::Value::Bool(false);
    }
    if tokens::scope_contains(&claims.scope, "roles") && !roles.is_empty() {
        out["roles"] = serde_json::json!(roles);
    }

    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(out))
}
