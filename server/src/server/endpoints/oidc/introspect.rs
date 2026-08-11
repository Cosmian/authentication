//! OAuth 2.0 Token Introspection endpoint (`POST /oidc/introspect`, RFC 7662).

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse,
    web::{Data, Form},
};

use crate::AuthError;
use crate::database::Database;
use crate::oidc::OidcState;
use crate::oidc::tokens;
use crate::server::endpoints::oidc::common::authenticate_client;

/// The inactive-token response (RFC 7662 §2.2).
fn inactive() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(serde_json::json!({ "active": false }))
}

/// Introspect an access or refresh token. Requires client authentication.
pub async fn introspect(
    req: HttpRequest,
    state: Data<Arc<OidcState>>,
    database: Data<Arc<dyn Database>>,
    form: Form<HashMap<String, String>>,
) -> Result<HttpResponse, AuthError> {
    let form = form.into_inner();
    let database = database.into_inner();

    let client = match authenticate_client(&req, &form, &database).await {
        Ok(ac) => ac.client,
        Err(resp) => return Ok(resp),
    };

    let Some(token) = form.get("token") else {
        return Ok(inactive());
    };

    // Try as an access token first (stateless JWT).
    if let Ok(claims) = tokens::validate_access_token(&state, token) {
        // Only reveal tokens issued to the authenticated client.
        if claims.client_id != client.client_id {
            return Ok(inactive());
        }
        return Ok(HttpResponse::Ok()
            .insert_header(("Cache-Control", "no-store"))
            .json(serde_json::json!({
                "active": true,
                "scope": claims.scope,
                "client_id": claims.client_id,
                "sub": claims.sub,
                "exp": claims.exp,
                "iat": claims.iat,
                "iss": claims.iss,
                "aud": claims.aud,
                "jti": claims.jti,
                "token_type": "Bearer",
            })));
    }

    // Otherwise try as a refresh token (opaque, stored hashed).
    let token_hash = tokens::sha256(token);
    if let Ok(Some(record)) = database.get_refresh_token(&token_hash).await {
        let now = chrono::Utc::now().timestamp();
        let active = !record.revoked && record.expiry > now && record.client_id == client.client_id;
        if active {
            return Ok(HttpResponse::Ok()
                .insert_header(("Cache-Control", "no-store"))
                .json(serde_json::json!({
                    "active": true,
                    "scope": record.scope,
                    "client_id": record.client_id,
                    "sub": record.subject,
                    "exp": record.expiry,
                    "token_type": "refresh_token",
                })));
        }
    }

    Ok(inactive())
}
