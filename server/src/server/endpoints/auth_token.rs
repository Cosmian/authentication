//! AppRole-compatible token self-service endpoints.
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/auth/token/lookup-self` | Return metadata for the bearer token |
//! | POST | `/auth/token/renew-self` | Renew a renewable token |
//! | POST | `/auth/token/revoke-self` | Revoke the current token |

use crate::{AuthError, database::Database, middleware::AppTokenClaims};
use actix_web::{HttpMessage, HttpRequest, HttpResponse, get, post, web::Data};
use auth_client::{AppTokenData, AppTokenLookupResponse};
use cosmian_logger::info;
use std::sync::Arc;

/// Return metadata for the current `X-Vault-Token`.
///
/// Equivalent to `GET /auth/token/lookup-self` in the AppRole auth API.
#[get("/lookup-self")]
pub async fn auth_token_lookup_self(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let claims = req
        .extensions()
        .get::<AppTokenClaims>()
        .cloned()
        .ok_or_else(|| AuthError::Session("missing app token claims".to_string()))?;

    // Re-read from DB to get the freshest TTL
    let token = database
        .lookup_app_token(&claims.token_hash)
        .await?
        .ok_or_else(|| AuthError::Session("token not found".to_string()))?;

    // The AppRole auth API spec (§3.1 of the AppRole wire protocol) requires
    // data.id to be the token itself.  SPIRE reads this field to verify the
    // token and warm its internal state.  The token was already sent by the
    // caller in the X-Vault-Token request header, so returning it here does
    // not reveal anything the caller does not already hold.
    let raw_token = req
        .headers()
        .get("X-Vault-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let now = chrono::Utc::now().timestamp();
    let ttl = if token.expiry == 0 {
        token.lease_duration_secs
    } else {
        (token.expiry - now).max(0)
    };

    let resp = AppTokenLookupResponse {
        data: AppTokenData {
            id: raw_token, // AppRole auth API spec §3.1: data.id is the token itself
            entity_id: token.entity.clone(),
            policies: token.policies.clone(),
            renewable: token.renewable,
            ttl,
            creation_time: token.created_at,
        },
    };
    Ok(HttpResponse::Ok().json(resp))
}

/// Renew a renewable token.
///
/// Equivalent to `POST /auth/token/renew-self` in the AppRole Auth API.
#[post("/renew-self")]
pub async fn auth_token_renew_self(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let claims = req
        .extensions()
        .get::<AppTokenClaims>()
        .cloned()
        .ok_or_else(|| AuthError::Session("missing app token claims".to_string()))?;

    database
        .renew_app_token(&claims.token_hash)
        .await
        .map_err(|e| AuthError::Forbidden(e.to_string()))?;

    // Return updated lookup
    let token = database
        .lookup_app_token(&claims.token_hash)
        .await?
        .ok_or_else(|| AuthError::Generic("token vanished after renew".to_string()))?;

    let now = chrono::Utc::now().timestamp();
    let ttl = if token.expiry == 0 {
        token.lease_duration_secs
    } else {
        (token.expiry - now).max(0)
    };

    // The AppRole auth API spec (§3.6) requires auth.client_token to be the
    // (possibly renewed) token.  SPIRE uses this to refresh its in-memory
    // token state.  The caller already holds this token.
    let raw_token = req
        .headers()
        .get("X-Vault-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let resp = serde_json::json!({
        "auth": {
            "client_token": raw_token, // AppRole auth API spec §3.6: echo the token back
            "renewable": token.renewable,
            "lease_duration": ttl,
            "policies": token.policies,
            "metadata": {}
        }
    });
    Ok(HttpResponse::Ok().json(resp))
}

/// Revoke (invalidate) the current token.
///
/// Equivalent to `POST /auth/token/revoke-self` in the AppRole Auth API.
#[post("/revoke-self")]
pub async fn auth_token_revoke_self(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let claims = req
        .extensions()
        .get::<AppTokenClaims>()
        .cloned()
        .ok_or_else(|| AuthError::Session("missing app token claims".to_string()))?;

    database.revoke_app_token(&claims.token_hash).await?;
    info!("app token revoked for entity '{}'", claims.entity);
    Ok(HttpResponse::NoContent().finish())
}
