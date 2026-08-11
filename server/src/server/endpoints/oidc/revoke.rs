//! OAuth 2.0 Token Revocation endpoint (`POST /oidc/revoke`, RFC 7009).

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse,
    web::{Data, Form},
};

use crate::AuthError;
use crate::database::Database;
use crate::oidc::tokens;
use crate::server::endpoints::oidc::common::authenticate_client;

/// Revoke a refresh token. Access tokens are stateless (short-lived JWTs) and
/// are not individually revocable, but — per RFC 7009 §2.2 — the endpoint still
/// responds `200 OK` for any token it does not recognise.
pub async fn revoke(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
    form: Form<HashMap<String, String>>,
) -> Result<HttpResponse, AuthError> {
    let form = form.into_inner();
    let database = database.into_inner();

    let client = match authenticate_client(&req, &form, &database).await {
        Ok(ac) => ac.client,
        Err(resp) => return Ok(resp),
    };

    if let Some(token) = form.get("token") {
        let token_hash = tokens::sha256(token);
        // Only revoke when the token belongs to the authenticated client.
        if let Ok(Some(record)) = database.get_refresh_token(&token_hash).await
            && record.client_id == client.client_id
        {
            let _ = database.revoke_refresh_token(&token_hash).await;
        }
    }

    // Always 200 OK regardless of whether the token existed.
    Ok(HttpResponse::Ok().finish())
}
