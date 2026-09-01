//! OIDC token endpoint (`POST /oidc/token`).
//!
//! Supports the `authorization_code` (with mandatory PKCE), `refresh_token`
//! (with rotation + reuse detection), and `client_credentials` grants.

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse,
    web::{Data, Form},
};

use crate::AuthError;
use crate::database::{Database, OAuthClient, RefreshToken};
use crate::oidc::tokens::{self, SubjectProfile};
use crate::oidc::{OidcState, pkce};
use crate::server::endpoints::oidc::common::authenticate_client;
use crate::server::endpoints::oidc::error::{
    invalid_grant, invalid_request, invalid_scope, unsupported_grant_type,
};

/// A token response with `Cache-Control: no-store` (RFC 6749 §5.1).
fn token_response(body: serde_json::Value) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Pragma", "no-cache"))
        .json(body)
}

/// Fetch the subject's profile attributes (roles, email as subject identity).
///
/// `email` is always set so that OIDC relying parties (e.g. KMS)
/// that use the `email` claim as the user identity always receive a value:
/// 1. If the user record has a dedicated `email` field set, that is used.
/// 2. Otherwise, `subject` is used as the fallback (covers both
///    email-style usernames like `"alice@example.com"` and plain
///    usernames like `"alice"`).
async fn build_profile(database: &Arc<dyn Database>, realm: &str, subject: &str) -> SubjectProfile {
    let (roles, stored_email) = match database.get_userpass(realm, subject).await {
        Ok(Some(up)) => (up.roles, up.email),
        _ => (Vec::new(), None),
    };
    // Prefer the stored email; fall back to subject as identifier.
    let email = Some(stored_email.unwrap_or_else(|| subject.to_string()));
    SubjectProfile {
        name: None,
        preferred_username: Some(subject.to_string()),
        email,
        roles,
    }
}

/// Dispatch the token request by `grant_type`.
pub async fn token(
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

    let grant_type = form.get("grant_type").map(String::as_str).unwrap_or("");
    match grant_type {
        "authorization_code" => {
            Ok(grant_authorization_code(&state, &database, &client, &form).await)
        }
        "refresh_token" => Ok(grant_refresh_token(&state, &database, &client, &form).await),
        "client_credentials" => {
            Ok(grant_client_credentials(&state, &database, &client, &form).await)
        }
        "" => Ok(invalid_request("missing grant_type")),
        other => Ok(unsupported_grant_type(&format!(
            "unsupported grant_type: {other}"
        ))),
    }
}

/// `grant_type=authorization_code` (RFC 6749 §4.1.3 + PKCE + OIDC).
async fn grant_authorization_code(
    state: &OidcState,
    database: &Arc<dyn Database>,
    client: &OAuthClient,
    form: &HashMap<String, String>,
) -> HttpResponse {
    if !client.grant_types.iter().any(|g| g == "authorization_code") {
        return invalid_grant("client may not use the authorization_code grant");
    }
    let Some(code) = form.get("code") else {
        return invalid_request("missing code");
    };
    let Some(redirect_uri) = form.get("redirect_uri") else {
        return invalid_request("missing redirect_uri");
    };
    let Some(code_verifier) = form.get("code_verifier") else {
        return invalid_request("missing PKCE code_verifier");
    };

    let code_hash = tokens::sha256(code);
    let record = match database.consume_authorization_code(&code_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return invalid_grant("authorization code is invalid or expired"),
        Err(e) => return invalid_grant(&format!("code lookup failed: {e}")),
    };

    if record.client_id != client.client_id {
        return invalid_grant("authorization code was issued to a different client");
    }
    if &record.redirect_uri != redirect_uri {
        return invalid_grant("redirect_uri does not match the authorization request");
    }
    if !pkce::verify_s256(
        code_verifier,
        &record.code_challenge,
        &record.code_challenge_method,
    ) {
        return invalid_grant("PKCE verification failed");
    }

    issue_tokens(
        state,
        database,
        client,
        &record.subject,
        &record.realm,
        &record.scope,
        record.nonce.as_deref(),
        record.auth_time,
        true,
    )
    .await
}

/// `grant_type=refresh_token` (RFC 6749 §6) with rotation + reuse detection.
async fn grant_refresh_token(
    state: &OidcState,
    database: &Arc<dyn Database>,
    client: &OAuthClient,
    form: &HashMap<String, String>,
) -> HttpResponse {
    if !client.grant_types.iter().any(|g| g == "refresh_token") {
        return invalid_grant("client may not use the refresh_token grant");
    }
    let Some(refresh_token) = form.get("refresh_token") else {
        return invalid_request("missing refresh_token");
    };
    let token_hash = tokens::sha256(refresh_token);
    let record = match database.get_refresh_token(&token_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return invalid_grant("unknown refresh token"),
        Err(e) => return invalid_grant(&format!("refresh token lookup failed: {e}")),
    };

    if record.client_id != client.client_id {
        return invalid_grant("refresh token was issued to a different client");
    }
    // Reuse detection: a revoked token replay invalidates the whole family.
    if record.revoked {
        let _ = database
            .revoke_refresh_tokens_for_subject(&record.realm, &record.subject)
            .await;
        return invalid_grant("refresh token has been revoked (possible reuse)");
    }
    if record.expiry < chrono::Utc::now().timestamp() {
        return invalid_grant("refresh token has expired");
    }

    // Optionally narrow scope on refresh (RFC 6749 §6); must be a subset.
    let scope = match narrow_scope(form.get("scope"), &record.scope) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // Rotate: revoke the presented token before issuing the replacement.
    let _ = database.revoke_refresh_token(&token_hash).await;

    issue_tokens(
        state,
        database,
        client,
        &record.subject,
        &record.realm,
        &scope,
        None,
        chrono::Utc::now().timestamp(),
        true,
    )
    .await
}

/// `grant_type=client_credentials` (RFC 6749 §4.4). No id_token, no refresh.
async fn grant_client_credentials(
    state: &OidcState,
    _database: &Arc<dyn Database>,
    client: &OAuthClient,
    form: &HashMap<String, String>,
) -> HttpResponse {
    if !client.grant_types.iter().any(|g| g == "client_credentials") {
        return invalid_grant("client may not use the client_credentials grant");
    }
    if client.is_public() {
        return invalid_grant("public clients may not use the client_credentials grant");
    }

    // Requested scope filtered to what the client is allowed (openid dropped —
    // there is no end-user, so no id_token).
    let requested = form.get("scope").map(String::as_str).unwrap_or("");
    let scope: Vec<String> = requested
        .split_whitespace()
        .filter(|s| *s != "openid")
        .filter(|s| client.scopes.is_empty() || client.scopes.iter().any(|x| x == *s))
        .map(|s| s.to_string())
        .collect();
    let scope = scope.join(" ");

    let profile = SubjectProfile {
        preferred_username: Some(client.client_id.clone()),
        // Use client_id as the email identity for service accounts so relying
        // parties that require an email claim (e.g. KMS) always get a value.
        email: Some(client.client_id.clone()),
        ..Default::default()
    };
    match tokens::issue_access_token(
        state,
        &client.client_id,
        &client.client_id,
        &client.realm,
        &scope,
        &profile,
    ) {
        Ok((access_token, expires_in)) => token_response(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": scope,
        })),
        Err(e) => invalid_grant(&format!("failed to issue access token: {e}")),
    }
}

/// Ensure a requested refresh scope is a subset of the original; default to the
/// original scope when none is requested.
fn narrow_scope(requested: Option<&String>, original: &str) -> Result<String, HttpResponse> {
    let Some(requested) = requested else {
        return Ok(original.to_string());
    };
    let original_set: Vec<&str> = original.split_whitespace().collect();
    for s in requested.split_whitespace() {
        if !original_set.contains(&s) {
            return Err(invalid_scope(
                "requested scope exceeds the originally granted scope",
            ));
        }
    }
    Ok(requested.clone())
}

/// Build access + (optionally) id + refresh tokens and return the token response.
#[allow(clippy::too_many_arguments)]
async fn issue_tokens(
    state: &OidcState,
    database: &Arc<dyn Database>,
    client: &OAuthClient,
    subject: &str,
    realm: &str,
    scope: &str,
    nonce: Option<&str>,
    auth_time: i64,
    allow_refresh: bool,
) -> HttpResponse {
    let profile = build_profile(database, realm, subject).await;

    let (access_token, expires_in) =
        match tokens::issue_access_token(state, &client.client_id, subject, realm, scope, &profile)
        {
            Ok(t) => t,
            Err(e) => return invalid_grant(&format!("failed to issue access token: {e}")),
        };

    let mut body = serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": scope,
    });

    // ID token when the openid scope is present.
    if tokens::scope_contains(scope, "openid") {
        match tokens::issue_id_token(
            state,
            &client.client_id,
            subject,
            scope,
            nonce,
            auth_time,
            &profile,
            Some(&access_token),
        ) {
            Ok(id_token) => {
                body["id_token"] = serde_json::Value::String(id_token);
            }
            Err(e) => return invalid_grant(&format!("failed to issue id token: {e}")),
        }
    }

    // Refresh token when allowed and the client supports it.
    let wants_refresh = allow_refresh
        && client.grant_types.iter().any(|g| g == "refresh_token")
        && (tokens::scope_contains(scope, "offline_access")
            || tokens::scope_contains(scope, "openid"));
    if wants_refresh {
        let (raw, hash) = tokens::generate_opaque_token("rt-");
        let record = RefreshToken {
            token_hash: hash,
            client_id: client.client_id.clone(),
            subject: subject.to_string(),
            realm: realm.to_string(),
            scope: scope.to_string(),
            expiry: chrono::Utc::now().timestamp() + state.refresh_token_ttl_secs,
            created_at: chrono::Utc::now().timestamp(),
            revoked: false,
        };
        if let Err(e) = database.create_refresh_token(&record).await {
            return invalid_grant(&format!("failed to issue refresh token: {e}"));
        }
        body["refresh_token"] = serde_json::Value::String(raw);
    }

    token_response(body)
}
