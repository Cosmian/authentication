//! Shared client-authentication and secret helpers for the OIDC back-channel
//! endpoints (`/token`, `/introspect`, `/revoke`).

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sha2::{Digest, Sha256};

use crate::database::{Database, OAuthClient};
use crate::server::endpoints::oidc::error::invalid_client;

/// SHA-256 hash of a client secret for storage/comparison.
pub fn hash_secret(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// Constant-time comparison of a presented secret against a stored hash.
pub fn verify_secret(presented: &str, stored_hash: &[u8]) -> bool {
    let presented_hash = hash_secret(presented);
    if presented_hash.len() != stored_hash.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in presented_hash.iter().zip(stored_hash.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Percent-decode an `application/x-www-form-urlencoded` component (RFC 6749
/// §2.3.1 encodes the userid/password of HTTP Basic this way). `+` maps to space.
fn form_urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse HTTP Basic credentials from the `Authorization` header, returning the
/// `(client_id, client_secret)` pair (form-urldecoded per RFC 6749 §2.3.1).
fn parse_basic_auth(req: &HttpRequest) -> Option<(String, String)> {
    let header = req.headers().get(actix_web::http::header::AUTHORIZATION)?;
    let value = header.to_str().ok()?;
    let b64 = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = BASE64_STANDARD.decode(b64.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((form_urldecode(id), form_urldecode(secret)))
}

/// The outcome of client authentication at a token/introspection/revocation
/// endpoint.
pub struct AuthenticatedClient {
    pub client: OAuthClient,
}

/// Authenticate the OAuth client using the presented credentials.
///
/// Supports `client_secret_basic` (Authorization header), `client_secret_post`
/// (form body), and `none` (public clients that authenticate with `client_id`
/// alone and rely on PKCE). Returns an `invalid_client` [`HttpResponse`] on
/// failure.
pub async fn authenticate_client(
    req: &HttpRequest,
    form: &HashMap<String, String>,
    database: &Arc<dyn Database>,
) -> Result<AuthenticatedClient, HttpResponse> {
    // Prefer HTTP Basic; fall back to form body parameters.
    let (client_id, client_secret) = match parse_basic_auth(req) {
        Some((id, secret)) => (id, Some(secret)),
        None => {
            let id = form
                .get("client_id")
                .cloned()
                .ok_or_else(|| invalid_client("missing client authentication"))?;
            (id, form.get("client_secret").cloned())
        }
    };

    let client = database
        .get_oauth_client(&client_id)
        .await
        .map_err(|e| invalid_client(&format!("client lookup failed: {e}")))?
        .ok_or_else(|| invalid_client("unknown client"))?;

    if client.is_public() {
        // Public client: no secret expected. Reject if one was presented.
        if client_secret.is_some() {
            return Err(invalid_client(
                "public client must not present a client secret",
            ));
        }
        return Ok(AuthenticatedClient { client });
    }

    // Confidential client: a valid secret is required.
    let secret = client_secret.ok_or_else(|| invalid_client("missing client secret"))?;
    let stored = client
        .client_secret_hash
        .as_deref()
        .ok_or_else(|| invalid_client("client has no secret configured"))?;
    if !verify_secret(&secret, stored) {
        return Err(invalid_client("invalid client secret"));
    }
    Ok(AuthenticatedClient { client })
}
