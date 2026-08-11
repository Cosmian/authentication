//! OIDC token issuance and validation.
//!
//! - **ID Token** — RFC 7519 JWT, `aud = client_id`, carries `nonce`,
//!   `auth_time`, `at_hash`, and scope-gated profile claims.
//! - **Access Token** — RFC 9068 JWT with header `typ: at+jwt` and a distinct
//!   audience; validated by [`validate_access_token`].
//! - **Refresh Token** — opaque random string; only its SHA-256 hash is stored.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AuthError, oidc::OidcState};

/// RFC 9068 access-token JWT type.
pub const AT_JWT_TYP: &str = "at+jwt";

/// ID Token claims (OpenID Connect Core §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Access-token hash (OIDC Core §3.1.3.6) binding the ID token to the AT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    /// Authorized party — the client the token was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    // ── scope-gated profile/email claims ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

/// Access Token claims (RFC 9068 §2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub client_id: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Realm the subject authenticated against (private claim).
    #[serde(rename = "as_rid", skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
}

/// The subject's profile attributes used to populate scope-gated claims.
#[derive(Debug, Clone, Default)]
pub struct SubjectProfile {
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub roles: Vec<String>,
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Header with the OIDC signing `kid` and a specific `typ`.
fn signing_header(state: &OidcState, typ: Option<&str>) -> Header {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(state.signing_kid.clone());
    if let Some(t) = typ {
        header.typ = Some(t.to_string());
    }
    header
}

/// Compute the OIDC `at_hash`: base64url of the left-most half of the SHA-256 of
/// the ASCII access-token string (ES256 ⇒ SHA-256 ⇒ 16-byte half).
pub fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

/// Whether a space-delimited scope string contains `scope`.
pub fn scope_contains(scope: &str, target: &str) -> bool {
    scope.split_whitespace().any(|s| s == target)
}

/// Issue an RFC 9068 `at+jwt` access token. Returns `(token, expires_in_secs)`.
pub fn issue_access_token(
    state: &OidcState,
    client_id: &str,
    subject: &str,
    realm: &str,
    scope: &str,
    profile: &SubjectProfile,
) -> Result<(String, i64), AuthError> {
    let now = now_ts();
    let exp = now + state.access_token_ttl_secs;
    let audience = state
        .default_audience
        .clone()
        .unwrap_or_else(|| state.issuer.clone());

    let roles = if scope_contains(scope, "roles") && !profile.roles.is_empty() {
        Some(profile.roles.clone())
    } else {
        None
    };

    let claims = AccessTokenClaims {
        iss: state.issuer.clone(),
        sub: subject.to_string(),
        aud: audience,
        exp,
        iat: now,
        jti: random_id(),
        client_id: client_id.to_string(),
        scope: scope.to_string(),
        roles,
        realm: Some(realm.to_string()),
    };

    let header = signing_header(state, Some(AT_JWT_TYP));
    let token = encode(&header, &claims, &state.encoding_key)
        .map_err(|e| AuthError::Unexpected(format!("Failed to issue access token: {e}")))?;
    Ok((token, state.access_token_ttl_secs))
}

/// Issue an OIDC ID token bound to `access_token` via `at_hash`.
#[allow(clippy::too_many_arguments)]
pub fn issue_id_token(
    state: &OidcState,
    client_id: &str,
    subject: &str,
    scope: &str,
    nonce: Option<&str>,
    auth_time: i64,
    profile: &SubjectProfile,
    access_token: Option<&str>,
) -> Result<String, AuthError> {
    let now = now_ts();
    let exp = now + state.id_token_ttl_secs;

    let (name, preferred_username) = if scope_contains(scope, "profile") {
        (profile.name.clone(), profile.preferred_username.clone())
    } else {
        (None, None)
    };
    let email = if scope_contains(scope, "email") {
        profile.email.clone()
    } else {
        None
    };
    let roles = if scope_contains(scope, "roles") && !profile.roles.is_empty() {
        Some(profile.roles.clone())
    } else {
        None
    };

    let claims = IdTokenClaims {
        iss: state.issuer.clone(),
        sub: subject.to_string(),
        aud: client_id.to_string(),
        exp,
        iat: now,
        auth_time: Some(auth_time),
        nonce: nonce.map(str::to_string),
        at_hash: access_token.map(at_hash),
        azp: Some(client_id.to_string()),
        name,
        preferred_username,
        email,
        roles,
    };

    let header = signing_header(state, None);
    encode(&header, &claims, &state.encoding_key)
        .map_err(|e| AuthError::Unexpected(format!("Failed to issue ID token: {e}")))
}

/// Validate an access token: ES256 signature, `exp`, issuer, and the mandatory
/// `typ: at+jwt` header (RFC 9068 §4). Returns the parsed claims.
pub fn validate_access_token(
    state: &OidcState,
    token: &str,
) -> Result<AccessTokenClaims, AuthError> {
    let header = decode_header(token)
        .map_err(|e| AuthError::Unexpected(format!("Failed to decode token header: {e}")))?;
    match header.typ.as_deref() {
        Some(t) if t.eq_ignore_ascii_case(AT_JWT_TYP) => {}
        _ => {
            return Err(AuthError::Unexpected(
                "not an access token (missing typ: at+jwt header)".to_string(),
            ));
        }
    }

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;
    validation.leeway = 1;
    validation.set_issuer(std::slice::from_ref(&state.issuer));
    // Audience varies per resource; issuer + typ + signature are authoritative.
    validation.validate_aud = false;

    let data = decode::<AccessTokenClaims>(token, &state.decoding_key, &validation)
        .map_err(|e| AuthError::Unexpected(format!("Failed to validate access token: {e}")))?;
    Ok(data.claims)
}

/// Generate a URL-safe random identifier (used for `jti`).
pub fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate an opaque token string with the given prefix, returning
/// `(raw_token, sha256_hash)`. The raw token is returned to the client; only the
/// hash is persisted.
pub fn generate_opaque_token(prefix: &str) -> (String, Vec<u8>) {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let raw = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = Sha256::digest(raw.as_bytes()).to_vec();
    (raw, hash)
}

/// SHA-256 of a string, as raw bytes (for looking up stored token/code hashes).
pub fn sha256(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}
