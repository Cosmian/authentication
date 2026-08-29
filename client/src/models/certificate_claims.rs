use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AuthScheme;

/// Payload of the JWS returned by `POST /certify`.
///
/// Deliberately a distinct shape from [`crate::ClientClaims`] (no `roles`, no `as_*`-prefixed
/// names) and signed with a certificate signing key separate from the session JWT key, so a
/// certificate can never be confused with, or substituted for, a session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateClaims {
    /// Realm the caller authenticated to.
    pub realm_id: String,

    /// Subject (authenticated username) the verification key is certified for.
    /// `sub` can be sensitive; omitted when the caller sets `exclude_sub` in the
    /// `/certify` request (only allowed when `claims` is non-empty — a certificate
    /// must identify its holder by at least one claim).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Authentication scheme that was used to establish the session under which
    /// certification was requested.
    pub auth_scheme: AuthScheme,

    /// The caller-supplied PEM public key being certified, opaque to the server.
    pub verification_key: String,

    /// Issued-at (Unix seconds).
    pub iat: i64,

    /// Expiration (Unix seconds).
    pub exp: i64,

    /// Extra claims copied from the session's own `extra` claims, restricted to the
    /// names the caller explicitly listed in the `/certify` request body — never copied
    /// wholesale, since a certificate can outlive its session by a long margin.
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}
