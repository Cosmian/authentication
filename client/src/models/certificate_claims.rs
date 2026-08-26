use serde::{Deserialize, Serialize};

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
    pub sub: String,

    /// Authentication scheme that was used to establish the session under which
    /// certification was requested.
    pub auth_scheme: AuthScheme,

    /// The caller-supplied PEM public key being certified, opaque to the server.
    pub verification_key: String,

    /// Issued-at (Unix seconds).
    pub iat: i64,

    /// Expiration (Unix seconds).
    pub exp: i64,
}
