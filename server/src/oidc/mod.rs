//! OpenID Connect (OIDC) Provider core.
//!
//! This module holds the OP building blocks that are independent of the HTTP
//! layer: token issuance/validation ([`tokens`]), PKCE verification ([`pkce`]),
//! the combined JWKS document ([`jwks`]), and the shared runtime state
//! ([`OidcState`]) that the endpoint handlers consume via Actix `Data`.
//!
//! # Security separation (see the crate-level design notes)
//! ID tokens and RFC 9068 `at+jwt` access tokens are signed with a **dedicated
//! OIDC key** whose `kid` is distinct from the session-JWT key. Access tokens
//! carry an explicit `typ: at+jwt` header and a distinct audience from ID
//! tokens (whose `aud` is the `client_id`), so the two token types can never be
//! substituted for one another.

pub mod jwks;
pub mod pkce;
pub mod tokens;

use jsonwebtoken::{DecodingKey, EncodingKey};

use crate::{AuthError, session::JwksData};

/// Shared OIDC provider runtime state, built once at startup.
pub struct OidcState {
    /// Issuer identifier (`iss`) and discovery base URL.
    pub issuer: String,
    /// Signing key for ID and access tokens.
    pub encoding_key: EncodingKey,
    /// Verification key for access tokens (introspection / userinfo).
    pub decoding_key: DecodingKey,
    /// `kid` of the OIDC signing key, placed in issued-token headers and JWKS.
    pub signing_kid: String,
    /// ID token lifetime, seconds.
    pub id_token_ttl_secs: i64,
    /// Access token lifetime, seconds.
    pub access_token_ttl_secs: i64,
    /// Refresh token lifetime, seconds.
    pub refresh_token_ttl_secs: i64,
    /// Authorization code lifetime, seconds.
    pub code_ttl_secs: i64,
    /// Scopes advertised in discovery and accepted at `/authorize`.
    pub supported_scopes: Vec<String>,
    /// Default access-token audience when a client requests no resource.
    pub default_audience: Option<String>,
    /// Combined JWKS (OIDC signing key + session key) served at the jwks_uri.
    pub jwks: JwksData,
}

impl OidcState {
    /// The absolute URL of an OIDC endpoint under this issuer.
    pub fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.issuer.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

/// Build the [`OidcState`] from resolved server parameters.
///
/// The OIDC signing key is loaded from the dedicated `oidc_params` key path when
/// configured, otherwise it falls back to the session/TLS key (a warning is
/// logged by the caller). The combined JWKS publishes both the OIDC signing key
/// and the session key so relying parties can validate any token this server
/// issues from a single `jwks_uri`.
pub fn build_oidc_state(
    params: &crate::server::parameters::ServerParams,
) -> Result<OidcState, AuthError> {
    use crate::server::parameters::OidcParams;

    let oidc = params.oidc_params.clone().unwrap_or_default();
    let issuer = params.oidc_issuer();

    let encoding_key = params.get_oidc_encoding_key()?;
    let decoding_key = params.get_oidc_decoding_key()?;

    // Compute the OIDC signing kid from its public key PEM.
    let oidc_pub_path = params.oidc_signing_public_key_path()?;
    let oidc_pub_pem = std::fs::read_to_string(&oidc_pub_path).map_err(|e| {
        AuthError::Init(format!(
            "Failed to read OIDC signing public key PEM at {oidc_pub_path}: {e}"
        ))
    })?;
    let (oidc_jwk, signing_kid) = crate::session::build_jwk_from_pem(&oidc_pub_pem)?;

    // Session public key (for the combined JWKS); may equal the OIDC key.
    let session_pub_path = params
        .session_jwt_params
        .as_ref()
        .map(|p| p.jwt_ec_public_key.clone())
        .or_else(|| {
            params
                .tls_params
                .as_ref()
                .map(|t| t.server_certificate.clone())
        });

    let jwks = jwks::build_combined_jwks(&oidc_jwk, session_pub_path.as_deref())?;

    let OidcParams {
        id_token_ttl_secs,
        access_token_ttl_secs,
        refresh_token_ttl_secs,
        code_ttl_secs,
        supported_scopes,
        default_audience,
        ..
    } = oidc;

    Ok(OidcState {
        issuer,
        encoding_key,
        decoding_key,
        signing_kid,
        id_token_ttl_secs,
        access_token_ttl_secs,
        refresh_token_ttl_secs,
        code_ttl_secs,
        supported_scopes,
        default_audience,
        jwks,
    })
}
