use jsonwebtoken::{DecodingKey, EncodingKey};

use crate::{AuthError, server::parameters::ServerParams};

/// Default OIDC scopes advertised in discovery and accepted at `/authorize`.
fn default_supported_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "offline_access".to_string(),
        "roles".to_string(),
    ]
}

fn default_id_token_ttl_secs() -> i64 {
    3600
}

fn default_access_token_ttl_secs() -> i64 {
    3600
}

fn default_refresh_token_ttl_secs() -> i64 {
    1_209_600 // 14 days
}

fn default_code_ttl_secs() -> i64 {
    60
}

/// OpenID Provider (OP) configuration.
///
/// When present, the server exposes the OIDC front-channel (`/authorize`,
/// login + consent) and back-channel (`/token`, `/userinfo`, `/introspect`,
/// `/revoke`) endpoints plus discovery metadata at
/// `/.well-known/openid-configuration`.
///
/// # Security separation
/// The OIDC signing key is intentionally kept *separate* from the session-JWT
/// key. ID tokens and `at+jwt` access tokens are signed with this key; the
/// opaque `_ea_` session cookie keeps its own key. When the dedicated key paths
/// are omitted, the server falls back to the session-JWT key and logs a warning
/// — acceptable for development but discouraged in production.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct OidcParams {
    /// Public issuer base URL (e.g. `https://auth.example.com`). This value is
    /// used verbatim as the `iss` claim and as the base for the advertised
    /// endpoint URLs in the discovery document. When omitted, it is derived
    /// from the server host/port and TLS configuration.
    #[serde(default)]
    pub issuer: Option<String>,

    /// Path to the dedicated OIDC signing EC private key PEM. Falls back to the
    /// session-JWT / TLS private key when omitted.
    #[serde(default)]
    pub oidc_signing_private_key: Option<String>,

    /// Path to the dedicated OIDC signing EC public key PEM. Falls back to the
    /// session-JWT / TLS public key when omitted.
    #[serde(default)]
    pub oidc_signing_public_key: Option<String>,

    /// Lifetime of issued ID tokens, in seconds.
    #[serde(default = "default_id_token_ttl_secs")]
    pub id_token_ttl_secs: i64,

    /// Lifetime of issued access tokens, in seconds.
    #[serde(default = "default_access_token_ttl_secs")]
    pub access_token_ttl_secs: i64,

    /// Lifetime of issued refresh tokens, in seconds.
    #[serde(default = "default_refresh_token_ttl_secs")]
    pub refresh_token_ttl_secs: i64,

    /// Lifetime of issued authorization codes, in seconds.
    #[serde(default = "default_code_ttl_secs")]
    pub code_ttl_secs: i64,

    /// Scopes advertised in discovery and accepted at the authorization endpoint.
    #[serde(default = "default_supported_scopes")]
    pub supported_scopes: Vec<String>,

    /// Default audience placed in the `aud` claim of access tokens when a client
    /// does not request a specific resource. Keeping the access-token audience
    /// distinct from the ID-token audience (`client_id`) prevents token
    /// substitution between the two token types.
    #[serde(default)]
    pub default_audience: Option<String>,
}

impl Default for OidcParams {
    fn default() -> Self {
        Self {
            issuer: None,
            oidc_signing_private_key: None,
            oidc_signing_public_key: None,
            id_token_ttl_secs: default_id_token_ttl_secs(),
            access_token_ttl_secs: default_access_token_ttl_secs(),
            refresh_token_ttl_secs: default_refresh_token_ttl_secs(),
            code_ttl_secs: default_code_ttl_secs(),
            supported_scopes: default_supported_scopes(),
            default_audience: None,
        }
    }
}

impl ServerParams {
    /// Resolve the OIDC issuer URL.
    ///
    /// Uses the explicit `oidc_params.issuer` when set, otherwise derives it
    /// from the server host/port and whether TLS is enabled.
    pub fn oidc_issuer(&self) -> String {
        if let Some(oidc) = &self.oidc_params
            && let Some(issuer) = &oidc.issuer
        {
            return issuer.trim_end_matches('/').to_string();
        }
        let scheme = if self.tls_params.is_some() {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://{}:{}", self.host_name, self.host_port)
    }

    /// Path to the OIDC signing private key PEM, falling back to the
    /// session-JWT / TLS private key when no dedicated key is configured.
    fn oidc_signing_private_key_path(&self) -> Result<String, AuthError> {
        if let Some(oidc) = &self.oidc_params
            && let Some(path) = &oidc.oidc_signing_private_key
        {
            return Ok(path.clone());
        }
        self.session_jwt_params
            .as_ref()
            .map(|p| p.jwt_ec_private_key.clone())
            .or_else(|| {
                self.tls_params
                    .as_ref()
                    .map(|t| t.server_private_key.clone())
            })
            .ok_or_else(|| {
                AuthError::Init(
                    "No OIDC signing private key: set oidc_params.oidc_signing_private_key, \
                     session_jwt_params or tls_params"
                        .to_owned(),
                )
            })
    }

    /// Path to the OIDC signing public key PEM, falling back to the
    /// session-JWT / TLS public key / certificate when no dedicated key is
    /// configured.
    pub fn oidc_signing_public_key_path(&self) -> Result<String, AuthError> {
        if let Some(oidc) = &self.oidc_params
            && let Some(path) = &oidc.oidc_signing_public_key
        {
            return Ok(path.clone());
        }
        self.session_jwt_params
            .as_ref()
            .map(|p| p.jwt_ec_public_key.clone())
            .or_else(|| {
                self.tls_params
                    .as_ref()
                    .map(|t| t.server_certificate.clone())
            })
            .ok_or_else(|| {
                AuthError::Init(
                    "No OIDC signing public key: set oidc_params.oidc_signing_public_key, \
                     session_jwt_params or tls_params"
                        .to_owned(),
                )
            })
    }

    /// Build the OIDC signing (encoding) key from the resolved private-key PEM.
    pub fn get_oidc_encoding_key(&self) -> Result<EncodingKey, AuthError> {
        let path = self.oidc_signing_private_key_path()?;
        let pem = std::fs::read_to_string(&path).map_err(|e| {
            AuthError::Init(format!(
                "Failed to read OIDC signing private key PEM at {path}: {e}"
            ))
        })?;
        EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| {
            AuthError::Init(format!(
                "Failed to create OIDC encoding key from PEM at {path}: {e}"
            ))
        })
    }

    /// Build the OIDC verification (decoding) key from the resolved public-key PEM.
    pub fn get_oidc_decoding_key(&self) -> Result<DecodingKey, AuthError> {
        let path = self.oidc_signing_public_key_path()?;
        let pem = std::fs::read_to_string(&path).map_err(|e| {
            AuthError::Init(format!(
                "Failed to read OIDC signing public key PEM at {path}: {e}"
            ))
        })?;
        DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| {
            AuthError::Init(format!(
                "Failed to create OIDC decoding key from PEM at {path}: {e}"
            ))
        })
    }
}
