use jsonwebtoken::{DecodingKey, EncodingKey};

use crate::{
    AuthError,
    server::parameters::{DatabaseParams, OidcParams, ProxyParams, SessionJwtParams, TlsParams},
    session::StaleSessionCollectorConfig,
};

#[derive(Clone, Debug, serde::Deserialize)]
/// The Forward Proxy Parameters
pub struct ServerParams {
    pub host_name: String,
    pub host_port: u16,
    /// TLS configuration. When `None`, the server binds plain HTTP (dev only).
    pub tls_params: Option<TlsParams>,
    pub default_username: Option<String>,

    pub session_jwt_params: Option<SessionJwtParams>,

    /// Optional database parameters for all objects but the sessions -
    /// if not provided an in-memory SQLite database will be used
    /// Only PostgreSQL, SQLite and MySQL are supported. Redis is not supported.
    pub database_params: Option<DatabaseParams>,

    /// Optional session store parameters -
    /// if not provided the database parameters will be used for session storage (if any)
    /// PostgreSQL, SQLite, MySQL and Redis are supported.
    pub sessions_store_params: Option<DatabaseParams>,

    /// Forward proxy parameters to use when fetching external data (e.g. JWKS )
    pub proxy_params: Option<ProxyParams>,

    /// Optional configuration for the stale session collector background task.
    /// If not provided, defaults to a 60-second cleanup interval.
    /// Only applicable to SQL-based session stores (SQLite, PostgreSQL, MySQL);
    /// Redis handles expiration automatically via TTL.
    pub stale_session_collector_config: Option<StaleSessionCollectorConfig>,

    /// Optional development seed: creates a realm-admin account on first start.
    /// Intended only for `auth_verifier.dev.toml` — do not use in production.
    pub dev_seed: Option<DevSeedParams>,

    /// Console logging configuration. When omitted, defaults to info level.
    pub log: Option<crate::server::parameters::LogConfig>,

    /// OpenID Provider (OP) configuration. When present, the server exposes the
    /// full OIDC front-channel and back-channel endpoints plus discovery
    /// metadata. When omitted, the OIDC endpoints are still mounted using
    /// default parameters and the session/TLS signing key (dev fallback).
    #[serde(default)]
    pub oidc_params: Option<OidcParams>,

    /// Path to the pre-built admin UI `dist/` directory.
    /// When set and the `admin-ui` feature is enabled, the server serves those
    /// static files at `/admin-ui` with a SPA fallback for client-side routing.
    pub admin_ui_path: Option<std::path::PathBuf>,

    /// Available RBAC role names exposed via `GET /public/roles`.
    /// These are the roles that can be assigned to users and evaluated by OPA.
    /// Example: `["SuperAdmin", "DomainAdmin", "CryptoOfficer", "Auditor", "User"]`
    #[serde(default)]
    pub roles: Vec<String>,

    /// Allowed CORS origins for authenticated (admin) scopes.
    ///
    /// When non-empty, only the listed origins receive `Access-Control-Allow-Origin` headers
    /// on admin endpoints (`/admins/*`, `/realms/*`, `/sessions`, `/auth/approle`,
    /// `/auth/kubernetes`). When empty (the default) these scopes use same-origin policy
    /// and reject all cross-origin requests.
    ///
    /// Public endpoints (`/login`, `/.well-known`, `/public`, AppRole/K8s login) always
    /// remain permissive so that browser clients and external services can reach them.
    ///
    /// Example: `["https://admin.example.com", "https://localhost:3000"]`
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// Parameters for seeding a realm-admin on first start in development mode.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct DevSeedParams {
    /// ID of the realm to create (if it does not already exist).
    pub realm_id: String,
    /// Username for the realm-admin account.
    pub admin_username: String,
    /// Plain-text password for the realm-admin account.
    /// Either this or `admin_password_env` must be set.
    pub admin_password: Option<String>,
    /// Name of an environment variable that holds the admin password.
    /// Takes precedence over `admin_password` when both are set.
    /// Allows keeping secrets out of config files.
    pub admin_password_env: Option<String>,
    /// Username for a TOTP-enabled regular user in the seeded realm (optional).
    pub totp_username: Option<String>,
    /// Plain-text password for the TOTP-enabled user (optional).
    pub totp_password: Option<String>,
    /// Fixed Base32 TOTP secret for the TOTP user (optional).
    /// If omitted, a random secret is generated and logged at startup.
    pub totp_secret: Option<String>,
    /// Optional OIDC client to pre-seed in the realm.
    ///
    /// When present, `seed_dev_realm_admin` creates this client (idempotent)
    /// so that development environments have a known, stable client_id /
    /// client_secret without requiring a separate registration step.
    pub oidc_client: Option<DevSeedOidcClient>,
    /// Plain regular users to pre-seed in the realm (optional).
    ///
    /// Each entry is created as a non-admin userpass credential in `realm_id`.
    /// Useful to provide a ready-to-use test user without a manual registration step.
    #[serde(default)]
    pub users: Vec<DevSeedUser>,
}

/// Development-only OIDC client seed — creates a registered OAuth client with
/// predictable credentials on first startup.
///
/// **Never use in production** — the secret is stored in plain text in the
/// config file only for developer convenience.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct DevSeedOidcClient {
    /// Fixed `client_id` to register (e.g. `"kms-ui-dev"`).
    pub client_id: String,
    /// Plain-text client secret.  Stored hashed (SHA-256) in the database.
    pub client_secret: String,
    /// Human-readable name for the client.
    pub client_name: String,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed grant types (defaults: `["authorization_code","refresh_token"]`).
    #[serde(default = "default_dev_grant_types")]
    pub grant_types: Vec<String>,
    /// Allowed scopes (defaults: `["openid","profile","email"]`).
    #[serde(default = "default_dev_scopes")]
    pub scopes: Vec<String>,
}

fn default_dev_grant_types() -> Vec<String> {
    vec!["authorization_code".to_owned(), "refresh_token".to_owned()]
}

fn default_dev_scopes() -> Vec<String> {
    vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ]
}

/// A plain (non-admin) user to pre-seed in the realm for development.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct DevSeedUser {
    pub username: String,
    pub password: String,
    /// Optional dedicated email address for this user.
    ///
    /// When set, stored in the `email` column and used as the OIDC `email` claim
    /// instead of the username.
    #[serde(default)]
    pub email: Option<String>,
}

impl DevSeedParams {
    /// Return the resolved admin password: `admin_password_env` takes precedence over `admin_password`.
    ///
    /// Returns an error if neither is set.
    pub fn resolve_admin_password(&self) -> crate::AuthResult<String> {
        if let Some(ref env_name) = self.admin_password_env {
            return std::env::var(env_name).map_err(|_| {
                crate::AuthError::Init(format!(
                    "dev_seed: environment variable '{}' (admin_password_env) is not set",
                    env_name
                ))
            });
        }
        self.admin_password.clone().ok_or_else(|| {
            crate::AuthError::Init(
                "dev_seed: neither `admin_password` nor `admin_password_env` is set".to_string(),
            )
        })
    }
}

impl ServerParams {
    pub fn get_jwt_decoding_key(&self) -> Result<DecodingKey, AuthError> {
        let jwt_decoding_key_path = self
            .session_jwt_params
            .as_ref()
            .map(|auth_params| auth_params.jwt_ec_public_key.clone())
            .or_else(|| {
                self.tls_params
                    .as_ref()
                    .map(|t| t.server_certificate.clone())
            })
            .ok_or_else(|| {
                AuthError::Init(
                    "No JWT decoding key: set session_jwt_params or tls_params".to_owned(),
                )
            })?;
        let jwt_decoding_key = std::fs::read_to_string(&jwt_decoding_key_path).map_err(|e| {
            AuthError::Init(format!(
                "Failed to read JWT decoding key PEM file at {jwt_decoding_key_path}: {e}"
            ))
        })?;
        DecodingKey::from_ec_pem(jwt_decoding_key.as_bytes()).map_err(|e| {
            AuthError::Init(format!(
                "Failed to create decoding key from PEM at {jwt_decoding_key_path}: {e}"
            ))
        })
    }
    pub fn get_jwt_encoding_key(&self) -> Result<EncodingKey, AuthError> {
        let jwt_encoding_key_path = self
            .session_jwt_params
            .as_ref()
            .map(|auth_params| auth_params.jwt_ec_private_key.clone())
            .or_else(|| {
                self.tls_params
                    .as_ref()
                    .map(|t| t.server_private_key.clone())
            })
            .ok_or_else(|| {
                AuthError::Init(
                    "No JWT encoding key: set session_jwt_params or tls_params".to_owned(),
                )
            })?;
        let jwt_encoding_key = std::fs::read_to_string(&jwt_encoding_key_path).map_err(|e| {
            AuthError::Init(format!(
                "Failed to read JWT encoding key PEM file at {jwt_encoding_key_path}: {e}"
            ))
        })?;
        EncodingKey::from_ec_pem(jwt_encoding_key.as_bytes()).map_err(|e| {
            AuthError::Init(format!(
                "Failed to create encoding key from PEM at {jwt_encoding_key_path}: {e}"
            ))
        })
    }
}
