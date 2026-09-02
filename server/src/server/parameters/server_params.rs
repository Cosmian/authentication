use jsonwebtoken::{DecodingKey, EncodingKey};

use crate::{
    AuthError,
    server::parameters::{
        CertificateJwtParams, DatabaseParams, ProxyParams, SessionJwtParams, TlsParams,
    },
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

    /// Optional certificate signing key for `POST /certify`. Deliberately separate from
    /// `session_jwt_params`. When unset, `/certify` and `/.well-known/certificate-jwks.json`
    /// are unavailable (500 / 404 respectively) but the rest of the server is unaffected.
    pub certificate_jwt_params: Option<CertificateJwtParams>,

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

    /// Sustained per-IP requests/second allowed on `POST /login` (default: 5). Limits
    /// brute-force credential-stuffing without impacting normal usage. See
    /// `login_rate_limit_burst`.
    #[serde(default = "default_login_rate_limit_per_second")]
    pub login_rate_limit_per_second: u32,

    /// Burst capacity above the sustained rate for `POST /login` (default: 10) — how many
    /// requests a single IP may send back-to-back before being throttled to the sustained
    /// rate above.
    #[serde(default = "default_login_rate_limit_burst")]
    pub login_rate_limit_burst: u32,
}

fn default_login_rate_limit_per_second() -> u32 {
    5
}

fn default_login_rate_limit_burst() -> u32 {
    10
}

/// Parameters for seeding a realm-admin on first start in development mode.
// TODO: "seed" has a specific meaning in crypto, consider using a different
// name like "init" or "config".
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

    /// Returns `Ok(None)` when `certificate_jwt_params` is unset (the certificate feature is
    /// disabled). Returns `Err` only when it's set but the PEM file is unreadable/malformed.
    pub fn get_certificate_decoding_key(&self) -> Result<Option<DecodingKey>, AuthError> {
        let Some(cert_params) = self.certificate_jwt_params.as_ref() else {
            return Ok(None);
        };
        let path = &cert_params.cert_ec_public_key;
        let pem = std::fs::read_to_string(path).map_err(|e| {
            AuthError::Init(format!(
                "Failed to read certificate decoding key PEM file at {path}: {e}"
            ))
        })?;
        DecodingKey::from_ec_pem(pem.as_bytes())
            .map(Some)
            .map_err(|e| {
                AuthError::Init(format!(
                    "Failed to create certificate decoding key from PEM at {path}: {e}"
                ))
            })
    }

    /// Returns `Ok(None)` when `certificate_jwt_params` is unset (the certificate feature is
    /// disabled). Returns `Err` only when it's set but the PEM file is unreadable/malformed.
    pub fn get_certificate_encoding_key(&self) -> Result<Option<EncodingKey>, AuthError> {
        let Some(cert_params) = self.certificate_jwt_params.as_ref() else {
            return Ok(None);
        };
        let path = &cert_params.cert_ec_private_key;
        let pem = std::fs::read_to_string(path).map_err(|e| {
            AuthError::Init(format!(
                "Failed to read certificate encoding key PEM file at {path}: {e}"
            ))
        })?;
        EncodingKey::from_ec_pem(pem.as_bytes())
            .map(Some)
            .map_err(|e| {
                AuthError::Init(format!(
                    "Failed to create certificate encoding key from PEM at {path}: {e}"
                ))
            })
    }
}
