use jsonwebtoken::{DecodingKey, EncodingKey};

use crate::{
    AuthError,
    server::parameters::{DatabaseParams, ProxyParams, SessionJwtParams, TlsParams},
    session::StaleSessionCollectorConfig,
};

#[derive(Clone, Debug, serde::Deserialize)]
/// The Forward Proxy Parameters
pub struct ServerParams {
    pub host_name: String,
    pub host_port: u16,
    pub tls_params: TlsParams,
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
    /// Intended only for `auth_server.dev.toml` — do not use in production.
    pub dev_seed: Option<DevSeedParams>,

    /// Path to the pre-built admin UI `dist/` directory.
    /// When set and the `admin-ui` feature is enabled, the server serves those
    /// static files at `/admin-ui` with a SPA fallback for client-side routing.
    pub admin_ui_path: Option<std::path::PathBuf>,
}

/// Parameters for seeding a realm-admin on first start in development mode.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct DevSeedParams {
    /// ID of the realm to create (if it does not already exist).
    pub realm_id: String,
    /// Username for the realm-admin account.
    pub admin_username: String,
    /// Plain-text password for the realm-admin account.
    pub admin_password: String,
}

impl ServerParams {
    pub fn get_jwt_decoding_key(&self) -> Result<DecodingKey, AuthError> {
        let jwt_decoding_key_path = self
            .session_jwt_params
            .as_ref()
            .map(|auth_params| auth_params.jwt_ec_public_key.clone())
            .unwrap_or(self.tls_params.server_certificate.clone());
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
            .unwrap_or(self.tls_params.server_private_key.clone());
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
