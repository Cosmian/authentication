//! AppRole-compatible API wire types.
//!
//! These structs are serialised/deserialised over the HTTP API.  They mirror the
//! SPIRE plugin response shape so that SPIRE integrations need no changes.

use serde::{Deserialize, Serialize};

// ── AppRole auth ─────────────────────────────────────────────────────────────

/// Request body for `POST /auth/approle/login`.
///
/// `secret_id` is optional: it is required only when the role's `bind_secret_id`
/// flag is `true` (the default). Roles with `bind_secret_id: false` may login
/// with `role_id` alone, in keeping with the Vault AppRole API spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleLoginRequest {
    pub role_id: String,
    #[serde(default)]
    pub secret_id: Option<String>,
}

/// Request body for `POST /auth/approle/role/{name}` (create/update).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleRoleRequest {
    /// TTL for secret IDs in seconds (0 = no expiry).
    #[serde(default)]
    pub secret_id_ttl: i64,
    /// TTL for issued tokens in seconds.
    #[serde(default = "default_token_ttl")]
    pub token_ttl: i64,
    /// List of policies to attach to issued tokens.
    #[serde(default)]
    pub token_policies: Vec<String>,
    /// Whether `secret_id` is required for login. Defaults to `true`; set to
    /// `false` to allow login with `role_id` only (not recommended for production).
    #[serde(default = "default_true")]
    pub bind_secret_id: bool,
}

fn default_token_ttl() -> i64 {
    3600
}

fn default_true() -> bool {
    true
}

/// Response body for `GET /auth/approle/role/{name}/role-id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleRoleIdResponse {
    pub data: AppRoleRoleIdData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleRoleIdData {
    pub role_id: String,
}

/// Request body for `POST /auth/approle/role/{name}/secret-id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleSecretIdRequest {
    /// TTL override for this specific secret ID (0 = use role default).
    #[serde(default)]
    pub ttl: i64,
    /// Maximum number of uses (0 = unlimited).
    #[serde(default)]
    pub num_uses: i64,
}

/// Response body for `POST /auth/approle/role/{name}/secret-id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleSecretIdResponse {
    pub data: AppRoleSecretIdData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleSecretIdData {
    pub secret_id: String,
    pub secret_id_accessor: String,
}

/// Request body for `POST /auth/approle/role/{name}/secret-id/destroy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleDestroySecretIdRequest {
    pub secret_id_accessor: String,
}

/// Response body for `GET /auth/approle/role?list=true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleListRolesResponse {
    pub data: AppRoleListData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleListData {
    pub keys: Vec<String>,
}

/// Response body for `GET /auth/approle/role/{name}`.
///
/// Returns the full configuration of an AppRole role so a UI can inspect it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleRoleConfigResponse {
    pub data: AppRoleRoleConfigData,
}

/// Configuration payload for an AppRole role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleRoleConfigData {
    /// The stable `role_id` (UUID) of the role.
    pub role_id: String,
    /// TTL for issued tokens in seconds (0 = non-expiring).
    pub token_ttl: i64,
    /// TTL for secret IDs in seconds (0 = non-expiring).
    pub secret_id_ttl: i64,
    /// Whether a `secret_id` is required for login.
    pub bind_secret_id: bool,
    /// Policies attached to tokens issued for this role.
    pub token_policies: Vec<String>,
}

// ── Kubernetes auth ───────────────────────────────────────────────────────────

/// Request body for `POST /auth/kubernetes/login`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sLoginRequest {
    pub role: String,
    pub jwt: String,
}

/// Request body for `POST /auth/kubernetes/role/{name}` (admin CRUD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sRoleRequest {
    /// URL of the Kubernetes JWKS endpoint for verifying service-account JWTs.
    pub jwks_url: String,
    /// Allowed service-account names (glob patterns, `["*"]` for any).
    #[serde(default)]
    pub bound_service_account_names: Vec<String>,
    /// Allowed namespaces (glob patterns, `["*"]` for any).
    #[serde(default)]
    pub bound_service_account_namespaces: Vec<String>,
    /// TTL for issued tokens in seconds.
    #[serde(default = "default_token_ttl")]
    pub token_ttl: i64,
    /// Expected `iss` (issuer) claim in the Kubernetes service-account JWT.
    ///
    /// When set, JWTs whose `iss` does not match are rejected.
    /// Modern Kubernetes clusters emit the API server URL (e.g.
    /// `https://kubernetes.default.svc.cluster.local`). Recommended for
    /// production deployments to prevent cross-cluster token acceptance.
    #[serde(default)]
    pub expected_issuer: Option<String>,
    /// Expected `aud` (audience) claim values in the Kubernetes service-account JWT.
    ///
    /// When non-empty, the JWT must carry at least one matching audience value.
    /// Required for Kubernetes ≥1.21 projected service-account tokens, which
    /// always include an `aud` claim. Set to the SPIRE server address or the
    /// audience configured in the pod's projected service-account volume.
    #[serde(default)]
    pub bound_audiences: Vec<String>,
}

/// Response body for `GET /auth/kubernetes/role?list=true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sListRolesResponse {
    pub data: K8sListData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sListData {
    pub keys: Vec<String>,
}

/// Response body for `GET /auth/kubernetes/role/{name}`.
///
/// Returns the full configuration of a Kubernetes auth role so a UI can inspect it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sRoleConfigResponse {
    pub data: K8sRoleConfigData,
}

/// Configuration payload for a Kubernetes auth role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sRoleConfigData {
    /// URL of the Kubernetes JWKS endpoint for verifying service-account JWTs.
    pub jwks_url: String,
    /// Allowed service-account names (`["*"]` for any).
    pub bound_service_account_names: Vec<String>,
    /// Allowed namespaces (`["*"]` for any).
    pub bound_service_account_namespaces: Vec<String>,
    /// TTL for issued tokens in seconds (0 = non-expiring).
    pub token_ttl: i64,
    /// Expected `iss` (issuer) claim, when configured.
    pub expected_issuer: Option<String>,
    /// Expected `aud` (audience) claim values, when configured.
    pub bound_audiences: Vec<String>,
}

/// Response body for `GET /auth/token/lookup-self` and auth login responses.
///
/// Used by SPIRE to verify a token is still valid and to extract the entity name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAuthResponse {
    pub auth: AppAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAuth {
    pub client_token: String,
    pub renewable: bool,
    pub lease_duration: i64,
    pub policies: Vec<String>,
    pub metadata: std::collections::HashMap<String, String>,
}

/// Response body for `GET /auth/token/lookup-self`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppTokenLookupResponse {
    pub data: AppTokenData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppTokenData {
    pub id: String,
    pub entity_id: String,
    pub policies: Vec<String>,
    pub renewable: bool,
    pub ttl: i64,
    pub creation_time: i64,
}
