//! Kubernetes service-account JWT authentication.
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | POST | `/auth/kubernetes/login` | Login with K8s service-account JWT → returns token |
//!
//! ## Admin CRUD (requires CookieAuthSameServer + AdminAuth)
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | POST | `/auth/kubernetes/role/{name}` | Create or update a K8s role |
//! | GET | `/auth/kubernetes/role?list=true` | List all K8s roles |
//! | GET | `/auth/kubernetes/role/{name}` | Get a K8s role's full configuration |
//! | DELETE | `/auth/kubernetes/role/{name}` | Delete a K8s role |

use crate::{
    AuthError,
    database::{Database, K8sRole},
};
use actix_web::{
    HttpResponse, delete, get, post,
    web::{Bytes, Data, Json, Path, Query},
};
use auth_client::{
    AppAuth, AppAuthResponse, K8sListData, K8sListRolesResponse, K8sLoginRequest,
    K8sRoleConfigData, K8sRoleConfigResponse, K8sRoleRequest,
};
use cosmian_logger::{error, info, warn};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode_header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Minimal JWT claims needed to validate a Kubernetes service-account token.
#[derive(Debug, Deserialize, Serialize)]
struct K8sClaims {
    /// `sub` is `system:serviceaccount:<namespace>:<name>`
    pub sub: Option<String>,
    pub iss: Option<String>,
}

/// Uniform client-facing error for all Kubernetes login failures.
///
/// Returning the same message for "role not found" and every JWT/binding
/// validation failure prevents role-name enumeration via error-message
/// discrepancy (CWE-204). The specific reason is logged server-side only.
const K8S_LOGIN_GENERIC_ERR: &str = "invalid Kubernetes login credentials";

/// Login with a Kubernetes service-account JWT and receive an app token.
///
/// `POST /auth/kubernetes/login`
#[post("")]
pub async fn k8s_login(
    body: Bytes,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    // Content-Type-agnostic body parsing, mirroring `approle_login`: SPIRE's Go
    // `hashicorp_vault` client does not reliably set `Content-Type`, so a strict
    // `Json<...>` extractor would reject valid login requests with a 415 (see ADR
    // "Decision 1").
    let payload: K8sLoginRequest = serde_json::from_slice(&body)
        .map_err(|e| AuthError::BadRequest(format!("invalid Kubernetes login body: {e}")))?;

    // Uniform client-facing error for every authentication failure below, so the
    // response cannot be used to enumerate valid role names (role-not-found is
    // indistinguishable from a bad/mismatched JWT). Specific reasons are logged
    // server-side only. Mirrors AppRole's single "invalid role_id or secret_id".
    let role = database.get_k8s_role(&payload.role).await?.ok_or_else(|| {
        warn!("Kubernetes login: role '{}' not found", payload.role);
        AuthError::Forbidden(K8S_LOGIN_GENERIC_ERR.to_owned())
    })?;

    // Fetch JWKS from the role's configured URL (Fix 3: don't leak the URL in error responses)
    let jwks = fetch_jwks(&role.jwks_url).await.map_err(|e| {
        error!(
            "Kubernetes login: failed to fetch JWKS from {}: {e}",
            role.jwks_url
        );
        AuthError::Generic("JWKS fetch failed; check server logs".to_string())
    })?;

    // Validate the JWT (Fix 1: enforce issuer and audience when configured on the role)
    // Fail closed: a malformed stored JSON means the role data is corrupt — reject immediately.
    let bound_audiences: Vec<String> = serde_json::from_str(&role.bound_audiences)
        .map_err(|_| AuthError::Generic("role has corrupt bound_audiences data".to_string()))?;
    let claims = validate_k8s_jwt(
        &payload.jwt,
        &jwks,
        role.expected_issuer.as_deref(),
        &bound_audiences,
    )
    .map_err(|e| {
        warn!(
            "Kubernetes login: JWT validation failed for role '{}': {e}",
            payload.role
        );
        AuthError::Forbidden(K8S_LOGIN_GENERIC_ERR.to_owned())
    })?;

    // Extract namespace and service account name from `sub`
    // Format: `system:serviceaccount:<namespace>:<name>`
    let (ns, sa_name) = parse_k8s_sub(&claims.sub.unwrap_or_default()).map_err(|e| {
        warn!(
            "Kubernetes login: invalid JWT subject for role '{}': {e}",
            payload.role
        );
        AuthError::Forbidden(K8S_LOGIN_GENERIC_ERR.to_owned())
    })?;

    // Check bound service account names (fail closed on corrupt data)
    let bound_names: Vec<String> = serde_json::from_str(&role.bound_sa_names)
        .map_err(|_| AuthError::Generic("role has corrupt bound_sa_names data".to_string()))?;
    if !bound_names.iter().any(|s| s == "*") && !bound_names.contains(&sa_name) {
        warn!(
            "Kubernetes login: service account '{sa_name}' not in bound_service_account_names \
             for role '{}'",
            payload.role
        );
        return Err(AuthError::Forbidden(K8S_LOGIN_GENERIC_ERR.to_owned()));
    }

    // Check bound namespaces (fail closed on corrupt data)
    let bound_namespaces: Vec<String> = serde_json::from_str(&role.bound_sa_namespaces)
        .map_err(|_| AuthError::Generic("role has corrupt bound_sa_namespaces data".to_string()))?;
    if !bound_namespaces.iter().any(|s| s == "*") && !bound_namespaces.contains(&ns) {
        warn!(
            "Kubernetes login: namespace '{ns}' not in bound_service_account_namespaces \
             for role '{}'",
            payload.role
        );
        return Err(AuthError::Forbidden(K8S_LOGIN_GENERIC_ERR.to_owned()));
    }

    let entity = format!("{ns}/{sa_name}");
    let token = super::issue_app_token(&database, &entity, &[], role.token_ttl_secs, true).await?;

    info!(
        "Kubernetes login: issued token for entity '{}' (role='{}', ttl={}s)",
        entity, payload.role, role.token_ttl_secs
    );

    let resp = AppAuthResponse {
        auth: AppAuth {
            client_token: token,
            renewable: true,
            lease_duration: role.token_ttl_secs,
            policies: Vec::new(),
            metadata: std::collections::HashMap::from([
                ("role".to_string(), payload.role.clone()),
                ("service_account_name".to_string(), sa_name),
                ("service_account_namespace".to_string(), ns),
            ]),
        },
    };
    Ok(HttpResponse::Ok().json(resp))
}

// ── Admin CRUD ────────────────────────────────────────────────────────────────

/// Create or update a Kubernetes auth role.
///
/// `POST /auth/kubernetes/role/{name}`
#[post("/role/{name}")]
pub async fn k8s_create_role(
    name: Path<String>,
    payload: Json<K8sRoleRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let name = name.into_inner();
    let payload = payload.into_inner();

    // Reject non-HTTPS JWKS URLs to prevent SSRF via plaintext HTTP.
    // Private-IP targets are still permitted to support internal K8s clusters.
    if !payload.jwks_url.starts_with("https://") {
        return Err(AuthError::BadRequest(
            "jwks_url must use the https:// scheme".to_string(),
        ));
    }

    // Reject negative TTL values; 0 means non-expiring.
    if payload.token_ttl < 0 {
        return Err(AuthError::BadRequest(
            "token_ttl must be >= 0 (0 = non-expiring)".to_string(),
        ));
    }

    // Normalize empty allowlists to ["*"] so omitting a field means "allow all".
    // An explicit empty array (deny-all) is semantically different and must be
    // set intentionally by passing a non-empty, restrictive list.
    let bound_sa_names_effective: Vec<String> = if payload.bound_service_account_names.is_empty() {
        vec!["*".to_string()]
    } else {
        payload.bound_service_account_names.clone()
    };
    let bound_sa_namespaces_effective: Vec<String> =
        if payload.bound_service_account_namespaces.is_empty() {
            vec!["*".to_string()]
        } else {
            payload.bound_service_account_namespaces.clone()
        };

    let bound_sa_names = serde_json::to_string(&bound_sa_names_effective)
        .map_err(|e| AuthError::BadRequest(format!("invalid bound_service_account_names: {e}")))?;
    let bound_sa_namespaces =
        serde_json::to_string(&bound_sa_namespaces_effective).map_err(|e| {
            AuthError::BadRequest(format!("invalid bound_service_account_namespaces: {e}"))
        })?;
    let bound_audiences = serde_json::to_string(&payload.bound_audiences)
        .map_err(|e| AuthError::BadRequest(format!("invalid bound_audiences: {e}")))?;

    let role = K8sRole {
        name: name.clone(),
        jwks_url: payload.jwks_url,
        bound_sa_names,
        bound_sa_namespaces,
        token_ttl_secs: payload.token_ttl,
        expected_issuer: payload.expected_issuer,
        bound_audiences,
    };
    database.create_k8s_role(&role).await?;

    info!(
        "Kubernetes role '{}' created/updated (ttl={}s)",
        name, role.token_ttl_secs
    );
    Ok(HttpResponse::NoContent().finish())
}

/// Delete a Kubernetes auth role.
///
/// `DELETE /auth/kubernetes/role/{name}`
#[delete("/role/{name}")]
pub async fn k8s_delete_role(
    name: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let name = name.into_inner();
    database.delete_k8s_role(&name).await?;
    info!("Kubernetes role '{}' deleted", name);
    Ok(HttpResponse::NoContent().finish())
}

/// Query params for the K8s role list endpoint (`?list=true`).
#[derive(Deserialize)]
pub struct ListQuery {
    /// Query param `?list=true` — accepted but not checked (presence of the param is sufficient).
    #[allow(dead_code)]
    pub list: Option<String>,
}

/// List all Kubernetes auth role names.
///
/// `GET /auth/kubernetes/role?list=true`
#[get("/role")]
pub async fn k8s_list_roles(
    _query: Query<ListQuery>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let keys = database.list_k8s_role_names().await?;
    Ok(HttpResponse::Ok().json(K8sListRolesResponse {
        data: K8sListData { keys },
    }))
}

/// Return the full configuration of a Kubernetes auth role.
///
/// `GET /auth/kubernetes/role/{name}`
#[get("/role/{name}")]
pub async fn k8s_get_role(
    name: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let name = name.into_inner();
    let role = database
        .get_k8s_role(&name)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("role '{name}' not found")))?;

    // The bound lists are stored as JSON strings. Fail closed on corrupt data,
    // mirroring the parsing in `k8s_login`.
    let bound_service_account_names: Vec<String> = serde_json::from_str(&role.bound_sa_names)
        .map_err(|_| AuthError::Generic("role has corrupt bound_sa_names data".to_string()))?;
    let bound_service_account_namespaces: Vec<String> =
        serde_json::from_str(&role.bound_sa_namespaces).map_err(|_| {
            AuthError::Generic("role has corrupt bound_sa_namespaces data".to_string())
        })?;
    let bound_audiences: Vec<String> = serde_json::from_str(&role.bound_audiences)
        .map_err(|_| AuthError::Generic("role has corrupt bound_audiences data".to_string()))?;

    Ok(HttpResponse::Ok().json(K8sRoleConfigResponse {
        data: K8sRoleConfigData {
            jwks_url: role.jwks_url,
            bound_service_account_names,
            bound_service_account_namespaces,
            token_ttl: role.token_ttl_secs,
            expected_issuer: role.expected_issuer,
            bound_audiences,
        },
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse `system:serviceaccount:<namespace>:<name>` and return `(namespace, sa_name)`.
fn parse_k8s_sub(sub: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = sub.splitn(4, ':').collect();
    match parts.as_slice() {
        ["system", "serviceaccount", ns, name] => Ok(((*ns).to_string(), (*name).to_string())),
        _ => Err(format!("unexpected sub format: '{sub}'")),
    }
}

/// Minimal JWKS representation for parsing the Kubernetes API server's JWKS.
#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<serde_json::Value>,
}

async fn fetch_jwks(url: &str) -> Result<JwksResponse, reqwest::Error> {
    // 5-second timeout prevents the server from hanging on a slow/unreachable JWKS endpoint.
    // Redirects are disabled: the admin must configure the final JWKS URL directly.
    // This prevents an attacker from causing the server to follow redirects to a plaintext
    // HTTP endpoint, which would undermine the https:// scheme requirement on jwks_url.
    let builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none());

    // In test mode the JWKS endpoint may use a self-signed TLS certificate that is
    // not in the system trust store (the test server uses its own test CA).  Skip TLS
    // verification only in the test binary so production builds remain strict.
    #[cfg(test)]
    let builder = builder.danger_accept_invalid_certs(true);

    builder
        .build()?
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json::<JwksResponse>()
        .await
}

/// Algorithms accepted for Kubernetes service-account JWTs.
///
/// Kubernetes API servers use RS256 (most common) or ES256 (ECDSA P-256).
/// RS384/RS512/ES384/ES512 are included for completeness and future-proofing.
/// Symmetric algorithms (HS256 etc.) are explicitly excluded — a Kubernetes API
/// server never issues HS-signed tokens, and accepting them would make the
/// verification trivially bypassable by a party that knows (or guesses) the secret.
const ALLOWED_K8S_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

fn validate_k8s_jwt(
    token: &str,
    jwks: &JwksResponse,
    expected_issuer: Option<&str>,
    bound_audiences: &[String],
) -> Result<K8sClaims, String> {
    let header = decode_header(token).map_err(|e| format!("invalid JWT header: {e}"))?;
    let alg = header.alg;

    // Reject algorithms outside the explicit allowlist (RFC 7518 compliance).
    // This prevents acceptance of weak or symmetric algorithms even if a JWKS key
    // were somehow able to validate them.
    if !ALLOWED_K8S_ALGORITHMS.contains(&alg) {
        return Err(format!(
            "unsupported JWT algorithm '{alg:?}': only asymmetric algorithms (RS256/RS384/RS512/ES256/ES384) are accepted"
        ));
    }

    // RFC 7517 §4.5: when the JWT header carries a `kid`, only try keys with a
    // matching `kid` field.  Fall back to trying all keys when either the header
    // has no `kid` or no key in the JWKS declares a `kid`.
    let header_kid = header.kid.as_deref();
    let candidate_keys: Vec<&serde_json::Value> = jwks
        .keys
        .iter()
        .filter(|k| match header_kid {
            Some(kid) => k.get("kid").and_then(|v| v.as_str()) == Some(kid),
            None => true,
        })
        .collect();

    // If kid-filtering produced an empty set (no key declared a matching kid),
    // fall back to trying all keys — some JWKS endpoints omit the kid field.
    let candidates: Vec<&serde_json::Value> = if candidate_keys.is_empty() {
        jwks.keys.iter().collect()
    } else {
        candidate_keys
    };

    let validation = build_validation(alg, expected_issuer, bound_audiences);

    for key_value in &candidates {
        let Ok(jwk_str) = serde_json::to_string(key_value) else {
            continue;
        };
        let Ok(jwk) = serde_json::from_str::<jsonwebtoken::jwk::Jwk>(&jwk_str) else {
            continue;
        };
        let Ok(decoding_key) = DecodingKey::from_jwk(&jwk) else {
            continue;
        };
        if let Ok(data) = jsonwebtoken::decode::<K8sClaims>(token, &decoding_key, &validation) {
            return Ok(data.claims);
        }
    }

    Err("JWT validation failed: no key in JWKS could verify the signature".to_string())
}

/// Build a [`Validation`] object with issuer, audience, and time-claim enforcement.
///
/// - `expected_issuer`: when `Some`, the JWT `iss` claim must match (RFC 7519 §4.1.1).
/// - `bound_audiences`: when non-empty, the JWT `aud` claim must contain at least one
///   matching value (RFC 7519 §4.1.3). When empty, audience checking is **disabled** —
///   required because jsonwebtoken 10.3 rejects *any* token carrying an `aud` claim when
///   `validation.aud` is `None`, which would break Kubernetes ≥1.21 projected tokens.
/// - `exp` (RFC 7519 §4.1.4) and `nbf` (RFC 7519 §4.1.5) are both validated.
fn build_validation(
    alg: Algorithm,
    expected_issuer: Option<&str>,
    bound_audiences: &[String],
) -> Validation {
    let mut validation = Validation::new(alg);
    // RFC 7519 §4.1.4 — Expiration Time MUST be checked.
    validation.validate_exp = true;
    // RFC 7519 §4.1.5 — Not Before MUST be checked when present.
    validation.validate_nbf = true;
    // Require `exp` to be present — Kubernetes API servers always include it and
    // accepting tokens without an expiry would allow them to be used indefinitely.
    // Other standard claims (sub, iss, iat) are not required here since older K8s
    // versions may omit them.
    validation.required_spec_claims = std::iter::once("exp".to_string()).collect();

    if bound_audiences.is_empty() {
        // Disable audience check when not configured: modern K8s tokens carry an `aud`
        // claim and would be rejected by default if we leave `validation.aud = None`.
        validation.validate_aud = false;
    } else {
        validation.set_audience(bound_audiences);
    }

    if let Some(iss) = expected_issuer {
        validation.set_issuer(&[iss]);
    }

    validation
}
