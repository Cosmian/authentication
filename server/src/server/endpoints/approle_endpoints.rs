//! Vault-compatible AppRole authentication endpoints.
//!
//! Implements the subset of the HashCorp Vault AppRole auth method used by SPIRE:
//!
//! **Admin-protected** (require session-cookie `AdminAuth`):
//! - `POST   /v1/auth/approle/role/{name}` — create or update a role
//! - `GET    /v1/auth/approle/role`        — list role names
//! - `GET    /v1/auth/approle/role/{name}/role-id`       — read stable role_id
//! - `POST   /v1/auth/approle/role/{name}/secret-id`     — generate a secret_id
//! - `POST   /v1/auth/approle/role/{name}/secret-id/destroy` — revoke by accessor
//! - `DELETE /v1/auth/approle/role/{name}` — delete a role
//!
//! **Public** (no authentication):
//! - `POST /v1/auth/approle/login`         — exchange role_id + secret_id for a Vault token
//!
//! **Token-validated** (reads `X-Vault-Token`, no admin auth):
//! - `GET  /v1/auth/token/lookup-self`     — validate caller's token; called by the KMS middleware
//! - `POST /v1/auth/token/renew-self`      — extend token TTL
//! - `POST /v1/auth/token/revoke-self`     — revoke token

use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, delete, get, post,
    web::{Data, Json, Path},
};
use base64::Engine as _;
use chrono::Utc;
use cosmian_logger::info;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AuthError,
    database::{
        Database,
        vault_models::{VaultRole, VaultSecretId, VaultToken},
    },
    server::endpoints::admin_from_request,
};

// ── Wire types ────────────────────────────────────────────────────────────────

/// Body for `POST /v1/auth/approle/role/{name}`.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateRoleRequest {
    pub token_ttl: Option<i64>,
    pub token_policies: Option<Vec<String>>,
    pub secret_id_ttl: Option<i64>,
    pub bind_secret_id: Option<bool>,
}

/// Body for `POST /v1/auth/approle/login`.
#[derive(Debug, Deserialize)]
pub(crate) struct AppRoleLoginRequest {
    pub role_id: String,
    pub secret_id: String,
}

/// Body for `POST /v1/auth/approle/role/{name}/secret-id/destroy`.
#[derive(Debug, Deserialize)]
pub(crate) struct DestroySecretIdRequest {
    pub secret_id_accessor: String,
}

#[derive(Serialize)]
struct VaultData<T: Serialize> {
    data: T,
}

#[derive(Serialize)]
struct RoleIdData {
    role_id: String,
}

#[derive(Serialize)]
struct SecretIdData {
    secret_id: String,
    secret_id_accessor: String,
    secret_id_ttl: i64,
}

#[derive(Serialize)]
struct ListData {
    keys: Vec<String>,
}

#[derive(Serialize)]
struct AuthData {
    client_token: String,
    policies: Vec<String>,
    token_type: &'static str,
    lease_duration: i64,
    renewable: bool,
}

#[derive(Serialize)]
struct AuthWrapper {
    auth: AuthData,
}

#[derive(Serialize)]
struct LookupSelfData {
    entity_id: String,
    policies: Vec<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generate a Vault service token: `hvs.` + base64url(32 random bytes).
fn generate_vault_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!(
        "hvs.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Generate a secret_id: base64url(32 random bytes).
fn generate_secret_id_value() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a UUID v4 from 16 random bytes.
fn generate_uuid() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&b[0..4]),
        hex::encode(&b[4..6]),
        hex::encode(&b[6..8]),
        hex::encode(&b[8..10]),
        hex::encode(&b[10..16]),
    )
}

/// SHA-256 hash of a string value.
fn sha256(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

// ── Admin-protected role CRUD handlers ───────────────────────────────────────

/// `POST /v1/auth/approle/role/{name}` — create or update an AppRole role.
#[post("/{name}")]
pub(crate) async fn create_or_update_role(
    req: HttpRequest,
    name: Path<String>,
    body: Json<CreateRoleRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let requester = admin_from_request(&req)?;
    let role_name = name.into_inner();
    let body = body.into_inner();

    let now = Utc::now().timestamp();

    // Preserve existing role_id if the role already exists, otherwise generate one.
    let role_id = if let Some(existing) = database.get_vault_role(&role_name).await? {
        existing.role_id
    } else {
        generate_uuid()
    };

    let role = VaultRole {
        role_name: role_name.clone(),
        role_id,
        token_ttl: body.token_ttl.unwrap_or(3600),
        token_policies: body.token_policies.unwrap_or_default(),
        secret_id_ttl: body.secret_id_ttl.unwrap_or(0),
        bind_secret_id: body.bind_secret_id.unwrap_or(true),
        created_at: now,
    };

    database.create_vault_role(&role).await?;
    info!(
        "vault approle: '{}' created/updated role '{}'",
        requester.id, role_name
    );

    Ok(HttpResponse::NoContent().finish())
}

/// `GET /v1/auth/approle/role` — list all role names.
#[get("")]
pub(crate) async fn list_roles(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let _ = admin_from_request(&req)?;
    let keys = database.list_vault_roles().await?;
    Ok(HttpResponse::Ok().json(VaultData {
        data: ListData { keys },
    }))
}

/// `GET /v1/auth/approle/role/{name}/role-id` — retrieve a role's stable role_id.
#[get("/{name}/role-id")]
pub(crate) async fn get_role_id(
    req: HttpRequest,
    name: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let _ = admin_from_request(&req)?;
    let role_name = name.into_inner();
    let role = database
        .get_vault_role(&role_name)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("role '{role_name}' not found")))?;
    Ok(HttpResponse::Ok().json(VaultData {
        data: RoleIdData {
            role_id: role.role_id,
        },
    }))
}

/// `POST /v1/auth/approle/role/{name}/secret-id` — generate a new secret_id.
///
/// The plaintext secret_id is returned **once** and never stored — only its SHA-256
/// hash is persisted, alongside a stable accessor UUID for management operations.
#[post("/{name}/secret-id")]
pub(crate) async fn generate_secret_id(
    req: HttpRequest,
    name: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let requester = admin_from_request(&req)?;
    let role_name = name.into_inner();

    let role = database
        .get_vault_role(&role_name)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("role '{role_name}' not found")))?;

    let secret_id = generate_secret_id_value();
    let accessor = generate_uuid();
    let now = Utc::now().timestamp();
    let expiry_time = if role.secret_id_ttl > 0 {
        Some(now + role.secret_id_ttl)
    } else {
        None
    };

    let sid = VaultSecretId {
        secret_id_accessor: accessor.clone(),
        secret_id_hash: sha256(&secret_id),
        role_name: role_name.clone(),
        expiry_time,
        created_at: now,
    };
    database.create_vault_secret_id(&sid).await?;
    info!(
        "vault approle: '{}' generated secret_id for role '{}'",
        requester.id, role_name
    );

    Ok(HttpResponse::Ok().json(VaultData {
        data: SecretIdData {
            secret_id,
            secret_id_accessor: accessor,
            secret_id_ttl: role.secret_id_ttl,
        },
    }))
}

/// `POST /v1/auth/approle/role/{name}/secret-id/destroy` — revoke a secret_id by accessor.
#[post("/{name}/secret-id/destroy")]
pub(crate) async fn destroy_secret_id(
    req: HttpRequest,
    name: Path<String>,
    body: Json<DestroySecretIdRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let requester = admin_from_request(&req)?;
    let role_name = name.into_inner();
    let accessor = body.into_inner().secret_id_accessor;

    database
        .destroy_vault_secret_id_by_accessor(&role_name, &accessor)
        .await?;
    info!(
        "vault approle: '{}' destroyed secret_id accessor '{}' for role '{}'",
        requester.id, accessor, role_name
    );

    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /v1/auth/approle/role/{name}` — permanently delete a role.
#[delete("/{name}")]
pub(crate) async fn delete_role(
    req: HttpRequest,
    name: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let requester = admin_from_request(&req)?;
    let role_name = name.into_inner();
    database.delete_vault_role(&role_name).await?;
    info!(
        "vault approle: '{}' deleted role '{}'",
        requester.id, role_name
    );
    Ok(HttpResponse::NoContent().finish())
}

// ── Public: AppRole login ─────────────────────────────────────────────────────

/// `POST /v1/auth/approle/login` — exchange `role_id` + `secret_id` for a Vault token.
///
/// Vault semantics: the `role_id` is the stable public identifier, and the `secret_id`
/// is the one-time credential. Both are matched against the database; on success a
/// short-lived token is issued and the `secret_id` remains valid until its configured TTL.
#[post("/approle/login")]
pub(crate) async fn approle_login(
    body: Json<AppRoleLoginRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let body = body.into_inner();

    // Resolve role by role_id (the public, stable identifier).
    let role = database
        .get_vault_role_by_role_id(&body.role_id)
        .await?
        .ok_or_else(|| AuthError::Forbidden("invalid role_id or secret_id".to_string()))?;

    // Validate secret_id by SHA-256 hash.
    let secret_hash = sha256(&body.secret_id);
    let sid = database
        .find_vault_secret_id_by_hash(&secret_hash)
        .await?
        .ok_or_else(|| AuthError::Forbidden("invalid role_id or secret_id".to_string()))?;

    // Verify the secret_id belongs to this role.
    if sid.role_name != role.role_name {
        return Err(AuthError::Forbidden(
            "invalid role_id or secret_id".to_string(),
        ));
    }

    // Check secret_id expiry.
    let now = Utc::now().timestamp();
    if sid.expiry_time.is_some_and(|exp| now > exp) {
        return Err(AuthError::Forbidden("secret_id has expired".to_string()));
    }

    // Issue a new token.
    let client_token = generate_vault_token();
    let token_hash = sha256(&client_token);
    let ttl = if role.token_ttl > 0 {
        role.token_ttl
    } else {
        3600
    };
    let expiry_time = now + ttl;

    let vault_token = VaultToken {
        token_hash,
        role_name: role.role_name.clone(),
        policies: role.token_policies.clone(),
        ttl,
        renewable: true,
        expiry_time,
        created_at: now,
    };
    database.create_vault_token(&vault_token).await?;
    info!(
        "vault approle: issued token for role '{}' (TTL {}s)",
        role.role_name, ttl
    );

    Ok(HttpResponse::Ok().json(AuthWrapper {
        auth: AuthData {
            client_token,
            policies: role.token_policies,
            token_type: "service",
            lease_duration: ttl,
            renewable: true,
        },
    }))
}

// ── Token operations ──────────────────────────────────────────────────────────

const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";

/// Extract and validate the `X-Vault-Token` header, returning the matching DB record.
async fn validate_token_from_request(
    req: &HttpRequest,
    database: &Arc<dyn Database>,
) -> Result<VaultToken, AuthError> {
    let raw_token = req
        .headers()
        .get(VAULT_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::Forbidden("missing X-Vault-Token".to_string()))?
        .to_owned();

    let hash = sha256(&raw_token);
    let token = database
        .find_vault_token_by_hash(&hash)
        .await?
        .ok_or_else(|| AuthError::Forbidden("invalid or expired token".to_string()))?;

    let now = Utc::now().timestamp();
    if now > token.expiry_time {
        // Clean up the expired token.
        let _ = database.delete_vault_token_by_hash(&hash).await;
        return Err(AuthError::Forbidden("token has expired".to_string()));
    }

    Ok(token)
}

/// `GET /v1/auth/token/lookup-self` — validate the caller's own token.
///
/// This endpoint is called by the KMS `vault_token_middleware` on every cache
/// miss.  It must return `{"data": {"entity_id": "<role_name>", "policies": [...]}}`.
#[get("/token/lookup-self")]
pub(crate) async fn token_lookup_self(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let token = validate_token_from_request(&req, &database).await?;
    Ok(HttpResponse::Ok().json(VaultData {
        data: LookupSelfData {
            entity_id: token.role_name,
            policies: token.policies,
        },
    }))
}

/// `POST /v1/auth/token/renew-self` — extend the caller's token TTL.
#[post("/token/renew-self")]
pub(crate) async fn token_renew_self(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let token = validate_token_from_request(&req, &database).await?;

    if !token.renewable {
        return Err(AuthError::Forbidden("token is not renewable".to_string()));
    }

    // Re-issue a fresh token with the original TTL, keeping all other fields identical.
    // Simplest approach: delete old record and insert new one with same metadata.
    database
        .delete_vault_token_by_hash(&token.token_hash)
        .await?;

    let client_token = generate_vault_token();
    let now = Utc::now().timestamp();
    let renewed = VaultToken {
        token_hash: sha256(&client_token),
        role_name: token.role_name.clone(),
        policies: token.policies.clone(),
        ttl: token.ttl,
        renewable: true,
        expiry_time: now + token.ttl,
        created_at: now,
    };
    database.create_vault_token(&renewed).await?;

    Ok(HttpResponse::Ok().json(AuthWrapper {
        auth: AuthData {
            client_token,
            policies: token.policies,
            token_type: "service",
            lease_duration: token.ttl,
            renewable: true,
        },
    }))
}

/// `POST /v1/auth/token/revoke-self` — revoke the caller's own token.
#[post("/token/revoke-self")]
pub(crate) async fn token_revoke_self(
    req: HttpRequest,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let raw_token = req
        .headers()
        .get(VAULT_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::Forbidden("missing X-Vault-Token".to_string()))?
        .to_owned();

    let hash = sha256(&raw_token);
    database.delete_vault_token_by_hash(&hash).await?;
    Ok(HttpResponse::NoContent().finish())
}
