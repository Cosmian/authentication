//! AppRole-compatible authentication endpoints.
//!
//! ## Unauthenticated (login)
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | POST | `/auth/approle/login` | Login with role_id + secret_id → returns token |
//!
//! ## Admin CRUD (requires CookieAuthSameServer + AdminAuth)
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | POST | `/auth/approle/role/{name}` | Create or update a role |
//! | GET | `/auth/approle/role/{name}` | Get a role's full configuration |
//! | GET | `/auth/approle/role/{name}/role-id` | Get the stable role_id |
//! | POST | `/auth/approle/role/{name}/secret-id` | Generate a new secret ID |
//! | POST | `/auth/approle/role/{name}/secret-id/destroy` | Destroy a secret ID by accessor |
//! | DELETE | `/auth/approle/role/{name}` | Delete a role |
//! | GET | `/auth/approle/role?list=true` | List all roles |

use crate::{
    AuthError,
    database::{AppRole, AppSecretId, Database},
};
use actix_web::{
    HttpResponse, delete, get, post, route,
    web::{Bytes, Data, Json, Path, Query},
};
use auth_client::{
    AppAuth, AppAuthResponse, AppRoleDestroySecretIdRequest, AppRoleListData,
    AppRoleListRolesResponse, AppRoleLoginRequest, AppRoleRoleConfigData,
    AppRoleRoleConfigResponse, AppRoleRoleIdData, AppRoleRoleIdResponse, AppRoleRoleRequest,
    AppRoleSecretIdData, AppRoleSecretIdRequest, AppRoleSecretIdResponse,
};
use cosmian_logger::info;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

// ── Login (unauthenticated) ───────────────────────────────────────────────────

/// Login with role_id + secret_id and receive an app token.
///
/// `POST/PUT /auth/approle/login` — both methods accepted; Content-Type-agnostic body parsing.
#[route("", method = "POST", method = "PUT")]
pub async fn approle_login(
    body: Bytes,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let payload: AppRoleLoginRequest = serde_json::from_slice(&body)
        .map_err(|e| AuthError::BadRequest(format!("invalid AppRole login body: {e}")))?;
    // Resolve role by role_id
    let role = database
        .get_approle_by_role_id(&payload.role_id)
        .await?
        .ok_or_else(|| AuthError::Forbidden("invalid role_id or secret_id".to_string()))?;

    if role.bind_secret_id {
        // A secret_id is required — reject the request if one was not provided.
        let raw_secret_id = payload.secret_id.as_deref().unwrap_or("").to_string();
        if raw_secret_id.is_empty() {
            return Err(AuthError::BadRequest(
                "secret_id is required when bind_secret_id is true".to_string(),
            ));
        }
        // Hash the presented secret_id and consume it (validates + decrements uses)
        let secret_id_hash = Sha256::digest(raw_secret_id.as_bytes()).to_vec();
        let accessor = database
            .consume_secret_id(&role.name, &secret_id_hash)
            .await?
            .ok_or_else(|| AuthError::Forbidden("invalid role_id or secret_id".to_string()))?;
        cosmian_logger::trace!("AppRole login: consumed secret_id accessor={accessor}");
    }

    let token = super::issue_app_token(
        &database,
        &role.name,
        &role.token_policies,
        role.token_ttl_secs,
        true,
    )
    .await?;

    info!(
        "AppRole login: issued token for role '{}' (ttl={}s, policies={:?})",
        role.name, role.token_ttl_secs, role.token_policies
    );

    let resp = AppAuthResponse {
        auth: AppAuth {
            client_token: token,
            renewable: true,
            lease_duration: role.token_ttl_secs,
            policies: role.token_policies.clone(),
            metadata: std::collections::HashMap::from([(
                "role_name".to_string(),
                role.name.clone(),
            )]),
        },
    };
    Ok(HttpResponse::Ok().json(resp))
}

// ── Admin CRUD ────────────────────────────────────────────────────────────────

/// Create or update an AppRole role configuration.
///
/// `POST /auth/approle/role/{name}`
#[post("/role/{name}")]
pub async fn approle_create_role(
    name: Path<String>,
    payload: Json<AppRoleRoleRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let name = name.into_inner();
    let payload = payload.into_inner();

    // Reject negative TTL values; 0 means non-expiring.
    if payload.secret_id_ttl < 0 || payload.token_ttl < 0 {
        return Err(AuthError::BadRequest(
            "secret_id_ttl and token_ttl must be >= 0 (0 = non-expiring)".to_string(),
        ));
    }

    // Re-use existing role_id if the role already exists (idempotent update)
    let existing_role_id = database
        .get_approle_by_name(&name)
        .await?
        .map(|r| r.role_id);
    let role_id = existing_role_id.unwrap_or_else(|| Uuid::new_v4().to_string());

    let role = AppRole {
        name: name.clone(),
        role_id,
        secret_id_ttl_secs: payload.secret_id_ttl,
        token_ttl_secs: payload.token_ttl,
        bind_secret_id: payload.bind_secret_id,
        token_policies: payload.token_policies,
    };
    database.create_approle(&role).await?;

    info!(
        "AppRole role '{}' created/updated (bind_secret_id={}, ttl={}s, policies={:?})",
        name, role.bind_secret_id, role.token_ttl_secs, role.token_policies
    );
    Ok(HttpResponse::NoContent().finish())
}

/// Return the full configuration of an AppRole role.
///
/// `GET /auth/approle/role/{name}`
#[get("/role/{name}")]
pub async fn approle_get_role(
    name: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let name = name.into_inner();
    let role = database
        .get_approle_by_name(&name)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("role '{name}' not found")))?;

    Ok(HttpResponse::Ok().json(AppRoleRoleConfigResponse {
        data: AppRoleRoleConfigData {
            role_id: role.role_id,
            token_ttl: role.token_ttl_secs,
            secret_id_ttl: role.secret_id_ttl_secs,
            bind_secret_id: role.bind_secret_id,
            token_policies: role.token_policies,
        },
    }))
}

/// Return the stable `role_id` for a role.
///
/// `GET /auth/approle/role/{name}/role-id`
#[get("/role/{name}/role-id")]
pub async fn approle_get_role_id(
    name: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let name = name.into_inner();
    let role = database
        .get_approle_by_name(&name)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("role '{name}' not found")))?;

    Ok(HttpResponse::Ok().json(AppRoleRoleIdResponse {
        data: AppRoleRoleIdData {
            role_id: role.role_id,
        },
    }))
}

/// Generate a new secret ID for a role.
///
/// `POST /auth/approle/role/{name}/secret-id`
#[post("/role/{name}/secret-id")]
pub async fn approle_generate_secret_id(
    name: Path<String>,
    payload: Json<AppRoleSecretIdRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let name = name.into_inner();
    let payload = payload.into_inner();

    let role = database
        .get_approle_by_name(&name)
        .await?
        .ok_or_else(|| AuthError::BadRequest(format!("role '{name}' not found")))?;

    // Generate a random secret_id (UUID v4)
    let raw_secret_id = Uuid::new_v4().to_string();
    let secret_id_hash = Sha256::digest(raw_secret_id.as_bytes()).to_vec();
    let accessor = Uuid::new_v4().to_string();

    // Determine TTL: request overrides role default (0 = no expiry)
    let ttl_secs = if payload.ttl > 0 {
        payload.ttl
    } else {
        role.secret_id_ttl_secs
    };
    let expiry = if ttl_secs > 0 {
        chrono::Utc::now().timestamp() + ttl_secs
    } else {
        0
    };
    // Determine num_uses: -1 = unlimited
    let num_uses = if payload.num_uses > 0 {
        payload.num_uses
    } else {
        -1
    };

    let secret_id_rec = AppSecretId {
        accessor: accessor.clone(),
        secret_id_hash,
        role_name: name.clone(),
        expiry,
        num_uses_remaining: num_uses,
    };
    database.create_secret_id(&secret_id_rec).await?;

    Ok(HttpResponse::Ok().json(AppRoleSecretIdResponse {
        data: AppRoleSecretIdData {
            secret_id: raw_secret_id,
            secret_id_accessor: accessor,
        },
    }))
}

/// Destroy a secret ID by its accessor.
///
/// `POST /auth/approle/role/{name}/secret-id/destroy`
#[post("/role/{name}/secret-id/destroy")]
pub async fn approle_destroy_secret_id(
    name: Path<String>,
    payload: Json<AppRoleDestroySecretIdRequest>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let name = name.into_inner();
    database
        .destroy_secret_id(&name, &payload.secret_id_accessor)
        .await?;
    info!(
        "AppRole secret_id destroyed: role='{}' accessor={}",
        name, payload.secret_id_accessor
    );
    Ok(HttpResponse::NoContent().finish())
}

/// Delete an AppRole role and all its secret IDs.
///
/// `DELETE /auth/approle/role/{name}`
#[delete("/role/{name}")]
pub async fn approle_delete_role(
    name: Path<String>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let name = name.into_inner();
    database.delete_approle(&name).await?;
    info!("AppRole role '{}' deleted", name);
    Ok(HttpResponse::NoContent().finish())
}

#[derive(Deserialize)]
pub struct ListQuery {
    /// Query param `?list=true` — accepted but not checked (presence of the param is sufficient).
    #[allow(dead_code)]
    pub list: Option<String>,
}

/// List all AppRole role names.
///
/// `GET /auth/approle/role?list=true`
#[get("/role")]
pub async fn approle_list_roles(
    _query: Query<ListQuery>,
    database: Data<Arc<dyn Database>>,
) -> Result<HttpResponse, AuthError> {
    let keys = database.list_approle_names().await?;
    Ok(HttpResponse::Ok().json(AppRoleListRolesResponse {
        data: AppRoleListData { keys },
    }))
}
