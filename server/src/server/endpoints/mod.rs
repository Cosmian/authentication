mod super_admins_endpoints;
pub use super_admins_endpoints::{
    create_realm, delete_realm, get_realm, list_realms, update_realm,
};

mod admin_endpoints;
pub use admin_endpoints::{
    add_admin_to_realm, create_admin, delete_admin, get_admin, list_admins,
    remove_admin_from_realm, update_admin,
};

mod realms_endpoints;
pub use realms_endpoints::{
    create_userpass, delete_userpass, get_userpass, list_all_userpass, list_userpass_by_realm,
    update_userpass,
};

mod client_endpoints;
pub use client_endpoints::{jwks_well_known, login, roles_endpoint, version_endpoint, whoami};
#[cfg(feature = "swagger-ui")]
pub use client_endpoints::{openapi_yaml_endpoint, swagger_ui_endpoint};

mod totp_endpoints;
pub use totp_endpoints::{totp_disable, totp_generate, totp_verify};

mod sessions_endpoints;
pub use sessions_endpoints::{
    delete_expired_sessions, delete_sessions, delete_sessions_for_realm, get_session,
    get_session_by_id, get_sessions_for_clients, upsert_session,
};

mod auth_token;
pub use auth_token::{auth_token_lookup_self, auth_token_renew_self, auth_token_revoke_self};

mod approle;
pub use approle::{
    approle_create_role, approle_delete_role, approle_destroy_secret_id,
    approle_generate_secret_id, approle_get_role, approle_get_role_id, approle_list_roles,
    approle_login,
};

mod kubernetes;
pub use kubernetes::{k8s_create_role, k8s_delete_role, k8s_get_role, k8s_list_roles, k8s_login};

pub mod oidc;
pub use oidc::{
    authorize, authorize_consent, authorize_login, create_oauth_client, delete_oauth_client,
    get_oauth_client, introspect, list_oauth_clients, oidc_jwks, openid_configuration, revoke,
    token as oidc_token, update_oauth_client, userinfo,
};

use crate::{AuthError, models::Admin};
use actix_web::HttpMessage;
use actix_web::HttpRequest;

/// Helper function to extract the authenticated admin from the request extensions
pub fn admin_from_request(req: &HttpRequest) -> Result<Admin, AuthError> {
    req.extensions()
        .get::<Admin>()
        .cloned()
        .ok_or_else(|| AuthError::Session("No authenticated admin found in request".to_string()))
}

// ── Shared app token helper ─────────────────────────────────────────────────

/// Generate a new `hvs.<base64url>` token, persist it, and return the raw string.
///
/// Shared by [`approle`] and [`kubernetes`] login handlers.
pub(super) async fn issue_app_token(
    database: &actix_web::web::Data<std::sync::Arc<dyn crate::database::Database>>,
    entity: &str,
    policies: &[String],
    lease_duration_secs: i64,
    renewable: bool,
) -> Result<String, AuthError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    let mut raw_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut raw_bytes);
    let token_str = format!("hvs.{}", URL_SAFE_NO_PAD.encode(raw_bytes));

    let token_hash = Sha256::digest(token_str.as_bytes()).to_vec();
    let now = chrono::Utc::now().timestamp();
    let expiry = if lease_duration_secs > 0 {
        now + lease_duration_secs
    } else {
        0
    };

    let record = crate::database::AppToken {
        token_hash,
        entity: entity.to_string(),
        policies: policies.to_vec(),
        expiry,
        renewable,
        lease_duration_secs,
        created_at: now,
    };
    database.issue_app_token(&record).await?;
    Ok(token_str)
}
