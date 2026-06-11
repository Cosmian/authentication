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
pub use client_endpoints::{login, roles_endpoint, version_endpoint, whoami};
#[cfg(feature = "swagger-ui")]
pub use client_endpoints::{openapi_yaml_endpoint, swagger_ui_endpoint};

mod totp_endpoints;
pub use totp_endpoints::{totp_disable, totp_generate, totp_verify};

mod sessions_endpoints;
pub use sessions_endpoints::{
    delete_expired_sessions, delete_sessions, delete_sessions_for_realm, get_session,
    get_session_by_id, get_sessions_for_clients, upsert_session,
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
