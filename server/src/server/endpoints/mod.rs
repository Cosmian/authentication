mod super_admins_endpoints;
pub use super_admins_endpoints::{
    create_realm, delete_realm, get_realm, list_realms, update_realm,
};

mod user_endpoints;
pub use user_endpoints::{
    add_user_to_realm, create_user, delete_user, get_user, list_users, remove_user_from_realm,
    update_user,
};

mod realms_endpoints;
pub use realms_endpoints::{
    create_userpass, delete_userpass, get_userpass, list_all_userpass, list_userpass_by_realm,
    update_userpass,
};

mod client_endpoints;
pub use client_endpoints::{login, version_endpoint, whoami};

mod totp_endpoints;
pub use totp_endpoints::{totp_disable, totp_generate, totp_verify};

mod sessions_endpoints;
pub use sessions_endpoints::{
    delete_expired_sessions, delete_sessions, delete_sessions_for_realm, get_session,
    get_session_by_id, get_sessions_for_clients, upsert_session,
};

use crate::{AuthError, models::User};
use actix_web::HttpMessage;
use actix_web::HttpRequest;

/// Helper function to extract the authenticated user from the request extensions
pub fn user_from_request(req: &HttpRequest) -> Result<User, AuthError> {
    req.extensions()
        .get::<User>()
        .cloned()
        .ok_or_else(|| AuthError::Session("No authenticated user found in request".to_string()))
}
