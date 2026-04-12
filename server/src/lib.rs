// Re-export all public types from the authentication client
pub use auth_client::*;
// Macros must be re-exported explicitly
pub use auth_client::{auth_bail, auth_ensure, auth_error};

mod database;

mod middleware;
pub use middleware::*;

mod server;
pub use server::parameters::{DatabaseBackend, DatabaseParams, ServerParams};
pub use server::start_auth_server;

mod session;
pub use session::{build_cookie, delete_cookie};
pub use session::{
    create_session_store_with_collector, start_stale_session_collector, SessionStore,
    StaleSessionCollectorConfig,
};

pub mod tls;

pub mod totp;

pub mod client {
    pub use auth_client::{AuthClient, AuthClientCookieStore, AuthClientScheme};
}
pub mod models {
    pub use auth_client::{
        AuthPrivateClaims, AuthScheme, AuthenticatedClientScheme, AuthenticationNextStep,
        AuthenticationResult, ClientClaims, LoginRequest, Realm, RegisteredClaims, SessionData,
        User, UserPass, ADMIN_REALM,
    };
}

#[cfg(test)]
#[allow(dead_code)]
#[allow(clippy::expect_used)]
mod tests;
