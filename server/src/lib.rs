// Re-export all public types from the authentication client
pub use auth_client::*;

// Prevent the `no_jwt_validation` feature from being compiled outside of test builds.
// Enabling this feature in production would bypass JWT signature verification entirely.
#[cfg(all(feature = "no_jwt_validation", not(test)))]
compile_error!(
    "`no_jwt_validation` feature must not be enabled outside of test builds — \
     it bypasses JWT signature verification and is a critical security risk."
);
// Macros must be re-exported explicitly
pub use auth_client::{auth_bail, auth_ensure, auth_error};

pub mod error;
pub use error::{ServerError, ServerResult};

mod database;

mod middleware;
pub use middleware::*;

mod server;
pub use server::parameters::{DatabaseBackend, DatabaseParams, LogConfig, ServerParams};
pub use server::start_auth_verifier;

mod session;
pub use session::{
    SessionStore, StaleSessionCollectorConfig, create_session_store_with_collector,
    start_stale_session_collector,
};
pub use session::{build_cookie, delete_cookie};

pub mod tls;

pub mod totp;

pub mod client {
    pub use auth_client::{AuthClient, AuthClientCookieStore, AuthClientScheme};
}
pub mod models {
    pub use auth_client::{
        ADMIN_REALM, Admin, AuthPrivateClaims, AuthScheme, AuthenticatedClientScheme,
        AuthenticationNextStep, AuthenticationResult, AuthorizationClaims, CertificateClaims,
        ClientClaims, LoginRequest, Realm, RegisteredClaims, SessionData, UserPass,
    };
}

#[cfg(test)]
#[allow(dead_code)]
#[allow(clippy::expect_used)]
mod tests;
