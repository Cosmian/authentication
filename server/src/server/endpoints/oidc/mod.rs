//! OpenID Connect Provider HTTP endpoints.
//!
//! The front-channel (`authorize` + login/consent) and back-channel (`token`,
//! `userinfo`, `introspect`, `revoke`) handlers, plus discovery and the admin
//! client-CRUD handlers. All are wired into an isolated Actix scope in
//! [`crate::server`] with dedicated CORS/CSP/rate-limit policy.

mod common;
mod error;

pub mod authorize;
pub mod clients;
pub mod discovery;
pub mod introspect;
pub mod revoke;
pub mod token;
pub mod userinfo;

pub use authorize::{authorize, authorize_consent, authorize_login};
pub use clients::{
    create_oauth_client, delete_oauth_client, get_oauth_client, list_oauth_clients,
    update_oauth_client,
};
pub use discovery::{oidc_jwks, openid_configuration};
pub use introspect::introspect;
pub use revoke::revoke;
pub use token::token;
pub use userinfo::userinfo;
