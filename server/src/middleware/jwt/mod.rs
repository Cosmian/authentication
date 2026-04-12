//! JWT Authentication Module
//!
//! This module provides JWT (JSON Web Token) based authentication for the Authentication server.
//! It includes components for token validation, JWKS (JSON Web Key Set) management,
//! and middleware integration.

mod jwks;
pub use jwks::JwksManager;

mod jwt_middleware;
pub use jwt_middleware::JwtAuth;

mod client_claim;
