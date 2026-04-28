//! Auth Authentication Client
//!
//! Provides the HTTP client ([`AuthClient`]) and all shared types (models, DTOs, error types)
//! used by both the authentication client and the authentication server.

mod client;
pub use client::{AuthClient, AuthClientCookieStore, AuthClientScheme};

mod error;
pub use error::{AuthError, AuthResult, AuthResultHelper};

pub mod dto;
pub use dto::{
    DeleteSessionsRequest, GetSessionRequest, GetSessionRequest as GetSessionWithActionRequest,
    GetSessionsForClientsRequest, GetSessionsForClientsResponse, SessionsAction,
    TotpGenerateRequest, TotpGenerateResponse, TotpVerifyRequest, UpsertSessionRequest, Version,
};

mod models;
pub use models::{
    ADMIN_REALM, Admin, AuthPrivateClaims, AuthScheme, AuthenticatedClientScheme,
    AuthenticationNextStep, AuthenticationResult, ClientClaims, LoginRequest, Realm,
    RegisteredClaims, SessionData, UserPass,
};

mod params;
pub use params::{IdpParams, JwtParams, RealmAuthParams, TotpRealmParams, UsernamePasswordParams};
