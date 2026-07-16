//! Auth Authentication Client
//!
//! Provides the HTTP client ([`AuthClient`]) and all shared types (models, DTOs, error types)
//! used by both the authentication client and the authentication server.

mod client;
pub use client::{APP_TOKEN_HEADER, AuthClient, AuthClientCookieStore, AuthClientScheme};

mod error;
pub use error::{AuthError, AuthResult, AuthResultHelper};

pub mod dto;
pub use dto::{
    AppAuth,
    AppAuthResponse,
    // App auth wire types
    AppRoleDestroySecretIdRequest,
    AppRoleListData,
    AppRoleListRolesResponse,
    AppRoleLoginRequest,
    AppRoleRoleConfigData,
    AppRoleRoleConfigResponse,
    AppRoleRoleIdData,
    AppRoleRoleIdResponse,
    AppRoleRoleRequest,
    AppRoleSecretIdData,
    AppRoleSecretIdRequest,
    AppRoleSecretIdResponse,
    AppTokenData,
    AppTokenLookupResponse,
    DeleteSessionsRequest,
    GetSessionRequest,
    GetSessionRequest as GetSessionWithActionRequest,
    GetSessionsForClientsRequest,
    GetSessionsForClientsResponse,
    K8sListData,
    K8sListRolesResponse,
    K8sLoginRequest,
    K8sRoleConfigData,
    K8sRoleConfigResponse,
    K8sRoleRequest,
    SessionsAction,
    TotpGenerateRequest,
    TotpGenerateResponse,
    TotpVerifyRequest,
    UpsertSessionRequest,
    Version,
};

mod models;
pub use models::{
    ADMIN_REALM, Admin, AuthPrivateClaims, AuthScheme, AuthenticatedClientScheme,
    AuthenticationNextStep, AuthenticationResult, AuthorizationClaims, ClientClaims, LoginRequest,
    Realm, RegisteredClaims, SessionData, UserPass,
};

mod params;
pub use params::{IdpParams, JwtParams, RealmAuthParams, TotpRealmParams, UsernamePasswordParams};
