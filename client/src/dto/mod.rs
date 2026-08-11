use serde::{Deserialize, Serialize};

/// Server version response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub version: String,
}

mod sessions;
pub use sessions::{
    DeleteSessionsRequest, GetSessionRequest, GetSessionsForClientsRequest,
    GetSessionsForClientsResponse, SessionsAction, UpsertSessionRequest,
};

mod totp;
pub use totp::{TotpGenerateRequest, TotpGenerateResponse, TotpVerifyRequest};

pub mod app_auth;
pub use app_auth::{
    AppAuth, AppAuthResponse, AppRoleDestroySecretIdRequest, AppRoleListData,
    AppRoleListRolesResponse, AppRoleLoginRequest, AppRoleRoleConfigData,
    AppRoleRoleConfigResponse, AppRoleRoleIdData, AppRoleRoleIdResponse, AppRoleRoleRequest,
    AppRoleSecretIdData, AppRoleSecretIdRequest, AppRoleSecretIdResponse, AppTokenData,
    AppTokenLookupResponse, K8sListData, K8sListRolesResponse, K8sLoginRequest, K8sRoleConfigData,
    K8sRoleConfigResponse, K8sRoleRequest,
};

mod oauth;
pub use oauth::{OAuthClientRequest, OAuthClientResponse};
