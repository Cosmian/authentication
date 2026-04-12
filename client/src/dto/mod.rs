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
