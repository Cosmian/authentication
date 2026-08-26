use serde::{self, Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationNextStep {
    ChangePassword,
    /// TOTP (two-factor authentication) code required to complete login
    TotpRequired,
    Authenticated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResult {
    pub next_step: AuthenticationNextStep,
    pub session_id: Option<String>,
}
