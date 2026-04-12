use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpGenerateRequest {
    pub username: String,
    pub issuer: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpGenerateResponse {
    pub secret_base32: String,
    pub otpauth_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpVerifyRequest {
    pub username: String,
    pub token: String,
    pub secret: String,
    pub issuer: Option<String>,
}
