//! Response models for TOTP/2FA operations

use serde::{Deserialize, Serialize};

/// Response when enabling 2FA for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnableTotpResponse {
    /// The generated TOTP secret (Base32 encoded)
    pub secret: String,
    /// The OTPAuth URL for QR code generation
    pub otpauth_url: String,
}

/// Response when disabling 2FA for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableTotpResponse {
    /// Whether 2FA was successfully disabled
    pub success: bool,
}

/// Response containing TOTP status for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpStatus {
    /// Whether 2FA is enabled for this user
    pub enabled: Option<bool>,
}

impl EnableTotpResponse {
    /// Creates a new `EnableTotpResponse` with the given secret and URL
    #[must_use]
    pub fn new(secret: String, otpauth_url: String) -> Self {
        Self {
            secret,
            otpauth_url,
        }
    }

    /// Serializes the response as a JSON string
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

impl DisableTotpResponse {
    /// Creates a new `DisableTotpResponse` indicating success
    #[must_use]
    pub fn success() -> Self {
        Self { success: true }
    }

    /// Creates a new `DisableTotpResponse` indicating failure
    #[must_use]
    pub fn failure() -> Self {
        Self { success: false }
    }

    /// Serializes the response as a JSON string
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

impl TotpStatus {
    /// Creates a new `TotpStatus` with 2FA enabled
    #[must_use]
    pub fn enabled() -> Self {
        Self { enabled: Some(true) }
    }

    /// Creates a new `TotpStatus` with 2FA disabled
    #[must_use]
    pub fn disabled() -> Self {
        Self { enabled: Some(false) }
    }

    /// Creates a new `TotpStatus` with no status (not enrolled)
    #[must_use]
    pub fn not_enrolled() -> Self {
        Self { enabled: None }
    }

    /// Serializes the response as a JSON string
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enable_totp_response() {
        let response = EnableTotpResponse::new(
            "JBSWY3DPEHPK3PXP".to_string(),
            "otpauth://totp/Auth:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30".to_string(),
        );

        let json = response.to_json().unwrap();
        assert!(json.contains("JBSWY3DPEHPK3PXP"));
        assert!(json.contains("otpauth://totp"));
    }

    #[test]
    fn test_disable_totp_response_success() {
        let response = DisableTotpResponse::success();
        let json = response.to_json().unwrap();
        assert_eq!(json, "{\"success\":true}");
    }

    #[test]
    fn test_totp_status_enabled() {
        let status = TotpStatus::enabled();
        let json = status.to_json().unwrap();
        assert!(json.contains("\"enabled\":true"));
    }
}
