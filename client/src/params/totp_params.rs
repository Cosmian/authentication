use serde::{Deserialize, Serialize};

/// Per-realm TOTP configuration stored in `RealmAuthParams`.
///
/// All fields have sensible defaults so existing realm records without
/// TOTP configuration continue to work without modification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpRealmParams {
    /// TOTP algorithm: `"SHA1"`, `"SHA256"`, or `"SHA512"` (default: `"SHA1"`)
    #[serde(default = "default_totp_algorithm")]
    pub algorithm: String,
    /// Time step in seconds for token rotation (default: 30)
    #[serde(default = "default_totp_step")]
    pub step: u64,
}

fn default_totp_algorithm() -> String {
    "SHA1".to_string()
}
fn default_totp_step() -> u64 {
    30
}

impl Default for TotpRealmParams {
    fn default() -> Self {
        Self {
            algorithm: default_totp_algorithm(),
            step: default_totp_step(),
        }
    }
}
