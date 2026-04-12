use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// The Forward Proxy Parameters
pub struct UsernamePasswordParams {
    /// Allow login with expired username passwords
    pub allow_expired_passwords: bool,
}
