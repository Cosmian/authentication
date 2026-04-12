use crate::AuthResult;

pub trait IdP {
    fn get_jwks_json(&self) -> AuthResult<String>;

    /// Issue a JWT token for a given email/subject
    fn issue_token(&self, email: &str, audience: &str, validity_secs: u64) -> AuthResult<String>;

    /// Issue a JWT token whose `exp` is set to Unix epoch (definitely expired).
    /// Use this in tests that verify the server rejects expired tokens, to avoid
    /// relying on the validation leeway (default 60 s in `jsonwebtoken`).
    fn issue_definitely_expired_token(&self, email: &str, audience: &str) -> AuthResult<String>;

    /// Get the JWKS as a JSON value
    fn get_jwks(&self) -> &serde_json::Value;

    /// Get the issuer URI
    fn get_issuer(&self) -> &str;
}
