//! TOTP (Time-based One-Time Password) middleware for 2FA authentication

use crate::{AuthError, AuthResult};
use cosmian_logger::{debug, trace, warn};
use std::sync::Arc;

/// TOTP middleware for handling 2FA operations
///
/// This middleware provides endpoints and handlers for:
/// - Generating new TOTP secrets
/// - Validating TOTP tokens
/// - Enabling/disabling 2FA for users
#[derive(Clone)]
pub struct TotpMiddleware {
    /// Database for user lookups and updates
    database: Arc<dyn crate::database::Database>,
}

impl TotpMiddleware {
    /// Creates a new `TotpMiddleware` instance
    pub fn new(database: Arc<dyn crate::database::Database>) -> Self {
        Self { database }
    }

    /// Handles TOTP secret generation for a user.
    ///
    /// Generates a new TOTP secret and returns the Base32 secret
    /// and the `otpauth://` URL that can be turned into a QR code.
    pub async fn handle_totp_generate(
        &self,
        realm: &str,
        username: &str,
        issuer: Option<&str>,
    ) -> AuthResult<(String, String)> {
        trace!("Generating new TOTP secret for user '{username}' in realm '{realm}'");

        let issuer_name = issuer.unwrap_or("Auth");

        let realm_params = self
            .database
            .get_realm(realm)
            .await?
            .and_then(|r| r.auth_params.totp_params)
            .unwrap_or_default();
        let totp_params = crate::totp::realm_params_to_totp_params(&realm_params)?;

        let (totps, secret_base32) =
            crate::totp::create_totp_secret(issuer_name, username, Some(totp_params))?;

        let otpauth_url = totps.get_otpauth_url();

        debug!("TOTP secret generated for user '{username}'");

        Ok((secret_base32, otpauth_url))
    }

    /// Handles TOTP token verification.
    ///
    /// Validates a TOTP token against the stored secret. If valid and 2FA is
    /// not yet enabled, enables it by storing the secret in the database.
    pub async fn handle_totp_verify(
        &self,
        realm: &str,
        username: &str,
        totp_token: &str,
        totp_secret_base32: &str,
        issuer: Option<&str>,
    ) -> AuthResult<()> {
        trace!("Validating TOTP token for user '{username}' in realm '{realm}'");

        let issuer_name = issuer.unwrap_or("Auth");

        let realm_params = self
            .database
            .get_realm(realm)
            .await?
            .and_then(|r| r.auth_params.totp_params)
            .unwrap_or_default();
        let totp_params = crate::totp::realm_params_to_totp_params(&realm_params)?;

        // Recreate the Totps from the known secret
        let totps = crate::totp::Totps::from_secret(
            totp_secret_base32,
            Some(issuer_name.to_string()),
            username.to_string(),
            Some(totp_params),
        )?;

        // Validate the provided token
        let valid = totps.validate_token(totp_token)?;
        if !valid {
            warn!("Invalid TOTP token for user '{username}'");
            return Err(AuthError::Totp("Invalid TOTP token".to_string()));
        }

        debug!("TOTP token validated successfully for user '{username}'");

        // Enable 2FA in the database
        self.database
            .enable_totp(realm, username, totp_secret_base32, issuer_name)
            .await?;

        Ok(())
    }

    /// Handles disabling 2FA for a user.
    pub async fn handle_totp_disable(&self, realm: &str, username: &str) -> AuthResult<()> {
        trace!("Disabling TOTP for user '{username}' in realm '{realm}'");
        self.database.disable_totp(realm, username).await?;
        debug!("TOTP disabled for user '{username}'");
        Ok(())
    }

    /// Checks if a user has 2FA enabled.
    pub async fn check_totp_enabled(
        &self,
        realm: &str,
        username: &str,
    ) -> AuthResult<Option<bool>> {
        trace!("Checking TOTP status for user '{username}' in realm '{realm}'");
        Ok(self.database.is_totp_enabled(realm, username).await?)
    }

    /// Retrieves the current TOTP secret for a user.
    pub async fn handle_totp_get_secret(
        &self,
        realm: &str,
        username: &str,
    ) -> AuthResult<Option<String>> {
        trace!("Fetching TOTP secret for user '{username}' in realm '{realm}'");
        Ok(self.database.get_totp_secret(realm, username).await?)
    }
}
