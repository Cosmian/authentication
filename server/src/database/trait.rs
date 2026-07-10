use crate::database::{AuthDbError, AuthDbResult, hash_password_with_argon2};
use crate::models::{ADMIN_REALM, Admin, AuthScheme, Realm, UserPass};
use crate::{RealmAuthParams, UsernamePasswordParams};
use async_trait::async_trait;

pub const APP_REALM_ADMIN_USERNAME: &str = "admin";
pub const APP_REALM_ADMIN_INITIAL_PASSWORD: &str = "change_me";

/// Database trait for authentication data storage
#[async_trait]
pub trait Database: Send + Sync {
    /// Initialize database schema (create tables if they don't exist)
    async fn init(&self) -> AuthDbResult<()>;

    // ===== Realm CRUD operations =====

    /// Initialize the database with the application realm and the `remove_me` user
    async fn initialize_db(&self) -> AuthDbResult<()> {
        // create the application realm if it doesn't exist
        if self.get_realm(ADMIN_REALM).await?.is_none() {
            // create the application realm with the generated cookie key
            let app_realm = Realm {
                id: ADMIN_REALM.to_string(),
                auth_params: RealmAuthParams {
                    username_password_params: Some(UsernamePasswordParams {
                        allow_expired_passwords: true,
                    }),
                    ..Default::default()
                },
                session_max_age_seconds: 3600,
                session_max_stale_age_seconds: 3600,
            };
            self.create_realm(&app_realm).await?;
        }

        // create the  entry in the userpass table
        if self
            .get_userpass(ADMIN_REALM, APP_REALM_ADMIN_USERNAME)
            .await?
            .is_none()
        {
            let app_user_pass = UserPass {
                realm: ADMIN_REALM.to_string(),
                username: APP_REALM_ADMIN_USERNAME.to_string(),
                password: hash_password_with_argon2(
                    APP_REALM_ADMIN_USERNAME,
                    APP_REALM_ADMIN_INITIAL_PASSWORD,
                )
                .map_err(|e| {
                    AuthDbError::Init(format!("failed to set the app admin initial password: {e}"))
                })?,
                change_password: true,
                roles: Vec::new(),
            };
            self.create_userpass(&app_user_pass).await?;
            // create the admin in the admin table
            let admin = Admin {
                id: APP_REALM_ADMIN_USERNAME.to_string(),
                realms: vec![ADMIN_REALM.to_string()],
                userpass: Some(APP_REALM_ADMIN_USERNAME.to_owned()),
                jwt: None,
                fido2: None,
                digital_credentials: None,
                client_certificate: None,
                totp_enabled: None,
                totp_secret: None,
                totp_auth_url: None,
            };
            self.create_admin(&admin).await?;
        }

        Ok(())
    }

    /// Create a new realm
    async fn create_realm(&self, realm: &Realm) -> AuthDbResult<()>;

    /// Read a realm by ID
    async fn get_realm(&self, id: &str) -> AuthDbResult<Option<Realm>>;

    /// Update an existing realm
    async fn update_realm(&self, realm: &Realm) -> AuthDbResult<()>;

    /// Delete a realm by ID
    async fn delete_realm(&self, id: &str) -> AuthDbResult<()>;

    /// List all realms
    async fn list_realms(&self) -> AuthDbResult<Vec<Realm>>;

    // ===== UserPass CRUD operations =====

    /// Create a new user password entry
    async fn create_userpass(&self, userpass: &UserPass) -> AuthDbResult<()>;

    /// Read a user password entry by realm and username
    async fn get_userpass(&self, realm: &str, username: &str) -> AuthDbResult<Option<UserPass>>;

    /// Update an existing user password entry
    async fn update_userpass(&self, userpass: &UserPass) -> AuthDbResult<()>;

    /// Delete a user password entry by realm and username
    async fn delete_userpass(&self, realm: &str, username: &str) -> AuthDbResult<()>;

    /// Delete all user password entries for a username across all realms.
    /// Used to cascade-delete credentials when an Admin record is deleted.
    async fn delete_userpass_by_username(&self, username: &str) -> AuthDbResult<()>;

    /// List all user password entries for a specific realm
    async fn list_userpass_by_realm(&self, realm: &str) -> AuthDbResult<Vec<UserPass>>;

    /// List all user password entries
    async fn list_all_userpass(&self) -> AuthDbResult<Vec<UserPass>>;

    /// Validate username and password credentials
    /// Returns:
    /// * `Err()` if credentials are invalid
    /// * `Ok(true)` if credentials are valid and the password must be changed
    /// * `Ok(false)` if credentials are valid and the password does not need to be changed
    async fn validate_userpass(
        &self,
        realm: &str,
        username: &str,
        password: &str,
    ) -> AuthDbResult<bool>;

    // ===== Admin CRUD operations =====

    /// Create a new admin
    async fn create_admin(&self, admin: &Admin) -> AuthDbResult<()>;

    /// Read an admin by ID
    async fn get_admin(&self, id: &str) -> AuthDbResult<Option<Admin>>;

    /// Update an existing admin
    async fn update_admin(&self, admin: &Admin) -> AuthDbResult<()>;

    /// Delete an admin by ID
    async fn delete_admin(&self, id: &str) -> AuthDbResult<()>;

    /// List all admins
    async fn list_admins(&self) -> AuthDbResult<Vec<Admin>>;

    // Find Admins by authentication scheme (e.g. userpass, jwt, fido2, vp, certificate) and value (e.g. username for userpass, subject for jwt, etc.)
    async fn find_admins_by_auth_scheme(
        &self,
        auth_scheme: AuthScheme,
        value: &str,
    ) -> AuthDbResult<Vec<Admin>>;

    // ===== TOTP/2FA operations =====

    /// Generate a new TOTP secret for a user
    async fn generate_totp_secret(&self, realm: &str, username: &str) -> AuthDbResult<String>;

    /// Update a user's TOTP information (enable 2FA)
    async fn enable_totp(
        &self,
        realm: &str,
        username: &str,
        totp_secret: &str,
        issuer: &str,
    ) -> AuthDbResult<()>;

    /// Disable TOTP for a user (reset 2FA)
    async fn disable_totp(&self, realm: &str, username: &str) -> AuthDbResult<()>;

    /// Get the current TOTP secret for a user (for re-enrollment)
    async fn get_totp_secret(&self, realm: &str, username: &str) -> AuthDbResult<Option<String>>;

    /// Check if 2FA is enabled for a user
    async fn is_totp_enabled(&self, realm: &str, username: &str) -> AuthDbResult<Option<bool>>;
}
