use crate::database::{AuthDbError, AuthDbResult, hash_password_with_argon2};
use crate::models::{ADMIN_REALM, Admin, AuthScheme, Realm, UserPass};
use crate::{RealmAuthParams, UsernamePasswordParams};
use async_trait::async_trait;

// ── App auth DB types ─────────────────────────────────────────────────────────

/// An app token record as stored in the database.
#[derive(Debug, Clone)]
pub struct AppToken {
    /// SHA-256 hash of the raw `hvs.<base64>` token string.
    pub token_hash: Vec<u8>,
    /// Logical entity name (e.g. AppRole role name, K8s SA name).
    pub entity: String,
    /// Policy names attached to this token.
    pub policies: Vec<String>,
    /// Unix timestamp (seconds) when the token expires.
    pub expiry: i64,
    pub renewable: bool,
    /// Remaining lifetime in seconds at creation time.
    pub lease_duration_secs: i64,
    /// Unix timestamp of creation.
    pub created_at: i64,
}

/// An AppRole role configuration record.
#[derive(Debug, Clone)]
pub struct AppRole {
    pub name: String,
    /// Stable UUID string identifying the role (used by SPIRE as a stable identifier).
    pub role_id: String,
    /// TTL for secret IDs in seconds (0 = no expiry).
    pub secret_id_ttl_secs: i64,
    /// TTL for tokens issued by this role.
    pub token_ttl_secs: i64,
    pub bind_secret_id: bool,
    /// Policy names attached to tokens issued by this role.
    pub token_policies: Vec<String>,
}

/// A single-use (or limited-use) secret ID for an AppRole.
#[derive(Debug, Clone)]
pub struct AppSecretId {
    /// Stable accessor UUID (returned to the admin; used for destroy).
    pub accessor: String,
    /// SHA-256 hash of the raw secret-ID string.
    pub secret_id_hash: Vec<u8>,
    pub role_name: String,
    /// Unix timestamp expiry (0 = no expiry).
    pub expiry: i64,
    /// Remaining uses (-1 = unlimited).
    pub num_uses_remaining: i64,
}

/// A Kubernetes auth role configuration.
#[derive(Debug, Clone)]
pub struct K8sRole {
    pub name: String,
    /// URL of the Kubernetes JWKS endpoint.
    pub jwks_url: String,
    /// JSON-encoded list of allowed service-account names.
    pub bound_sa_names: String,
    /// JSON-encoded list of allowed namespaces.
    pub bound_sa_namespaces: String,
    pub token_ttl_secs: i64,
    /// Expected `iss` claim; `None` disables issuer validation.
    pub expected_issuer: Option<String>,
    /// JSON-encoded list of expected `aud` values; `"[]"` disables audience validation.
    pub bound_audiences: String,
}

pub const APP_REALM_ADMIN_USERNAME: &str = "admin";
pub const APP_REALM_ADMIN_INITIAL_PASSWORD: &str = "change_me";

// ── OIDC / OAuth 2.0 DB types ─────────────────────────────────────────────────

/// A registered OAuth 2.0 / OpenID Connect client (relying party).
#[derive(Debug, Clone)]
pub struct OAuthClient {
    /// Public client identifier.
    pub client_id: String,
    /// SHA-256 hash of the client secret. `None` for public (PKCE-only) clients
    /// whose `token_endpoint_auth_method` is `none`.
    pub client_secret_hash: Option<Vec<u8>>,
    /// Human-readable client name.
    pub client_name: String,
    /// Allowed redirect URIs (exact match at the authorization endpoint).
    pub redirect_uris: Vec<String>,
    /// Allowed grant types (e.g. `authorization_code`, `refresh_token`,
    /// `client_credentials`).
    pub grant_types: Vec<String>,
    /// Allowed response types (only `code` is supported — no implicit/hybrid).
    pub response_types: Vec<String>,
    /// Scopes this client may request.
    pub scopes: Vec<String>,
    /// Token-endpoint client authentication method:
    /// `client_secret_basic`, `client_secret_post`, or `none`.
    pub token_endpoint_auth_method: String,
    /// Realm this client belongs to (users authenticate against this realm).
    pub realm: String,
    /// Unix timestamp of creation.
    pub created_at: i64,
}

impl OAuthClient {
    /// Whether this is a public client (no secret, PKCE-only).
    pub fn is_public(&self) -> bool {
        self.token_endpoint_auth_method == "none" || self.client_secret_hash.is_none()
    }
}

/// A single-use OAuth 2.0 authorization code with its PKCE binding.
#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    /// SHA-256 hash of the raw authorization code string.
    pub code_hash: Vec<u8>,
    pub client_id: String,
    pub redirect_uri: String,
    /// Space-delimited granted scope.
    pub scope: String,
    /// OIDC `nonce` echoed into the issued ID token.
    pub nonce: Option<String>,
    /// PKCE code challenge (RFC 7636).
    pub code_challenge: String,
    /// PKCE code challenge method (only `S256` is accepted).
    pub code_challenge_method: String,
    /// Authenticated end-user (the ID-token `sub`).
    pub subject: String,
    pub realm: String,
    /// Unix timestamp when the end-user authenticated (ID-token `auth_time`).
    pub auth_time: i64,
    /// Unix timestamp when this code expires.
    pub expiry: i64,
}

/// A refresh token record. Opaque to the client; stored hashed at rest.
#[derive(Debug, Clone)]
pub struct RefreshToken {
    /// SHA-256 hash of the raw refresh-token string.
    pub token_hash: Vec<u8>,
    pub client_id: String,
    pub subject: String,
    pub realm: String,
    /// Space-delimited scope associated with this refresh token.
    pub scope: String,
    /// Unix timestamp when this token expires.
    pub expiry: i64,
    /// Unix timestamp of creation.
    pub created_at: i64,
    /// Whether this token has been revoked (rotation or explicit revocation).
    pub revoked: bool,
}

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
                password: hash_password_with_argon2(APP_REALM_ADMIN_INITIAL_PASSWORD).map_err(
                    |e| {
                        AuthDbError::Init(format!(
                            "failed to set the app admin initial password: {e}"
                        ))
                    },
                )?,
                change_password: true,
                roles: Vec::new(),
                email: None,
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

    /// Update an existing user password entry (including the password hash)
    async fn update_userpass(&self, userpass: &UserPass) -> AuthDbResult<()>;

    /// Update only the metadata of a user password entry (roles and change_password flag),
    /// leaving the stored password hash untouched.
    /// Used when the client sends an empty password field (e.g. roles-only updates).
    async fn update_userpass_metadata(
        &self,
        realm: &str,
        username: &str,
        change_password: bool,
        roles: &[String],
    ) -> AuthDbResult<()>;

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

    // ── App token operations ────────────────────────────────────────────────

    /// Insert a new app token into the store.
    async fn issue_app_token(&self, token: &AppToken) -> AuthDbResult<()>;

    /// Look up an app token by its SHA-256 hash.
    ///
    /// Returns `None` if the token does not exist or has expired.
    async fn lookup_app_token(&self, token_hash: &[u8]) -> AuthDbResult<Option<AppToken>>;

    /// Extend a renewable token's expiry by `lease_duration_secs` seconds.
    async fn renew_app_token(&self, token_hash: &[u8]) -> AuthDbResult<()>;

    /// Delete a token from the store (revoke).
    async fn revoke_app_token(&self, token_hash: &[u8]) -> AuthDbResult<()>;

    // ── AppRole operations ──────────────────────────────────────────────────

    /// Create or replace an AppRole role configuration.
    async fn create_approle(&self, role: &AppRole) -> AuthDbResult<()>;

    /// Look up an AppRole role configuration by `role_id` (the stable UUID).
    async fn get_approle_by_role_id(&self, role_id: &str) -> AuthDbResult<Option<AppRole>>;

    /// Look up an AppRole role configuration by `name`.
    async fn get_approle_by_name(&self, name: &str) -> AuthDbResult<Option<AppRole>>;

    /// Delete an AppRole role and all its secret IDs.
    async fn delete_approle(&self, name: &str) -> AuthDbResult<()>;

    /// List all AppRole role names.
    async fn list_approle_names(&self) -> AuthDbResult<Vec<String>>;

    /// Insert a new secret ID for a role.
    async fn create_secret_id(&self, secret_id: &AppSecretId) -> AuthDbResult<()>;

    /// Validate and consume a secret ID.
    ///
    /// Finds the secret ID by hash, checks it belongs to `role_name`, has not
    /// expired, and has remaining uses.  Decrements `num_uses_remaining` (or
    /// deletes if it was the last use).  Returns the accessor on success.
    async fn consume_secret_id(
        &self,
        role_name: &str,
        secret_id_hash: &[u8],
    ) -> AuthDbResult<Option<String>>;

    /// Destroy a secret ID by accessor UUID.
    async fn destroy_secret_id(&self, role_name: &str, accessor: &str) -> AuthDbResult<()>;

    // ── Kubernetes role operations ──────────────────────────────────────────

    /// Create or replace a Kubernetes auth role.
    async fn create_k8s_role(&self, role: &K8sRole) -> AuthDbResult<()>;

    /// Look up a Kubernetes auth role by name.
    async fn get_k8s_role(&self, name: &str) -> AuthDbResult<Option<K8sRole>>;

    /// Delete a Kubernetes auth role by name.
    async fn delete_k8s_role(&self, name: &str) -> AuthDbResult<()>;

    /// List all Kubernetes auth role names.
    async fn list_k8s_role_names(&self) -> AuthDbResult<Vec<String>>;

    // ── OIDC / OAuth 2.0 client operations ──────────────────────────────────

    /// Create a new OAuth client.
    async fn create_oauth_client(&self, client: &OAuthClient) -> AuthDbResult<()>;

    /// Look up an OAuth client by `client_id`.
    async fn get_oauth_client(&self, client_id: &str) -> AuthDbResult<Option<OAuthClient>>;

    /// Update an existing OAuth client (identified by `client_id`).
    async fn update_oauth_client(&self, client: &OAuthClient) -> AuthDbResult<()>;

    /// Delete an OAuth client by `client_id`.
    async fn delete_oauth_client(&self, client_id: &str) -> AuthDbResult<()>;

    /// List all OAuth clients belonging to a realm.
    async fn list_oauth_clients_by_realm(&self, realm: &str) -> AuthDbResult<Vec<OAuthClient>>;

    // ── OIDC authorization-code operations ──────────────────────────────────

    /// Persist a freshly issued authorization code.
    async fn create_authorization_code(&self, code: &AuthorizationCode) -> AuthDbResult<()>;

    /// Atomically consume a single-use authorization code by its hash.
    ///
    /// Deletes the record and returns it if present and not expired; returns
    /// `None` if the code is unknown, already consumed, or expired.
    async fn consume_authorization_code(
        &self,
        code_hash: &[u8],
    ) -> AuthDbResult<Option<AuthorizationCode>>;

    // ── OIDC refresh-token operations ───────────────────────────────────────

    /// Persist a freshly issued refresh token.
    async fn create_refresh_token(&self, token: &RefreshToken) -> AuthDbResult<()>;

    /// Look up a refresh token by its hash.
    ///
    /// Returns the record regardless of `revoked`/expiry state so callers can
    /// implement rotation reuse-detection; callers MUST validate `revoked` and
    /// `expiry` themselves.
    async fn get_refresh_token(&self, token_hash: &[u8]) -> AuthDbResult<Option<RefreshToken>>;

    /// Mark a refresh token as revoked (rotation or explicit RFC 7009 revocation).
    async fn revoke_refresh_token(&self, token_hash: &[u8]) -> AuthDbResult<()>;

    /// Revoke every refresh token issued to `subject` within `realm`.
    ///
    /// Used for reuse-detection: when a revoked refresh token is replayed, the
    /// entire token family for that subject is invalidated.
    async fn revoke_refresh_tokens_for_subject(
        &self,
        realm: &str,
        subject: &str,
    ) -> AuthDbResult<()>;
}
