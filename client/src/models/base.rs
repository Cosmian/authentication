use std::collections::HashMap;

use crate::RealmAuthParams;
use serde::{Deserialize, Serialize};

pub const ADMIN_REALM: &str = "_";

/// Represents an authenticated client scheme.
///
/// This struct is stored in the request extensions after successful
/// authentication and can be used by request handlers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedClientScheme {
    /// The authenticated username
    pub username: String,
    /// Authentication Scheme used
    pub auth_scheme: AuthScheme,
}

/// Realm configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    pub id: String,
    pub auth_params: RealmAuthParams,
    pub session_max_age_seconds: i64,
    pub session_max_stale_age_seconds: i64,
    #[serde(default = "default_certificate_max_age_seconds")]
    pub certificate_max_age_seconds: i64,
}

/// Default `Realm::certificate_max_age_seconds`: one year.
fn default_certificate_max_age_seconds() -> i64 {
    365 * 24 * 3600
}

/// How a caller provides a user's password on create/update, mutually exclusive by
/// construction. Omit `UserPass::password_input` entirely (`None`) on update to keep
/// the existing password unchanged; it is required on create.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordInput {
    /// Plaintext UTF-8 password, hashed with Argon2 by the server before storage.
    Plaintext(String),
    /// A pre-computed Argon2 PHC string (e.g. `$argon2id$v=19$m=...$...$...`), stored
    /// as-is without server-side hashing — for callers migrating already-hashed
    /// credentials from another Argon2-based system. Must match this server's own
    /// cost parameters.
    Hashed(String),
}

/// Username password entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPass {
    pub realm: String,
    pub username: String,
    /// The stored password hash, as a PHC string (e.g. `$argon2id$v=19$...`).
    /// Server-computed and server-owned: ignored on input (see `password_input` to
    /// set/change the password) and always emitted empty in responses, since the hash
    /// is never returned to callers.
    #[serde(default, skip_deserializing)]
    pub password_hash: String,
    /// How to set the password on create/update. Required on create; omit on update
    /// to keep the existing password unchanged. Never present in responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_input: Option<PasswordInput>,
    pub change_password: bool,
    /// RBAC roles assigned to this user (e.g. `["CryptoOfficer", "Auditor"]`).
    /// Emitted in the JWT `roles` claim for OPA policy evaluation.
    #[serde(default)]
    pub roles: Vec<String>,

    /// Arbitrary extra claims set by the realm admin at enrollment, merged into the
    /// session JWT's `extra` claims on login (username/password sessions only — see
    /// `AuthPrivateClaims` for why this isn't sourced from other auth schemes) and,
    /// when explicitly requested by the caller, into `POST /certify` certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_claims: Option<HashMap<String, serde_json::Value>>,
}

/// Authentication server admins.
/// These are the administrators that have a role on this server and its endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admin {
    pub id: String,
    /// Realms that the admin administers.
    /// An admin administering the ADMIN_REALM is a super admin and can administer all realms.
    pub realms: Vec<String>,
    pub userpass: Option<String>,
    pub jwt: Option<String>,
    pub fido2: Option<String>,
    pub digital_credentials: Option<HashMap<String, String>>,
    pub client_certificate: Option<String>,

    /// 2FA/TOTP fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>, // Base32 encoded secret for authenticator apps
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_auth_url: Option<String>, // otpauth:// URL for QR code generation
}

impl Admin {
    pub fn is_super_admin(&self) -> bool {
        self.realms.contains(&ADMIN_REALM.to_string())
    }

    pub fn can_administer_realm(&self, realm: &str) -> bool {
        self.realms.contains(&ADMIN_REALM.to_string()) || self.realms.contains(&realm.to_string())
    }
}

/// Authentication schemes supported
#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    #[serde(rename = "up")]
    UsernamePassword,

    #[serde(rename = "jwt")]
    Jwt,

    #[serde(rename = "f2")]
    Fido2,

    #[serde(rename = "dc")]
    DigitalCredentials,

    #[serde(rename = "cc")]
    ClientCertificate,
}

/// The Data of a Session stored in the session store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub session_id: String,
    pub realm_id: String,
    pub username: String,
    pub auth_scheme: String,
    pub cookie_string: String,
    pub max_stale_age_seconds: i64,
    pub max_age_seconds: i64,
    pub created_at: i64,
}
