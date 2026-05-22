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
}

/// Username password entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPass {
    pub realm: String,
    pub username: String,
    pub password: Vec<u8>,
    pub change_password: bool,
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
