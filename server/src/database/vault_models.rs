//! Internal database models for the Vault-compatible AppRole API.
//!
//! These structs map directly to the `vault_roles`, `vault_secret_ids`, and
//! `vault_tokens` tables.  They are never exposed to external callers — all
//! HTTP serialization uses the wire types defined in `approle_endpoints.rs`.

/// A Vault AppRole role stored in the `vault_roles` table.
#[derive(Debug, Clone)]
pub struct VaultRole {
    pub role_name: String,
    /// Stable UUID returned as the role's public identifier. Never changes after creation.
    pub role_id: String,
    /// Token TTL in seconds (0 = unlimited).
    pub token_ttl: i64,
    /// Policies attached to tokens issued by this role (serialised as JSON).
    pub token_policies: Vec<String>,
    /// How long a generated `secret_id` is valid, in seconds (0 = no expiry).
    pub secret_id_ttl: i64,
    /// Whether callers must supply a `secret_id` to log in (always `true` here).
    pub bind_secret_id: bool,
    /// UNIX timestamp (seconds) when the role was created.
    pub created_at: i64,
}

/// A `secret_id` entry stored in `vault_secret_ids`.
#[derive(Debug, Clone)]
pub struct VaultSecretId {
    /// UUID used for revocation lookups — safe to expose to admins.
    pub secret_id_accessor: String,
    /// `SHA-256(secret_id)` — the plaintext `secret_id` is never stored.
    pub secret_id_hash: Vec<u8>,
    pub role_name: String,
    /// UNIX timestamp when this `secret_id` expires, or `None` for no expiry.
    pub expiry_time: Option<i64>,
    /// UNIX timestamp when this record was created.
    pub created_at: i64,
}

/// A token entry stored in `vault_tokens`.
#[derive(Debug, Clone)]
pub struct VaultToken {
    /// `SHA-256(client_token)` — the plaintext token is never stored.
    pub token_hash: Vec<u8>,
    pub role_name: String,
    /// Policies attached to this token (serialised as JSON).
    pub policies: Vec<String>,
    /// TTL in seconds.
    pub ttl: i64,
    pub renewable: bool,
    /// UNIX timestamp when this token expires.
    pub expiry_time: i64,
    /// UNIX timestamp when this token was created.
    pub created_at: i64,
}
