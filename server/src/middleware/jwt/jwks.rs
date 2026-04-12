//! JWKS (JSON Web Key Set) management for realm-based JWT authentication.
//!
//! This module provides a caching layer for JWKS endpoints, enabling efficient
//! and reliable retrieval of public keys used to verify JWT signatures. It is designed
//! for multi-realm architectures where each realm may have one or more JWKS URIs.
//!
//! # Overview
//!
//! The primary component is [`JwksManager`], which:
//! - Maintains an in-memory cache of JWKS for multiple realms
//! - Periodically refreshes JWKS from configured endpoints
//! - Throttles refresh requests to avoid overwhelming upstream servers
//! - Supports proxy configuration for environments with restricted network access
//! - Provides thread-safe concurrent access to cached key sets
//!
//! # Key Components
//!
//! - [`JwksManager`]: The main manager that orchestrates JWKS fetching, caching, and lookups
//! - [`RealmJWKS`]: Holds the cached JWKS and metadata for a single realm
//! - [`parse_jwks`]: HTTP client function for fetching and parsing JWKS from remote URIs
//!
//! # Usage Example
//!
//! ```rust,no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use auth_server::JwksManager;
//!
//! // Create a new JWKS manager
//! let manager = JwksManager::new(None).await;
//!
//! // Add a realm with JWKS endpoints
//! manager.upsert_realm(
//!     "my-realm",
//!     vec!["https://auth.example.com/.well-known/jwks.json".to_string()],
//!     None,  // Use default refresh interval
//! ).await?;
//!
//! // Find a specific JWK by key ID - automatically refreshes if key not found
//! if let Some(jwk) = manager.find_jwk("my-realm", "key-id-123").await? {
//!     // Use the JWK to verify a JWT signature
//!     let _ = jwk;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Refresh Strategy
//!
//! JWKS are refreshed automatically and transparently by [`JwksManager::find_jwk`]
//! when a requested key is not found in the cache. The actual fetch is throttled
//! by a configurable interval (default: 60 seconds) to prevent excessive requests.
//! This approach ensures that key rotations are detected in a timely manner while
//! avoiding unnecessary load on upstream identity providers.
//!
//! # Error Handling
//!
//! The module gracefully handles individual JWKS fetch failures:
//! - Invalid or unreachable URIs are logged as warnings
//! - Malformed JWKs within a valid JWKS response are filtered out
//! - Successful fetches still populate the cache even if some URIs fail
//! - The cache retains previous data if all refreshes fail
//!
//! # Thread Safety
//!
//! All operations are thread-safe. The internal cache uses `RwLock` to allow
//! concurrent reads while ensuring atomic writes during refresh operations.

use crate::{AuthError, AuthResult, AuthResultHelper, server::parameters::ProxyParams};
use chrono::{DateTime, Duration, Utc};
use cosmian_logger::{debug, info, trace, warn};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use reqwest::{Client, header::HeaderValue};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

/// Interval in seconds before the cached JWKS are considered stale
/// and a background refresh is allowed.
static SMALLEST_REFRESH_INTERVAL: i64 = 60; // in secs

/// Interval in seconds to retain stale JWKS entries after the last successful refresh.
static JWKS_CACHE_RETENTION_INTERVAL: i64 = 24 * 3600; // in secs

/// Interval in seconds to perform periodic cleanup of stale JWKS entries.
static JWKS_CACHE_CLEANUP_INTERVAL: i64 = 3600; // in secs

#[derive(Debug, Clone)]
pub struct RealmJWKS {
    // Unique identifier for the realm this JWKS belongs to
    pub(crate) realm_id: String,

    // List of JWKS URIs for this realm
    pub(crate) uris: Vec<String>,

    // A map of JWKS URIs to fetched JWKS for this realm
    pub(crate) jwks: HashMap<String, JwkSet>,

    /// Last update timestamp for the JWKS
    /// Used to remove stale JWKS entries after a configurable retention period (e.g., 24 hours)
    /// and enforce a minimum refresh interval between fetches (e.g., 60 seconds)
    pub(crate) last_update: Option<DateTime<Utc>>,

    /// Smallest interval in seconds between JWKS refreshes
    pub(crate) smallest_refresh_interval: Option<i64>,
}

impl RealmJWKS {
    /// Find a JSON Web Key (JWK) by its key identifier within the cached JWKS.
    ///
    /// This method searches through all JWKS URIs associated with this realm,
    /// looking for a JWK with a matching `kid` (key identifier). The search
    /// returns the first matching key found across all cached key sets.
    ///
    /// # Arguments
    ///
    /// * `kid` - The key identifier (kid) to search for. This should match
    ///   the `kid` field in the JWT header.
    ///
    /// # Returns
    ///
    /// * `Some(&JWK)` - A reference to the matching JWK if found
    /// * `None` - If no key with the specified `kid` exists in any cached JWKS
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // RealmJWKS is an internal type; use JwksManager::find_jwk for the public API.
    /// // The manager searches all configured realms automatically:
    /// //
    /// //   if let Some(jwk) = manager.find_jwk("my-realm", "key-2024-01").await? {
    /// //       // use jwk to verify a JWT signature
    /// //   }
    /// ```
    pub fn find_jwk(&self, kid: &str) -> Option<&Jwk> {
        for jwks in self.jwks.values() {
            if let Some(jwk) = jwks
                .keys
                .iter()
                .find(|jwk| jwk.common.key_id.as_ref().is_some_and(|k| k == kid))
            {
                return Some(jwk);
            }
        }
        None
    }

    /// Check if a refresh of the JWKS is allowed based on the configured interval.
    pub fn is_refresh_allowed(&self) -> bool {
        self.last_update.is_none_or(|lu| {
            (lu + Duration::seconds(
                self.smallest_refresh_interval
                    .unwrap_or(SMALLEST_REFRESH_INTERVAL),
            )) < Utc::now()
        })
    }
}

/// Manager of JWKS endpoints for Realm-based JWT authentication.
///
/// For each Realm, the manager:
/// - keeps track of one or more JWKS URIs,
/// - caches the downloaded key sets in memory, and
/// - periodically refreshes them based on a configurable interval (defaults to [`SMALLEST_REFRESH_INTERVAL`]).
///
/// All access to the underlying cache is synchronized using `RwLock` so
/// that lookups are cheap while refreshes replace the whole map atomically.
pub struct JwksManager {
    pub(crate) realm_jwks: RwLock<HashMap<String, RealmJWKS>>,
    pub(crate) proxy_params: Option<ProxyParams>,
}

impl JwksManager {
    /// Create a new [`JwksManager`] and eagerly fetch all configured JWKS.
    ///
    /// # Arguments
    ///
    /// * `proxy_params` - Optional proxy configuration used for all HTTP requests.
    ///
    pub async fn new(proxy_params: Option<&ProxyParams>) -> Arc<Self> {
        // start a thread that will garbage collect stale JWKS entries based on the retention policy
        let manager = Arc::new(Self {
            realm_jwks: RwLock::new(HashMap::new()),
            proxy_params: proxy_params.cloned(),
        });
        let cleanup_manager = manager.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = cleanup_manager.remove_stale_entries() {
                    warn!("Failed to remove stale JWKS entries: {e}");
                }
                tokio::time::sleep(std::time::Duration::from_secs(
                    JWKS_CACHE_CLEANUP_INTERVAL as u64,
                ))
                .await;
            }
        });

        manager
    }

    /// Atomically replace the in‑memory JWKS cache for a specific realm with a new map.
    ///
    /// This acquires a write lock on `jwks` and completely swaps the
    /// existing content with `new_jwks`.
    fn set_jwks(&self, realm_id: &str, new_jwks: HashMap<String, JwkSet>) -> AuthResult<()> {
        let mut realm_jwks_map = self
            .realm_jwks
            .write()
            .map_err(|e| AuthError::Generic(format!("cannot lock JWKS for write. Error: {e:?}")))?;

        let realm_jwks = realm_jwks_map.get_mut(realm_id).ok_or_else(|| {
            AuthError::JWKS(format!(
                "Realm `{realm_id}`, is not configured for JWKS refresh"
            ))
        })?;

        realm_jwks.last_update = Some(Utc::now());
        realm_jwks.jwks = new_jwks;
        Ok(())
    }

    /// Find a JSON Web Key (JWK) by realm and key identifier, with automatic refresh fallback.
    ///
    /// This method first searches the cached JWKS for the specified realm to find a JWK
    /// with a matching `kid` (key identifier). If the key is not found in the cache and
    /// the refresh interval has elapsed, it automatically attempts to refresh the JWKS
    /// from the configured URIs and searches again.
    ///
    /// This automatic refresh behavior helps handle key rotation scenarios where a new
    /// key is introduced by the identity provider but hasn't been cached yet.
    ///
    /// # Arguments
    ///
    /// * `realm_id` - The unique identifier of the realm to search in
    /// * `kid` - The key identifier to search for. This should match the `kid` field
    ///   from the JWT header.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(JWK))` - The matching JWK was found (either in cache or after refresh)
    /// * `Ok(None)` - No JWK with the specified `kid` exists in the realm's JWKS
    /// * `Err(AuthError)` - If the realm doesn't exist or the cache cannot be accessed
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The specified realm is not configured in the manager
    /// - The JWKS cache cannot be locked for reading or writing
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_server::JwksManager;
    ///
    /// let manager = JwksManager::new(None).await;
    /// manager.upsert_realm("my-realm", vec!["https://idp.example.com/jwks".to_string()], None).await?;
    ///
    /// // Find a JWK for verifying a JWT
    /// match manager.find_jwk("my-realm", "key-2024-01").await? {
    ///     Some(jwk) => {
    ///         let _ = jwk; // Use the JWK to verify the JWT signature
    ///     }
    ///     None => {
    ///         // Key not found, JWT verification will fail
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn find_jwk(&self, realm_id: &str, kid: &str) -> AuthResult<Option<Jwk>> {
        let realm = {
            self.realm_jwks
                .read()
                .context("cannot lock JWKS cache for read")?
                .get(realm_id)
                .cloned()
                .ok_or_else(|| AuthError::JWKS(format!("Realm `{realm_id}` not found")))?
        };

        if let Some(jwk) = realm.find_jwk(kid) {
            return Ok(Some(jwk.clone()));
        }

        if realm.is_refresh_allowed() {
            debug!("JWK with kid `{kid}` not found in realm `{realm_id}`; attempting refresh.");
            let refreshed_jwks = Self::fetch_all(&realm.uris, &self.proxy_params).await;
            info!("Refresh of JWKS for realm `{realm_id}` completed.");
            self.set_jwks(realm_id, refreshed_jwks)?;
        }

        Ok(realm.find_jwk(kid).cloned())
    }

    /// Refresh the JWK Set by making an external HTTP call to all the `uris`.
    ///
    /// The JWK Sets are fetched in parallel. Individual failures are
    /// logged as warnings and silently ignored so that successful
    /// endpoints still populate the resulting map.
    ///
    /// The returned map uses the JWKS URI as the key.
    async fn fetch_all(
        uris: &[String],
        proxy_params: &Option<ProxyParams>,
    ) -> HashMap<String, JwkSet> {
        // Create a vector of futures to fetch JWKS from each URI
        let jwks_downloads: Vec<_> = uris
            .iter()
            .map(|uri| parse_jwks(uri, proxy_params))
            .collect();
        // Use `join_all` to fetch all JWKS in parallel
        futures::future::join_all(jwks_downloads)
            .await
            .into_iter()
            .filter(|res| {
                // log errors and filter them out
                res.as_ref()
                    .map_err(|e| {
                        warn!("{e}");
                    })
                    .is_ok()
            })
            .flatten()
            .collect::<HashMap<_, _>>()
    }

    /// Remove a realm from the JWKS manager.
    ///
    /// This will remove all cached JWKS for the realm.
    ///
    /// # Arguments
    ///
    /// * `realm_id` - The unique identifier for the realm to remove.
    ///
    /// # Errors
    ///
    /// Returns an error if the realm does not exist.
    pub fn remove_realm(&self, realm_id: &str) -> AuthResult<()> {
        let mut realm_jwks_map = self
            .realm_jwks
            .write()
            .context("cannot lock JWKS for write")?;

        realm_jwks_map
            .remove(realm_id)
            .ok_or_else(|| AuthError::JWKS(format!("Realm `{realm_id}` not found")))?;

        info!("Removed realm `{realm_id}` from JWKS manager");
        Ok(())
    }

    /// Upsert a realm in the JWKS manager.
    ///
    /// This will either create a new realm or update an existing one,
    /// completely overriding any previous configuration.
    ///
    /// # Arguments
    ///
    /// * `realm_id` - The unique identifier for the realm.
    /// * `uris` - List of JWKS URIs for this realm.
    /// * `smallest_refresh_interval` - Optional custom refresh interval in seconds.
    ///   Defaults to [`SMALLEST_REFRESH_INTERVAL`] if not provided.
    ///
    /// # Errors
    ///
    /// Returns an error if failed to fetch JWKS from any of the URIs.
    pub async fn upsert_realm(
        &self,
        realm_id: &str,
        uris: Vec<String>,
        smallest_refresh_interval: Option<i64>,
    ) -> AuthResult<()> {
        let jwks = Self::fetch_all(&uris, &self.proxy_params).await;

        let mut realm_jwks_map = self
            .realm_jwks
            .write()
            .context("cannot lock JWKS for write")?;

        let realm_jwks = RealmJWKS {
            realm_id: realm_id.to_owned(),
            uris,
            jwks,
            last_update: Some(Utc::now()),
            smallest_refresh_interval,
        };

        let action = if realm_jwks_map.contains_key(realm_id) {
            "Updated"
        } else {
            "Added"
        };

        realm_jwks_map.insert(realm_id.to_string(), realm_jwks);
        info!("{action} realm `{realm_id}` in JWKS manager");
        Ok(())
    }

    /// Check if a realm exists in the JWKS manager.
    pub async fn has_realm(&self, realm_id: &str) -> AuthResult<bool> {
        let realm_jwks_map = self
            .realm_jwks
            .read()
            .context("cannot lock JWKS cache for read")?;

        Ok(realm_jwks_map.contains_key(realm_id))
    }

    pub fn remove_stale_entries(&self) -> AuthResult<()> {
        let realm_jwks = self
            .realm_jwks
            .read()
            .context("cannot lock JWKS cache for read")?;

        let realm_jwks = realm_jwks.values().cloned();

        let now = Utc::now();
        let retention_interval = Duration::seconds(JWKS_CACHE_RETENTION_INTERVAL);

        for realm_jwks in realm_jwks {
            if let Some(last_update) = realm_jwks.last_update
                && last_update + retention_interval < now
            {
                debug!(
                    "Removing stale JWKS realm `{}` due to retention policy.",
                    realm_jwks.realm_id
                );
                let _err = self.remove_realm(&realm_jwks.realm_id);
            }
        }

        Ok(())
    }
}

/// Fetch a JWKS from the provided URI and parse it.
///
/// # Arguments
///
/// * `jwks_uri` - The URI endpoint from which to fetch the JWKS.
/// * `proxy_params` - Optional proxy configuration parameters for the HTTP request.
///
/// # Returns
///
/// On success returns a tuple `(jwks_uri, jwks)` where `jwks_uri` is
/// the original URI as a `String` and `jwks` is the parsed [`JWKS`].
///
/// # Errors
///
/// This function will return an error if:
/// * The HTTP client fails to build with the provided proxy configuration.
/// * The HTTP request to fetch the JWKS fails.
/// * The response cannot be parsed as valid JSON.
/// * The JSON response is missing the required `"keys"` field.
/// * No valid JWK entries are found in the `"keys"` array.
/// * The JWKS cannot be deserialized from the filtered valid JWKs.
///
/// # Behavior
///
/// - Configures an HTTP client with optional proxy settings (basic auth,
///   custom headers, exclusion lists).
/// - Fetches the JWKS from the provided URI.
/// - Validates that the response contains a `"keys"` field with an array
///   of JWKs.
/// - Filters out invalid JWK entries, logging them at trace level.
/// - Reconstructs a valid [`JWKS`] from the filtered JWK array.
/// - Invalid JWKs are logged but do not halt the parsing process.
async fn parse_jwks(
    jwks_uri: &String,
    proxy_params: &Option<ProxyParams>,
) -> AuthResult<(String, JwkSet)> {
    debug!("fetching {jwks_uri}");
    // Fetch the JWKS from the provided URI,
    let mut client = Client::builder();

    // Configure the client with proxy settings if available
    if let Some(proxy_params) = proxy_params {
        debug!("Configuring JWKS fetch via proxy: {:?}", proxy_params);
        let mut proxy = reqwest::Proxy::all(proxy_params.url.clone()).map_err(|e| {
            AuthError::JWKS(format!(
                "failed to configure the HTTPS proxy for JWKS fetch: {e})"
            ))
        })?;
        if let Some(username) = &proxy_params.basic_auth_username {
            proxy = proxy.basic_auth(
                username,
                &proxy_params.basic_auth_password.clone().unwrap_or_default(),
            );
        } else if let Some(custom_auth_header) = &proxy_params.custom_auth_header {
            proxy =
                proxy.custom_http_auth(HeaderValue::from_str(custom_auth_header).map_err(|e| {
                    AuthError::JWKS(format!(
                        "failed to set custom HTTP auth header for JWKS fetch: {e})"
                    ))
                })?);
        }
        if !proxy_params.exclusion_list.is_empty() {
            proxy = proxy.no_proxy(reqwest::NoProxy::from_string(
                &proxy_params.exclusion_list.join(","),
            ));
        }
        client = client.proxy(proxy);
    }

    #[cfg(test)]
    let client = client.danger_accept_invalid_certs(true);

    let response = client
        .build()
        .context("failed to build HTTP client for JWKS fetch")?
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| AuthError::JWKS(format!("failed to fetch JWKS from {jwks_uri}: {e}")))?;
    // Check if the response status is successful
    let json_value = response.json::<Value>().await.map_err(|e| {
        AuthError::JWKS(format!(
            "failed to parse JWKS response from {jwks_uri}: {e}"
        ))
    })?;
    // Ensure that the JSON value contains the "keys" field
    let Some(keys) = json_value.get("keys") else {
        return Err(AuthError::JWKS(format!(
            "JSON key 'keys' not found in JWKS at {jwks_uri}"
        )));
    };
    // Ensure that the keys are an array of valid JWKs
    let jwks = match keys {
        Value::Array(array) => array
            .clone()
            .into_iter()
            .filter(|v| match serde_json::from_value::<Jwk>(v.clone()) {
                Ok(jwk) => {
                    trace!("Found valid JWK in JWKS at `{jwks_uri}`: {jwk:#?}");
                    true
                }
                Err(e) => {
                    trace!("Ignoring invalid JWK in JWKS at `{jwks_uri}`: {e}: {v:#?}",);
                    false
                }
            })
            .collect::<Vec<Value>>(),
        _ => vec![],
    };
    // If no valid JWKs are found, return an error
    if jwks.is_empty() {
        return Err(AuthError::JWKS(format!(
            "No valid JWK found in JWKS at `{jwks_uri}`"
        )));
    }
    // Attempt to deserialize the JWKS from the JSON value
    let jwks = json!({"keys": Value::Array(jwks)});
    let jwks = serde_json::from_value::<JwkSet>(jwks.clone()).map_err(|e| {
        AuthError::JWKS(format!(
            "failed to reconstruct JWKS from array of JWK at `{jwks_uri}`: {e}: {jwks:#?}"
        ))
    })?;
    info!("Successfully fetched JWKS from {jwks_uri}");
    Ok((jwks_uri.clone(), jwks))
}
