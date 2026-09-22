use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::AuthResult;

/// A stored SP-initiated `<AuthnRequest>` awaiting its matching `<Response>`.
///
/// Persisted when `/saml/{realm_id}/login` issues an `AuthnRequest`, and consumed
/// (single-use) at the ACS to correlate the response's `InResponseTo` and recover the
/// server-side return URL — so neither the correlation nor the return URL can be tampered
/// with in transit through the browser or IdP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSamlRequest {
    /// The `<AuthnRequest>` ID, matched against the response's `InResponseTo`.
    pub request_id: String,
    /// Realm that initiated the request; the ACS must belong to the same realm.
    pub realm_id: String,
    /// Validated post-login redirect URL, bound to this request server-side.
    pub return_url: String,
    /// Unix seconds when the request was created.
    pub created_at: i64,
    /// Unix seconds after which the pending request is invalid and may be purged.
    pub expires_at: i64,
}

/// Storage for the two pieces of short-lived state SP-initiated SAML SSO needs: outstanding
/// `AuthnRequest`s (for `InResponseTo` correlation and return-URL binding) and consumed
/// assertion IDs (for replay defense).
#[async_trait]
pub trait SamlRequestStore: Send + Sync {
    /// Persist a pending SP-initiated `AuthnRequest`, keyed by its `request_id`.
    async fn store_pending_request(&self, request: &PendingSamlRequest) -> AuthResult<()>;

    /// Atomically fetch and delete the pending request for `request_id` in `realm_id`,
    /// enforcing single use. Returns `None` if it is absent, expired, or belongs to a
    /// different realm.
    async fn take_pending_request(
        &self,
        request_id: &str,
        realm_id: &str,
    ) -> AuthResult<Option<PendingSamlRequest>>;

    /// Record a consumed assertion ID for replay defense. Returns `true` if it was newly
    /// recorded, `false` if it had already been seen (a replay). `expires_at` bounds how
    /// long the entry must be retained (typically the assertion's `NotOnOrAfter` + skew).
    async fn record_assertion_id(&self, assertion_id: &str, expires_at: i64) -> AuthResult<bool>;

    /// Delete expired pending requests and replay-cache entries. Called periodically.
    async fn delete_expired(&self) -> AuthResult<()>;
}
