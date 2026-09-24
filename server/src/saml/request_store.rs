use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{AuthError, AuthResult};

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
    /// Persist a pending SP-initiated `AuthnRequest`, keyed by its `request_id`. Fails if it
    /// has already expired.
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
    /// recorded, `false` if it had already been seen (a replay). Fails if `expires_at` has
    /// already passed. `expires_at` must cover every instant at which the assertion could still
    /// be accepted (its `NotOnOrAfter` plus the validator's clock-skew allowance), because the
    /// entry may be forgotten after that.
    async fn record_assertion_id(&self, assertion_id: &str, expires_at: i64) -> AuthResult<bool>;

    /// Delete expired pending requests and replay-cache entries. Called periodically.
    async fn delete_expired(&self) -> AuthResult<()>;
}

/// Returns the remaining lifetime in seconds (always >= 1), or an error if `expires_at` has
/// passed: expired state is never stored, so no backend can hand it back or drop it early.
pub(super) fn ensure_unexpired(expires_at: i64, what: &str) -> AuthResult<u64> {
    let remaining = expires_at - Utc::now().timestamp();
    if remaining <= 0 {
        return Err(AuthError::Generic(format!(
            "refusing to store an already-expired {what}"
        )));
    }
    Ok(remaining as u64)
}
