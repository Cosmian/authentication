use async_trait::async_trait;
use chrono::Utc;
use redis::{AsyncCommands, Client};
use std::sync::Arc;

use crate::{
    AuthError, AuthResult,
    saml::request_store::{PendingSamlRequest, SamlRequestStore, ensure_unexpired},
};

/// Redis/ValKey-backed store for pending SAML requests and the assertion replay cache.
///
/// Both kinds of state carry a TTL, so Redis expires them automatically:
/// - `saml:pending:{realm_id}:{request_id}` -> JSON `PendingSamlRequest`
/// - `saml:seen:{assertion_id}` -> a marker set only while the id must be remembered
pub struct RedisSamlRequestStore {
    client: Arc<Client>,
}

impl RedisSamlRequestStore {
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    fn pending_key(realm_id: &str, request_id: &str) -> String {
        format!("saml:pending:{realm_id}:{request_id}")
    }

    fn seen_key(assertion_id: &str) -> String {
        format!("saml:seen:{assertion_id}")
    }

    async fn conn(&self) -> AuthResult<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to get Redis connection: {e}")))
    }
}

#[async_trait]
impl SamlRequestStore for RedisSamlRequestStore {
    async fn store_pending_request(&self, request: &PendingSamlRequest) -> AuthResult<()> {
        let mut conn = self.conn().await?;
        let key = Self::pending_key(&request.realm_id, &request.request_id);
        let json = serde_json::to_string(request).map_err(|e| {
            AuthError::Generic(format!("Failed to serialize SAML pending request: {e}"))
        })?;
        // TTL bounds the request lifetime; Redis purges it automatically once it lapses.
        let ttl = ensure_unexpired(request.expires_at, "SAML pending request")?;
        let _: () = conn.set_ex(&key, json, ttl).await.map_err(|e| {
            AuthError::Generic(format!("Failed to store SAML pending request: {e}"))
        })?;
        Ok(())
    }

    async fn take_pending_request(
        &self,
        request_id: &str,
        realm_id: &str,
    ) -> AuthResult<Option<PendingSamlRequest>> {
        let mut conn = self.conn().await?;
        let key = Self::pending_key(realm_id, request_id);
        // GETDEL is atomic fetch-and-delete (Redis 6.2+), enforcing single use; the realm is
        // part of the key. TTLs are whole seconds, so expiry is re-checked like the SQL
        // backends do rather than trusting the TTL alone.
        let json: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to take SAML pending request: {e}")))?;

        match json {
            None => Ok(None),
            Some(json) => {
                let request: PendingSamlRequest = serde_json::from_str(&json).map_err(|e| {
                    AuthError::Generic(format!("Failed to deserialize SAML pending request: {e}"))
                })?;
                if request.expires_at <= Utc::now().timestamp() {
                    return Ok(None);
                }
                Ok(Some(request))
            }
        }
    }

    async fn record_assertion_id(&self, assertion_id: &str, expires_at: i64) -> AuthResult<bool> {
        let ttl = ensure_unexpired(expires_at, "SAML assertion id")?;
        let mut conn = self.conn().await?;
        let key = Self::seen_key(assertion_id);
        // `SET key 1 NX EX ttl` sets only if the key is absent: a reply of OK means newly
        // recorded, a nil reply means the id was already seen (a replay). One atomic command.
        let set: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(ttl)
            .query_async(&mut conn)
            .await
            .map_err(|e| AuthError::Generic(format!("Failed to record SAML assertion id: {e}")))?;
        Ok(set.is_some())
    }

    async fn delete_expired(&self) -> AuthResult<()> {
        // Redis expires both key families automatically via their TTLs; nothing to purge.
        Ok(())
    }
}
