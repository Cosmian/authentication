//! Stale Session Collector
//!
//! This module provides a background task that periodically cleans up stale sessions.
//! It is designed for SQL-based session stores (SQLite, PostgreSQL, MySQL).
//!
//! **Note:** For Redis-based session stores, this collector is NOT needed as Redis
//! automatically handles expiration via TTL. Sessions in Redis expire automatically
//! after the configured max_stale_age_seconds from the Realm, and the TTL is refreshed on every access.
//!
//! # Usage
//!
//! ```rust,no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use auth_server::{DatabaseParams, StaleSessionCollectorConfig, create_session_store_with_collector, start_stale_session_collector};
//!
//! // Create a session store (the factory also starts the collector automatically)
//! let params = DatabaseParams::in_memory();
//! let (session_store, _auto_collector) =
//!     create_session_store_with_collector(&params, StaleSessionCollectorConfig::default()).await?;
//!
//! // Or manage the collector lifecycle manually:
//! let config = StaleSessionCollectorConfig {
//!     cleanup_interval_seconds: 300, // Run every 5 minutes
//! };
//! let _collector_handle = start_stale_session_collector(session_store.clone(), config);
//!
//! // The collector now runs in the background...
//! // Your application can continue using the session_store
//! # Ok(())
//! # }
//! ```

use crate::session::SessionStore;
use cosmian_logger::{error, info};
use std::{sync::Arc, time::Duration};
use tokio::time::interval;

/// Configuration for the stale session collector
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StaleSessionCollectorConfig {
    /// How often to run the cleanup task (in seconds)
    pub cleanup_interval_seconds: u64,
}

impl Default for StaleSessionCollectorConfig {
    fn default() -> Self {
        Self {
            cleanup_interval_seconds: 60, // 1 minute
        }
    }
}

/// Starts a background task that periodically cleans up stale sessions
///
/// This should be used for SQL-based session stores (SQLite, PostgreSQL, MySQL).
/// For Redis, this is not needed as Redis can handle expiration automatically via TTL.
///
/// # Example
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use auth_server::{DatabaseParams, StaleSessionCollectorConfig, create_session_store_with_collector, start_stale_session_collector};
///
/// let (session_store, _) =
///     create_session_store_with_collector(&DatabaseParams::in_memory(), StaleSessionCollectorConfig::default()).await?;
/// let config = StaleSessionCollectorConfig::default();
///
/// // Start the collector
/// let _handle = start_stale_session_collector(session_store, config);
/// # Ok(())
/// # }
/// ```
pub fn start_stale_session_collector<S>(
    session_store: Arc<S>,
    config: StaleSessionCollectorConfig,
) -> tokio::task::JoinHandle<()>
where
    S: SessionStore + 'static + ?Sized,
{
    info!(
        "Starting stale session collector: cleanup every {} seconds",
        config.cleanup_interval_seconds
    );

    // Ensure the interval is never zero to avoid tokio::time::interval panicking.
    let interval_secs = std::cmp::max(config.cleanup_interval_seconds, 1);

    tokio::spawn(async move {
        let mut interval_timer = interval(Duration::from_secs(interval_secs));

        loop {
            interval_timer.tick().await;

            match session_store.delete_expired_sessions().await {
                Ok(()) => {
                    info!("Successfully cleaned up stale sessions");
                }
                Err(e) => {
                    error!("Failed to clean up stale sessions: {}", e);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthResult, AuthenticatedClientScheme, models::SessionData, session::SessionStore,
    };
    use async_trait::async_trait;

    // Mock session store for testing
    struct MockSessionStore {
        delete_called: Arc<std::sync::Mutex<bool>>,
    }

    #[async_trait]
    impl SessionStore for MockSessionStore {
        async fn upsert_session(
            &self,
            _session_id: &str,
            _realm: &crate::Realm,
            _authenticated_client: &AuthenticatedClientScheme,
            _session_value: &str,
        ) -> AuthResult<()> {
            Ok(())
        }

        async fn get_session(&self, _session_id: &str) -> AuthResult<Option<SessionData>> {
            Ok(None)
        }

        async fn get_sessions_for_clients(
            &self,
            _realm_id: &str,
            _authenticated_users: &[&AuthenticatedClientScheme],
        ) -> AuthResult<Vec<SessionData>> {
            Ok(vec![])
        }

        async fn delete_sessions(&self, _session_ids: &[&str]) -> AuthResult<()> {
            Ok(())
        }

        async fn delete_expired_sessions(&self) -> AuthResult<()> {
            let mut called = self.delete_called.lock().unwrap();
            *called = true;
            Ok(())
        }

        async fn delete_sessions_for_realm(&self, _realm_id: &str) -> AuthResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_collector_runs() {
        let delete_called = Arc::new(std::sync::Mutex::new(false));
        let mock_store = Arc::new(MockSessionStore {
            delete_called: delete_called.clone(),
        });

        let config = StaleSessionCollectorConfig {
            cleanup_interval_seconds: 1, // 1 second for testing
        };

        let handle = start_stale_session_collector(mock_store, config);

        // Wait for at least one execution
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Check that delete_expired_sessions was called
        let was_called = *delete_called.lock().unwrap();
        assert!(
            was_called,
            "delete_expired_sessions should have been called"
        );

        // Abort the task
        handle.abort();
    }
}
