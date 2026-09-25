use std::{sync::Arc, time::Duration};

use cosmian_logger::error;

use crate::{
    AuthError, AuthResult,
    saml::{
        SamlRequestStore,
        impls::{
            MySqlSamlRequestStore, PostgresSamlRequestStore, RedisSamlRequestStore,
            SqliteSamlRequestStore,
        },
    },
    server::parameters::{DatabaseBackend, DatabaseParams},
};

/// Create a [`SamlRequestStore`] for the configured database backend.
///
/// Mirrors the session-store factory: it opens its own pool/connection, initializing the
/// SAML tables when `auto_init_schema` is set. SQL backends accumulate expired rows until
/// [`SamlRequestStore::delete_expired`] is called; Redis expires them automatically via TTL.
pub async fn create_saml_request_store(
    params: &DatabaseParams,
) -> AuthResult<Arc<dyn SamlRequestStore>> {
    match params.backend {
        DatabaseBackend::PostgreSQL => {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(params.max_connections)
                .min_connections(params.min_connections)
                .acquire_timeout(Duration::from_secs(params.connect_timeout_secs))
                .idle_timeout(Duration::from_secs(params.idle_timeout_secs))
                .connect(&params.connection_url)
                .await
                .map_err(|e| AuthError::Init(format!("Failed to connect to PostgreSQL: {e}")))?;
            let store = PostgresSamlRequestStore::new(pool);
            if params.auto_init_schema {
                store.init().await?;
            }
            Ok(Arc::new(store))
        }
        DatabaseBackend::SQLite => {
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(params.max_connections)
                .min_connections(params.min_connections)
                .acquire_timeout(Duration::from_secs(params.connect_timeout_secs))
                .idle_timeout(Duration::from_secs(params.idle_timeout_secs))
                .connect(&params.connection_url)
                .await
                .map_err(|e| AuthError::Init(format!("Failed to connect to SQLite: {e}")))?;
            let store = SqliteSamlRequestStore::new(pool);
            if params.auto_init_schema {
                store.init().await?;
            }
            Ok(Arc::new(store))
        }
        DatabaseBackend::MySQL => {
            let pool = sqlx::mysql::MySqlPoolOptions::new()
                .max_connections(params.max_connections)
                .min_connections(params.min_connections)
                .acquire_timeout(Duration::from_secs(params.connect_timeout_secs))
                .idle_timeout(Duration::from_secs(params.idle_timeout_secs))
                .connect(&params.connection_url)
                .await
                .map_err(|e| AuthError::Init(format!("Failed to connect to MySQL: {e}")))?;
            let store = MySqlSamlRequestStore::new(pool);
            if params.auto_init_schema {
                store.init().await?;
            }
            Ok(Arc::new(store))
        }
        DatabaseBackend::Redis => {
            let client = redis::Client::open(params.connection_url.as_str())
                .map_err(|e| AuthError::Init(format!("Failed to create Redis client: {e}")))?;
            let mut conn = client
                .get_multiplexed_async_connection()
                .await
                .map_err(|e| AuthError::Init(format!("Failed to connect to Redis: {e}")))?;
            let _: String = redis::cmd("PING")
                .query_async(&mut conn)
                .await
                .map_err(|e| AuthError::Init(format!("Failed to ping Redis: {e}")))?;
            Ok(Arc::new(RedisSamlRequestStore::new(client)))
        }
    }
}

/// Periodically purge expired pending requests and replay-cache entries (a no-op on Redis,
/// which expires them itself).
pub(crate) fn start_saml_request_store_cleanup(
    store: Arc<dyn SamlRequestStore>,
    interval_seconds: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(interval_seconds.max(1)));
        loop {
            timer.tick().await;
            if let Err(e) = store.delete_expired().await {
                error!("Failed to purge expired SAML requests: {e}");
            }
        }
    })
}
