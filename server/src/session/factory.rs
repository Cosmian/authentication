use crate::{
    AuthError, AuthResult,
    server::parameters::{DatabaseBackend, DatabaseParams},
    session::{
        SessionStore,
        impls::{
            MySqlSessionStore, PostgresSessionStore, RedisSessionStore, SqliteSessionStore,
            StaleSessionCollectorConfig, start_stale_session_collector,
        },
    },
};
use std::{sync::Arc, time::Duration};

/// Create a session store with automatic stale session cleanup
///
/// This function creates a session store and automatically starts a background task
/// to clean up stale sessions for SQL-based backends (PostgreSQL, MySQL, SQLite).
/// For Redis, no background task is started since Redis handles expiration automatically via TTL.
///
/// # Arguments
/// * `params` - Database parameters specifying the backend type and connection details
/// * `collector_config` - Configuration for the stale session collector (cleanup interval, max age)
///
/// # Returns
/// A tuple containing:
/// - The Arc-wrapped session store
/// - An optional JoinHandle to the collector task (Some for SQL backends, None for Redis)
///
/// # Examples
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use auth_server::{DatabaseParams, StaleSessionCollectorConfig, create_session_store_with_collector};
///
/// // Create a PostgreSQL session store with automatic cleanup
/// let params = DatabaseParams::postgres("postgresql://localhost/mydb");
/// let config = StaleSessionCollectorConfig::default();
/// let (session_store, collector_handle) = create_session_store_with_collector(&params, config).await?;
///
/// // The collector runs in the background for SQL backends
/// // For Redis, collector_handle will be None
/// # Ok(())
/// # }
/// ```
pub async fn create_session_store_with_collector(
    params: &DatabaseParams,
    collector_config: StaleSessionCollectorConfig,
) -> AuthResult<(Arc<dyn SessionStore>, Option<tokio::task::JoinHandle<()>>)> {
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

            let store = PostgresSessionStore::new(pool);

            if params.auto_init_schema {
                store.init().await?;
            }

            let store_arc = Arc::new(store);
            let handle = start_stale_session_collector(store_arc.clone(), collector_config);

            Ok((store_arc as Arc<dyn SessionStore>, Some(handle)))
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

            let store = SqliteSessionStore::new(pool);

            if params.auto_init_schema {
                store.init().await?;
            }

            let store_arc = Arc::new(store);
            let handle = start_stale_session_collector(store_arc.clone(), collector_config);

            Ok((store_arc as Arc<dyn SessionStore>, Some(handle)))
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

            let store = MySqlSessionStore::new(pool);

            if params.auto_init_schema {
                store.init().await?;
            }

            let store_arc = Arc::new(store);
            let handle = start_stale_session_collector(store_arc.clone(), collector_config);

            Ok((store_arc as Arc<dyn SessionStore>, Some(handle)))
        }
        DatabaseBackend::Redis => {
            let client = redis::Client::open(params.connection_url.as_str())
                .map_err(|e| AuthError::Init(format!("Failed to create Redis client: {e}")))?;

            // Test the connection
            let mut conn = client
                .get_multiplexed_async_connection()
                .await
                .map_err(|e| AuthError::Init(format!("Failed to connect to Redis: {e}")))?;

            // Verify connection with a PING
            let _: String = redis::cmd("PING")
                .query_async(&mut conn)
                .await
                .map_err(|e| AuthError::Init(format!("Failed to ping Redis: {e}")))?;

            // Create the session store
            let store = RedisSessionStore::new(client);
            let arc_store = Arc::new(store);

            Ok((arc_store as Arc<dyn SessionStore>, None))
        }
    }
}
