use crate::{
    database::{
        AuthDbError, AuthDbResult, Database, MySqlDatabase, PostgresDatabase, SqliteDatabase,
    },
    server::parameters::{DatabaseBackend, DatabaseParams},
};
use std::{sync::Arc, time::Duration};

/// Create a database instance based on the provided parameters
pub async fn create_database(params: &DatabaseParams) -> AuthDbResult<Arc<dyn Database>> {
    match params.backend {
        DatabaseBackend::PostgreSQL => {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(params.max_connections)
                .min_connections(params.min_connections)
                .acquire_timeout(Duration::from_secs(params.connect_timeout_secs))
                .idle_timeout(Duration::from_secs(params.idle_timeout_secs))
                .connect(&params.connection_url)
                .await
                .map_err(|e| AuthDbError::Init(format!("{e}")))?;

            let db = PostgresDatabase::new(pool);

            if params.auto_init_schema {
                db.init().await?;
            }

            Ok(Arc::new(db))
        }
        DatabaseBackend::SQLite => {
            let connect_opts = params
                .connection_url
                .parse::<sqlx::sqlite::SqliteConnectOptions>()
                .map_err(|e| {
                    AuthDbError::Init(format!(
                        "Invalid SQLite URL {}: {e}",
                        &params.connection_url
                    ))
                })?
                .create_if_missing(true);

            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(params.max_connections)
                .min_connections(params.min_connections)
                .acquire_timeout(Duration::from_secs(params.connect_timeout_secs))
                .idle_timeout(Duration::from_secs(params.idle_timeout_secs))
                .connect_with(connect_opts)
                .await
                .map_err(|e| AuthDbError::Init(format!("{e}")))?;

            let db = SqliteDatabase::new(pool);

            if params.auto_init_schema {
                db.init().await?;
            }

            Ok(Arc::new(db))
        }
        DatabaseBackend::MySQL => {
            let pool = sqlx::mysql::MySqlPoolOptions::new()
                .max_connections(params.max_connections)
                .min_connections(params.min_connections)
                .acquire_timeout(Duration::from_secs(params.connect_timeout_secs))
                .idle_timeout(Duration::from_secs(params.idle_timeout_secs))
                .connect(&params.connection_url)
                .await
                .map_err(|e| AuthDbError::Init(format!("{e}")))?;

            let db = MySqlDatabase::new(pool);

            if params.auto_init_schema {
                db.init().await?;
            }

            Ok(Arc::new(db))
        }
        DatabaseBackend::Redis => Err(AuthDbError::Init(
            "Redis database backend is not supported".to_string(),
        )),
    }
}
