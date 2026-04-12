use serde::{Deserialize, Serialize};

/// Database backend type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseBackend {
    PostgreSQL,
    SQLite,
    MySQL,
    Redis,
}

/// Database configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseParams {
    /// Database backend type
    pub backend: DatabaseBackend,

    /// Database connection URL/string
    ///
    /// Format examples:
    /// - PostgreSQL: `postgresql://user:password@localhost:5432/database`
    /// - SQLite: `sqlite://path/to/database.db` or `sqlite::memory:` for in-memory
    /// - MySQL: `mysql://user:password@localhost:3306/database`
    /// - Redis: `redis://localhost:6379`
    pub connection_url: String,

    /// Maximum number of connections in the pool (default: 10)
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Minimum number of idle connections in the pool (default: 0)
    #[serde(default)]
    pub min_connections: u32,

    /// Connection timeout in seconds (default: 30)
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// Idle timeout in seconds (default: 600 = 10 minutes)
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Whether to initialize the database schema on startup (default: true)
    #[serde(default = "default_true")]
    pub auto_init_schema: bool,
}

fn default_max_connections() -> u32 {
    10
}

fn default_connect_timeout() -> u64 {
    30
}

fn default_idle_timeout() -> u64 {
    600
}

fn default_true() -> bool {
    true
}

impl Default for DatabaseParams {
    fn default() -> Self {
        Self {
            backend: DatabaseBackend::SQLite,
            connection_url: "sqlite::memory:".to_string(),
            max_connections: 10,
            min_connections: 0,
            connect_timeout_secs: 30,
            idle_timeout_secs: 600,
            auto_init_schema: true,
        }
    }
}

impl DatabaseParams {
    /// Create PostgreSQL database parameters
    pub fn postgres(connection_url: impl Into<String>) -> Self {
        Self {
            backend: DatabaseBackend::PostgreSQL,
            connection_url: connection_url.into(),
            ..Default::default()
        }
    }

    /// Create SQLite database parameters
    pub fn sqlite(connection_url: impl Into<String>) -> Self {
        Self {
            backend: DatabaseBackend::SQLite,
            connection_url: connection_url.into(),
            ..Default::default()
        }
    }

    /// Create MySQL database parameters
    pub fn mysql(connection_url: impl Into<String>) -> Self {
        Self {
            backend: DatabaseBackend::MySQL,
            connection_url: connection_url.into(),
            ..Default::default()
        }
    }

    /// Create in-memory SQLite database (useful for testing)
    pub fn in_memory() -> Self {
        Self::sqlite("sqlite::memory:")
    }

    /// Create Redis database parameters
    pub fn redis(connection_url: impl Into<String>) -> Self {
        Self {
            backend: DatabaseBackend::Redis,
            connection_url: connection_url.into(),
            ..Default::default()
        }
    }

    /// Set maximum connections
    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }

    /// Set minimum connections
    pub fn with_min_connections(mut self, min: u32) -> Self {
        self.min_connections = min;
        self
    }

    /// Set connection timeout
    pub fn with_connect_timeout(mut self, secs: u64) -> Self {
        self.connect_timeout_secs = secs;
        self
    }

    /// Set idle timeout
    pub fn with_idle_timeout(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = secs;
        self
    }

    /// Set auto schema initialization
    pub fn with_auto_init_schema(mut self, auto_init: bool) -> Self {
        self.auto_init_schema = auto_init;
        self
    }
}
