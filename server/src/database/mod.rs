mod error;
pub use error::{AuthDbError, AuthDbResult};

mod factory;
pub use factory::create_database;

mod impls;
pub use impls::{MySqlDatabase, PostgresDatabase, SqliteDatabase};

mod passwords;
pub use passwords::hash_password_with_argon2;

mod r#trait;
pub use r#trait::Database;
#[cfg(test)]
pub use r#trait::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME};

pub(crate) mod vault_models;
pub use vault_models::{VaultRole, VaultSecretId, VaultToken};

#[cfg(test)]
mod tests;
