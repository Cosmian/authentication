use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthDbError {
    #[error("unexpected DB error: {0}")]
    Unexpected(String),

    #[error("DB initialization error: {0}")]
    Init(String),

    #[error("DB query error: {0}")]
    Sql(#[from] sqlx::Error),

    #[error("Invalid DB auth method error: {0}")]
    AuthMethod(String),

    #[error("Password hashing error: {0}")]
    PasswordHashing(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("{0}")]
    Conflict(String),
}

pub type AuthDbResult<T> = Result<T, AuthDbError>;

impl AuthDbError {
    /// Maps a `sqlx::Error` from an INSERT into a uniquely-keyed table to `Conflict`
    /// when it's a unique/primary-key violation, or `Sql` otherwise — so callers can
    /// distinguish "this row already exists" from a genuine database failure without
    /// parsing backend-specific error text.
    pub fn from_insert_error(e: sqlx::Error, conflict_message: impl Into<String>) -> Self {
        if e.as_database_error()
            .is_some_and(|db_err| db_err.is_unique_violation())
        {
            Self::Conflict(conflict_message.into())
        } else {
            Self::Sql(e)
        }
    }
}

impl From<AuthDbError> for crate::AuthError {
    fn from(e: AuthDbError) -> Self {
        match e {
            AuthDbError::Conflict(msg) => crate::AuthError::Conflict(msg),
            other => crate::AuthError::Db(other.to_string()),
        }
    }
}
