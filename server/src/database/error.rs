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
}

pub type AuthDbResult<T> = Result<T, AuthDbError>;

impl From<AuthDbError> for crate::AuthError {
    fn from(e: AuthDbError) -> Self {
        crate::AuthError::Db(e.to_string())
    }
}
