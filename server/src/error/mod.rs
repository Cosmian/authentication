use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("TLS error: {0}")]
    Tls(String),
}

pub type ServerResult<T> = Result<T, ServerError>;

#[cfg(feature = "rustls")]
impl From<rustls::Error> for ServerError {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e.to_string())
    }
}

impl From<ServerError> for crate::AuthError {
    fn from(e: ServerError) -> Self {
        Self::Generic(e.to_string())
    }
}
