use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Cookie error: {0}")]
    Cookie(String),

    #[error("DB Error: {0}")]
    Db(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("{0}")]
    Generic(String),

    #[error("server initialization error: {0}")]
    Init(String),

    #[error("JWT error: {0}")]
    JWT(String),

    #[error("JWKS error: {0}")]
    JWKS(String),

    #[error("failed HTTP status: {0}")]
    FailedHttpStatus(String),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Session not found")]
    SessionNotFound,

    #[error("TOTP/2FA error: {0}")]
    Totp(String),

    #[cfg(test)]
    #[error("Test error: {0}")]
    TestError(String),

    #[error("unexpected error: {0}")]
    Unexpected(String),
}

#[cfg(feature = "_server")]
impl actix_web::ResponseError for AuthError {
    fn error_response(&self) -> actix_web::HttpResponse {
        match self {
            Self::BadRequest(_) => actix_web::HttpResponse::BadRequest().json(format!("{self}")),
            Self::Conflict(_) => actix_web::HttpResponse::Conflict().json(format!("{self}")),
            Self::JWT(_) | Self::Session(_) | Self::Cookie(_) => {
                actix_web::HttpResponse::Unauthorized().json(format!("{self}"))
            }
            Self::Forbidden(_) => actix_web::HttpResponse::Forbidden().json(format!("{self}")),
            Self::SessionNotFound => actix_web::HttpResponse::NotFound().json(format!("{self}")),
            _ => actix_web::HttpResponse::InternalServerError().json(format!("{self}")),
        }
    }
}
