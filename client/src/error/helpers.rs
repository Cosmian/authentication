use crate::AuthError;

pub type AuthResult<R> = Result<R, AuthError>;

/// A helper trait for `AuthResult` that provides additional methods for error handling.
pub trait AuthResultHelper<T> {
    /// Sets the context for the error.
    fn context(self, context: &str) -> AuthResult<T>;

    /// Sets the context for the error using a closure.
    fn with_context<O>(self, op: O) -> AuthResult<T>
    where
        O: FnOnce() -> String;
}

impl<T, E> AuthResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> AuthResult<T> {
        self.map_err(|e| AuthError::Generic(format!("{context}: {e}")))
    }

    fn with_context<O>(self, op: O) -> AuthResult<T>
    where
        O: FnOnce() -> String,
    {
        self.map_err(|e| AuthError::Generic(format!("{}: {e}", op())))
    }
}

impl<T> AuthResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> AuthResult<T> {
        self.ok_or_else(|| AuthError::Generic(context.to_string()))
    }

    fn with_context<O>(self, op: O) -> AuthResult<T>
    where
        O: FnOnce() -> String,
    {
        self.ok_or_else(|| AuthError::Generic(op()))
    }
}
