use crate::{AuthError, AuthResultHelper, auth_bail, auth_ensure, auth_error};

#[test]
fn test_auth_error_interpolation() {
    let var = 42;
    let err = auth_error!("interpolate {var}");
    assert_eq!("interpolate 42", err.to_string());
}

#[test]
fn test_result_helper_context() {
    let result: Result<(), AuthError> = Err(AuthError::JWT("original error".to_owned()));
    let err = result.context("additional context").unwrap_err();
    assert_eq!(
        "additional context: JWT error: original error",
        err.to_string()
    );

    let var = "test";
    let result: Result<(), AuthError> = Err(AuthError::JWT("original error".to_owned()));
    let err = result.context(&format!("context with {var}")).unwrap_err();
    assert_eq!(
        "context with test: JWT error: original error",
        err.to_string()
    );
}

#[test]
fn test_result_helper_with_context() {
    let result: Result<(), AuthError> = Err(AuthError::JWT("original error".to_owned()));
    let err = result
        .with_context(|| "closure context".to_string())
        .unwrap_err();
    assert_eq!(
        "closure context: JWT error: original error",
        err.to_string()
    );
}

#[test]
fn test_option_helper_context() {
    let opt: Option<i32> = None;
    let err = opt.context("missing value").unwrap_err();
    assert_eq!("missing value", err.to_string());
}

#[test]
fn test_auth_ensure_literal() {
    fn check() -> Result<(), AuthError> {
        auth_ensure!(false, "a literal message");
        Ok(())
    }
    assert_eq!("a literal message", check().unwrap_err().to_string());
}

#[test]
fn test_auth_bail() {
    fn bail_fn() -> Result<(), AuthError> {
        auth_bail!("bailing out {}", 42);
    }
    assert_eq!("bailing out 42", bail_fn().unwrap_err().to_string());
}
