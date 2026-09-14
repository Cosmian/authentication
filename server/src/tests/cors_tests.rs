//! Regression tests for `build_admin_cors` (see `server/auth_verifier.rs`).
//!
//! `/whoami` and the other `CookieAuthSameServer`-protected scopes are
//! cookie-authenticated, so a cross-origin admin UI needs
//! `Access-Control-Allow-Credentials: true` on the response — otherwise the
//! browser refuses to let JS read the response even though the request
//! itself succeeds server-side. These tests exercise the raw HTTP response
//! headers directly (not the typed `AuthClient`, which doesn't expose them).

use crate::{
    AuthError, AuthResult,
    client::AuthClientScheme,
    database::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME},
    models::ADMIN_REALM,
    tests::{get_default_server_params, start_test_server},
};

fn admin_scheme() -> AuthClientScheme {
    AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    }
}

fn test_http_client() -> AuthResult<reqwest::Client> {
    reqwest::Client::builder()
        // The test server uses a self-signed dev certificate; only the
        // response headers are under test here, not certificate validation.
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| AuthError::Unexpected(format!("failed to build test HTTP client: {e}")))
}

/// Once an origin is configured via `allowed_origins`, an authenticated
/// cross-origin request to a cookie-authenticated admin scope (`/whoami`)
/// must carry `Access-Control-Allow-Credentials: true`, echoing the caller's
/// origin — otherwise the browser blocks the response from being read
/// cross-origin even though the request itself succeeds server-side.
#[actix_web::test]
async fn test_whoami_cross_origin_includes_credentials_header() -> AuthResult<()> {
    let origin = "https://admin-ui.example.com";

    let mut server_params = get_default_server_params()?;
    server_params.allowed_origins = vec![origin.to_string()];
    let ctx = start_test_server(server_params).await?;

    // Log in through the typed client to obtain a valid session cookie.
    let login_client = ctx.get_test_client(admin_scheme());
    let (_result, cookie) = login_client.login(ADMIN_REALM, None).await?;
    let cookie = cookie.expect("Expected an _ea_ cookie after login");

    // Replay the session cookie on a raw cross-origin request so the response
    // headers (not exposed by the typed client) can be inspected directly.
    let client = test_http_client()?;
    let response = client
        .get(format!(
            "{}/whoami?realm={}",
            ctx.get_client_url(),
            ADMIN_REALM
        ))
        .header("Origin", origin)
        .header("Cookie", format!("{}={}", cookie.name(), cookie.value()))
        .send()
        .await
        .map_err(|e| AuthError::Unexpected(format!("request failed: {e}")))?;

    assert!(
        response.status().is_success(),
        "Expected a successful whoami response, got {}",
        response.status()
    );

    let headers = response.headers();
    assert_eq!(
        headers
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
        "Expected Access-Control-Allow-Credentials: true on a configured cross-origin request"
    );
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some(origin),
        "Expected the specific origin to be echoed back, not a wildcard"
    );

    ctx.stop_server().await
}

/// With no `allowed_origins` configured (the default), a request carrying a
/// foreign `Origin` header must not receive any CORS allow-origin header —
/// the admin scopes stay same-origin-only unless explicitly opened up.
#[actix_web::test]
async fn test_whoami_same_origin_only_by_default() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params()?).await?;

    let client = test_http_client()?;
    let response = client
        .get(format!(
            "{}/whoami?realm={}",
            ctx.get_client_url(),
            ADMIN_REALM
        ))
        .header("Origin", "https://not-allowed.example.com")
        .send()
        .await
        .map_err(|e| AuthError::Unexpected(format!("request failed: {e}")))?;

    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "Expected no Access-Control-Allow-Origin header when allowed_origins is empty"
    );

    ctx.stop_server().await
}
