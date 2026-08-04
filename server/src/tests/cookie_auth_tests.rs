//! Integration tests for the `CookieAuthSameServer` middleware via the
//! `/login` and `/whoami` endpoints.
//!
//! Each test spins up a fresh in-memory server, authenticates as the seeded
//! `admin` user (realm `_`), and exercises various success / failure paths.

use crate::{
    AuthError, AuthResult, AuthenticationNextStep,
    client::AuthClientScheme,
    database::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME},
    models::ADMIN_REALM,
    session::StaleSessionCollectorConfig,
    tests::{start_default_test_server, start_test_server},
};
use cosmian_logger::info;
use tokio::time::{Duration, sleep};

fn admin_scheme() -> AuthClientScheme {
    AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    }
}

/// Login as admin, verify the `_ea_` cookie is issued, then call `whoami` and
/// confirm the returned claims identify the admin user.
#[actix_web::test]
async fn test_login_and_whoami_success() -> AuthResult<()> {
    // init_test_logging(Some("info"));
    let ctx = start_default_test_server().await?;

    let client = ctx.get_test_client(admin_scheme());

    // --- login ---
    let (result, cookie) = client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated next step, got {:?}",
        result.next_step
    );
    assert!(
        result.session_id.is_some(),
        "Expected a session_id in the login response"
    );
    assert!(cookie.is_some(), "Expected an _ea_ cookie after login");

    info!(
        "Logged in; session_id={:?} cookie={}",
        result.session_id,
        cookie.as_ref().unwrap().name()
    );

    // --- whoami ---
    // The same client instance holds the cookie in its jar; it will be sent
    // automatically on the next request.
    let claims = client.whoami(ADMIN_REALM).await?;
    info!("whoami claims: {claims:?}");

    // The admin user's subject should identify the admin account.
    assert_eq!(
        claims.registered.sub.as_deref(),
        Some("admin"),
        "whoami sub should be 'admin'"
    );

    ctx.stop_server().await
}

// ── Failure: no cookie ───────────────────────────────────────────────────────

/// A client that was never authenticated (cookie jar is empty) must receive
/// a 401 response when it calls `whoami`.
#[actix_web::test]
async fn test_whoami_without_cookie_fails() -> AuthResult<()> {
    // init_test_logging(Some("info"));
    let ctx = start_default_test_server().await?;

    // Fresh client — no credentials, no cookie.
    let unauthenticated_client = ctx.get_test_client(AuthClientScheme::None);

    let err = unauthenticated_client
        .whoami(ADMIN_REALM)
        .await
        .expect_err("Expected whoami to fail without a cookie");

    assert!(
        matches!(err, AuthError::FailedHttpStatus(_)),
        "Expected FailedHttpStatus error, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 in error message, got: {msg}"
    );
    info!("Got expected 401 with no cookie: {err}");

    ctx.stop_server().await
}

// ── Failure: invalid/tampered cookie ────────────────────────────────────────

/// Sending a `Cookie` header whose `_ea_` value is syntactic garbage must be
/// rejected with 401.
#[actix_web::test]
async fn test_whoami_with_invalid_cookie_fails() -> AuthResult<()> {
    // init_test_logging(Some("info"));
    let ctx = start_default_test_server().await?;

    // Use a plain `None`-scheme client so that no real credentials or cookies
    // are injected by the client itself.
    let client = ctx.get_test_client(AuthClientScheme::None);

    let response = client
        .get_raw_with_header(
            &format!("/whoami?realm={ADMIN_REALM}"),
            "Cookie",
            "_ea_=this-is-not-a-valid-signed-cookie",
        )
        .await?;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Expected 401 for tampered cookie, got {}",
        response.status()
    );
    info!("Got expected 401 for invalid cookie");

    ctx.stop_server().await
}

// ── Failure: session deleted server-side ────────────────────────────────────

/// After the server-side session record has been explicitly deleted, a `whoami`
/// request with the (now stale) cookie must be rejected with 401.
#[actix_web::test]
async fn test_whoami_after_session_deleted_fails() -> AuthResult<()> {
    // init_test_logging(Some("info"));
    let ctx = start_default_test_server().await?;

    let client = ctx.get_test_client(admin_scheme());

    // Authenticate and capture the session ID.
    let (result, _cookie) = client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Login should succeed"
    );
    let session_id = result.session_id.expect("Login must return a session_id");

    // Confirm whoami works before the session is deleted.
    let claims = client.whoami(ADMIN_REALM).await?;
    assert_eq!(
        claims.registered.sub.as_deref(),
        Some("admin"),
        "whoami should succeed before session deletion"
    );

    // Delete the session server-side.
    // The client still has the cookie in its jar; only the server record is gone.
    client.delete_sessions(&[session_id]).await?;
    info!("Session deleted; next whoami should fail");

    // whoami must now fail because the session can no longer be found.
    let err = client
        .whoami(ADMIN_REALM)
        .await
        .expect_err("Expected whoami to fail after session deletion");

    assert!(
        matches!(err, AuthError::FailedHttpStatus(_)),
        "Expected FailedHttpStatus, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 in error message, got: {msg}"
    );
    info!("Got expected 401 after session deletion: {err}");

    ctx.stop_server().await
}

// ── Failure: session expired ─────────────────────────────────────────────────

/// After the session's maximum age has elapsed (realm configured with
/// `session_max_age_seconds = 1`), a `whoami` request must be rejected with 401.
///
/// Steps:
/// 1. Authenticate as admin with a long-lived session to gain super-admin access.
/// 2. Update the `_` realm to have a 1-second session lifetime.
/// 3. Login again (fresh client) — this new session inherits the 1-second TTL.
/// 4. Verify `whoami` succeeds immediately.
/// 5. Wait 2 seconds for the session to expire.
/// 6. Verify `whoami` now returns 401.
#[actix_web::test]
async fn test_whoami_after_session_expired_fails() -> AuthResult<()> {
    // init_test_logging(Some("info"));
    let ctx = start_default_test_server().await?;

    // Step 1: Authenticate as admin (session_max_age = 3600 – the default).
    let admin_client = ctx.get_test_client(admin_scheme());
    let (result, _) = admin_client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Admin login must succeed"
    );

    // Step 2: Retrieve the current realm configuration and set a 1-second TTL.
    let mut realm = admin_client.get_realm_as_super_admin(ADMIN_REALM).await?;
    realm.session_max_age_seconds = 1;
    realm.session_max_stale_age_seconds = 1;
    admin_client
        .update_realm_as_super_admin(ADMIN_REALM, &realm)
        .await?;
    info!("Realm updated: session_max_age_seconds = 1");

    // Step 3: Login again with a brand-new client so the new session is created
    //         with the updated (1-second) TTL stored in the session table.
    let short_lived_client = ctx.get_test_client(admin_scheme());
    let (result2, _) = short_lived_client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result2.next_step, AuthenticationNextStep::Authenticated),
        "Second login must succeed"
    );

    // Step 4: whoami succeeds right after login.
    let claims = short_lived_client.whoami(ADMIN_REALM).await?;
    assert_eq!(
        claims.registered.sub.as_deref(),
        Some("admin"),
        "whoami should succeed immediately after login"
    );

    // Step 5: Wait for the session to expire.
    info!("Waiting 2 seconds for the short-lived session to expire...");
    sleep(Duration::from_secs(2)).await;

    // Step 6: whoami must now fail.
    let err = short_lived_client
        .whoami(ADMIN_REALM)
        .await
        .expect_err("Expected whoami to fail after session expiry");

    assert!(
        matches!(err, AuthError::FailedHttpStatus(_)),
        "Expected FailedHttpStatus, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 in error message, got: {msg}"
    );
    info!("Got expected 401 after session expiry: {err}");

    ctx.stop_server().await
}

// ── Stale session collector ───────────────────────────────────────────────────

/// Starts a server with a very short stale-session-collector period (2 s),
/// creates a session that expires after 1 s, waits long enough for both the
/// expiration and the next collector sweep to complete, and then verifies that
/// the session record has been physically removed from the store.
///
/// Steps:
/// 1. Authenticate as admin to gain super-admin access (long-lived session).
/// 2. Shorten the realm's `session_max_age_seconds` to 1 s.
/// 3. Login again — this new session inherits the 1-second TTL.
/// 4. Confirm the session exists immediately via `get_session`.
/// 5. Wait 5 seconds (1 s expiry + 2 s collector interval + 2 s safety margin).
/// 6. Confirm the session has been physically deleted (`get_session` → `None`).
#[actix_web::test]
async fn test_stale_session_collector_removes_expired_sessions() -> AuthResult<()> {
    // init_test_logging(Some("info"));

    // Start a server with a 2-second stale session collector interval.
    let mut server_params = crate::tests::get_default_server_params()?;
    server_params.stale_session_collector_config = Some(StaleSessionCollectorConfig {
        cleanup_interval_seconds: 2,
    });
    let ctx = start_test_server(server_params).await?;

    // Step 1: Authenticate as admin (default long-lived session).
    let admin_client = ctx.get_test_client(admin_scheme());
    let (result, _) = admin_client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Admin login must succeed"
    );

    // Step 2: Shorten the session TTL to 1 s so sessions expire quickly.
    let mut realm = admin_client.get_realm_as_super_admin(ADMIN_REALM).await?;
    realm.session_max_age_seconds = 1;
    realm.session_max_stale_age_seconds = 1;
    admin_client
        .update_realm_as_super_admin(ADMIN_REALM, &realm)
        .await?;
    info!("Realm updated: session_max_age_seconds = 1");

    // Step 3: Login with a fresh client so the new session uses the 1-second TTL.
    let short_lived_client = ctx.get_test_client(admin_scheme());
    let (result2, _) = short_lived_client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result2.next_step, AuthenticationNextStep::Authenticated),
        "Second login must succeed"
    );
    let session_id = result2.session_id.expect("Login must return a session_id");
    info!("Short-lived session created: {session_id}");

    // Step 4: The session should still exist in the store immediately after login.
    // Use admin_client (long-lived session) rather than short_lived_client: the
    // short-lived cookie has Max-Age=1, so it may expire before the request
    // completes (Argon2 + test overhead).  admin_client's session is 3600 s.
    let session_value = admin_client.get_session(&session_id).await?;
    assert!(
        session_value.is_some(),
        "Session must exist in the store right after login"
    );
    info!("Session confirmed present in store immediately after login");

    // Step 5: Wait for the session to expire (1 s) and the collector to sweep (2 s),
    //         with an extra 2 s safety margin.
    info!("Waiting 5 seconds for the session to expire and be collected...");
    sleep(Duration::from_secs(5)).await;

    // Step 6: The collector must have physically removed the record.
    // Use admin_client (long-lived session) since the short-lived cookie
    // expired after 1 s and can no longer authenticate.
    let session_value_after = admin_client.get_session(&session_id).await?;
    assert!(
        session_value_after.is_none(),
        "Session must have been physically removed from the store by the collector"
    );
    info!("Session confirmed absent from store after collector sweep");

    ctx.stop_server().await
}

// ── Login with wrong / unknown credentials ────────────────────────────────────

/// Submitting a valid username but an incorrect password must return HTTP 401
/// and must NOT issue a session cookie.
#[actix_web::test]
async fn test_login_wrong_password_returns_401() -> AuthResult<()> {
    // init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let bad_scheme = AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: "this-is-definitely-the-wrong-password".to_string(),
    };
    let client = ctx.get_test_client(bad_scheme);

    let result = client.login(ADMIN_REALM, None, None).await;

    assert!(
        result.is_err(),
        "Expected login to fail with wrong password"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected HTTP 401 for wrong password, got: {msg}"
    );
    info!("Login with wrong password correctly returned 401");

    ctx.stop_server().await
}

/// Submitting a username that does not exist must return HTTP 401 and must NOT
/// leak whether the username exists (same response shape as wrong-password).
#[actix_web::test]
async fn test_login_unknown_username_returns_401() -> AuthResult<()> {
    // init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let unknown_scheme = AuthClientScheme::UsernamePassword {
        username: "user-that-does-not-exist".to_string(),
        password: "some-password".to_string(),
    };
    let client = ctx.get_test_client(unknown_scheme);

    let result = client.login(ADMIN_REALM, None, None).await;

    assert!(
        result.is_err(),
        "Expected login to fail for unknown username"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected HTTP 401 for unknown username, got: {msg}"
    );
    info!("Login with unknown username correctly returned 401");

    ctx.stop_server().await
}
