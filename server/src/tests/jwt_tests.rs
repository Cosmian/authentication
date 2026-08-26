//! JWT Authentication Integration Tests
//!
//! Verifies that the JWT authentication middleware correctly accepts and
//! rejects tokens through the `/login` endpoint.
//!
//! ## Test setup
//!
//! Each test starts a fresh in-memory server and, where necessary, creates a
//! dedicated realm configured with JWT auth params that point to the test
//! server's own `/public/jwks` endpoint (registered in test mode only).
//! Tokens are issued by [`RsaIdp`] using the same key pair that backs the
//! JWKS endpoint.
//!
//! ## Test Coverage
//!
//! - **Valid JWT token**: login succeeds, session cookie is issued, `whoami`
//!   returns the expected username.
//! - **No token**: login without any credentials is rejected with HTTP 401.
//! - **Malformed token**: a garbage Bearer value is rejected with HTTP 401.
//! - **Wrong audience**: a valid JWT whose `aud` claim does not match the
//!   realm configuration is rejected with HTTP 401.
//! - **Expired token**: a token whose `exp` has passed is rejected.
//! - **Token reuse**: the same JWT can be used to open multiple sessions.
//! - **Multiple users**: different users authenticate independently and
//!   `whoami` correctly reflects each identity.
//! - **Session persistence**: after a JWT login the resulting session cookie
//!   is accepted by `whoami` without re-sending the JWT.
//! - **Missing Bearer prefix**: a raw token without the `Bearer ` scheme is
//!   rejected with HTTP 401.

use crate::{
    AuthError, AuthResult, AuthenticationNextStep, IdpParams, JwtParams, LoginRequest, Realm,
    RealmAuthParams,
    client::AuthClientScheme,
    database::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME},
    models::ADMIN_REALM,
    tests::{IdP, RsaIdp, start_default_test_server},
};
use cosmian_logger::info;

/// Realm used for all JWT tests.
const TEST_JWT_REALM: &str = "jwt_test_realm";

/// Issuer URI that matches the hardcoded value in the test server's dummy
/// [`RsaIdp`] (see `auth_verifier.rs`, `#[cfg(test)]` block).
const TEST_JWT_ISSUER: &str = "test_auth_issuer";

/// Audience expected by the test realm.
const TEST_JWT_AUDIENCE: &str = "test-audience";

// ── helpers ──────────────────────────────────────────────────────────────────

/// Log in as the pre-seeded admin, create [`TEST_JWT_REALM`] configured with
/// JWT auth params pointing to the test server JWKS endpoint, then return.
async fn setup_jwt_realm(ctx: &crate::tests::TestsContext) -> AuthResult<()> {
    let admin_client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });
    admin_client.login(ADMIN_REALM, None).await?;

    admin_client
        .create_realm(&Realm {
            id: TEST_JWT_REALM.to_string(),
            auth_params: RealmAuthParams {
                jwt_params: Some(JwtParams {
                    idp_params: vec![IdpParams {
                        jwt_issuer_uri: TEST_JWT_ISSUER.to_string(),
                        // Test-only JWKS endpoint registered by the server in test mode.
                        jwks_uri: format!("{}/public/jwks", ctx.get_client_url()),
                        jwt_audience: Some(TEST_JWT_AUDIENCE.to_string()),
                    }],
                    // 0 = fetch JWKS immediately on first use
                    smallest_refresh_interval_seconds: Some(0),
                }),
                ..Default::default()
            },
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
            certificate_max_age_seconds: 365 * 24 * 3600,
        })
        .await
}

/// Issue a valid JWT for `email` signed by the test RsaIdp.
fn make_jwt_token(email: &str) -> AuthResult<String> {
    RsaIdp::new(TEST_JWT_ISSUER)?.issue_token(email, TEST_JWT_AUDIENCE, 3600)
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// A valid JWT token allows login; a session cookie is issued and `whoami`
/// returns the correct username.
#[tokio::test]
async fn test_jwt_auth_valid_token() -> Result<(), AuthError> {
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    setup_jwt_realm(&ctx).await?;

    let username = "user@example.com";
    let token = make_jwt_token(username)?;
    let client = ctx.get_test_client(AuthClientScheme::Jwt { token });

    info!("Logging in with a valid JWT token...");
    let (result, cookie) = client.login(TEST_JWT_REALM, None).await?;

    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated next step"
    );
    assert!(
        result.session_id.is_some(),
        "Expected a session_id in the login response"
    );
    assert!(
        cookie.is_some(),
        "Expected a session cookie after JWT login"
    );
    assert_eq!(
        cookie.unwrap().name(),
        "_ea_",
        "Expected session cookie name '_ea_'"
    );

    info!("Verifying identity via whoami...");
    let claims = client.whoami(TEST_JWT_REALM).await?;
    assert_eq!(
        claims.registered.sub.as_deref(),
        Some(username),
        "whoami should return the JWT subject as the username"
    );

    info!("Stopping test server...");
    ctx.stop_server().await
}

/// A request without any authentication is rejected with HTTP 401.
#[tokio::test]
async fn test_jwt_auth_no_token() -> Result<(), AuthError> {
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    setup_jwt_realm(&ctx).await?;

    let none_client = ctx.get_test_client(AuthClientScheme::None);

    info!("Attempting login without a token (should fail)...");
    let result = none_client.login(TEST_JWT_REALM, None).await;

    assert!(
        matches!(result, Err(AuthError::FailedHttpStatus(ref m)) if m.contains("401")),
        "Expected HTTP 401 for unauthenticated login, got: {:?}",
        result
    );

    info!("Stopping test server...");
    ctx.stop_server().await
}

/// A malformed Bearer value (not a valid JWT) is rejected with HTTP 401.
#[tokio::test]
async fn test_jwt_auth_malformed_token() -> Result<(), AuthError> {
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    setup_jwt_realm(&ctx).await?;

    let client = ctx.get_test_client(AuthClientScheme::Jwt {
        token: "not-a-valid-jwt-token".to_string(),
    });

    info!("Attempting login with a malformed JWT token (should fail)...");
    let result = client.login(TEST_JWT_REALM, None).await;

    assert!(
        matches!(result, Err(AuthError::FailedHttpStatus(ref m)) if m.contains("401")),
        "Expected HTTP 401 for malformed JWT, got: {:?}",
        result
    );

    info!("Stopping test server...");
    ctx.stop_server().await
}

/// A JWT whose `aud` claim does not match the realm configuration is rejected.
#[tokio::test]
async fn test_jwt_auth_wrong_audience() -> Result<(), AuthError> {
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    setup_jwt_realm(&ctx).await?;

    // Issue a token with the wrong audience.
    let token = RsaIdp::new(TEST_JWT_ISSUER)?.issue_token(
        "user@example.com",
        "wrong-audience", // does not match TEST_JWT_AUDIENCE
        3600,
    )?;
    let client = ctx.get_test_client(AuthClientScheme::Jwt { token });

    info!("Attempting login with wrong audience in JWT (should fail)...");
    let result = client.login(TEST_JWT_REALM, None).await;

    assert!(
        matches!(result, Err(AuthError::FailedHttpStatus(ref m)) if m.contains("401")),
        "Expected HTTP 401 for wrong audience, got: {:?}",
        result
    );

    info!("Stopping test server...");
    ctx.stop_server().await
}

/// An expired JWT is rejected with HTTP 401.
#[tokio::test]
async fn test_jwt_auth_expired_token() -> Result<(), AuthError> {
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    setup_jwt_realm(&ctx).await?;

    // Issue a token whose `exp` is set to Unix epoch + 1 s — so far in the
    // past that no validation leeway can rescue it.
    let token = RsaIdp::new(TEST_JWT_ISSUER)?
        .issue_definitely_expired_token("user@example.com", TEST_JWT_AUDIENCE)?;

    let client = ctx.get_test_client(AuthClientScheme::Jwt { token });

    info!("Attempting login with a definitely-expired JWT (should fail)...");
    let result = client.login(TEST_JWT_REALM, None).await;

    assert!(
        matches!(result, Err(AuthError::FailedHttpStatus(ref m)) if m.contains("401")),
        "Expected HTTP 401 for expired JWT, got: {:?}",
        result
    );

    info!("Stopping test server...");
    ctx.stop_server().await
}

/// The same JWT token can be used to open several independent sessions.
#[tokio::test]
async fn test_jwt_auth_multiple_requests_same_token() -> Result<(), AuthError> {
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    setup_jwt_realm(&ctx).await?;

    let username = "user@example.com";
    let token = make_jwt_token(username)?;
    let client = ctx.get_test_client(AuthClientScheme::Jwt { token });

    info!("Logging in three times with the same JWT token...");
    for i in 1..=3u8 {
        let (result, _) = client.login(TEST_JWT_REALM, None).await?;
        assert!(
            matches!(result.next_step, AuthenticationNextStep::Authenticated),
            "Login attempt {} must succeed",
            i
        );
    }

    info!("All three logins with the same token succeeded.");
    info!("Stopping test server...");
    ctx.stop_server().await
}

/// Different users can independently authenticate with their own JWTs.
#[tokio::test]
async fn test_jwt_auth_different_users() -> Result<(), AuthError> {
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    setup_jwt_realm(&ctx).await?;

    let users = [
        "alice@example.com",
        "bob@example.com",
        "charlie@example.com",
    ];

    for username in users {
        info!("Testing JWT authentication for: {username}");

        let token = make_jwt_token(username)?;
        let client = ctx.get_test_client(AuthClientScheme::Jwt { token });

        let (result, _) = client.login(TEST_JWT_REALM, None).await?;
        assert!(
            matches!(result.next_step, AuthenticationNextStep::Authenticated),
            "Login should succeed for {username}"
        );

        let claims = client.whoami(TEST_JWT_REALM).await?;
        assert_eq!(
            claims.registered.sub.as_deref(),
            Some(username),
            "whoami should identify {username}"
        );
    }

    info!("Stopping test server...");
    ctx.stop_server().await
}

/// After JWT login the session cookie is stored in the client jar; `whoami`
/// uses that cookie and does not need the JWT header to be re-sent.
#[tokio::test]
async fn test_jwt_auth_session_persistence() -> Result<(), AuthError> {
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    setup_jwt_realm(&ctx).await?;

    let username = "user@example.com";
    let token = make_jwt_token(username)?;
    let client = ctx.get_test_client(AuthClientScheme::Jwt { token });

    info!("First request — login via JWT (creates session cookie)...");
    let (_, cookie) = client.login(TEST_JWT_REALM, None).await?;
    assert!(
        cookie.is_some(),
        "Session cookie should be set after JWT login"
    );

    info!("Second request — whoami using the session cookie...");
    let claims = client.whoami(TEST_JWT_REALM).await?;
    assert_eq!(
        claims.registered.sub.as_deref(),
        Some(username),
        "whoami should return the same username after session cookie is stored"
    );

    info!("Stopping test server...");
    ctx.stop_server().await
}

/// A raw JWT token sent without the `Bearer ` prefix is rejected with HTTP 401.
#[tokio::test]
async fn test_jwt_auth_without_bearer_prefix() -> Result<(), AuthError> {
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    setup_jwt_realm(&ctx).await?;

    // A syntactically valid token, but sent without the required "Bearer " prefix.
    let token =
        RsaIdp::new(TEST_JWT_ISSUER)?.issue_token("user@example.com", TEST_JWT_AUDIENCE, 3600)?;

    // Use a None-auth client so no default Authorization header is added.
    let base_client = ctx.get_test_client(AuthClientScheme::None);

    info!("POSTing to login with token but without 'Bearer ' prefix (should fail)...");
    let response = base_client
        .post_raw_with_header(
            &format!("/login?realm={TEST_JWT_REALM}"),
            &LoginRequest { totp_code: None },
            "Authorization",
            &token, // raw token, no "Bearer " prefix
        )
        .await?;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Expected HTTP 401 when 'Bearer ' prefix is absent, got {}",
        response.status()
    );

    info!("Stopping test server...");
    ctx.stop_server().await
}
