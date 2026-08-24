//! Integration tests for `POST /certify` and `GET /.well-known/certificate-jwks.json`.
//!
//! Each test spins up a fresh in-memory server, authenticates as the seeded
//! `admin` user (realm `_`), and exercises the certificate issuance flow.

use crate::{
    AuthError, AuthResult, AuthenticationNextStep,
    client::AuthClientScheme,
    database::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME},
    models::ADMIN_REALM,
    tests::{get_default_server_params, get_default_server_params_with_certify, start_test_server},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

fn admin_scheme() -> AuthClientScheme {
    AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    }
}

const SAMPLE_VERIFICATION_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----";

/// A verification key certified while authenticated must be signed with the server's
/// dedicated certificate key (ES256), carry the caller's own identity — never taken from
/// the request body — and must be cryptographically rejected by the session-token validator
/// (proving certificates and session JWTs are isolated).
#[actix_web::test]
async fn test_certify_returns_isolated_certificate() -> AuthResult<()> {
    let params = get_default_server_params_with_certify()?;
    let session_decoding_key = params.get_jwt_decoding_key()?;
    let ctx = start_test_server(params).await?;
    let client = ctx.get_test_client(admin_scheme());

    let (result, _cookie) = client.login(ADMIN_REALM, None).await?;
    assert!(matches!(
        result.next_step,
        AuthenticationNextStep::Authenticated
    ));

    let body = serde_json::json!({ "verification_key": SAMPLE_VERIFICATION_KEY });
    let response: serde_json::Value = client
        .post(&format!("/certify?realm={ADMIN_REALM}"), &body)
        .await?;
    let certificate = response
        .get("certificate")
        .and_then(|v| v.as_str())
        .expect("certify response should contain a string 'certificate' field");

    let header = decode_header(certificate).expect("certificate should have a valid JWT header");
    assert_eq!(header.alg, Algorithm::ES256);

    // The certificate signing key (auth.user1) must successfully validate it, and the
    // claims must identify the authenticated caller — not anything from the request body.
    let cert_decoding_key = DecodingKey::from_ec_pem(
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/tests/certificates/ec/auth.user1.cert.pem"
        ))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;
    let claims: serde_json::Value = decode(certificate, &cert_decoding_key, &validation)
        .expect("certificate should validate against the certificate signing key")
        .claims;
    assert_eq!(claims["sub"], "admin");
    assert_eq!(claims["realm_id"], ADMIN_REALM);
    assert_eq!(claims["auth_scheme"], "up");
    assert_eq!(claims["verification_key"], SAMPLE_VERIFICATION_KEY);

    // Isolation: the very same token must NOT validate against the session JWT's own
    // decoding key — it was signed with a different key entirely.
    let mut session_validation = Validation::new(Algorithm::ES256);
    session_validation.validate_exp = true;
    let isolation_result =
        decode::<serde_json::Value>(certificate, &session_decoding_key, &session_validation);
    assert!(
        isolation_result.is_err(),
        "a certificate must never validate against the session JWT decoding key"
    );

    ctx.stop_server().await
}

/// `POST /certify` must require an authenticated session, exactly like `/whoami`.
#[actix_web::test]
async fn test_certify_requires_session() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params_with_certify()?).await?;
    let unauthenticated_client = ctx.get_test_client(AuthClientScheme::None);

    let body = serde_json::json!({ "verification_key": SAMPLE_VERIFICATION_KEY });
    let err = unauthenticated_client
        .post::<_, serde_json::Value>(&format!("/certify?realm={ADMIN_REALM}"), &body)
        .await
        .expect_err("certify should fail without a session cookie");

    assert!(
        matches!(err, AuthError::FailedHttpStatus(ref m) if m.contains("401")),
        "Expected 401, got: {err:?}"
    );

    ctx.stop_server().await
}

/// An empty `verification_key` must be rejected with 400.
#[actix_web::test]
async fn test_certify_rejects_empty_verification_key() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params_with_certify()?).await?;
    let client = ctx.get_test_client(admin_scheme());
    client.login(ADMIN_REALM, None).await?;

    let body = serde_json::json!({ "verification_key": "" });
    let err = client
        .post::<_, serde_json::Value>(&format!("/certify?realm={ADMIN_REALM}"), &body)
        .await
        .expect_err("certify should reject an empty verification_key");

    assert!(
        matches!(err, AuthError::FailedHttpStatus(ref m) if m.contains("400")),
        "Expected 400, got: {err:?}"
    );

    ctx.stop_server().await
}

/// When the server has no `certificate_jwt_params` configured, `/certify` must fail closed
/// with 500 rather than silently signing with an unintended key.
#[actix_web::test]
async fn test_certify_without_configured_key_fails() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params()?).await?;
    let client = ctx.get_test_client(admin_scheme());
    client.login(ADMIN_REALM, None).await?;

    let body = serde_json::json!({ "verification_key": SAMPLE_VERIFICATION_KEY });
    let err = client
        .post::<_, serde_json::Value>(&format!("/certify?realm={ADMIN_REALM}"), &body)
        .await
        .expect_err("certify should fail when certificate signing is not configured");

    assert!(
        matches!(err, AuthError::FailedHttpStatus(ref m) if m.contains("500")),
        "Expected 500, got: {err:?}"
    );

    ctx.stop_server().await
}

/// The certificate JWKS document is only served when certificate signing is configured.
#[actix_web::test]
async fn test_certificate_jwks_availability() -> AuthResult<()> {
    let configured_ctx = start_test_server(get_default_server_params_with_certify()?).await?;
    let configured_client = configured_ctx.get_test_client(AuthClientScheme::None);
    let jwks: serde_json::Value = configured_client
        .get("/.well-known/certificate-jwks.json")
        .await?;
    assert!(
        jwks.get("keys")
            .and_then(|k| k.as_array())
            .is_some_and(|a| !a.is_empty()),
        "expected a non-empty keys array, got: {jwks:?}"
    );
    configured_ctx.stop_server().await?;

    let unconfigured_ctx = start_test_server(get_default_server_params()?).await?;
    let unconfigured_client = unconfigured_ctx.get_test_client(AuthClientScheme::None);
    let err = unconfigured_client
        .get::<serde_json::Value>("/.well-known/certificate-jwks.json")
        .await
        .expect_err("certificate JWKS should 404 when unconfigured");
    assert!(
        matches!(err, AuthError::FailedHttpStatus(ref m) if m.contains("404")),
        "Expected 404, got: {err:?}"
    );

    unconfigured_ctx.stop_server().await
}
