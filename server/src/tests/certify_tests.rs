//! Integration tests for `POST /certify` and `GET /.well-known/certificate-jwks.json`.
//!
//! Each test spins up a fresh in-memory server, authenticates as the seeded
//! `admin` user (realm `_`), and exercises the certificate issuance flow.

use crate::{
    AuthError, AuthResult, AuthenticationNextStep, Realm,
    client::AuthClientScheme,
    database::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME},
    models::{ADMIN_REALM, PasswordInput, UserPass},
    tests::{
        get_default_server_params, get_default_server_params_with_certify, helpers::test_realm,
        start_test_server,
    },
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use std::collections::HashMap;

/// Creates a username/password credential with the given `extra_claims` in `ADMIN_REALM`
/// (already username/password-enabled, since the seeded `admin` account logs in via it),
/// and returns an `AuthClientScheme` ready to log in as that new user.
async fn create_user_with_extra_claims(
    admin_client: &crate::client::AuthClient,
    username: &str,
    password: &str,
    extra_claims: HashMap<String, serde_json::Value>,
) -> AuthResult<AuthClientScheme> {
    let userpass = UserPass {
        realm: ADMIN_REALM.to_string(),
        username: username.to_string(),
        password_hash: String::new(),
        password_input: Some(PasswordInput::Plaintext(password.to_string())),
        change_password: false,
        roles: vec![],
        extra_claims: Some(extra_claims),
    };
    admin_client
        .create_admin_credentials_in_realm(ADMIN_REALM, &userpass)
        .await?;
    Ok(AuthClientScheme::UsernamePassword {
        username: username.to_string(),
        password: password.to_string(),
    })
}

/// Decodes a `/certify` certificate against the server's certificate signing key and
/// returns its claims as a raw JSON value, matching the style of the isolation test above.
fn decode_certificate_claims(certificate: &str) -> serde_json::Value {
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
    decode(certificate, &cert_decoding_key, &validation)
        .expect("certificate should validate against the certificate signing key")
        .claims
}

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

/// A `verification_key` longer than the accepted maximum must be rejected with 400.
#[actix_web::test]
async fn test_certify_rejects_oversized_verification_key() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params_with_certify()?).await?;
    let client = ctx.get_test_client(admin_scheme());
    client.login(ADMIN_REALM, None).await?;

    let oversized = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        "A".repeat(9000)
    );
    let body = serde_json::json!({ "verification_key": oversized });
    let err = client
        .post::<_, serde_json::Value>(&format!("/certify?realm={ADMIN_REALM}"), &body)
        .await
        .expect_err("certify should reject an oversized verification_key");

    assert!(
        matches!(err, AuthError::FailedHttpStatus(ref m) if m.contains("400")),
        "Expected 400, got: {err:?}"
    );

    ctx.stop_server().await
}

/// A `verification_key` that isn't PEM-shaped must be rejected with 400, rather than being
/// blindly trusted and embedded verbatim into a signed certificate.
#[actix_web::test]
async fn test_certify_rejects_non_pem_verification_key() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params_with_certify()?).await?;
    let client = ctx.get_test_client(admin_scheme());
    client.login(ADMIN_REALM, None).await?;

    let body = serde_json::json!({ "verification_key": "not-a-pem-key-at-all" });
    let err = client
        .post::<_, serde_json::Value>(&format!("/certify?realm={ADMIN_REALM}"), &body)
        .await
        .expect_err("certify should reject a non-PEM verification_key");

    assert!(
        matches!(err, AuthError::FailedHttpStatus(ref m) if m.contains("400")),
        "Expected 400, got: {err:?}"
    );

    ctx.stop_server().await
}

/// The certificate's `exp` must be computed from the session's own realm — never from the
/// `?realm=` query parameter, which a caller could set to a different, more permissive realm
/// while the certificate still (correctly) claims their real realm_id.
#[actix_web::test]
async fn test_certify_uses_session_realm_not_query_realm() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params_with_certify()?).await?;
    let client = ctx.get_test_client(admin_scheme());
    client.login(ADMIN_REALM, None).await?;

    // A realm with a deliberately short certificate TTL, distinct from ADMIN_REALM's.
    let other_realm_id = "certify-mismatch-realm";
    client
        .create_realm_as_super_admin(&Realm {
            certificate_max_age_seconds: 60,
            ..test_realm(other_realm_id)
        })
        .await?;

    // Still authenticated to ADMIN_REALM (`_`), but pass the other realm in the query string.
    let body = serde_json::json!({ "verification_key": SAMPLE_VERIFICATION_KEY });
    let response: serde_json::Value = client
        .post(&format!("/certify?realm={other_realm_id}"), &body)
        .await?;
    let certificate = response
        .get("certificate")
        .and_then(|v| v.as_str())
        .expect("certify response should contain a string 'certificate' field");

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    let cert_decoding_key = DecodingKey::from_ec_pem(
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/tests/certificates/ec/auth.user1.cert.pem"
        ))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    let claims: serde_json::Value = decode(certificate, &cert_decoding_key, &validation)
        .expect("certificate should validate against the certificate signing key")
        .claims;

    // realm_id claimed is the session's real realm, not the query-param realm.
    assert_eq!(claims["realm_id"], ADMIN_REALM);
    // The TTL used is ADMIN_REALM's (365 days), not other_realm's 60 seconds.
    let iat = claims["iat"].as_i64().expect("iat should be present");
    let exp = claims["exp"].as_i64().expect("exp should be present");
    assert_eq!(
        exp - iat,
        365 * 24 * 3600,
        "expected ADMIN_REALM's certificate TTL, not the query-param realm's"
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

/// `claims` only copies names that are both requested and actually present in the
/// session's own extra claims — nothing is copied by default, and requesting a claim
/// absent from the session is silently ignored rather than erroring.
#[actix_web::test]
async fn test_certify_copies_only_requested_and_present_extra_claims() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params_with_certify()?).await?;
    let admin_client = ctx.get_test_client(admin_scheme());
    admin_client.login(ADMIN_REALM, None).await?;

    let scheme = create_user_with_extra_claims(
        &admin_client,
        "certify-claims-user",
        "certify-claims-pw-1!",
        HashMap::from([("as_registrant".to_string(), serde_json::json!("acme-corp"))]),
    )
    .await?;
    let client = ctx.get_test_client(scheme);
    client.login(ADMIN_REALM, None).await?;

    // Request the present claim plus one that doesn't exist in the session.
    let body = serde_json::json!({
        "verification_key": SAMPLE_VERIFICATION_KEY,
        "claims": ["as_registrant", "does_not_exist"],
    });
    let response: serde_json::Value = client
        .post(&format!("/certify?realm={ADMIN_REALM}"), &body)
        .await?;
    let certificate = response
        .get("certificate")
        .and_then(|v| v.as_str())
        .expect("certify response should contain a string 'certificate' field");
    let claims = decode_certificate_claims(certificate);

    assert_eq!(claims["sub"], "certify-claims-user");
    assert_eq!(claims["as_registrant"], "acme-corp");
    assert!(
        claims.get("does_not_exist").is_none(),
        "a requested-but-absent claim must not appear in the certificate: {claims:?}"
    );

    ctx.stop_server().await
}

/// `exclude_sub: true` is only honored when the requested/present intersection of `claims`
/// actually yields something — a certificate must identify its holder by at least one claim,
/// so a session with no extra claims at all must be rejected with 400.
#[actix_web::test]
async fn test_certify_exclude_sub_rejected_without_a_present_claim() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params_with_certify()?).await?;
    let client = ctx.get_test_client(admin_scheme());
    client.login(ADMIN_REALM, None).await?;

    let body = serde_json::json!({
        "verification_key": SAMPLE_VERIFICATION_KEY,
        "exclude_sub": true,
    });
    let err = client
        .post::<_, serde_json::Value>(&format!("/certify?realm={ADMIN_REALM}"), &body)
        .await
        .expect_err("exclude_sub without any present claim must be rejected");

    assert!(
        matches!(err, AuthError::FailedHttpStatus(ref m) if m.contains("400")),
        "Expected 400, got: {err:?}"
    );

    ctx.stop_server().await
}

/// `exclude_sub: true` together with a requested claim that IS present in the session
/// produces a certificate carrying that claim but no `sub`.
#[actix_web::test]
async fn test_certify_exclude_sub_omits_subject_when_claim_present() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params_with_certify()?).await?;
    let admin_client = ctx.get_test_client(admin_scheme());
    admin_client.login(ADMIN_REALM, None).await?;

    let scheme = create_user_with_extra_claims(
        &admin_client,
        "certify-exclude-sub-user",
        "certify-exclude-sub-pw-1!",
        HashMap::from([("as_registrant".to_string(), serde_json::json!("acme-corp"))]),
    )
    .await?;
    let client = ctx.get_test_client(scheme);
    client.login(ADMIN_REALM, None).await?;

    let body = serde_json::json!({
        "verification_key": SAMPLE_VERIFICATION_KEY,
        "claims": ["as_registrant"],
        "exclude_sub": true,
    });
    let response: serde_json::Value = client
        .post(&format!("/certify?realm={ADMIN_REALM}"), &body)
        .await?;
    let certificate = response
        .get("certificate")
        .and_then(|v| v.as_str())
        .expect("certify response should contain a string 'certificate' field");
    let claims = decode_certificate_claims(certificate);

    assert!(
        claims.get("sub").is_none(),
        "sub must be absent when exclude_sub was requested and honored: {claims:?}"
    );
    assert_eq!(claims["as_registrant"], "acme-corp");
    assert_eq!(claims["realm_id"], ADMIN_REALM);

    ctx.stop_server().await
}

/// Requesting a reserved claim name via `claims` must be rejected with 400, even though it
/// would just intersect to nothing against the session's own extra claims otherwise — this is
/// defense in depth against a row provisioned before enrollment validated `extra_claims`.
#[actix_web::test]
async fn test_certify_rejects_reserved_claim_name_in_claims() -> AuthResult<()> {
    let ctx = start_test_server(get_default_server_params_with_certify()?).await?;
    let client = ctx.get_test_client(admin_scheme());
    client.login(ADMIN_REALM, None).await?;

    let body = serde_json::json!({
        "verification_key": SAMPLE_VERIFICATION_KEY,
        "claims": ["auth_scheme"],
    });
    let err = client
        .post::<_, serde_json::Value>(&format!("/certify?realm={ADMIN_REALM}"), &body)
        .await
        .expect_err("a reserved claim name in 'claims' must be rejected");

    assert!(
        matches!(err, AuthError::FailedHttpStatus(ref m) if m.contains("400")),
        "Expected 400, got: {err:?}"
    );

    ctx.stop_server().await
}
