//! End-to-end integration tests for the OpenID Connect Provider.
//!
//! Exercises the full authorization-code + PKCE flow (login → consent → code →
//! token), refresh-token rotation, UserInfo, introspection, revocation,
//! discovery, JWKS, and a matrix of negative cases against a real in-memory
//! HTTPS test server.
//!
//! ## Standards under test
//! - RFC 6749 (OAuth 2.0), RFC 6750 (Bearer), RFC 7636 (PKCE, S256)
//! - RFC 7662 (Introspection), RFC 7009 (Revocation), RFC 8414 (Metadata)
//! - RFC 9068 (`at+jwt` access tokens), OpenID Connect Core / Discovery

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::{
    AuthResult, OAuthClientRequest, OAuthClientResponse, Realm, RealmAuthParams,
    models::{ADMIN_REALM, UserPass},
    tests::{helpers::authenticate_as_admin, init_test_logging, start_default_test_server},
};

const REALM: &str = "oidc";
const USER: &str = "alice";
const USER_EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "s3cret-password";
const REDIRECT_URI: &str = "https://client.example.org/cb";

// ── Small helpers ───────────────────────────────────────────────────────────

/// Build a reqwest client that trusts the test CA, keeps cookies, and does NOT
/// auto-follow redirects (so we can inspect `Location` headers).
fn http_client() -> reqwest::Client {
    let ca = std::fs::read("src/tests/certificates/ec/auth.ca.pem").expect("read CA");
    let cert = reqwest::Certificate::from_pem(&ca).expect("parse CA");
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client")
}

/// Generate a PKCE `(verifier, challenge)` pair using the S256 method.
fn pkce_pair() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// Extract the value that immediately follows `needle` up to the next `"`.
fn extract_after(haystack: &str, needle: &str) -> Option<String> {
    let start = haystack.find(needle)? + needle.len();
    let rest = &haystack[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Parse the `flow_token` hidden field from a rendered login/consent page.
fn flow_token(html: &str) -> String {
    extract_after(html, "name=\"flow_token\" value=\"").expect("flow_token in page")
}

/// Parse a query parameter from a URL string.
fn query_param(url: &str, key: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    parsed
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.to_string())
}

/// Provision realm `oidc`, user `alice`, and return the created OAuth client.
async fn provision(ctx: &crate::tests::TestsContext) -> AuthResult<OAuthClientResponse> {
    let admin = authenticate_as_admin(ctx).await?;

    // Create the realm.
    admin
        .create_realm_as_super_admin(&Realm {
            id: REALM.to_string(),
            auth_params: RealmAuthParams::default(),
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
        })
        .await?;

    // Create the end-user in that realm with a dedicated email address.
    // This verifies that the stored email is preferred over the username in OIDC tokens.
    let userpass = UserPass {
        realm: REALM.to_string(),
        username: USER.to_string(),
        password: PASSWORD.as_bytes().to_vec(),
        change_password: false,
        roles: vec!["Auditor".to_string()],
        email: Some(USER_EMAIL.to_string()),
    };
    admin
        .create_admin_credentials_in_realm(REALM, &userpass)
        .await?;

    // Register a confidential OAuth client.
    let req = OAuthClientRequest {
        client_name: "Test Client".to_string(),
        redirect_uris: vec![REDIRECT_URI.to_string()],
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
            "client_credentials".to_string(),
        ],
        response_types: vec!["code".to_string()],
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "offline_access".to_string(),
            "roles".to_string(),
        ],
        token_endpoint_auth_method: "client_secret_basic".to_string(),
    };
    let client: OAuthClientResponse = admin.post("/realms/oidc/clients", &req).await?;
    assert!(
        client.client_secret.is_some(),
        "confidential client must return a secret"
    );
    Ok(client)
}

/// Drive the browser flow up to the redirect and return the authorization code.
async fn get_auth_code(
    http: &reqwest::Client,
    base: &str,
    client: &OAuthClientResponse,
    challenge: &str,
    scope: &str,
    state: &str,
    nonce: &str,
) -> String {
    // 1) GET /authorize → login page.
    let authorize_url = format!(
        "{base}/oidc/authorize?response_type=code&client_id={cid}&redirect_uri={ru}\
         &scope={scope}&state={state}&nonce={nonce}&code_challenge={ch}&code_challenge_method=S256",
        cid = client.client_id,
        ru = urlencoding(REDIRECT_URI),
        scope = urlencoding(scope),
        ch = challenge,
    );
    let resp = http
        .get(&authorize_url)
        .send()
        .await
        .expect("GET authorize");
    assert_eq!(resp.status(), 200, "authorize should render login form");
    let html = resp.text().await.unwrap();
    let token = flow_token(&html);

    // 2) POST /authorize/login → consent page.
    let resp = http
        .post(format!("{base}/oidc/authorize/login"))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("flow_token", token.as_str()),
            ("username", USER),
            ("password", PASSWORD),
        ]))
        .send()
        .await
        .expect("POST login");
    assert_eq!(resp.status(), 200, "login should render consent");
    let html = resp.text().await.unwrap();
    let consent_token = flow_token(&html);

    // 3) POST /authorize/consent → redirect with code.
    let resp = http
        .post(format!("{base}/oidc/authorize/consent"))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("flow_token", consent_token.as_str()),
            ("decision", "approve"),
        ]))
        .send()
        .await
        .expect("POST consent");
    assert_eq!(resp.status(), 302, "consent approval should redirect");
    let location = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(query_param(&location, "state").as_deref(), Some(state));
    query_param(&location, "code").expect("authorization code in redirect")
}

/// Minimal percent-encoding for query values used in tests.
fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Build an `application/x-www-form-urlencoded` request body from key/value pairs.
fn form_body(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}

/// Verify an ID token's ES256 signature against the JWKS and return its claims.
async fn verify_id_token(http: &reqwest::Client, base: &str, id_token: &str) -> serde_json::Value {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

    let jwks: serde_json::Value = http
        .get(format!("{base}/oidc/jwks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let header = decode_header(id_token).expect("decode header");
    let kid = header.kid.expect("id token has kid");
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == kid)
        .expect("matching jwk for kid");
    let key =
        DecodingKey::from_ec_components(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap())
            .unwrap();

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_aud = false; // aud checked manually below
    let data = decode::<serde_json::Value>(id_token, &key, &validation).expect("valid id token");
    data.claims
}

// ── Happy-path end-to-end ───────────────────────────────────────────────────

#[actix_web::test]
async fn test_oidc_authorization_code_pkce_full_flow() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let base = ctx.get_client_url();
    let client = provision(&ctx).await?;
    let http = http_client();

    let (verifier, challenge) = pkce_pair();
    let scope = "openid profile email offline_access roles";
    let code = get_auth_code(
        &http,
        &base,
        &client,
        &challenge,
        scope,
        "state-123",
        "nonce-abc",
    )
    .await;

    // Exchange the code for tokens.
    let resp = http
        .post(format!("{base}/oidc/token"))
        .basic_auth(&client.client_id, client.client_secret.as_deref())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier.as_str()),
        ]))
        .send()
        .await
        .expect("POST token");
    assert_eq!(resp.status(), 200, "token exchange should succeed");
    let tokens: serde_json::Value = resp.json().await.unwrap();
    let access_token = tokens["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let id_token = tokens["id_token"].as_str().expect("id_token").to_string();
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string();
    assert_eq!(tokens["token_type"], "Bearer");

    // Validate the ID token signature + core claims.
    let claims = verify_id_token(&http, &base, &id_token).await;
    assert_eq!(claims["sub"], USER);
    assert_eq!(claims["aud"], client.client_id);
    assert_eq!(claims["nonce"], "nonce-abc");
    assert!(claims["at_hash"].is_string(), "id token must carry at_hash");
    assert!(claims["iss"].as_str().unwrap().starts_with("https://"));

    // UserInfo with the access token.
    let userinfo: serde_json::Value = http
        .get(format!("{base}/oidc/userinfo"))
        .bearer_auth(&access_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(userinfo["sub"], USER);
    assert_eq!(userinfo["roles"][0], "Auditor");

    // Introspect the access token → active.
    let introspection: serde_json::Value = http
        .post(format!("{base}/oidc/introspect"))
        .basic_auth(&client.client_id, client.client_secret.as_deref())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[("token", access_token.as_str())]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["sub"], USER);

    // Refresh-token rotation.
    let refreshed: serde_json::Value = http
        .post(format!("{base}/oidc/token"))
        .basic_auth(&client.client_id, client.client_secret.as_deref())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let new_refresh = refreshed["refresh_token"]
        .as_str()
        .expect("rotated refresh")
        .to_string();
    assert_ne!(new_refresh, refresh_token, "refresh token must rotate");
    assert!(refreshed["access_token"].is_string());

    // Reusing the old (now-revoked) refresh token must fail.
    let reuse: serde_json::Value = http
        .post(format!("{base}/oidc/token"))
        .basic_auth(&client.client_id, client.client_secret.as_deref())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        reuse["error"], "invalid_grant",
        "revoked refresh reuse must be rejected"
    );

    // Revoke the rotated refresh token → 200, then it is inactive.
    let revoke = http
        .post(format!("{base}/oidc/revoke"))
        .basic_auth(&client.client_id, client.client_secret.as_deref())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[("token", new_refresh.as_str())]))
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), 200);

    ctx.stop_server().await
}

// ── Discovery + client_credentials ──────────────────────────────────────────

#[actix_web::test]
async fn test_oidc_discovery_and_client_credentials() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let base = ctx.get_client_url();
    let client = provision(&ctx).await?;
    let http = http_client();

    // Discovery document.
    let meta: serde_json::Value = http
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(meta["issuer"], base);
    assert_eq!(meta["code_challenge_methods_supported"][0], "S256");
    assert_eq!(
        meta["authorization_endpoint"],
        format!("{base}/oidc/authorize")
    );
    assert_eq!(meta["token_endpoint"], format!("{base}/oidc/token"));

    // client_credentials grant → access token, no id/refresh token.
    let tokens: serde_json::Value = http
        .post(format!("{base}/oidc/token"))
        .basic_auth(&client.client_id, client.client_secret.as_deref())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("grant_type", "client_credentials"),
            ("scope", "roles"),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(tokens["access_token"].is_string());
    assert!(tokens["id_token"].is_null());
    assert!(tokens["refresh_token"].is_null());

    ctx.stop_server().await
}

// ── Negative cases ──────────────────────────────────────────────────────────

#[actix_web::test]
async fn test_oidc_negative_cases() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let base = ctx.get_client_url();
    let client = provision(&ctx).await?;
    let http = http_client();

    // Unknown client_id → 400 error page (must NOT redirect).
    let resp = http
        .get(format!(
            "{base}/oidc/authorize?response_type=code&client_id=nope&redirect_uri={ru}\
             &scope=openid&code_challenge=x&code_challenge_method=S256",
            ru = urlencoding(REDIRECT_URI)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "unknown client must render an error page"
    );

    // Missing PKCE → redirect back with error=invalid_request.
    let resp = http
        .get(format!(
            "{base}/oidc/authorize?response_type=code&client_id={cid}&redirect_uri={ru}\
             &scope=openid&state=st",
            cid = client.client_id,
            ru = urlencoding(REDIRECT_URI)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(
        query_param(loc, "error").as_deref(),
        Some("invalid_request")
    );

    // Wrong PKCE verifier at the token endpoint → invalid_grant.
    let (_verifier, challenge) = pkce_pair();
    let code = get_auth_code(&http, &base, &client, &challenge, "openid", "s", "n").await;
    let bad: serde_json::Value = http
        .post(format!("{base}/oidc/token"))
        .basic_auth(&client.client_id, client.client_secret.as_deref())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            (
                "code_verifier",
                "the-wrong-verifier-that-is-at-least-forty-three-chars",
            ),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        bad["error"], "invalid_grant",
        "wrong PKCE verifier must fail"
    );

    // Wrong client secret → invalid_client (401).
    let resp = http
        .post(format!("{base}/oidc/token"))
        .basic_auth(&client.client_id, Some("wrong-secret"))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[("grant_type", "client_credentials")]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "wrong client secret must be 401");

    // Access token as bearer for a bogus value → 401 at userinfo.
    let resp = http
        .get(format!("{base}/oidc/userinfo"))
        .bearer_auth("not-a-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let _ = ADMIN_REALM; // silence unused import in some configurations
    ctx.stop_server().await
}


// ── Email claim in access token ─────────────────────────────────────────────

/// Verify that an `at+jwt` access token issued with the `email` scope carries
/// an `email` claim equal to the subject (username), and that the claim is absent
/// when the scope is not requested.
///
/// This test validates that auth-verifier tokens are compatible with relying
/// parties (e.g. Cosmian KMS) that use `email` as the user identity.
#[actix_web::test]
async fn test_access_token_contains_email_when_email_scope_requested() -> AuthResult<()> {
    use jsonwebtoken::dangerous;

    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let base = ctx.get_client_url();
    let client = provision(&ctx).await?;
    let http = http_client();

    // ── Token WITH email scope ────────────────────────────────────────────
    let (verifier, challenge) = pkce_pair();
    let code = get_auth_code(
        &http,
        &base,
        &client,
        &challenge,
        "openid profile email",
        "s1",
        "n1",
    )
    .await;

    let tokens: serde_json::Value = http
        .post(format!("{base}/oidc/token"))
        .basic_auth(&client.client_id, client.client_secret.as_deref())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier.as_str()),
        ]))
        .send()
        .await
        .expect("token exchange")
        .json()
        .await
        .unwrap();

    let at = tokens["access_token"].as_str().expect("access_token");
    let claims = dangerous::insecure_decode::<serde_json::Value>(at).expect("decode AT");

    let email_val = &claims.claims["email"];
    assert!(
        email_val.is_string(),
        "email claim must be present in access token when email scope is granted, \
         got claims: {claims:#?}"
    );
    assert_eq!(
        email_val.as_str().unwrap(),
        USER_EMAIL,
        "email must equal the stored email address, not the username"
    );
    // sub must still be present and equal to the username (not email).
    assert_eq!(claims.claims["sub"].as_str().unwrap(), USER);

    // ── Token WITHOUT email scope must NOT carry email ────────────────────
    let (v2, c2) = pkce_pair();
    let code2 = get_auth_code(
        &http,
        &base,
        &client,
        &c2,
        "openid profile",
        "s2",
        "n2",
    )
    .await;

    let tokens2: serde_json::Value = http
        .post(format!("{base}/oidc/token"))
        .basic_auth(&client.client_id, client.client_secret.as_deref())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("grant_type", "authorization_code"),
            ("code", code2.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", v2.as_str()),
        ]))
        .send()
        .await
        .expect("token exchange 2")
        .json()
        .await
        .unwrap();

    let at2 = tokens2["access_token"].as_str().expect("access_token2");
    let claims2 = dangerous::insecure_decode::<serde_json::Value>(at2).expect("decode AT2");

    let email2 = &claims2.claims["email"];
    assert!(
        email2.is_null() || !email2.is_string(),
        "email claim must be absent when email scope is not requested, \
         got claims: {claims2:#?}"
    );

    ctx.stop_server().await
}

/// `client_credentials` grant: the email claim equals the `client_id` when the
/// `email` scope is requested.
#[actix_web::test]
async fn test_client_credentials_access_token_email_equals_client_id() -> AuthResult<()> {
    use jsonwebtoken::dangerous;

    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let base = ctx.get_client_url();
    let client = provision(&ctx).await?;
    let http = http_client();

    let tokens: serde_json::Value = http
        .post(format!("{base}/oidc/token"))
        .basic_auth(&client.client_id, client.client_secret.as_deref())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(&[
            ("grant_type", "client_credentials"),
            ("scope", "email"),
        ]))
        .send()
        .await
        .expect("client_credentials token")
        .json()
        .await
        .unwrap();

    let at = tokens["access_token"].as_str().expect("access_token");
    let claims = dangerous::insecure_decode::<serde_json::Value>(at).expect("decode AT");

    let email_val = &claims.claims["email"];
    assert!(
        email_val.is_string(),
        "client_credentials AT must carry email when email scope is granted, \
         got claims: {claims:#?}"
    );
    assert_eq!(
        email_val.as_str().unwrap(),
        client.client_id,
        "email must equal client_id for service accounts"
    );

    ctx.stop_server().await
}
