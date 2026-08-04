//! Integration tests for the AppRole, Kubernetes, and Token Self-Service auth APIs.
//!
//! Each test:
//! 1. Starts a fresh in-memory test server.
//! 2. Authenticates as the seeded `admin` user.
//! 3. Uses the `AuthClient` wrappers to exercise the `/auth/approle/*`,
//!    `/auth/kubernetes/*`, and `/auth/token/*` endpoints.
//!
//! ## Standards under test
//!
//! - AppRole: Vault AppRole API wire protocol (de-facto standard used by SPIRE)
//! - Kubernetes: RFC 7519 (JWT), RFC 7517 (JWK/JWKS), RFC 7518 (JWA)
//! - Token self-service: Vault token self-service API

use crate::{
    AuthResult,
    client::AuthClientScheme,
    dto::{AppRoleRoleRequest, AppRoleSecretIdRequest, K8sRoleRequest},
    tests::{
        IdP, RsaIdp, helpers::authenticate_as_admin, init_test_logging, start_default_test_server,
    },
};
use cosmian_logger::info;

/// Issuer embedded in the test RSA IdP (matches `build_app`'s hardcoded value).
const TEST_ISSUER: &str = "test_auth_issuer";

// ── AppRole tests ─────────────────────────────────────────────────────────────

/// Full AppRole workflow: create role → get role_id → generate secret_id →
/// login → lookup-self → renew-self → revoke-self.
#[actix_web::test]
async fn test_approle_full_workflow() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    // Step 1: create a role
    admin
        .approle_create_role(
            "my-role",
            &AppRoleRoleRequest {
                token_ttl: 3600,
                secret_id_ttl: 0,
                token_policies: vec!["default".to_string()],
                bind_secret_id: true,
            },
        )
        .await?;

    // Step 2: read the stable role_id
    let role_id_resp = admin.approle_get_role_id("my-role").await?;
    let role_id = role_id_resp.data.role_id;
    assert!(!role_id.is_empty(), "role_id must be a non-empty UUID");
    info!("AppRole role_id: {role_id}");

    // Step 3: generate a secret_id
    let secret_resp = admin
        .approle_generate_secret_id(
            "my-role",
            &AppRoleSecretIdRequest {
                ttl: 0,
                num_uses: 0,
            },
        )
        .await?;
    let secret_id = secret_resp.data.secret_id;
    let _accessor = secret_resp.data.secret_id_accessor;
    assert!(!secret_id.is_empty(), "secret_id must be non-empty");

    // Step 4: login — receive an app token
    let login_resp = admin.approle_login(&role_id, Some(&secret_id)).await?;
    let token = login_resp.auth.client_token;
    assert!(token.starts_with("hvs."), "token must have hvs. prefix");
    assert!(login_resp.auth.renewable, "token must be renewable");
    assert_eq!(login_resp.auth.lease_duration, 3600);
    assert_eq!(login_resp.auth.policies, vec!["default"]);

    // Step 5: lookup-self — token must be valid
    let lookup = ctx
        .get_test_client(AuthClientScheme::None)
        .token_lookup_self(&token)
        .await?;
    assert_eq!(lookup.data.entity_id, "my-role");
    // Per Vault API spec §3.1, data.id echoes back the presented token
    // (SPIRE reads this field to verify its in-memory token state).
    assert_eq!(
        lookup.data.id, token,
        "data.id must echo the presented token per AppRole auth API spec §3.1"
    );

    // Step 6: renew-self
    let renew = ctx
        .get_test_client(AuthClientScheme::None)
        .token_renew_self(&token)
        .await?;
    assert!(renew.auth.renewable);

    // Step 7: revoke-self
    ctx.get_test_client(AuthClientScheme::None)
        .token_revoke_self(&token)
        .await?;

    // Token must now be rejected
    let status = ctx
        .get_test_client(AuthClientScheme::None)
        .token_lookup_self_status(&token)
        .await?;
    assert_eq!(status, 403, "revoked token must return 403");

    ctx.stop_server().await
}

/// When `bind_secret_id = false`, login with only `role_id` must succeed.
#[actix_web::test]
async fn test_approle_bind_secret_id_false() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    admin
        .approle_create_role(
            "open-role",
            &AppRoleRoleRequest {
                token_ttl: 3600,
                secret_id_ttl: 0,
                token_policies: vec![],
                bind_secret_id: false,
            },
        )
        .await?;

    let role_id = admin.approle_get_role_id("open-role").await?.data.role_id;

    // Login without a secret_id
    let login = ctx
        .get_test_client(AuthClientScheme::None)
        .approle_login(&role_id, None)
        .await?;
    assert!(login.auth.client_token.starts_with("hvs."));

    ctx.stop_server().await
}

/// A `secret_id` with `num_uses = 1` must be invalidated after the first login.
#[actix_web::test]
async fn test_approle_single_use_secret_id() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    admin
        .approle_create_role(
            "single-role",
            &AppRoleRoleRequest {
                token_ttl: 3600,
                secret_id_ttl: 0,
                token_policies: vec![],
                bind_secret_id: true,
            },
        )
        .await?;

    let role_id = admin.approle_get_role_id("single-role").await?.data.role_id;
    let secret_resp = admin
        .approle_generate_secret_id(
            "single-role",
            &AppRoleSecretIdRequest {
                ttl: 0,
                num_uses: 1,
            },
        )
        .await?;
    let secret_id = secret_resp.data.secret_id;

    // First login must succeed
    let noauth = ctx.get_test_client(AuthClientScheme::None);
    let first = noauth.approle_login(&role_id, Some(&secret_id)).await?;
    assert!(first.auth.client_token.starts_with("hvs."));

    // Second login with the same secret_id must fail (secret consumed)
    let second = noauth.approle_login(&role_id, Some(&secret_id)).await;
    assert!(
        second.is_err(),
        "second login with exhausted secret_id must fail"
    );

    ctx.stop_server().await
}

/// Login with a wrong `role_id` must return an error.
#[actix_web::test]
async fn test_approle_invalid_role_id() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let noauth = ctx.get_test_client(AuthClientScheme::None);
    let result = noauth
        .approle_login("00000000-0000-0000-0000-000000000000", Some("any-secret"))
        .await;
    assert!(result.is_err(), "login with non-existent role_id must fail");

    ctx.stop_server().await
}

/// Login with a wrong `secret_id` must return an error.
#[actix_web::test]
async fn test_approle_invalid_secret_id() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    admin
        .approle_create_role(
            "role-bad-secret",
            &AppRoleRoleRequest {
                token_ttl: 3600,
                secret_id_ttl: 0,
                token_policies: vec![],
                bind_secret_id: true,
            },
        )
        .await?;
    let role_id = admin
        .approle_get_role_id("role-bad-secret")
        .await?
        .data
        .role_id;

    let noauth = ctx.get_test_client(AuthClientScheme::None);
    let result = noauth
        .approle_login(&role_id, Some("completely-wrong-secret"))
        .await;
    assert!(result.is_err(), "login with wrong secret_id must fail");

    ctx.stop_server().await
}

/// Destroy a `secret_id` by accessor; subsequent login must fail.
#[actix_web::test]
async fn test_approle_destroy_secret_id() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    admin
        .approle_create_role(
            "destroy-role",
            &AppRoleRoleRequest {
                token_ttl: 3600,
                secret_id_ttl: 0,
                token_policies: vec![],
                bind_secret_id: true,
            },
        )
        .await?;

    let role_id = admin
        .approle_get_role_id("destroy-role")
        .await?
        .data
        .role_id;
    let secret_resp = admin
        .approle_generate_secret_id(
            "destroy-role",
            &AppRoleSecretIdRequest {
                ttl: 0,
                num_uses: 0,
            },
        )
        .await?;
    let secret_id = secret_resp.data.secret_id.clone();
    let accessor = secret_resp.data.secret_id_accessor.clone();

    // Destroy the secret_id by accessor
    admin
        .approle_destroy_secret_id("destroy-role", &accessor)
        .await?;

    // Login must now fail
    let noauth = ctx.get_test_client(AuthClientScheme::None);
    let result = noauth.approle_login(&role_id, Some(&secret_id)).await;
    assert!(result.is_err(), "login after destroy must fail");

    ctx.stop_server().await
}

/// List roles and verify new roles appear; delete a role and verify it's gone.
#[actix_web::test]
async fn test_approle_list_and_delete_roles() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    for name in &["list-role-a", "list-role-b"] {
        admin
            .approle_create_role(
                name,
                &AppRoleRoleRequest {
                    token_ttl: 3600,
                    secret_id_ttl: 0,
                    token_policies: vec![],
                    bind_secret_id: false,
                },
            )
            .await?;
    }

    let list = admin.approle_list_roles().await?;
    assert!(
        list.data.keys.contains(&"list-role-a".to_string()),
        "list must contain list-role-a"
    );
    assert!(
        list.data.keys.contains(&"list-role-b".to_string()),
        "list must contain list-role-b"
    );

    admin.approle_delete_role("list-role-a").await?;
    let list2 = admin.approle_list_roles().await?;
    assert!(
        !list2.data.keys.contains(&"list-role-a".to_string()),
        "deleted role must not appear in list"
    );

    ctx.stop_server().await
}

// ── Kubernetes tests ──────────────────────────────────────────────────────────

/// Full Kubernetes auth workflow: create role → login with SA JWT → lookup-self.
///
/// Uses the test server's `/public/jwks` endpoint (backed by the RSA test IdP)
/// as the JWKS URL for the Kubernetes role.
#[actix_web::test]
async fn test_k8s_full_workflow() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    // The test server registers its RSA IdP public key at /public/jwks.
    let jwks_url = format!("{}/public/jwks", ctx.get_client_url());

    admin
        .k8s_create_role(
            "k8s-role",
            &K8sRoleRequest {
                jwks_url: jwks_url.clone(),
                bound_service_account_names: vec!["*".to_string()],
                bound_service_account_namespaces: vec!["*".to_string()],
                token_ttl: 3600,
                expected_issuer: Some(TEST_ISSUER.to_string()),
                bound_audiences: vec![],
            },
        )
        .await?;

    // Issue a K8s service-account JWT using the test RSA IdP.
    // sub = "system:serviceaccount:<ns>:<sa>"
    let sa_sub = "system:serviceaccount:spire:spire-agent";
    let idp = RsaIdp::new(TEST_ISSUER)?;
    let jwt = idp.issue_token(sa_sub, "any-audience", 3600)?;

    let noauth = ctx.get_test_client(AuthClientScheme::None);
    let login = noauth.k8s_login("k8s-role", &jwt).await?;
    let token = login.auth.client_token;
    assert!(token.starts_with("hvs."));
    assert_eq!(login.auth.lease_duration, 3600);

    // Check metadata reflects the service account identity
    assert_eq!(
        login
            .auth
            .metadata
            .get("service_account_name")
            .map(String::as_str),
        Some("spire-agent")
    );
    assert_eq!(
        login
            .auth
            .metadata
            .get("service_account_namespace")
            .map(String::as_str),
        Some("spire")
    );

    // Token must validate
    let lookup = noauth.token_lookup_self(&token).await?;
    assert_eq!(lookup.data.entity_id, "spire/spire-agent");

    ctx.stop_server().await
}

/// Kubernetes login with a SA name not in `bound_service_account_names` must fail.
#[actix_web::test]
async fn test_k8s_wrong_sa_name() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let jwks_url = format!("{}/public/jwks", ctx.get_client_url());

    admin
        .k8s_create_role(
            "k8s-restricted-role",
            &K8sRoleRequest {
                jwks_url,
                bound_service_account_names: vec!["allowed-sa".to_string()],
                bound_service_account_namespaces: vec!["*".to_string()],
                token_ttl: 3600,
                expected_issuer: Some(TEST_ISSUER.to_string()),
                bound_audiences: vec![],
            },
        )
        .await?;

    let idp = RsaIdp::new(TEST_ISSUER)?;
    let jwt = idp.issue_token("system:serviceaccount:default:disallowed-sa", "aud", 3600)?;

    let result = ctx
        .get_test_client(AuthClientScheme::None)
        .k8s_login("k8s-restricted-role", &jwt)
        .await;
    assert!(result.is_err(), "login with disallowed SA name must fail");

    ctx.stop_server().await
}

/// Kubernetes login with a namespace not in `bound_service_account_namespaces` must fail.
#[actix_web::test]
async fn test_k8s_wrong_namespace() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let jwks_url = format!("{}/public/jwks", ctx.get_client_url());

    admin
        .k8s_create_role(
            "k8s-ns-role",
            &K8sRoleRequest {
                jwks_url,
                bound_service_account_names: vec!["*".to_string()],
                bound_service_account_namespaces: vec!["allowed-ns".to_string()],
                token_ttl: 3600,
                expected_issuer: Some(TEST_ISSUER.to_string()),
                bound_audiences: vec![],
            },
        )
        .await?;

    let idp = RsaIdp::new(TEST_ISSUER)?;
    let jwt = idp.issue_token("system:serviceaccount:disallowed-ns:my-sa", "aud", 3600)?;

    let result = ctx
        .get_test_client(AuthClientScheme::None)
        .k8s_login("k8s-ns-role", &jwt)
        .await;
    assert!(result.is_err(), "login with disallowed namespace must fail");

    ctx.stop_server().await
}

/// Kubernetes login with a wildcard allowlist must accept any SA name and namespace.
#[actix_web::test]
async fn test_k8s_wildcard_allowlist() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let jwks_url = format!("{}/public/jwks", ctx.get_client_url());

    admin
        .k8s_create_role(
            "k8s-wildcard-role",
            &K8sRoleRequest {
                jwks_url,
                bound_service_account_names: vec!["*".to_string()],
                bound_service_account_namespaces: vec!["*".to_string()],
                token_ttl: 600,
                expected_issuer: Some(TEST_ISSUER.to_string()),
                bound_audiences: vec![],
            },
        )
        .await?;

    let idp = RsaIdp::new(TEST_ISSUER)?;
    for subject in &[
        "system:serviceaccount:alpha:sa1",
        "system:serviceaccount:beta:sa2",
        "system:serviceaccount:gamma:sa3",
    ] {
        let jwt = idp.issue_token(subject, "aud", 600)?;
        let login = ctx
            .get_test_client(AuthClientScheme::None)
            .k8s_login("k8s-wildcard-role", &jwt)
            .await?;
        assert!(login.auth.client_token.starts_with("hvs."));
    }

    ctx.stop_server().await
}

/// Kubernetes login with an expired JWT must be rejected (RFC 7519 §4.1.4).
#[actix_web::test]
async fn test_k8s_expired_jwt() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let jwks_url = format!("{}/public/jwks", ctx.get_client_url());

    admin
        .k8s_create_role(
            "k8s-exp-role",
            &K8sRoleRequest {
                jwks_url,
                bound_service_account_names: vec!["*".to_string()],
                bound_service_account_namespaces: vec!["*".to_string()],
                token_ttl: 3600,
                expected_issuer: Some(TEST_ISSUER.to_string()),
                bound_audiences: vec![],
            },
        )
        .await?;

    let idp = RsaIdp::new(TEST_ISSUER)?;
    let jwt = idp.issue_definitely_expired_token("system:serviceaccount:ns:sa", "aud")?;

    let result = ctx
        .get_test_client(AuthClientScheme::None)
        .k8s_login("k8s-exp-role", &jwt)
        .await;
    assert!(result.is_err(), "expired JWT must be rejected");

    ctx.stop_server().await
}

/// Kubernetes login with a JWT whose issuer does not match `expected_issuer` must fail.
#[actix_web::test]
async fn test_k8s_issuer_mismatch() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let jwks_url = format!("{}/public/jwks", ctx.get_client_url());

    admin
        .k8s_create_role(
            "k8s-iss-role",
            &K8sRoleRequest {
                jwks_url,
                bound_service_account_names: vec!["*".to_string()],
                bound_service_account_namespaces: vec!["*".to_string()],
                token_ttl: 3600,
                expected_issuer: Some("https://expected-issuer.example.com".to_string()),
                bound_audiences: vec![],
            },
        )
        .await?;

    // Issue with the test issuer (mismatches role's expected_issuer)
    let idp = RsaIdp::new(TEST_ISSUER)?;
    let jwt = idp.issue_token("system:serviceaccount:ns:sa", "aud", 3600)?;

    let result = ctx
        .get_test_client(AuthClientScheme::None)
        .k8s_login("k8s-iss-role", &jwt)
        .await;
    assert!(result.is_err(), "JWT with wrong issuer must be rejected");

    ctx.stop_server().await
}

// ── Token self-service tests ──────────────────────────────────────────────────

/// `GET /auth/token/lookup-self` returns correct metadata for a valid token.
#[actix_web::test]
async fn test_token_lookup_self() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    admin
        .approle_create_role(
            "lookup-role",
            &AppRoleRoleRequest {
                token_ttl: 3600,
                secret_id_ttl: 0,
                token_policies: vec!["p1".to_string()],
                bind_secret_id: false,
            },
        )
        .await?;
    let role_id = admin.approle_get_role_id("lookup-role").await?.data.role_id;
    let token = ctx
        .get_test_client(AuthClientScheme::None)
        .approle_login(&role_id, None)
        .await?
        .auth
        .client_token;

    let noauth = ctx.get_test_client(AuthClientScheme::None);
    let lookup = noauth.token_lookup_self(&token).await?;

    assert_eq!(lookup.data.entity_id, "lookup-role");
    assert_eq!(lookup.data.policies, vec!["p1"]);
    assert!(lookup.data.renewable);
    assert!(lookup.data.ttl > 0 && lookup.data.ttl <= 3600);
    // Per Vault spec §3.1, data.id echoes the presented token (SPIRE reads this).
    assert_eq!(
        lookup.data.id, token,
        "data.id must echo the presented token per AppRole auth API spec §3.1"
    );

    ctx.stop_server().await
}

/// `POST /auth/token/renew-self` extends a renewable token's TTL.
#[actix_web::test]
async fn test_token_renew_self() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    admin
        .approle_create_role(
            "renew-role",
            &AppRoleRoleRequest {
                token_ttl: 3600,
                secret_id_ttl: 0,
                token_policies: vec![],
                bind_secret_id: false,
            },
        )
        .await?;
    let role_id = admin.approle_get_role_id("renew-role").await?.data.role_id;
    let noauth = ctx.get_test_client(AuthClientScheme::None);
    let token = noauth
        .approle_login(&role_id, None)
        .await?
        .auth
        .client_token;

    // Renew must succeed for a renewable token
    let renew = noauth.token_renew_self(&token).await?;
    assert!(renew.auth.renewable);
    // Per Vault spec §3.6, client_token echoes back the presented token (SPIRE uses this).
    assert_eq!(
        renew.auth.client_token, token,
        "client_token must echo the presented token per AppRole auth API spec §3.6"
    );

    ctx.stop_server().await
}

/// `POST /auth/token/revoke-self` invalidates the token; subsequent lookup must 403.
#[actix_web::test]
async fn test_token_revoke_self() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    admin
        .approle_create_role(
            "revoke-role",
            &AppRoleRoleRequest {
                token_ttl: 3600,
                secret_id_ttl: 0,
                token_policies: vec![],
                bind_secret_id: false,
            },
        )
        .await?;
    let role_id = admin.approle_get_role_id("revoke-role").await?.data.role_id;
    let noauth = ctx.get_test_client(AuthClientScheme::None);
    let token = noauth
        .approle_login(&role_id, None)
        .await?
        .auth
        .client_token;

    // Revoke the token
    noauth.token_revoke_self(&token).await?;

    // Subsequent lookup must return 403
    let status = noauth.token_lookup_self_status(&token).await?;
    assert_eq!(status, 403, "revoked token must return 403");

    ctx.stop_server().await
}

/// Missing `X-Vault-Token` header must return 403.
#[actix_web::test]
async fn test_token_missing_header() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // Call lookup-self with an empty string as "token" → header present but invalid hash
    let status = ctx
        .get_test_client(AuthClientScheme::None)
        .token_lookup_self_status("")
        .await?;
    // An empty header value produces a hash that won't match any real token → 403.
    assert_eq!(status, 403);

    ctx.stop_server().await
}

// ── Read-endpoint tests (list/inspect roles) ────────────────────────────────

/// Create an AppRole role, then `GET /auth/approle/role/{name}` returns its config.
#[actix_web::test]
async fn test_approle_get_role_config() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    admin
        .approle_create_role(
            "cfg-role",
            &AppRoleRoleRequest {
                token_ttl: 1800,
                secret_id_ttl: 600,
                token_policies: vec!["default".to_string(), "reader".to_string()],
                bind_secret_id: true,
            },
        )
        .await?;

    // The stable role_id assigned at creation must match the one returned here.
    let expected_role_id = admin.approle_get_role_id("cfg-role").await?.data.role_id;

    let cfg = admin.approle_get_role("cfg-role").await?;
    assert_eq!(cfg.data.role_id, expected_role_id);
    assert_eq!(cfg.data.token_ttl, 1800);
    assert_eq!(cfg.data.secret_id_ttl, 600);
    assert!(cfg.data.bind_secret_id);
    assert_eq!(cfg.data.token_policies, vec!["default", "reader"]);

    ctx.stop_server().await
}

/// `GET /auth/approle/role/{name}` for a nonexistent role must return a 4xx error.
#[actix_web::test]
async fn test_approle_get_role_not_found() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let resp = admin.get_raw("/auth/approle/role/does-not-exist").await?;
    assert!(
        resp.status().is_client_error(),
        "missing AppRole role must yield a 4xx status, got {}",
        resp.status()
    );

    ctx.stop_server().await
}

/// Create a K8s role, list it, and inspect its parsed configuration arrays.
#[actix_web::test]
async fn test_k8s_list_and_get_role() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let jwks_url = format!("{}/public/jwks", ctx.get_client_url());
    admin
        .k8s_create_role(
            "k8s-cfg-role",
            &K8sRoleRequest {
                jwks_url: jwks_url.clone(),
                bound_service_account_names: vec!["spire-agent".to_string()],
                bound_service_account_namespaces: vec!["spire".to_string()],
                token_ttl: 3600,
                expected_issuer: Some(TEST_ISSUER.to_string()),
                bound_audiences: vec!["spire-server".to_string()],
            },
        )
        .await?;

    // List must contain the created role.
    let list = admin.k8s_list_roles().await?;
    assert!(
        list.data.keys.contains(&"k8s-cfg-role".to_string()),
        "list must contain k8s-cfg-role"
    );

    // Inspect must return the JSON-stored arrays parsed back into vectors.
    let cfg = admin.k8s_get_role("k8s-cfg-role").await?;
    assert_eq!(cfg.data.jwks_url, jwks_url);
    assert_eq!(cfg.data.bound_service_account_names, vec!["spire-agent"]);
    assert_eq!(cfg.data.bound_service_account_namespaces, vec!["spire"]);
    assert_eq!(cfg.data.token_ttl, 3600);
    assert_eq!(cfg.data.expected_issuer, Some(TEST_ISSUER.to_string()));
    assert_eq!(cfg.data.bound_audiences, vec!["spire-server"]);

    ctx.stop_server().await
}

/// Listing K8s roles when none exist must return an empty `keys` array.
#[actix_web::test]
async fn test_k8s_list_roles_empty() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let list = admin.k8s_list_roles().await?;
    assert!(
        list.data.keys.is_empty(),
        "no K8s roles configured must yield keys: []"
    );

    ctx.stop_server().await
}

/// `GET /auth/kubernetes/role/{name}` for a nonexistent role must return a 4xx error.
#[actix_web::test]
async fn test_k8s_get_role_not_found() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let resp = admin
        .get_raw("/auth/kubernetes/role/does-not-exist")
        .await?;
    assert!(
        resp.status().is_client_error(),
        "missing K8s role must yield a 4xx status, got {}",
        resp.status()
    );

    ctx.stop_server().await
}
