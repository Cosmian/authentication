//! Authorization regression tests (issue #130): who may use `/sessions/*`, the AppRole and
//! Kubernetes admin endpoints, and the admin API from a session opened on another realm.

use crate::{
    AuthError, AuthResult, AuthScheme, AuthenticatedClientScheme, SessionsAction,
    client::{AuthClient, AuthClientScheme},
    database::APP_REALM_ADMIN_USERNAME,
    dto::{AppRoleRoleRequest, AppRoleSecretIdRequest, K8sRoleRequest},
    models::ADMIN_REALM,
    tests::{
        helpers::{
            admin_scheme, authenticate_as_admin, authenticate_new_realm_admin,
            create_and_authenticate_realm_admin, login_realm_user,
        },
        start_default_test_server,
    },
};

fn is_http<T>(result: &AuthResult<T>, status: u16) -> bool {
    matches!(result, Err(AuthError::FailedHttpStatus(m)) if m.contains(&status.to_string()))
}

fn up(username: &str) -> AuthenticatedClientScheme {
    AuthenticatedClientScheme {
        username: username.to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    }
}

async fn login_super_admin(ctx: &crate::tests::TestsContext) -> AuthResult<(AuthClient, String)> {
    let client = ctx.get_test_client(admin_scheme());
    let (result, _) = client.login(ADMIN_REALM, None).await?;
    Ok((client, result.session_id.expect("session id")))
}

// ── Admin API only accepts sessions opened on `_` ────────────────────────────

/// A session of another realm whose username equals an admin's login is not an admin session.
#[actix_web::test]
async fn test_admin_endpoints_reject_sessions_from_other_realms() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (user, _) = login_realm_user(&ctx, "acme", APP_REALM_ADMIN_USERNAME).await?;

    for path in [
        "/admins/realms",
        "/admins",
        "/realms/_/userpass",
        "/auth/approle/role?list=true",
        "/auth/kubernetes/role?list=true",
    ] {
        let status = user.get_raw(path).await?.status().as_u16();
        assert_eq!(
            status, 401,
            "GET {path} must reject a non-admin-realm session"
        );
    }
    user.whoami("acme").await?;
    ctx.stop_server().await
}

// ── /sessions: callers act only on their own sessions ────────────────────────

/// A realm user cannot see, list or revoke the sessions of other principals.
#[actix_web::test]
async fn test_realm_user_cannot_use_sessions_of_others() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (super_admin, admin_sid) = login_super_admin(&ctx).await?;
    let (joe, _) = login_realm_user(&ctx, "acme", "joe").await?;

    // Another principal's session is indistinguishable from a missing one.
    assert!(joe.get_session(&admin_sid).await?.is_none());
    assert!(
        joe.get_session_with_action(
            &admin_sid,
            vec![up("admin")],
            SessionsAction::LogoutAllSessions
        )
        .await?
        .is_none()
    );

    let listed = joe
        .get_sessions_for_clients(ADMIN_REALM, &[up("admin")])
        .await;
    assert!(is_http(&listed, 403), "listing admin sessions: {listed:?}");
    let own_realm_other_user = joe.get_sessions_for_clients("acme", &[up("bob")]).await;
    assert!(
        is_http(&own_realm_other_user, 403),
        "{own_realm_other_user:?}"
    );

    let deleted = joe.delete_sessions(std::slice::from_ref(&admin_sid)).await;
    assert!(is_http(&deleted, 403), "{deleted:?}");
    let realm_wide = joe.delete_sessions_for_realm(ADMIN_REALM).await;
    assert!(realm_wide.is_err(), "realm-wide revoke must be refused");
    let expired = joe.delete_expired_sessions().await;
    assert!(expired.is_err(), "purging expired sessions must be refused");

    super_admin.whoami(ADMIN_REALM).await?;
    ctx.stop_server().await
}

/// A user can still look up and log out their own sessions, across several logins.
#[actix_web::test]
async fn test_user_can_manage_own_sessions() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (joe_1, sid_1) = login_realm_user(&ctx, "acme", "joe").await?;
    let joe_2 = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: "joe".to_string(),
        password: "user_pass".to_string(),
    });
    let (result, _) = joe_2.login("acme", None).await?;
    let sid_2 = result.session_id.expect("session id");

    let own = joe_1.get_session(&sid_1).await?.expect("own session");
    assert_eq!(own.username, "joe");
    let ids = joe_1.get_sessions_for_clients("acme", &[up("joe")]).await?;
    assert!(ids.contains(&sid_1) && ids.contains(&sid_2));

    joe_1
        .get_session_with_action(&sid_1, vec![up("joe")], SessionsAction::LogoutOtherSessions)
        .await?;
    assert!(
        joe_2.whoami("acme").await.is_err(),
        "other session must be logged out"
    );
    joe_1.whoami("acme").await?;

    joe_1.delete_sessions(&[sid_1]).await?;
    assert!(joe_1.whoami("acme").await.is_err());
    ctx.stop_server().await
}

/// Session responses never carry the session credential.
#[actix_web::test]
async fn test_session_responses_omit_cookie_string() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (super_admin, sid) = login_super_admin(&ctx).await?;

    let get = super_admin
        .get_raw(&format!("/sessions/{sid}"))
        .await?
        .text()
        .await
        .unwrap_or_default();
    assert!(
        get.contains(&sid),
        "the session itself must be returned: {get}"
    );
    assert!(
        !get.contains("cookie_string"),
        "GET leaked the credential: {get}"
    );

    let post = super_admin
        .post_raw(
            &format!("/sessions/{sid}"),
            &serde_json::json!({"authenticated_clients": [], "sessions_action": null}),
        )
        .await?
        .text()
        .await
        .unwrap_or_default();
    assert!(
        !post.contains("cookie_string"),
        "POST leaked the credential: {post}"
    );
    ctx.stop_server().await
}

/// Sessions cannot be created over HTTP.
#[actix_web::test]
async fn test_post_sessions_is_not_exposed() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (super_admin, _) = login_super_admin(&ctx).await?;
    let status = super_admin
        .post_raw("/sessions", &serde_json::json!({}))
        .await?
        .status()
        .as_u16();
    assert!(status == 404 || status == 405, "got {status}");
    ctx.stop_server().await
}

// ── /sessions: administrators ────────────────────────────────────────────────

/// The super admin manages the sessions of unclaimed realms and of `_`.
#[actix_web::test]
async fn test_super_admin_manages_sessions_of_unclaimed_realm() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (joe, joe_sid) = login_realm_user(&ctx, "acme", "joe").await?;
    let (super_admin, _) = login_super_admin(&ctx).await?;

    assert!(super_admin.get_session(&joe_sid).await?.is_some());
    let ids = super_admin
        .get_sessions_for_clients("acme", &[up("joe")])
        .await?;
    assert_eq!(ids, vec![joe_sid]);

    super_admin.delete_sessions_for_realm("acme").await?;
    assert!(joe.whoami("acme").await.is_err());
    super_admin.delete_expired_sessions().await?;
    ctx.stop_server().await
}

/// Once a realm has its own admin, the super admin has no access to its sessions; that admin has.
#[actix_web::test]
async fn test_sessions_of_claimed_realm_belong_to_its_admins() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (joe, joe_sid) = login_realm_user(&ctx, "acme", "joe").await?;
    let realm_admin = authenticate_new_realm_admin(&ctx, "acme").await?;
    let (super_admin, _) = login_super_admin(&ctx).await?;

    assert!(super_admin.get_session(&joe_sid).await?.is_none());
    let listed = super_admin
        .get_sessions_for_clients("acme", &[up("joe")])
        .await;
    assert!(is_http(&listed, 403), "{listed:?}");
    let deleted = super_admin
        .delete_sessions(std::slice::from_ref(&joe_sid))
        .await;
    assert!(is_http(&deleted, 403), "{deleted:?}");
    assert!(super_admin.delete_sessions_for_realm("acme").await.is_err());
    joe.whoami("acme").await?;

    assert!(realm_admin.get_session(&joe_sid).await?.is_some());
    assert_eq!(
        realm_admin
            .get_sessions_for_clients("acme", &[up("joe")])
            .await?,
        vec![joe_sid]
    );
    realm_admin.delete_sessions_for_realm("acme").await?;
    assert!(joe.whoami("acme").await.is_err());
    ctx.stop_server().await
}

/// A realm admin only reaches the sessions of the realms it administers, and cannot purge.
#[actix_web::test]
async fn test_realm_admin_sessions_are_limited_to_its_realms() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (bob, bob_sid) = login_realm_user(&ctx, "beta", "bob").await?;
    let realm_admin = create_and_authenticate_realm_admin(&ctx, "acme").await?;

    assert!(realm_admin.get_session(&bob_sid).await?.is_none());
    let listed = realm_admin
        .get_sessions_for_clients("beta", &[up("bob")])
        .await;
    assert!(is_http(&listed, 403), "{listed:?}");
    assert!(realm_admin.delete_sessions_for_realm("beta").await.is_err());
    assert!(realm_admin.delete_sessions(&[bob_sid]).await.is_err());
    assert!(realm_admin.delete_expired_sessions().await.is_err());
    bob.whoami("beta").await?;
    ctx.stop_server().await
}

// ── AppRole / Kubernetes administration is for super admins ──────────────────

#[actix_web::test]
async fn test_machine_auth_administration_requires_super_admin() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let super_admin = authenticate_as_admin(&ctx).await?;
    let role = AppRoleRoleRequest {
        token_ttl: 60,
        secret_id_ttl: 0,
        token_policies: vec!["default".to_string()],
        bind_secret_id: true,
    };
    super_admin.approle_create_role("ops", &role).await?;
    let k8s = K8sRoleRequest {
        jwks_url: format!("{}/public/jwks", ctx.get_client_url()),
        bound_service_account_names: vec!["*".to_string()],
        bound_service_account_namespaces: vec!["*".to_string()],
        token_ttl: 60,
        expected_issuer: None,
        bound_audiences: vec![],
    };
    super_admin.k8s_create_role("ops-k8s", &k8s).await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "acme").await?;
    let secret = AppRoleSecretIdRequest {
        ttl: 0,
        num_uses: 0,
    };
    assert!(is_http(
        &realm_admin.approle_create_role("mine", &role).await,
        403
    ));
    assert!(is_http(&realm_admin.approle_list_roles().await, 403));
    assert!(is_http(&realm_admin.approle_get_role("ops").await, 403));
    assert!(is_http(&realm_admin.approle_get_role_id("ops").await, 403));
    assert!(is_http(
        &realm_admin.approle_generate_secret_id("ops", &secret).await,
        403
    ));
    assert!(is_http(
        &realm_admin.approle_destroy_secret_id("ops", "x").await,
        403
    ));
    assert!(is_http(&realm_admin.approle_delete_role("ops").await, 403));
    assert!(is_http(
        &realm_admin.k8s_create_role("mine", &k8s).await,
        403
    ));
    assert!(is_http(&realm_admin.k8s_list_roles().await, 403));
    assert!(is_http(&realm_admin.k8s_get_role("ops-k8s").await, 403));
    assert!(is_http(&realm_admin.k8s_delete_role("ops-k8s").await, 403));

    // Nothing was changed, and the super admin still manages both.
    assert_eq!(
        super_admin.approle_list_roles().await?.data.keys,
        vec!["ops"]
    );
    assert_eq!(
        super_admin.k8s_list_roles().await?.data.keys,
        vec!["ops-k8s"]
    );
    ctx.stop_server().await
}
