//! Integration tests for the Admin CRUD endpoints (`/admins/*`).
//!
//! Each test:
//! 1. Starts a fresh in-memory test server.
//! 2. Authenticates as the seeded `admin` user so the `_ea_` session cookie is
//!    stored in the client's cookie jar.
//! 3. Exercises one scenario against the `/users` scope.

use crate::{
    AuthResult, AuthenticationNextStep, Realm, RealmAuthParams,
    client::AuthClientScheme,
    database::{
        APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME, hash_password_with_argon2,
    },
    models::{ADMIN_REALM, Admin, UserPass},
    tests::{init_test_logging, start_default_test_server},
};
use cosmian_logger::info;

fn admin_scheme() -> AuthClientScheme {
    AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    }
}

/// Build a minimal `Admin` suitable for testing.
fn test_admin(id: &str) -> Admin {
    Admin {
        id: id.to_string(),
        realms: vec![],
        userpass: None,
        jwt: None,
        fido2: None,
        digital_credentials: None,
        client_certificate: None,
        totp_enabled: None,
        totp_secret: None,
        totp_auth_url: None,
    }
}

fn create_user(
    realm: &str,
    username: &str,
    password: &str,
    change_password: bool,
) -> AuthResult<UserPass> {
    Ok(UserPass {
        realm: realm.to_string(),
        username: username.to_string(),
        password: hash_password_with_argon2(username, password)?,
        change_password,
    })
}

/// Authenticate as `admin` and return the ready-to-use client.
async fn authenticate_as_admin(
    ctx: &crate::tests::TestsContext,
) -> AuthResult<crate::client::AuthClient> {
    let client = ctx.get_test_client(admin_scheme());
    let (result, cookie) = client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated next step after login"
    );
    assert!(cookie.is_some(), "Expected a session cookie after login");
    Ok(client)
}

// ── GET /users ──────────────────────────────────────────────────────────────

/// The list must include the seeded `admin` user that is always present.
#[actix_web::test]
async fn test_list_admins_contains_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    let admins = client.list_admins_as_super_admin().await?;

    assert!(!admins.is_empty(), "Expected at least one user");
    assert!(
        admins.iter().any(|u| u.id == APP_REALM_ADMIN_USERNAME),
        "Expected the seeded '{}' user to be present",
        APP_REALM_ADMIN_USERNAME
    );
    info!("list_admins returned {} admin(s)", admins.len());

    ctx.stop_server().await
}

// ── POST /users/user ─────────────────────────────────────────────────────────

/// Creating a brand-new user must succeed and be reflected in a subsequent GET.
#[actix_web::test]
async fn test_create_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    let new_user = test_admin("alice");
    let created = client.create_admin_as_super_admin(&new_user).await?;

    assert_eq!(created.id, "alice", "Created user ID must match");
    info!("create_user returned: {:?}", created.id);

    // The user must also be retrievable immediately after creation.
    let fetched = client.get_admin_as_super_admin("alice").await?;
    assert_eq!(fetched.id, "alice");

    ctx.stop_server().await
}

/// Creating a user whose ID already exists must return an error.
#[actix_web::test]
async fn test_create_duplicate_user_fails() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    // The `admin` user is always seeded — trying to create it again must fail.
    let result = client
        .create_admin_as_super_admin(&test_admin(APP_REALM_ADMIN_USERNAME))
        .await;

    assert!(
        result.is_err(),
        "Expected an error when creating a duplicate user"
    );
    info!(
        "create_duplicate_user returned expected error: {:?}",
        result
    );

    ctx.stop_server().await
}

// ── GET /users/user/{id} ─────────────────────────────────────────────────────

/// Fetching the seeded `admin` user must succeed.
#[actix_web::test]
async fn test_get_admin_existing() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    let admin = client
        .get_admin_as_super_admin(APP_REALM_ADMIN_USERNAME)
        .await?;

    assert_eq!(admin.id, APP_REALM_ADMIN_USERNAME);
    info!("get_admin returned: {:?}", admin.id);

    ctx.stop_server().await
}

/// Fetching a user that does not exist must return an error (HTTP 400 from the
/// endpoint's `BadRequest` response).
#[actix_web::test]
async fn test_get_admin_not_found() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    let result = client
        .get_admin_as_super_admin("user_that_does_not_exist")
        .await;

    assert!(result.is_err(), "Expected an error for a non-existent user");
    info!("get_user_not_found returned expected error");

    ctx.stop_server().await
}

// ── PUT /users/user/{id} ─────────────────────────────────────────────────────

/// Updating a user must persist the change and be visible on a subsequent GET.
#[actix_web::test]
async fn test_update_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    // First create a user to update.
    let admin = test_admin("bob");
    client.create_admin_as_super_admin(&admin).await?;

    // Modify it — assign it to the always-present admin realm.
    let mut updated = admin.clone();
    updated.realms = vec![ADMIN_REALM.to_string()];

    let returned = client.update_admin_as_super_admin("bob", &updated).await?;
    assert_eq!(returned.id, "bob");
    assert!(
        returned.realms.contains(&ADMIN_REALM.to_string()),
        "Updated user must reflect the new realm list"
    );

    // Verify persistence.
    let re_fetched = client.get_admin_as_super_admin("bob").await?;
    assert!(
        re_fetched.realms.contains(&ADMIN_REALM.to_string()),
        "Persisted realm list must match what was written"
    );
    info!("update_user: realm list updated and persisted");

    ctx.stop_server().await
}

/// The path `id` is authoritative: even if the JSON body carries a different
/// `id`, the server must use the one from the URL.
#[actix_web::test]
async fn test_update_admin_path_id_is_authoritative() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    client
        .create_admin_as_super_admin(&test_admin("charlie"))
        .await?;

    // Send a body with a different id — the path id must win.
    let mut body_with_wrong_id = test_admin("wrong_id");
    body_with_wrong_id.realms = vec![ADMIN_REALM.to_string()];

    let returned = client
        .update_admin_as_super_admin("charlie", &body_with_wrong_id)
        .await?;

    assert_eq!(
        returned.id, "charlie",
        "Server must use path id, not body id"
    );
    info!("update_user: path id took precedence over body id");

    ctx.stop_server().await
}

// ── DELETE /users/user/{id} ───────────────────────────────────────────────────

/// Deleting a user must remove it: a subsequent GET must return an error.
#[actix_web::test]
async fn test_delete_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    // Create then immediately delete.
    client
        .create_admin_as_super_admin(&test_admin("dave"))
        .await?;
    client.delete_admin_as_super_admin("dave").await?;
    info!("Admin 'dave' deleted");

    // Must be gone.
    let result = client.get_admin_as_super_admin("dave").await;
    assert!(result.is_err(), "Expected an error after deleting the user");
    info!("get_user after delete returned expected error");

    ctx.stop_server().await
}

/// Deleting a user that never existed is idempotent (no error).
#[actix_web::test]
async fn test_delete_nonexistent_user_is_idempotent() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    client
        .delete_admin_as_super_admin("user_that_never_existed")
        .await?;

    info!("delete_user for a non-existent user succeeded (no-op, idempotent)");

    ctx.stop_server().await
}

// ── Unauthenticated access ────────────────────────────────────────────────────

/// All `/users/*` endpoints require authentication; an unauthenticated client
/// must receive HTTP 401.
#[actix_web::test]
async fn test_admin_endpoints_require_authentication() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // Client with no credentials and no session cookie.
    let unauthenticated = ctx.get_test_client(AuthClientScheme::None);

    let result = unauthenticated.list_admins_as_super_admin().await;
    assert!(
        result.is_err(),
        "Expected an error for unauthenticated list_users"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 in error message, got: {msg}"
    );
    info!("Unauthenticated access correctly rejected with 401");

    ctx.stop_server().await
}

// ── Helpers for realm-admin tests ────────────────────────────────────────────

fn test_realm(id: &str) -> Realm {
    Realm {
        id: id.to_string(),
        auth_params: RealmAuthParams::default(),
        session_max_age_seconds: 3600,
        session_max_stale_age_seconds: 3600,
    }
}

/// Create a realm, register credentials for a realm-admin user, create the user with
/// `realm_id` in their `realms` list, and return a client authenticated as that realm admin.
///
/// The returned client session is **not** a super admin.
async fn create_and_authenticate_realm_admin(
    ctx: &crate::tests::TestsContext,
    realm_id: &str,
) -> AuthResult<crate::client::AuthClient> {
    let super_admin = authenticate_as_admin(ctx).await?;

    super_admin
        .create_realm_as_super_admin(&test_realm(realm_id))
        .await?;

    let username = format!("{realm_id}_radmin");
    let password = "realm_admin_pass";
    let userpass = create_user(ADMIN_REALM, &username, password, false)?;
    super_admin
        .create_admin_credentials_in_realm(ADMIN_REALM, &userpass)
        .await?;

    let mut realm_admin_user = test_admin(&format!("{realm_id}_radmin_user"));
    realm_admin_user.realms = vec![realm_id.to_string()];
    realm_admin_user.userpass = Some(username.clone());
    super_admin
        .create_admin_as_super_admin(&realm_admin_user)
        .await?;

    let scheme = AuthClientScheme::UsernamePassword {
        username: username.clone(),
        password: password.to_string(),
    };
    let client = ctx.get_test_client(scheme);
    let (result, cookie) = client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after realm admin login"
    );
    assert!(cookie.is_some(), "Expected session cookie for realm admin");
    info!("Authenticated as realm admin for '{}'", realm_id);
    Ok(client)
}

// ── Super-admin-only enforcement ──────────────────────────────────────────────

/// `get_user` requires super admin; a realm admin must receive HTTP 403.
#[actix_web::test]
async fn test_get_admin_requires_super_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "realm_get_guard").await?;

    let result = realm_admin
        .get_admin_as_super_admin(APP_REALM_ADMIN_USERNAME)
        .await;

    assert!(
        result.is_err(),
        "Expected an error when non-super-admin calls get_user"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 in error message, got: {msg}"
    );
    info!("get_user correctly rejected non-super-admin with 403");

    ctx.stop_server().await
}

/// `update_user` requires super admin; a realm admin must receive HTTP 403.
#[actix_web::test]
async fn test_update_admin_requires_super_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let super_admin = authenticate_as_admin(&ctx).await?;
    super_admin
        .create_admin_as_super_admin(&test_admin("user_to_update"))
        .await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "realm_update_user_guard").await?;

    let result = realm_admin
        .update_admin_as_super_admin("user_to_update", &test_admin("user_to_update"))
        .await;

    assert!(
        result.is_err(),
        "Expected an error when non-super-admin calls update_user"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 in error message, got: {msg}"
    );
    info!("update_user correctly rejected non-super-admin with 403");

    ctx.stop_server().await
}

/// `delete_user` requires super admin; a realm admin must receive HTTP 403.
#[actix_web::test]
async fn test_delete_admin_requires_super_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let super_admin = authenticate_as_admin(&ctx).await?;
    super_admin
        .create_admin_as_super_admin(&test_admin("user_to_delete"))
        .await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "realm_delete_user_guard").await?;

    let result = realm_admin
        .delete_admin_as_super_admin("user_to_delete")
        .await;

    assert!(
        result.is_err(),
        "Expected an error when non-super-admin calls delete_user"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 in error message, got: {msg}"
    );
    info!("delete_user correctly rejected non-super-admin with 403");

    ctx.stop_server().await
}

/// `list_users` requires super admin; a realm admin must receive HTTP 403.
#[actix_web::test]
async fn test_list_admins_requires_super_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "realm_list_users_guard").await?;

    let result = realm_admin.list_admins_as_super_admin().await;

    assert!(
        result.is_err(),
        "Expected an error when non-super-admin calls list_users"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 in error message, got: {msg}"
    );
    info!("list_users correctly rejected non-super-admin with 403");

    ctx.stop_server().await
}

// ── Realm membership management ───────────────────────────────────────────────

/// A realm admin can add a user to their realm.
#[actix_web::test]
async fn test_add_admin_to_realm_by_realm_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let super_admin = authenticate_as_admin(&ctx).await?;
    let admin = test_admin("membership_target");
    super_admin.create_admin_as_super_admin(&admin).await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "membership_realm").await?;

    let updated = realm_admin
        .add_admin_to_realm("membership_target", "membership_realm")
        .await?;

    assert!(
        updated.realms.contains(&"membership_realm".to_string()),
        "Updated user must now be a member of 'membership_realm'"
    );
    info!("add_user_to_realm succeeded for realm admin");

    ctx.stop_server().await
}

/// A realm admin can remove a user from their realm.
#[actix_web::test]
async fn test_remove_admin_from_realm_by_realm_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "removal_realm").await?;

    // First add, then remove
    let super_admin = authenticate_as_admin(&ctx).await?;
    let mut admin = test_admin("removal_target");
    admin.realms = vec!["removal_realm".to_string()];
    super_admin.create_admin_as_super_admin(&admin).await?;

    let updated = realm_admin
        .remove_admin_from_realm("removal_target", "removal_realm")
        .await?;

    assert!(
        !updated.realms.contains(&"removal_realm".to_string()),
        "Admin must no longer be a member of 'removal_realm'"
    );
    info!("remove_user_from_realm succeeded for realm admin");

    ctx.stop_server().await
}

// ── Realm-admin create_user ───────────────────────────────────────────────────

/// A realm admin can create a user that belongs exclusively to their realm.
#[actix_web::test]
async fn test_create_admin_by_realm_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "create_user_ra_realm").await?;

    let mut new_user = test_admin("ra_created_user");
    new_user.realms = vec!["create_user_ra_realm".to_string()];

    let created = realm_admin.create_admin_as_super_admin(&new_user).await?;
    assert_eq!(created.id, "ra_created_user");
    assert!(
        created.realms.contains(&"create_user_ra_realm".to_string()),
        "Created user must belong to the realm admin's realm"
    );
    info!("Realm admin successfully created user in their realm");

    ctx.stop_server().await
}

/// A realm admin cannot create a user with no realm (empty `realms` list).
#[actix_web::test]
async fn test_create_admin_by_realm_admin_forbidden_no_realm() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "create_no_realm_ra").await?;

    // User with no realm — the realm admin must not be allowed to create this.
    let new_user = test_admin("ra_no_realm_user");

    let result = realm_admin.create_admin_as_super_admin(&new_user).await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin creates a user with no realm"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("403"), "Expected HTTP 403, got: {msg}");
    info!("Realm admin correctly denied creating a user with no realm");

    ctx.stop_server().await
}

/// A realm admin cannot create a user that belongs to a realm they do not administer.
#[actix_web::test]
async fn test_create_admin_by_realm_admin_forbidden_other_realm() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "create_other_realm_ra").await?;

    // User assigned to a realm this admin doesn't control
    let mut new_user = test_admin("ra_other_realm_user");
    new_user.realms = vec!["some_other_realm".to_string()];

    let result = realm_admin.create_admin_as_super_admin(&new_user).await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin creates a user for a realm they don't administer"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("403"), "Expected HTTP 403, got: {msg}");
    info!("Realm admin correctly denied creating a user for a foreign realm");

    ctx.stop_server().await
}

// ── Realm-admin get_user ──────────────────────────────────────────────────────

/// A realm admin can get a user that belongs exclusively to their realm.
#[actix_web::test]
async fn test_get_admin_by_realm_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let super_admin = authenticate_as_admin(&ctx).await?;
    let mut admin = test_admin("get_ra_target");
    admin.realms = vec!["get_ra_realm".to_string()];

    // Create the realm first, then the user
    create_and_authenticate_realm_admin(&ctx, "get_ra_realm").await?;
    super_admin.create_admin_as_super_admin(&admin).await?;

    // A fresh client authenticated as realm admin for "get_ra_realm"
    let realm_admin = {
        let scheme = crate::client::AuthClientScheme::UsernamePassword {
            username: "get_ra_realm_radmin".to_string(),
            password: "realm_admin_pass".to_string(),
        };
        let client = ctx.get_test_client(scheme);
        let (result, cookie) = client.login(ADMIN_REALM, None, None).await?;
        assert!(matches!(
            result.next_step,
            crate::AuthenticationNextStep::Authenticated
        ));
        assert!(cookie.is_some());
        client
    };

    let fetched = realm_admin
        .get_admin_as_super_admin("get_ra_target")
        .await?;
    assert_eq!(fetched.id, "get_ra_target");
    info!("Realm admin successfully retrieved a user exclusively in their realm");

    ctx.stop_server().await
}

/// A realm admin cannot get a user that also belongs to another realm.
#[actix_web::test]
async fn test_get_admin_by_realm_admin_forbidden_multi_realm() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // create_and_authenticate_realm_admin creates "get_multi_ra_realm"
    let realm_admin = create_and_authenticate_realm_admin(&ctx, "get_multi_ra_realm").await?;

    let super_admin = authenticate_as_admin(&ctx).await?;

    // Create the second realm so the user can be assigned to both
    super_admin
        .create_realm_as_super_admin(&test_realm("another_realm_x"))
        .await?;

    let mut admin = test_admin("get_multi_realm_target");
    admin.realms = vec![
        "get_multi_ra_realm".to_string(),
        "another_realm_x".to_string(),
    ];
    super_admin.create_admin_as_super_admin(&admin).await?;

    let result = realm_admin
        .get_admin_as_super_admin("get_multi_realm_target")
        .await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin gets a user belonging to multiple realms"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("403"), "Expected HTTP 403, got: {msg}");
    info!("Realm admin correctly denied getting a user that belongs to multiple realms");

    ctx.stop_server().await
}

// ── Realm-admin delete_user ───────────────────────────────────────────────────

/// A realm admin can delete a user that belongs exclusively to their realm.
#[actix_web::test]
async fn test_delete_admin_by_realm_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let super_admin = authenticate_as_admin(&ctx).await?;

    // Ensure the realm exists first by setting up a realm admin for it
    create_and_authenticate_realm_admin(&ctx, "delete_ra_realm").await?;

    let mut admin = test_admin("delete_ra_target");
    admin.realms = vec!["delete_ra_realm".to_string()];
    super_admin.create_admin_as_super_admin(&admin).await?;

    let realm_admin = {
        let scheme = crate::client::AuthClientScheme::UsernamePassword {
            username: "delete_ra_realm_radmin".to_string(),
            password: "realm_admin_pass".to_string(),
        };
        let client = ctx.get_test_client(scheme);
        let (result, cookie) = client.login(ADMIN_REALM, None, None).await?;
        assert!(matches!(
            result.next_step,
            crate::AuthenticationNextStep::Authenticated
        ));
        assert!(cookie.is_some());
        client
    };

    realm_admin
        .delete_admin_as_super_admin("delete_ra_target")
        .await?;

    // Must be gone
    let result = super_admin
        .get_admin_as_super_admin("delete_ra_target")
        .await;
    assert!(
        result.is_err(),
        "Admin must be gone after realm admin deleted it"
    );
    info!("Realm admin successfully deleted a user exclusively in their realm");

    ctx.stop_server().await
}

/// A realm admin cannot delete a user that also belongs to another realm.
#[actix_web::test]
async fn test_delete_admin_by_realm_admin_forbidden_multi_realm() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // create_and_authenticate_realm_admin creates "del_multi_ra_realm"
    let realm_admin = create_and_authenticate_realm_admin(&ctx, "del_multi_ra_realm").await?;

    let super_admin = authenticate_as_admin(&ctx).await?;

    // Create the second realm so the user can be assigned to both
    super_admin
        .create_realm_as_super_admin(&test_realm("another_realm_y"))
        .await?;

    let mut admin = test_admin("del_multi_realm_target");
    admin.realms = vec![
        "del_multi_ra_realm".to_string(),
        "another_realm_y".to_string(),
    ];
    super_admin.create_admin_as_super_admin(&admin).await?;

    let result = realm_admin
        .delete_admin_as_super_admin("del_multi_realm_target")
        .await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin deletes a user belonging to multiple realms"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("403"), "Expected HTTP 403, got: {msg}");
    info!("Realm admin correctly denied deleting a user that belongs to multiple realms");

    ctx.stop_server().await
}

/// A realm admin must not be able to add a user to a realm they do not administer.
#[actix_web::test]
async fn test_add_admin_to_realm_unauthorized() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // realm_admin administers "authorized_realm" only
    let realm_admin = create_and_authenticate_realm_admin(&ctx, "authorized_realm").await?;

    // Create a second realm the realm admin does NOT administer
    let super_admin = authenticate_as_admin(&ctx).await?;
    super_admin
        .create_realm_as_super_admin(&test_realm("unauthorized_realm"))
        .await?;
    let admin = test_admin("cross_realm_target");
    super_admin.create_admin_as_super_admin(&admin).await?;

    // Attempt to add to a realm outside the admin's authority
    let result = realm_admin
        .add_admin_to_realm("cross_realm_target", "unauthorized_realm")
        .await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin tries to manage a different realm"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 in error message, got: {msg}"
    );
    info!("add_user_to_realm correctly rejected cross-realm attempt with 403");

    ctx.stop_server().await
}

/// Adding a user who is already a member of a realm is a no-op (idempotent).
#[actix_web::test]
async fn test_add_admin_to_realm_idempotent() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "idempotent_realm").await?;

    let super_admin = authenticate_as_admin(&ctx).await?;
    let admin = test_admin("idempotent_member");
    super_admin.create_admin_as_super_admin(&admin).await?;

    // Add once
    realm_admin
        .add_admin_to_realm("idempotent_member", "idempotent_realm")
        .await?;

    // Add again — must succeed without duplicating the entry
    let updated = realm_admin
        .add_admin_to_realm("idempotent_member", "idempotent_realm")
        .await?;

    let count = updated
        .realms
        .iter()
        .filter(|r| r.as_str() == "idempotent_realm")
        .count();
    assert_eq!(
        count, 1,
        "Realm must appear exactly once after two add calls"
    );
    info!(
        "add_user_to_realm is idempotent (realm appears {} time(s))",
        count
    );

    ctx.stop_server().await
}

// ── Realm-admin update_user ───────────────────────────────────────────────────

/// A realm admin can update a user that belongs exclusively to their realm.
#[actix_web::test]
async fn test_update_admin_by_realm_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "update_ra_realm").await?;

    let super_admin = authenticate_as_admin(&ctx).await?;
    let mut admin = test_admin("update_ra_target");
    admin.realms = vec!["update_ra_realm".to_string()];
    super_admin.create_admin_as_super_admin(&admin).await?;

    // Realm admin updates the user (realm membership must be preserved in the body)
    let mut update_body = test_admin("update_ra_target");
    update_body.realms = vec!["update_ra_realm".to_string()];

    let updated = realm_admin
        .update_admin_as_super_admin("update_ra_target", &update_body)
        .await?;
    assert_eq!(updated.id, "update_ra_target");
    info!("Realm admin successfully updated a user exclusively in their realm");

    ctx.stop_server().await
}

/// A realm admin cannot update a user that also belongs to another realm.
#[actix_web::test]
async fn test_update_admin_by_realm_admin_forbidden_multi_realm() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // create_and_authenticate_realm_admin creates "update_multi_ra_realm"
    let realm_admin = create_and_authenticate_realm_admin(&ctx, "update_multi_ra_realm").await?;

    let super_admin = authenticate_as_admin(&ctx).await?;
    super_admin
        .create_realm_as_super_admin(&test_realm("another_realm_z"))
        .await?;

    let mut admin = test_admin("update_multi_realm_target");
    admin.realms = vec![
        "update_multi_ra_realm".to_string(),
        "another_realm_z".to_string(),
    ];
    super_admin.create_admin_as_super_admin(&admin).await?;

    let result = realm_admin
        .update_admin_as_super_admin("update_multi_realm_target", &admin)
        .await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin updates a user belonging to multiple realms"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("403"), "Expected HTTP 403, got: {msg}");
    info!("Realm admin correctly denied updating a user that belongs to multiple realms");

    ctx.stop_server().await
}

// ── Privilege escalation prevention ──────────────────────────────────────────

/// A realm admin cannot use `add_user_to_realm` to add a user to the super-admin
/// realm `_`.  The `can_administer_realm("_")` check must return false → HTTP 403.
#[actix_web::test]
async fn test_add_admin_to_realm_prevents_super_admin_escalation() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "escal_realm").await?;

    // The victim user currently belongs only to the realm the admin controls.
    let super_admin = authenticate_as_admin(&ctx).await?;
    let mut victim = test_admin("escal_victim");
    victim.realms = vec!["escal_realm".to_string()];
    super_admin.create_admin_as_super_admin(&victim).await?;

    // Attempt to add the victim to the super-admin realm "_".
    let result = realm_admin
        .add_admin_to_realm("escal_victim", ADMIN_REALM)
        .await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin tries to add a user to the super-admin realm"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 in error message, got: {msg}"
    );
    info!("add_user_to_realm correctly blocked escalation to super-admin realm with 403");

    ctx.stop_server().await
}

/// A realm admin cannot create a user that already contains the super-admin realm
/// `_` in its `realms` list.  The exclusive-ownership check
/// (`can_administer_realm("_")` = false) must block it → HTTP 403.
#[actix_web::test]
async fn test_create_admin_with_super_admin_realm_forbidden() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "create_escal_realm").await?;

    let mut new_user = test_admin("create_escal_user");
    // Payload includes both the admin's own realm AND the super-admin realm.
    new_user.realms = vec!["create_escal_realm".to_string(), ADMIN_REALM.to_string()];

    let result = realm_admin.create_admin_as_super_admin(&new_user).await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin creates a user that includes the super-admin realm"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("403"), "Expected HTTP 403, got: {msg}");
    info!("create_user correctly blocked super-admin realm inclusion with 403");

    ctx.stop_server().await
}

/// A realm admin cannot escalate privilege via the `update_user` body by adding the
/// super-admin realm `_` to the updated user's `realms` list.
/// The new check on the **body** realms must block it → HTTP 403.
#[actix_web::test]
async fn test_update_admin_cannot_escalate_via_body() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "body_escal_realm").await?;

    let super_admin = authenticate_as_admin(&ctx).await?;
    let mut victim = test_admin("body_escal_victim");
    victim.realms = vec!["body_escal_realm".to_string()];
    super_admin.create_admin_as_super_admin(&victim).await?;

    // Craft a body that would silently promote the user to super admin.
    let mut escalated_body = test_admin("body_escal_victim");
    escalated_body.realms = vec!["body_escal_realm".to_string(), ADMIN_REALM.to_string()];

    let result = realm_admin
        .update_admin_as_super_admin("body_escal_victim", &escalated_body)
        .await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin tries to add super-admin realm via update body"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("403"), "Expected HTTP 403, got: {msg}");
    info!("update_user correctly blocked super-admin realm escalation in body with 403");

    ctx.stop_server().await
}

/// A realm admin cannot silently extend a user's realm membership to a foreign
/// realm via the `update_user` body.  Only realms the requester administers may
/// appear in the new `realms` list → HTTP 403.
#[actix_web::test]
async fn test_update_admin_cannot_add_foreign_realm_via_body() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "body_foreign_realm").await?;

    let super_admin = authenticate_as_admin(&ctx).await?;
    super_admin
        .create_realm_as_super_admin(&test_realm("foreign_realm_q"))
        .await?;

    let mut victim = test_admin("body_foreign_victim");
    victim.realms = vec!["body_foreign_realm".to_string()];
    super_admin.create_admin_as_super_admin(&victim).await?;

    // Body quietly adds a realm the admin doesn't control.
    let mut sneaky_body = test_admin("body_foreign_victim");
    sneaky_body.realms = vec![
        "body_foreign_realm".to_string(),
        "foreign_realm_q".to_string(),
    ];

    let result = realm_admin
        .update_admin_as_super_admin("body_foreign_victim", &sneaky_body)
        .await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin's update body includes a foreign realm"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("403"), "Expected HTTP 403, got: {msg}");
    info!("update_user correctly blocked foreign realm addition in body with 403");

    ctx.stop_server().await
}

// ── Realm-admin self-removal revokes access ───────────────────────────────────

/// After a realm admin removes themselves from their own realm they should no
/// longer be able to administer it.  A subsequent call that requires realm-admin
/// rights for that realm must be rejected.
///
/// Steps:
/// 1. Set up realm admin for "self_remove_realm" (call it RA).
/// 2. Create a target user in "self_remove_realm".
/// 3. RA removes themselves from "self_remove_realm" via the realm-membership endpoint.
/// 4. RA attempts to delete the target user → must fail with 403 because `can_administer_realm` is now false.
#[actix_web::test]
async fn test_realm_admin_self_removal_revokes_access() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "self_remove_realm").await?;

    let super_admin = authenticate_as_admin(&ctx).await?;
    let mut target = test_admin("self_remove_target");
    target.realms = vec!["self_remove_realm".to_string()];
    super_admin.create_admin_as_super_admin(&target).await?;

    // The realm admin user object is named "{realm_id}_radmin_user" by the helper.
    let ra_admin_id = "self_remove_realm_radmin_user";

    // RA removes themselves from "self_remove_realm".
    realm_admin
        .remove_admin_from_realm(ra_admin_id, "self_remove_realm")
        .await?;
    info!("Realm admin removed themselves from 'self_remove_realm'");

    // RA now attempts to delete the target user — must fail because RA no longer
    // administers any realm that contains the target.
    let result = realm_admin
        .delete_admin_as_super_admin("self_remove_target")
        .await;

    assert!(
        result.is_err(),
        "Expected an error after realm admin removed themselves from their own realm"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 after self-removal, got: {msg}"
    );
    info!("API correctly rejected realm admin requests after self-removal with 403");

    ctx.stop_server().await
}

// ── User-deletion security properties ────────────────────────────────────────

/// After a user is deleted, their existing session can no longer be used to
/// access the API.  The `UserAuth` middleware resolves users by a fresh DB
/// lookup on every request, so deleting the User record immediately invalidates
/// any outstanding sessions without requiring an explicit session-store wipe.
#[actix_web::test]
async fn test_session_invalidated_after_admin_deletion() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let super_admin = authenticate_as_admin(&ctx).await?;

    // Create a transient user and give them credentials.
    let mut transient_user = test_admin("deleted_user_session");
    transient_user.realms = vec![ADMIN_REALM.to_string()];
    transient_user.userpass = Some("deleted_user_session".to_string());
    super_admin
        .create_admin_as_super_admin(&transient_user)
        .await?;
    let userpass = create_user(ADMIN_REALM, "deleted_user_session", "temp_pass", false)?;
    super_admin
        .create_admin_credentials_in_realm(ADMIN_REALM, &userpass)
        .await?;

    // Log in as the transient user and verify the session works.
    let scheme = crate::client::AuthClientScheme::UsernamePassword {
        username: "deleted_user_session".to_string(),
        password: "temp_pass".to_string(),
    };
    let transient_client = ctx.get_test_client(scheme);
    let (res, cookie) = transient_client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(res.next_step, AuthenticationNextStep::Authenticated),
        "Transient user login must succeed"
    );
    assert!(cookie.is_some());

    // The session works before deletion — call a UserAuth-guarded endpoint.
    transient_client.list_admins_as_super_admin().await?;

    // Delete the user record.
    super_admin
        .delete_admin_as_super_admin("deleted_user_session")
        .await?;
    info!("Transient user 'deleted_user_session' deleted");

    // The session must now be rejected on any UserAuth-guarded endpoint.
    // (whoami has no UserAuth layer and reflects the cookie's claims without a DB
    // lookup; /users goes through UserAuth which does find_users_by_auth_scheme
    // → returns nothing for the deleted user → 401.)
    let err = transient_client
        .list_admins_as_super_admin()
        .await
        .expect_err("Expected 401 after user deletion");
    let msg = err.to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 after user deletion, got: {msg}"
    );
    info!("Session correctly invalidated after user deletion (401)");

    ctx.stop_server().await
}

/// After a user is deleted, the associated `userpass` credentials must also be
/// deleted (cascade delete).  The `delete_user` endpoint calls
/// `delete_userpass_by_username` on the retrieved credential username so no
/// orphaned entries remain in the `userpass` table.
#[actix_web::test]
async fn test_delete_admin_cascades_credentials() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let super_admin = authenticate_as_admin(&ctx).await?;

    // Create user with credentials.
    let mut cascade_user = test_admin("cascade_creds_user");
    cascade_user.realms = vec![ADMIN_REALM.to_string()];
    cascade_user.userpass = Some("cascade_creds_user".to_string());
    super_admin
        .create_admin_as_super_admin(&cascade_user)
        .await?;
    let userpass = create_user(ADMIN_REALM, "cascade_creds_user", "cascade_pass", false)?;
    super_admin
        .create_admin_credentials_in_realm(ADMIN_REALM, &userpass)
        .await?;

    // Verify credentials exist before deletion.
    let before = super_admin
        .get_admin_credentials_in_realm(ADMIN_REALM, "cascade_creds_user")
        .await;
    assert!(
        before.is_ok(),
        "Credentials must exist before user deletion"
    );

    // Delete the user.
    super_admin
        .delete_admin_as_super_admin("cascade_creds_user")
        .await?;
    info!("Admin 'cascade_creds_user' deleted");

    // Credentials must be gone — cascade delete must have cleaned them up.
    let after = super_admin
        .get_admin_credentials_in_realm(ADMIN_REALM, "cascade_creds_user")
        .await;
    assert!(
        after.is_err(),
        "Credentials must be removed after user deletion (cascade delete)"
    );
    info!("Confirmed: userpass credentials correctly cascade-deleted with the user");

    ctx.stop_server().await
}

/// After a session is explicitly deleted the same session ID must be rejected on
/// all subsequent requests.  This verifies that a captured token cannot be
/// replayed after the victim logs out (session invalidation).
#[actix_web::test]
async fn test_session_replay_after_logout() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // Create a fresh user so we can independently manage sessions.
    let super_admin = authenticate_as_admin(&ctx).await?;
    let mut replay_user = test_admin("replay_user");
    replay_user.realms = vec![ADMIN_REALM.to_string()];
    replay_user.userpass = Some("replay_user".to_string());
    super_admin
        .create_admin_as_super_admin(&replay_user)
        .await?;
    let userpass = create_user(ADMIN_REALM, "replay_user", "replay_pass", false)?;
    super_admin
        .create_admin_credentials_in_realm(ADMIN_REALM, &userpass)
        .await?;

    // Log in as the replay user.
    let scheme = crate::client::AuthClientScheme::UsernamePassword {
        username: "replay_user".to_string(),
        password: "replay_pass".to_string(),
    };
    let victim_client = ctx.get_test_client(scheme);
    let (res, _cookie) = victim_client.login(ADMIN_REALM, None, None).await?;
    assert!(matches!(
        res.next_step,
        AuthenticationNextStep::Authenticated
    ));
    let session_id = res.session_id.expect("Login must return a session_id");

    // Confirm the session is live.
    let session_value = victim_client.get_session(&session_id).await?;
    assert!(
        session_value.is_some(),
        "Session must be retrievable after login"
    );

    // Simulate explicit logout: delete the session.
    victim_client
        .delete_sessions(std::slice::from_ref(&session_id))
        .await?;
    info!("Session '{session_id}' deleted (logout)");

    // The session must now be gone from the store.
    let replayed = victim_client.get_session(&session_id).await?;
    assert!(
        replayed.is_none(),
        "Session must not be retrievable after deletion (replay blocked)"
    );
    info!("Session replay correctly blocked after logout");

    ctx.stop_server().await
}

/// Submitting an excessively long admin ID (1 000 chars) must be handled
/// gracefully by the server — no panic, no 500, just a 4xx response.
#[actix_web::test]
async fn test_oversized_admin_id_rejected() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    let long_id = "x".repeat(1000);
    let result = client.get_admin_as_super_admin(&long_id).await;

    assert!(
        result.is_err(),
        "Expected an error for an excessively long admin ID"
    );
    // Must not be a 500 — the server must not panic.
    let msg = result.unwrap_err().to_string();
    assert!(
        !msg.contains("500"),
        "Server must handle oversized IDs without a 500 error, got: {msg}"
    );
    info!("Oversized admin ID handled gracefully (no 500): {msg}");

    ctx.stop_server().await
}

/// Submitting a realm ID containing a path-traversal attempt must be handled
/// gracefully — the router's path extractor must reject or normalise it without
/// a 500 / panic.
#[actix_web::test]
async fn test_realm_id_with_special_characters() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    // `%2F` is URL-encoded `/` — a classic path-traversal attempt.
    // The raw HTTP path `/admins/realms/..%2F_` should not expose `_` via traversal.
    let result = client.get_realm_as_super_admin("..%2F_").await;

    assert!(
        result.is_err(),
        "Expected an error for a realm ID with path-traversal characters"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        !msg.contains("500"),
        "Server must handle special-character realm IDs without a 500, got: {msg}"
    );
    info!("Special-character realm ID handled gracefully (no 500): {msg}");

    ctx.stop_server().await
}

// ── Password field security ───────────────────────────────────────────────────

/// The `get_userpass` endpoint must never return the stored password hash.
/// The `password` field on the returned [`UserPass`] must be empty.
#[actix_web::test]
async fn test_get_adminpass_returns_empty_password() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    // Create a test realm and credentials to retrieve.
    let realm_id = "pw_security_realm";
    let username = "pw_security_user";
    let password = "super_secret_password";

    client
        .create_realm_as_super_admin(&Realm {
            id: realm_id.to_string(),
            auth_params: RealmAuthParams::default(),
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
        })
        .await?;

    let userpass = create_user(realm_id, username, password, false)?;
    client
        .create_admin_credentials_in_realm(realm_id, &userpass)
        .await?;

    info!("Retrieving credentials via get_userpass...");
    let retrieved = client
        .get_admin_credentials_in_realm(realm_id, username)
        .await?;

    assert_eq!(retrieved.username, username, "username must round-trip");
    assert_eq!(retrieved.realm, realm_id, "realm must round-trip");
    assert!(
        retrieved.password.is_empty(),
        "password hash must not be returned to callers; expected empty Vec<u8>, got {} bytes",
        retrieved.password.len()
    );

    ctx.stop_server().await
}
