//! API tests for the super-admin realm endpoints (`/admins/realms/*`).
//!
//! Each test:
//! 1. Starts a fresh in-memory test server.
//! 2. Authenticates as the seeded `admin` user via [`AuthClient::authenticate`], which stores
//!    the resulting `_ea_` session cookie in the client's cookie jar.
//! 3. Makes subsequent requests with the **same** [`AuthClient`] instance so the cookie is
//!    automatically sent on every call.

use crate::{
    AuthError, AuthResult,
    models::ADMIN_REALM,
    tests::{
        helpers::{
            authenticate_as_admin, create_and_authenticate_realm_admin, create_userpass, test_realm,
        },
        init_test_logging, start_default_test_server,
    },
};
use cosmian_logger::info;

// Alias for backwards-compatibility with local call sites.
fn create_user(
    realm: &str,
    username: &str,
    password: &str,
    change_password: bool,
) -> AuthResult<crate::models::UserPass> {
    create_userpass(realm, username, password, change_password)
}

// ── GET /admins/realms ────────────────────────────────────────────────────────

/// After authentication the realm list must include at least the seeded `_` realm.
#[actix_web::test]
async fn test_list_realms() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    let realms = client.list_realms_as_super_admin().await?;

    assert!(
        !realms.is_empty(),
        "Expected at least one realm in the list"
    );
    assert!(
        realms.iter().any(|r| r.id == ADMIN_REALM),
        "Expected the default '{}' realm to be present",
        ADMIN_REALM
    );
    info!("list_realms returned {} realm(s)", realms.len());

    ctx.stop_server().await
}

// ── GET /admins/realms/{id} ──────────────────────────────────────────────────

/// Fetching the seeded `_` realm must succeed and return its ID.
#[actix_web::test]
async fn test_get_realm() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    let realm = client.get_realm_as_super_admin(ADMIN_REALM).await?;

    assert_eq!(realm.id, ADMIN_REALM, "Expected realm ID to match");
    assert!(
        realm.session_max_age_seconds > 0,
        "Expected a positive session max age"
    );
    info!("get_realm returned realm: {}", realm.id);

    ctx.stop_server().await
}

/// Requesting a realm that does not exist must return an error.
#[actix_web::test]
async fn test_get_realm_not_found() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    let result = client
        .get_realm_as_super_admin("realm_that_does_not_exist")
        .await;

    assert!(
        result.is_err(),
        "Expected an error for a non-existent realm"
    );
    info!("get_realm_not_found returned expected error");

    ctx.stop_server().await
}

// ── PUT /admins/realms/{id} ──────────────────────────────────────────────────

/// Updating the `_` realm with a new `session_max_age_seconds` must succeed and
/// the change must be visible on a subsequent GET.
#[actix_web::test]
async fn test_update_realm() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    // Fetch current state
    let mut realm = client.get_realm_as_super_admin(ADMIN_REALM).await?;
    let original = realm.session_max_age_seconds;
    let updated_max_age = original + 100;
    realm.session_max_age_seconds = updated_max_age;

    // Issue the update
    let updated = client
        .update_realm_as_super_admin(ADMIN_REALM, &realm)
        .await?;

    assert_eq!(updated.id, ADMIN_REALM);
    assert_eq!(
        updated.session_max_age_seconds, updated_max_age,
        "Response must reflect the new max_age"
    );

    // Verify the change was persisted
    let re_fetched = client.get_realm_as_super_admin(ADMIN_REALM).await?;
    assert_eq!(
        re_fetched.session_max_age_seconds, updated_max_age,
        "Persisted max_age must match what was written"
    );
    info!(
        "update_realm: session_max_age_seconds changed from {} to {}",
        original, updated_max_age
    );

    ctx.stop_server().await
}

// ── DELETE /admins/realms/{id} ───────────────────────────────────────────────

/// Deleting a realm that does not exist returns HTTP 204 (the underlying SQL
/// DELETE is a no-op and does not raise an error).
#[actix_web::test]
async fn test_delete_realm_nonexistent_is_idempotent() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    client
        .delete_realm_as_super_admin("realm_that_never_existed")
        .await?;

    info!("delete_realm for a non-existent realm succeeded (no-op, idempotent)");

    ctx.stop_server().await
}

// ── POST /admins/realms ──────────────────────────────────────────────────────

#[actix_web::test]
async fn test_create_realm() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    let result = client
        .create_realm_as_super_admin(&test_realm("new_realm_under_test"))
        .await;

    assert!(
        result.is_ok(),
        "Expected create_realm to succeed: {:?}",
        result
    );
    info!(
        "create_realm returned expected result: {:?}",
        result.unwrap()
    );

    ctx.stop_server().await
}

/// Creating a realm whose ID already exists must return a clean `409 Conflict`,
/// not a `500` leaking the underlying database error.
#[actix_web::test]
async fn test_create_duplicate_realm_fails() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    // The `_` admin realm is always seeded — trying to create it again must fail.
    let result = client
        .create_realm_as_super_admin(&test_realm(ADMIN_REALM))
        .await;

    let err = result.expect_err("Expected an error when creating a duplicate realm");
    assert!(
        matches!(err, AuthError::FailedHttpStatus(ref m) if m.contains("409")),
        "Expected a 409 Conflict, got: {err:?}"
    );
    info!("create_duplicate_realm returned expected error: {err:?}");

    ctx.stop_server().await
}

// ── Authorization enforcement ────────────────────────────────────────────────

/// A realm admin (non-super-admin) must not be able to update any realm (HTTP 403).
#[actix_web::test]
async fn test_update_realm_requires_super_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "realm_update_guard").await?;
    let realm = test_realm("realm_update_guard");

    let result = realm_admin
        .update_realm_as_super_admin("realm_update_guard", &realm)
        .await;

    assert!(
        result.is_err(),
        "Expected an error when a non-super-admin tries to update a realm"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 in error message, got: {msg}"
    );
    info!("update_realm correctly rejected non-super-admin with 403");

    ctx.stop_server().await
}

/// A realm admin must not be able to delete any realm (HTTP 403).
#[actix_web::test]
async fn test_delete_realm_requires_super_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "realm_delete_guard").await?;

    let result = realm_admin
        .delete_realm_as_super_admin("realm_delete_guard")
        .await;

    assert!(
        result.is_err(),
        "Expected an error when a non-super-admin tries to delete a realm"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 in error message, got: {msg}"
    );
    info!("delete_realm correctly rejected non-super-admin with 403");

    ctx.stop_server().await
}

/// `list_realms` must return only the realms administered by the caller when the
/// caller is not a super admin.
#[actix_web::test]
async fn test_list_realms_filtered_for_realm_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // create_and_authenticate_realm_admin creates "realm_visible" and makes this client its admin
    let realm_admin = create_and_authenticate_realm_admin(&ctx, "realm_visible").await?;

    // Super admin creates a second realm that the realm admin has no rights to
    let super_admin = authenticate_as_admin(&ctx).await?;
    super_admin
        .create_realm_as_super_admin(&test_realm("realm_invisible"))
        .await?;

    let visible = realm_admin.list_realms_as_super_admin().await?;

    assert!(
        visible.iter().any(|r| r.id == "realm_visible"),
        "Realm admin must see their own realm"
    );
    assert!(
        !visible.iter().any(|r| r.id == "realm_invisible"),
        "Realm admin must NOT see a realm they don't administer"
    );
    assert!(
        !visible.iter().any(|r| r.id == ADMIN_REALM),
        "Realm admin must NOT see the super-admin realm '{}' unless they administer it",
        ADMIN_REALM
    );
    info!(
        "list_realms filtered: realm admin sees {:?}",
        visible.iter().map(|r| &r.id).collect::<Vec<_>>()
    );

    ctx.stop_server().await
}

// ── Userpass endpoint authorisation ──────────────────────────────────────────

/// A realm admin for realm X must not be able to manage credentials in the admin
/// realm `_` because they do not administer it.
///
/// `create_admin_credentials_in_realm(ADMIN_REALM, …)` calls
/// `POST /realms/_/userpass?realm=_`.  The cookie used was issued by `_` (so
/// decryption succeeds), but the authorisation check — `can_administer_realm("_")`
/// — is false for the realm admin → HTTP 403.
#[actix_web::test]
async fn test_userpass_endpoints_require_realm_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // realm admin for "rp_realm" does NOT administer ADMIN_REALM ("_")
    let realm_admin = create_and_authenticate_realm_admin(&ctx, "rp_realm").await?;

    let userpass = create_user(ADMIN_REALM, "some_user", "some_pass", false)?;
    let result = realm_admin
        .create_admin_credentials_in_realm(ADMIN_REALM, &userpass)
        .await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin creates credentials in a realm they don't administer"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("403"), "Expected HTTP 403, got: {msg}");
    info!("userpass endpoint correctly rejected realm admin with 403");

    ctx.stop_server().await
}

// ── Userpass CRUD (super admin in their own realm) ────────────────────────────

/// Super admin can create, retrieve, update, and delete credentials in `_`.
#[actix_web::test]
async fn test_userpass_crud_by_super_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    let userpass = create_user(ADMIN_REALM, "crud_test_user", "initial_pass", false)?;

    // CREATE
    client
        .create_admin_credentials_in_realm(ADMIN_REALM, &userpass)
        .await?;
    info!("userpass created");

    // READ
    let fetched = client
        .get_admin_credentials_in_realm(ADMIN_REALM, "crud_test_user")
        .await?;
    assert_eq!(fetched.username, "crud_test_user");
    assert_eq!(fetched.realm, ADMIN_REALM);
    info!("userpass retrieved");

    // UPDATE
    let new_pass = create_user(ADMIN_REALM, "crud_test_user", "updated_pass", false)?;
    let updated = client
        .update_admin_credentials_in_realm(ADMIN_REALM, "crud_test_user", &new_pass)
        .await?;
    assert_eq!(updated.username, "crud_test_user");
    info!("userpass updated");

    // LIST BY REALM
    let list = client.list_admin_credentials_in_realm(ADMIN_REALM).await?;
    assert!(
        list.iter().any(|u| u.username == "crud_test_user"),
        "crud_test_user must appear in the realm list"
    );
    info!("userpass listed by realm ({} entries)", list.len());

    // LIST ALL (super admin only)
    let all = client.list_all_userpass_as_super_admin().await?;
    assert!(
        all.iter().any(|u| u.username == "crud_test_user"),
        "crud_test_user must appear in the global list"
    );
    info!("list_all_userpass returned {} entries", all.len());

    // DELETE
    client
        .delete_admin_credentials_in_realm(ADMIN_REALM, "crud_test_user")
        .await?;
    info!("userpass deleted");

    // Must be gone
    let result = client
        .get_admin_credentials_in_realm(ADMIN_REALM, "crud_test_user")
        .await;
    assert!(result.is_err(), "Expected not-found after deletion");
    info!("userpass CRUD roundtrip complete");

    ctx.stop_server().await
}

// ── list_all_userpass requires super admin ────────────────────────────────────

/// `GET /admins/userpass` is in the `/admins` scope which hosts super-admin-only
/// endpoints.  A realm admin calling it must receive HTTP 403.
#[actix_web::test]
async fn test_list_all_userpass_requires_super_admin() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let realm_admin = create_and_authenticate_realm_admin(&ctx, "list_all_up_guard").await?;

    let result = realm_admin.list_all_userpass_as_super_admin().await;

    assert!(
        result.is_err(),
        "Expected an error when realm admin calls list_all_userpass"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 in error message, got: {msg}"
    );
    info!("list_all_userpass correctly rejected non-super-admin with 403");

    ctx.stop_server().await
}

// ── Unauthenticated access to protected scopes ────────────────────────────────

/// All `/admins/realms/*` endpoints must return HTTP 401 for a client that has never
/// authenticated (no session cookie, no credentials).
#[actix_web::test]
async fn test_unauthenticated_access_to_admin_endpoints() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let unauthenticated = ctx.get_test_client(crate::client::AuthClientScheme::None);

    // GET /admins/realms/_
    let result = unauthenticated.get_realm_as_super_admin(ADMIN_REALM).await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 for unauthenticated GET /admins/realms/_, got: {msg}"
    );

    // GET /admins/realms
    let result = unauthenticated.list_realms_as_super_admin().await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 for unauthenticated GET /admins/realms, got: {msg}"
    );

    // GET /admins/userpass
    let result = unauthenticated.list_all_userpass_as_super_admin().await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 for unauthenticated GET /admins/userpass, got: {msg}"
    );

    info!("All /admins/realms/* endpoints correctly returned 401 for unauthenticated requests");

    ctx.stop_server().await
}

/// All `/realms/*` credential endpoints must return HTTP 401 for a client that
/// has never authenticated.
#[actix_web::test]
async fn test_unauthenticated_access_to_realms_endpoints() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let unauthenticated = ctx.get_test_client(crate::client::AuthClientScheme::None);

    // GET /realms/_/userpass/someuser?realm=_
    let result = unauthenticated
        .get_admin_credentials_in_realm(ADMIN_REALM, "someuser")
        .await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 for unauthenticated GET /realms/_, got: {msg}"
    );

    // GET /realms/_/userpass?realm=_
    let result = unauthenticated
        .list_admin_credentials_in_realm(ADMIN_REALM)
        .await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 for unauthenticated GET /realms/_/userpass, got: {msg}"
    );

    info!("All /realms/* endpoints correctly returned 401 for unauthenticated requests");

    ctx.stop_server().await
}

// ── updateUserpass cannot change realm ───────────────────────────────────────

/// Even if the PUT body contains a different `realm` value, the handler
/// overwrites it with the realm from the URL path.  This prevents a credential
/// from being silently moved to a different realm.
#[actix_web::test]
async fn test_update_userpass_cannot_change_realm() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    // Create credentials in the admin realm.
    let userpass = create_user(ADMIN_REALM, "realm_change_user", "initial_pass", false)?;
    client
        .create_admin_credentials_in_realm(ADMIN_REALM, &userpass)
        .await?;

    // Create a second realm to smuggle the credential into.
    client
        .create_realm_as_super_admin(&test_realm("realm_change_target"))
        .await?;

    // Craft a body that claims to belong to "realm_change_target".
    let smuggled = create_user(
        "realm_change_target",
        "realm_change_user",
        "new_pass",
        false,
    )?;

    // Update via the `_` path — the endpoint must keep realm = "_".
    let updated = client
        .update_admin_credentials_in_realm(ADMIN_REALM, "realm_change_user", &smuggled)
        .await?;

    assert_eq!(
        updated.realm, ADMIN_REALM,
        "Realm must be taken from the URL path, not the body; got: {}",
        updated.realm
    );
    assert_eq!(updated.username, "realm_change_user");
    info!("update_userpass correctly ignores the realm in the body; uses path realm");

    ctx.stop_server().await
}

// Test that the user that authenticates against a particular realm (mot being the ADMIN realm) cannot perform an operation on another realm.
// For example, a user that authenticates against realm "A" cannot perform an operation on realm "B".
#[actix_web::test]
async fn test_realm_admin_cannot_operate_on_other_realms() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = authenticate_as_admin(&ctx).await?;

    // Create realm B
    client
        .create_realm_as_super_admin(&test_realm("realm_b"))
        .await?;

    // Create a realm admin for realm A
    let realm_admin_a = create_and_authenticate_realm_admin(&ctx, "realm_a").await?;

    // Attempt to create credentials in realm B using realm admin A - should fail with 403
    let userpass = create_user("realm_b", "user_in_b", "password", false)?;
    let result = realm_admin_a
        .create_admin_credentials_in_realm("realm_b", &userpass)
        .await;
    assert!(
        result.is_err(),
        "Expected an error when realm admin tries to operate on another realm"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("403"), "Expected HTTP 403, got: {msg}");
    info!(
        "Realm admin for realm_a correctly received 403 when trying to create credentials in realm_b"
    );
    Ok(())
}
