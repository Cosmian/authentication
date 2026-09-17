//! Shared test helpers used across multiple integration test modules.

use crate::{
    AuthResult, AuthenticationNextStep, Realm, RealmAuthParams,
    client::{AuthClient, AuthClientScheme},
    database::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME},
    models::{ADMIN_REALM, Admin, PasswordInput, UserPass},
    tests::TestsContext,
};
use cosmian_logger::info;

// ── Common builder helpers ────────────────────────────────────────────────────

pub fn admin_scheme() -> AuthClientScheme {
    AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    }
}

pub fn test_realm(id: &str) -> Realm {
    Realm {
        id: id.to_string(),
        auth_params: RealmAuthParams::default(),
        session_max_age_seconds: 3600,
        session_max_stale_age_seconds: 3600,
        certificate_max_age_seconds: 365 * 24 * 3600,
    }
}

pub fn test_admin(id: &str) -> Admin {
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

/// Build a [`UserPass`] with plaintext password bytes for use with the HTTP API.
/// The server is responsible for hashing the password before storage.
pub fn create_userpass(
    realm: &str,
    username: &str,
    password: &str,
    change_password: bool,
) -> AuthResult<UserPass> {
    Ok(UserPass {
        realm: realm.to_string(),
        username: username.to_string(),
        password_hash: String::new(),
        password_input: Some(PasswordInput::Plaintext(password.to_string())),
        change_password,
        roles: Vec::new(),
        extra_claims: None,
    })
}

/// Authenticate as the seeded super admin and return a ready-to-use client.
pub async fn authenticate_as_admin(ctx: &TestsContext) -> AuthResult<AuthClient> {
    let client = ctx.get_test_client(admin_scheme());
    let (result, cookie) = client.login(ADMIN_REALM, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated next step after super admin login"
    );
    assert!(cookie.is_some(), "Expected a session cookie after login");
    Ok(client)
}

/// Create a realm, register userpass credentials for a realm-admin user, create
/// the corresponding `Admin` record with `realm_id` in its `realms` list, and
/// return a client that is already authenticated as that realm admin.
///
/// The returned client session is **not** a super admin.
pub async fn create_and_authenticate_realm_admin(
    ctx: &TestsContext,
    realm_id: &str,
) -> AuthResult<AuthClient> {
    let super_admin = authenticate_as_admin(ctx).await?;

    super_admin
        .create_realm_as_super_admin(&test_realm(realm_id))
        .await?;

    authenticate_new_realm_admin(ctx, realm_id).await
}

/// Like [`create_and_authenticate_realm_admin`], but for a realm that
/// already exists (e.g. one created earlier in the test while still
/// unclaimed) — does not attempt to create the realm itself, so it can be
/// used without hitting the duplicate-realm `409 Conflict`.
///
/// The returned client session is **not** a super admin.
pub async fn authenticate_new_realm_admin(
    ctx: &TestsContext,
    realm_id: &str,
) -> AuthResult<AuthClient> {
    let super_admin = authenticate_as_admin(ctx).await?;

    let username = format!("{realm_id}_radmin");
    let password = "realm_admin_pass";
    let userpass = create_userpass(ADMIN_REALM, &username, password, false)?;
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
    let (result, cookie) = client.login(ADMIN_REALM, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after realm admin login"
    );
    assert!(cookie.is_some(), "Expected session cookie for realm admin");
    info!("Authenticated as realm admin for '{}'", realm_id);
    Ok(client)
}

/// Build a "multi-realm target" admin spanning `realm_a` and `realm_b`
/// (created while both are still unclaimed, so a super admin may do it in
/// one call) plus a genuinely separate admin exclusively scoped to
/// `realm_a` — used by tests asserting that a realm admin cannot act on an
/// admin that also belongs to a foreign realm they don't control.
///
/// Once `target_id` exists with `realm_a` in its `realms`, `realm_a` counts
/// as claimed — no one but an existing admin of `realm_a` (i.e. the target
/// itself) can grant further admins membership in it. So the target is
/// given login credentials and used, via `add_admin_to_realm`, to admit the
/// separate "solo" admin into `realm_a` — the only way to construct this
/// state once the exclusive-ownership rule closes bootstrap access to an
/// already-claimed realm.
///
/// Returns a client authenticated as the solo admin (a real, independent
/// admin of `realm_a` that does not control `realm_b`).
pub async fn create_multi_realm_target_and_foreign_realm_admin(
    ctx: &TestsContext,
    realm_a: &str,
    realm_b: &str,
    target_id: &str,
) -> AuthResult<AuthClient> {
    let super_admin = authenticate_as_admin(ctx).await?;
    super_admin
        .create_realm_as_super_admin(&test_realm(realm_a))
        .await?;
    super_admin
        .create_realm_as_super_admin(&test_realm(realm_b))
        .await?;

    let target_username = format!("{target_id}_login");
    let target_password = "target_login_pass";
    let target_userpass = create_userpass(ADMIN_REALM, &target_username, target_password, false)?;
    super_admin
        .create_admin_credentials_in_realm(ADMIN_REALM, &target_userpass)
        .await?;

    let mut target = test_admin(target_id);
    target.realms = vec![realm_a.to_string(), realm_b.to_string()];
    target.userpass = Some(target_username.clone());
    super_admin.create_admin_as_super_admin(&target).await?;

    let target_client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: target_username,
        password: target_password.to_string(),
    });
    let (result, cookie) = target_client.login(ADMIN_REALM, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after target login"
    );
    assert!(cookie.is_some(), "Expected session cookie for target");

    let solo_id = format!("{realm_a}_solo_admin");
    let solo_username = format!("{solo_id}_login");
    let solo_password = "solo_login_pass";
    let solo_userpass = create_userpass(ADMIN_REALM, &solo_username, solo_password, false)?;
    super_admin
        .create_admin_credentials_in_realm(ADMIN_REALM, &solo_userpass)
        .await?;
    let mut solo_admin = test_admin(&solo_id);
    solo_admin.userpass = Some(solo_username.clone());
    super_admin.create_admin_as_super_admin(&solo_admin).await?;

    // The target already directly belongs to realm_a, so it may grant the
    // solo admin membership in it.
    target_client
        .add_admin_to_realm(&solo_id, realm_a)
        .await?;

    let solo_client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: solo_username,
        password: solo_password.to_string(),
    });
    let (result, cookie) = solo_client.login(ADMIN_REALM, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after solo admin login"
    );
    assert!(cookie.is_some(), "Expected session cookie for solo admin");
    info!(
        "Authenticated as a solo admin of '{}', separate from multi-realm target '{}'",
        realm_a, target_id
    );
    Ok(solo_client)
}
