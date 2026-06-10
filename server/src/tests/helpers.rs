//! Shared test helpers used across multiple integration test modules.

use crate::{
    AuthResult, AuthenticationNextStep, Realm, RealmAuthParams,
    client::{AuthClient, AuthClientScheme},
    database::{
        APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME, hash_password_with_argon2,
    },
    models::{ADMIN_REALM, Admin, UserPass},
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

pub fn create_userpass(
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
        roles: Vec::new(),
        domain: None,
    })
}

/// Authenticate as the seeded super admin and return a ready-to-use client.
pub async fn authenticate_as_admin(ctx: &TestsContext) -> AuthResult<AuthClient> {
    let client = ctx.get_test_client(admin_scheme());
    let (result, cookie) = client.login(ADMIN_REALM, None, None).await?;
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
    let (result, cookie) = client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after realm admin login"
    );
    assert!(cookie.is_some(), "Expected session cookie for realm admin");
    info!("Authenticated as realm admin for '{}'", realm_id);
    Ok(client)
}
