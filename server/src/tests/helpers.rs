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

/// Base64 DER of the EC test server certificate, as it appears in an `<X509Certificate>`.
#[cfg(feature = "saml")]
pub fn test_idp_certificate_base64() -> String {
    include_str!("certificates/ec/auth.server.cert.pem")
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect()
}

/// SAML 2.0 IdP metadata signing with the EC test certificate; `extra` is inserted into the
/// `IDPSSODescriptor` (e.g. a `NameIDFormat`).
#[cfg(feature = "saml")]
pub fn test_idp_metadata(sso_binding: &str, sso_url: &str, extra: &str) -> String {
    format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com/metadata">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    {extra}
    <md:SingleSignOnService Binding="{sso_binding}" Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
        cert = test_idp_certificate_base64()
    )
}

/// SAML settings for `realm_id` that pass validation.
#[cfg(feature = "saml")]
pub fn test_saml_params(realm_id: &str) -> crate::SamlParams {
    crate::SamlParams {
        metadata_xml: Some(test_idp_metadata(
            samael::metadata::HTTP_REDIRECT_BINDING,
            "https://idp.example.com/sso",
            "",
        )),
        sp_entity_id: format!("https://auth.example.com/saml/{realm_id}"),
        sp_acs_url: format!("https://auth.example.com/saml/{realm_id}/acs"),
        allowed_return_origins: vec!["https://app.example.com".to_string()],
        default_return_url: "https://app.example.com/home".to_string(),
        ..Default::default()
    }
}

/// SAML SP signing key configuration using the RSA-4096 test server key and certificate.
#[cfg(feature = "saml")]
pub fn test_saml_sp_params() -> crate::server::parameters::SamlSpParams {
    let rsa_dir = format!("{}/src/tests/certificates/rsa", env!("CARGO_MANIFEST_DIR"));
    crate::server::parameters::SamlSpParams {
        saml_rsa_private_key: format!("{rsa_dir}/auth.server.key.pem"),
        saml_certificate: format!("{rsa_dir}/auth.server.cert.pem"),
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
    target_client.add_admin_to_realm(&solo_id, realm_a).await?;

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
