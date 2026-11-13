//! Regression tests for issue #130, findings A-F: who may manage the `_` login and the 2FA of an
//! admin, and what admin and credential responses may contain.
//!
//! Rule under test: to create, read, change or delete the `_` login `u`, or its 2FA, the caller
//! must be able to manage every admin record using `u` (its `userpass` or its id); when no admin
//! uses `u`, only a super admin may.

use crate::{
    AuthError, AuthResult, AuthScheme, AuthenticationNextStep,
    client::{AuthClient, AuthClientScheme},
    database::{
        APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME, Database, SqliteDatabase,
    },
    middleware::find_admin_for_claims,
    models::{ADMIN_REALM, ClientClaims},
    tests::{
        TestsContext,
        helpers::{
            authenticate_as_admin, create_and_authenticate_realm_admin, create_userpass, is_http,
            login_realm_user, test_admin,
        },
        start_default_test_server,
    },
};
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePoolOptions;

const REALM_ADMIN_LOGIN: &str = "acme_radmin";
const REALM_ADMIN_RECORD: &str = "acme_radmin_user";
const REALM_ADMIN_PASSWORD: &str = "realm_admin_pass";

fn totp_code(secret: &str, username: &str) -> AuthResult<String> {
    crate::totp::Totps::from_secret(secret, None, username.to_string(), None)?
        .generate_current_token()
}

/// Enrols 2FA for the `_` login `username` through the API and returns the secret.
async fn enrol_totp(client: &AuthClient, username: &str) -> AuthResult<String> {
    let generated = client.generate_totp(ADMIN_REALM, username, None).await?;
    let token = totp_code(&generated.secret_base32, username)?;
    client
        .verify_and_enable_totp(
            ADMIN_REALM,
            username,
            &generated.secret_base32,
            &token,
            None,
        )
        .await?;
    Ok(generated.secret_base32)
}

async fn login_step(
    ctx: &TestsContext,
    username: &str,
    password: &str,
    code: Option<String>,
) -> AuthResult<AuthenticationNextStep> {
    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: username.to_string(),
        password: password.to_string(),
    });
    Ok(client.login(ADMIN_REALM, code).await?.0.next_step)
}

async fn body_of(client: &AuthClient, path: &str) -> AuthResult<String> {
    Ok(client.get_raw(path).await?.text().await.unwrap_or_default())
}

// ── A, C: 2FA ────────────────────────────────────────────────────────────────

/// A realm admin cannot turn off or replace the 2FA of an admin it does not manage.
#[actix_web::test]
async fn test_realm_admin_cannot_change_the_2fa_of_other_admins() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let alice = create_and_authenticate_realm_admin(&ctx, "acme").await?;
    let super_admin = authenticate_as_admin(&ctx).await?;
    let secret = enrol_totp(&super_admin, APP_REALM_ADMIN_USERNAME).await?;

    let attacker_secret = crate::totp::Totps::new()?.generate_secret();
    let attacker_token = totp_code(&attacker_secret, APP_REALM_ADMIN_USERNAME)?;
    for realm in [ADMIN_REALM, "acme"] {
        let disabled = alice.disable_totp(realm, APP_REALM_ADMIN_USERNAME).await;
        assert!(disabled.is_err(), "disable via '{realm}' must be refused");
        let replaced = alice
            .verify_and_enable_totp(
                realm,
                APP_REALM_ADMIN_USERNAME,
                &attacker_secret,
                &attacker_token,
                None,
            )
            .await;
        assert!(replaced.is_err(), "replace via '{realm}' must be refused");
    }
    let through_admin_realm = alice
        .disable_totp(ADMIN_REALM, APP_REALM_ADMIN_USERNAME)
        .await;
    assert!(
        is_http(&through_admin_realm, 403),
        "{through_admin_realm:?}"
    );

    let step = login_step(
        &ctx,
        APP_REALM_ADMIN_USERNAME,
        APP_REALM_ADMIN_INITIAL_PASSWORD,
        None,
    )
    .await?;
    assert!(matches!(step, AuthenticationNextStep::TotpRequired));
    let code = totp_code(&secret, APP_REALM_ADMIN_USERNAME)?;
    let step = login_step(
        &ctx,
        APP_REALM_ADMIN_USERNAME,
        APP_REALM_ADMIN_INITIAL_PASSWORD,
        Some(code),
    )
    .await?;
    assert!(matches!(step, AuthenticationNextStep::Authenticated));
    ctx.stop_server().await
}

/// 2FA enrolment for ordinary realm users is refused instead of answering "ok" and storing nothing.
#[actix_web::test]
async fn test_2fa_enrolment_outside_the_admin_realm_is_refused() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (joe, _) = login_realm_user(&ctx, "globex", "joe").await?;
    let super_admin = authenticate_as_admin(&ctx).await?;

    let secret = crate::totp::Totps::new()?.generate_secret();
    let token = totp_code(&secret, "joe")?;
    let verified = super_admin
        .verify_and_enable_totp("globex", "joe", &secret, &token, None)
        .await;
    assert!(is_http(&verified, 400), "{verified:?}");
    let generated = super_admin.generate_totp("globex", "joe", None).await;
    assert!(is_http(&generated, 400), "{generated:?}");
    joe.whoami("globex").await?;
    ctx.stop_server().await
}

/// 2FA is enforced for an admin whose record id differs from its login name.
#[actix_web::test]
async fn test_2fa_is_enforced_when_the_admin_id_differs_from_the_login() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let super_admin = authenticate_as_admin(&ctx).await?;
    super_admin
        .create_admin_credentials_in_realm(
            ADMIN_REALM,
            &create_userpass(ADMIN_REALM, "carol", "carol_pass", false)?,
        )
        .await?;
    let mut carol = test_admin("carol_user");
    carol.userpass = Some("carol".to_string());
    super_admin.create_admin_as_super_admin(&carol).await?;

    let secret = enrol_totp(&super_admin, "carol").await?;

    let step = login_step(&ctx, "carol", "carol_pass", None).await?;
    assert!(matches!(step, AuthenticationNextStep::TotpRequired));
    let code = totp_code(&secret, "carol")?;
    let step = login_step(&ctx, "carol", "carol_pass", Some(code)).await?;
    assert!(matches!(step, AuthenticationNextStep::Authenticated));
    ctx.stop_server().await
}
/// A realm admin enrols and removes the 2FA of its own login.
#[actix_web::test]
async fn test_realm_admin_manages_its_own_2fa() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let alice = create_and_authenticate_realm_admin(&ctx, "acme").await?;

    let secret = enrol_totp(&alice, REALM_ADMIN_LOGIN).await?;
    let step = login_step(&ctx, REALM_ADMIN_LOGIN, REALM_ADMIN_PASSWORD, None).await?;
    assert!(matches!(step, AuthenticationNextStep::TotpRequired));
    let code = totp_code(&secret, REALM_ADMIN_LOGIN)?;
    let step = login_step(&ctx, REALM_ADMIN_LOGIN, REALM_ADMIN_PASSWORD, Some(code)).await?;
    assert!(matches!(step, AuthenticationNextStep::Authenticated));

    alice.disable_totp(ADMIN_REALM, REALM_ADMIN_LOGIN).await?;
    let step = login_step(&ctx, REALM_ADMIN_LOGIN, REALM_ADMIN_PASSWORD, None).await?;
    assert!(matches!(step, AuthenticationNextStep::Authenticated));
    ctx.stop_server().await
}
// ── B: links and deletion ────────────────────────────────────────────────────

/// A realm admin cannot point an admin record at a login it does not manage, and deleting an
/// admin only removes that admin's own `_` login.
#[actix_web::test]
async fn test_realm_admin_cannot_target_or_delete_other_logins() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (_teamjoe, _) = login_realm_user(&ctx, "globex", "teamjoe").await?;
    let alice = create_and_authenticate_realm_admin(&ctx, "acme").await?;

    for userpass in [APP_REALM_ADMIN_USERNAME, "teamjoe"] {
        let mut decoy = test_admin("decoy");
        decoy.realms = vec!["acme".to_string()];
        decoy.userpass = Some(userpass.to_string());
        let created = alice.create_admin_as_super_admin(&decoy).await;
        assert!(is_http(&created, 403), "userpass '{userpass}': {created:?}");
    }

    let mut teamjoe = test_admin("teamjoe");
    teamjoe.realms = vec!["acme".to_string()];
    alice.create_admin_as_super_admin(&teamjoe).await?;
    alice
        .create_admin_credentials_in_realm(
            ADMIN_REALM,
            &create_userpass(ADMIN_REALM, "teamjoe", "joe_admin_pass", false)?,
        )
        .await?;
    alice.delete_admin_as_super_admin("teamjoe").await?;

    let globex_user = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: "teamjoe".to_string(),
        password: "user_pass".to_string(),
    });
    globex_user.login("globex", None).await?;
    assert!(
        login_step(&ctx, "teamjoe", "joe_admin_pass", None)
            .await
            .is_err(),
        "the deleted admin's `_` login must be gone"
    );
    authenticate_as_admin(&ctx).await?;
    ctx.stop_server().await
}

/// A login can be linked to one admin only, and only by someone who manages it.
#[actix_web::test]
async fn test_admin_login_links_are_validated() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let alice = create_and_authenticate_realm_admin(&ctx, "acme").await?;
    let super_admin = authenticate_as_admin(&ctx).await?;
    super_admin
        .create_admin_credentials_in_realm(
            ADMIN_REALM,
            &create_userpass(ADMIN_REALM, "dave", "dave_pass", false)?,
        )
        .await?;
    let mut dave = test_admin("dave_admin");
    dave.userpass = Some("dave".to_string());
    super_admin.create_admin_as_super_admin(&dave).await?;

    let mut second = test_admin("dave_two");
    second.userpass = Some("dave".to_string());
    let duplicate = super_admin.create_admin_as_super_admin(&second).await;
    assert!(is_http(&duplicate, 409), "{duplicate:?}");

    let mut mine = alice.get_admin_as_super_admin(REALM_ADMIN_RECORD).await?;
    for userpass in ["dave", "orphan"] {
        mine.userpass = Some(userpass.to_string());
        let updated = alice
            .update_admin_as_super_admin(REALM_ADMIN_RECORD, &mine)
            .await;
        assert!(is_http(&updated, 403), "userpass '{userpass}': {updated:?}");
    }
    mine.userpass = Some(REALM_ADMIN_LOGIN.to_string());
    alice
        .update_admin_as_super_admin(REALM_ADMIN_RECORD, &mine)
        .await?;
    ctx.stop_server().await
}

/// A JWT subject can be used by one admin only: copying another admin's subject would lock that
/// admin out (its login would match two admins).
#[actix_web::test]
async fn test_admin_jwt_subjects_are_validated() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let alice = create_and_authenticate_realm_admin(&ctx, "acme").await?;
    let super_admin = authenticate_as_admin(&ctx).await?;
    let mut victim = test_admin("jwt_victim");
    victim.jwt = Some("victim-subject".to_string());
    victim.client_certificate = Some("victim-certificate".to_string());
    super_admin.create_admin_as_super_admin(&victim).await?;

    let mut copied_certificate = test_admin("certificate_copy");
    copied_certificate.realms = vec!["acme".to_string()];
    copied_certificate.client_certificate = victim.client_certificate.clone();
    let created = alice.create_admin_as_super_admin(&copied_certificate).await;
    assert!(is_http(&created, 403), "{created:?}");

    let mut copy = test_admin("jwt_copy");
    copy.realms = vec!["acme".to_string()];
    copy.jwt = victim.jwt.clone();
    let created = alice.create_admin_as_super_admin(&copy).await;
    assert!(is_http(&created, 403), "{created:?}");
    let mut mine = alice.get_admin_as_super_admin(REALM_ADMIN_RECORD).await?;
    mine.jwt = victim.jwt.clone();
    let updated = alice
        .update_admin_as_super_admin(REALM_ADMIN_RECORD, &mine)
        .await;
    assert!(is_http(&updated, 403), "{updated:?}");

    copy.realms = Vec::new();
    let duplicate = super_admin.create_admin_as_super_admin(&copy).await;
    assert!(is_http(&duplicate, 409), "{duplicate:?}");

    let users_of_subject = super_admin
        .list_admins_as_super_admin()
        .await?
        .into_iter()
        .filter(|a| a.jwt == victim.jwt)
        .count();
    assert_eq!(users_of_subject, 1);
    ctx.stop_server().await
}

/// Two admin records sharing a login, possible in a database created before logins were unique,
/// make the admin lookup refuse both; starting on such a database skips the unique index.
#[actix_web::test]
async fn test_admin_lookup_fails_closed_when_a_login_is_shared() -> AuthResult<()> {
    let db_error = |e: &dyn std::fmt::Display| AuthError::Unexpected(e.to_string());
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .map_err(|e| db_error(&e))?;
    let database = SqliteDatabase::new(pool.clone());
    database.init().await.map_err(|e| db_error(&e))?;
    // A database from before logins were unique has no such index.
    sqlx::query("DROP INDEX admin_userpass_unique")
        .execute(&pool)
        .await
        .map_err(|e| db_error(&e))?;
    for id in ["first", "second"] {
        let mut admin = test_admin(id);
        admin.userpass = Some("shared".to_string());
        database
            .create_admin(&admin)
            .await
            .map_err(|e| db_error(&e))?;
    }

    let mut claims = ClientClaims::default();
    claims.private.realm_id = Some(ADMIN_REALM.to_string());
    claims.private.auth_scheme = Some(AuthScheme::UsernamePassword);
    claims.registered.sub = Some("shared".to_string());
    assert!(find_admin_for_claims(&database, &claims).await.is_err());

    // Starting again with the duplicates in place works and leaves the column non-unique.
    database.init().await.map_err(|e| db_error(&e))?;
    let indexes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'admin_userpass_unique'",
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| db_error(&e))?;
    assert_eq!(indexes, 0);
    Ok(())
}

// ── D: who may manage a `_` login ────────────────────────────────────────────

/// Once a realm has its own admin, the super admin cannot touch that admin's login or 2FA.
#[actix_web::test]
async fn test_super_admin_cannot_take_over_the_login_of_a_claimed_realm_admin() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let alice = create_and_authenticate_realm_admin(&ctx, "acme").await?;
    let super_admin = authenticate_as_admin(&ctx).await?;

    let reset = super_admin
        .update_admin_credentials_in_realm(
            ADMIN_REALM,
            REALM_ADMIN_LOGIN,
            &create_userpass(ADMIN_REALM, REALM_ADMIN_LOGIN, "taken_over", false)?,
        )
        .await;
    assert!(is_http(&reset, 403), "{reset:?}");
    let step = login_step(&ctx, REALM_ADMIN_LOGIN, REALM_ADMIN_PASSWORD, None).await?;
    assert!(matches!(step, AuthenticationNextStep::Authenticated));

    // A login named like her record id must not re-point the record.
    let hijack = super_admin
        .create_admin_credentials_in_realm(
            ADMIN_REALM,
            &create_userpass(ADMIN_REALM, REALM_ADMIN_RECORD, "taken_over", false)?,
        )
        .await;
    assert!(is_http(&hijack, 403), "{hijack:?}");
    let record = alice.get_admin_as_super_admin(REALM_ADMIN_RECORD).await?;
    assert_eq!(record.userpass.as_deref(), Some(REALM_ADMIN_LOGIN));

    let removed = super_admin
        .delete_admin_credentials_in_realm(ADMIN_REALM, REALM_ADMIN_LOGIN)
        .await;
    assert!(is_http(&removed, 403), "{removed:?}");
    let generated = super_admin
        .generate_totp(ADMIN_REALM, REALM_ADMIN_LOGIN, None)
        .await;
    assert!(is_http(&generated, 403), "{generated:?}");
    let disabled = super_admin
        .disable_totp(ADMIN_REALM, REALM_ADMIN_LOGIN)
        .await;
    assert!(is_http(&disabled, 403), "{disabled:?}");

    // Its own login stays manageable.
    super_admin
        .get_admin_credentials_in_realm(ADMIN_REALM, APP_REALM_ADMIN_USERNAME)
        .await?;
    ctx.stop_server().await
}

/// Realm admins manage their own login and their colleagues', nothing else in `_`.
#[actix_web::test]
async fn test_realm_admin_manages_its_own_and_its_colleagues_logins() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let alice = create_and_authenticate_realm_admin(&ctx, "acme").await?;

    alice
        .update_admin_credentials_in_realm(
            ADMIN_REALM,
            REALM_ADMIN_LOGIN,
            &create_userpass(ADMIN_REALM, REALM_ADMIN_LOGIN, "new_pass", false)?,
        )
        .await?;
    let step = login_step(&ctx, REALM_ADMIN_LOGIN, "new_pass", None).await?;
    assert!(matches!(step, AuthenticationNextStep::Authenticated));

    let mut bob = test_admin("bob");
    bob.realms = vec!["acme".to_string()];
    alice.create_admin_as_super_admin(&bob).await?;
    alice
        .create_admin_credentials_in_realm(
            ADMIN_REALM,
            &create_userpass(ADMIN_REALM, "bob", "bob_pass", false)?,
        )
        .await?;
    let linked = alice.get_admin_as_super_admin("bob").await?;
    assert_eq!(linked.userpass.as_deref(), Some("bob"));

    let orphan = alice
        .create_admin_credentials_in_realm(
            ADMIN_REALM,
            &create_userpass(ADMIN_REALM, "zed", "zed_pass", false)?,
        )
        .await;
    assert!(is_http(&orphan, 403), "{orphan:?}");
    let foreign = alice
        .get_admin_credentials_in_realm(ADMIN_REALM, APP_REALM_ADMIN_USERNAME)
        .await;
    assert!(is_http(&foreign, 403), "{foreign:?}");

    let listed: Vec<Value> = serde_json::from_str(&body_of(&alice, "/realms/_/userpass").await?)
        .map_err(|e| AuthError::Unexpected(e.to_string()))?;
    let mut names: Vec<&str> = listed
        .iter()
        .filter_map(|entry| entry["username"].as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec![REALM_ADMIN_LOGIN, "bob"]);
    ctx.stop_server().await
}

// ── E, F: leaks ──────────────────────────────────────────────────────────────

/// Credential lists never carry password hashes.
#[actix_web::test]
async fn test_credential_lists_never_return_password_hashes() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let (_joe, _) = login_realm_user(&ctx, "globex", "joe").await?;
    let super_admin = authenticate_as_admin(&ctx).await?;

    for path in [
        "/realms/_/userpass",
        "/admins/userpass",
        "/realms/globex/userpass",
    ] {
        let body = body_of(&super_admin, path).await?;
        assert!(
            body.contains("username"),
            "{path} returned no entries: {body}"
        );
        assert!(!body.contains("argon2"), "{path} leaked a hash: {body}");
    }
    ctx.stop_server().await
}

/// Admin records never carry 2FA secrets, and 2FA fields in request bodies are ignored.
#[actix_web::test]
async fn test_admin_records_do_not_expose_or_accept_2fa_secrets() -> AuthResult<()> {
    let ctx = start_default_test_server().await?;
    let super_admin = authenticate_as_admin(&ctx).await?;
    let secret = enrol_totp(&super_admin, APP_REALM_ADMIN_USERNAME).await?;

    for path in ["/admins/admin", "/admins"] {
        let body = body_of(&super_admin, path).await?;
        assert!(!body.contains("totp_secret"), "{path}: {body}");
        assert!(!body.contains("totp_auth_url"), "{path}: {body}");
    }
    assert!(
        body_of(&super_admin, "/admins/admin")
            .await?
            .contains("\"totp_enabled\":true")
    );

    // Saving the record without, or with other, 2FA fields keeps the stored 2FA.
    for body in [
        json!({"id": "admin", "realms": ["_"], "userpass": "admin"}),
        json!({"id": "admin", "realms": ["_"], "userpass": "admin",
               "totp_enabled": false, "totp_secret": null, "totp_auth_url": null}),
    ] {
        let _: Value = super_admin.put("/admins/admin", &body).await?;
        let step = login_step(
            &ctx,
            APP_REALM_ADMIN_USERNAME,
            APP_REALM_ADMIN_INITIAL_PASSWORD,
            None,
        )
        .await?;
        assert!(
            matches!(step, AuthenticationNextStep::TotpRequired),
            "{body}"
        );
    }

    // 2FA cannot be switched on by posting a secret.
    let created: Value = super_admin
        .post(
            "/admins",
            &json!({"id": "mallory", "realms": [], "totp_enabled": true,
                    "totp_secret": secret, "totp_auth_url": "otpauth://totp/x"}),
        )
        .await?;
    assert_ne!(created["totp_enabled"], json!(true), "{created}");
    assert!(
        !body_of(&super_admin, "/admins/mallory")
            .await?
            .contains("\"totp_enabled\":true")
    );
    ctx.stop_server().await
}
