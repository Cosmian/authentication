use crate::{
    AuthResult, AuthenticationNextStep,
    client::AuthClientScheme,
    database::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME},
    models::ADMIN_REALM,
    tests::start_default_test_server,
};
use cosmian_logger::info;

/// Test that logging in without TOTP configured works as before (TotpRequired is NOT returned).
#[actix_web::test]
async fn test_login_without_totp_succeeds_normally() -> AuthResult<()> {
    // init_test_logging(Some(
    //     "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
    // ));
    let ctx = start_default_test_server().await?;

    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });

    let (result, cookie) = client.login(ADMIN_REALM, None, None).await?;

    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated when TOTP is disabled, got {:?}",
        result.next_step
    );
    assert!(result.session_id.is_some(), "Expected a session ID");
    assert!(cookie.is_some(), "Expected a session cookie");

    ctx.stop_server().await
}

/// Test that after enabling TOTP, logging in without providing a code returns TotpRequired.
#[actix_web::test]
async fn test_login_totp_required_when_no_code() -> AuthResult<()> {
    // init_test_logging(Some(
    //     "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
    // ));
    let ctx = start_default_test_server().await?;

    let admin = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });

    // Login first so admin client has a valid session cookie
    admin.login(ADMIN_REALM, None, None).await?;

    // Generate and immediately enroll TOTP for the admin user
    let generated = admin
        .generate_totp(ADMIN_REALM, APP_REALM_ADMIN_USERNAME, None)
        .await?;
    let totps = crate::totp::Totps::from_secret(
        &generated.secret_base32,
        None,
        APP_REALM_ADMIN_USERNAME.to_string(),
        None,
    )?;
    let current_token = totps.generate_current_token()?;
    admin
        .verify_and_enable_totp(
            ADMIN_REALM,
            APP_REALM_ADMIN_USERNAME,
            &generated.secret_base32,
            &current_token,
            None,
        )
        .await?;

    // Now try to log in without providing a TOTP code
    let fresh_client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });
    let (result, cookie) = fresh_client.login(ADMIN_REALM, None, None).await?;

    assert!(
        matches!(result.next_step, AuthenticationNextStep::TotpRequired),
        "Expected TotpRequired when TOTP is enabled and no code provided, got {:?}",
        result.next_step
    );
    assert!(
        result.session_id.is_none(),
        "Expected no session ID when TOTP code is missing"
    );
    assert!(
        cookie.is_none(),
        "Expected no session cookie when TOTP code is missing"
    );

    info!("Cleaning up: disabling TOTP");
    admin
        .disable_totp(ADMIN_REALM, APP_REALM_ADMIN_USERNAME)
        .await?;

    ctx.stop_server().await
}

/// Test that logging in with a valid TOTP code succeeds and returns a session.
#[actix_web::test]
async fn test_login_with_valid_totp_succeeds() -> AuthResult<()> {
    // init_test_logging(Some(
    //     "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
    // ));
    let ctx = start_default_test_server().await?;

    let admin = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });

    // Establish admin session
    admin.login(ADMIN_REALM, None, None).await?;

    // Set up TOTP for the admin user
    let generated = admin
        .generate_totp(ADMIN_REALM, APP_REALM_ADMIN_USERNAME, None)
        .await?;
    let totps = crate::totp::Totps::from_secret(
        &generated.secret_base32,
        None,
        APP_REALM_ADMIN_USERNAME.to_string(),
        None,
    )?;
    let enroll_token = totps.generate_current_token()?;
    admin
        .verify_and_enable_totp(
            ADMIN_REALM,
            APP_REALM_ADMIN_USERNAME,
            &generated.secret_base32,
            &enroll_token,
            None,
        )
        .await?;

    // Log in fresh with correct TOTP code
    let fresh_client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });
    let login_token = totps.generate_current_token()?;
    let (result, cookie) = fresh_client
        .login(ADMIN_REALM, None, Some(login_token))
        .await?;

    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated with valid TOTP code, got {:?}",
        result.next_step
    );
    assert!(result.session_id.is_some(), "Expected a session ID");
    assert!(cookie.is_some(), "Expected a session cookie");

    // Clean up
    admin
        .disable_totp(ADMIN_REALM, APP_REALM_ADMIN_USERNAME)
        .await?;

    ctx.stop_server().await
}

/// Test that logging in with an incorrect TOTP code yields a 401 error.
#[actix_web::test]
async fn test_login_with_invalid_totp_returns_error() -> AuthResult<()> {
    // init_test_logging(Some(
    //     "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
    // ));
    let ctx = start_default_test_server().await?;

    let admin = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });

    // Establish admin session and enable TOTP
    admin.login(ADMIN_REALM, None, None).await?;
    let generated = admin
        .generate_totp(ADMIN_REALM, APP_REALM_ADMIN_USERNAME, None)
        .await?;
    let totps = crate::totp::Totps::from_secret(
        &generated.secret_base32,
        None,
        APP_REALM_ADMIN_USERNAME.to_string(),
        None,
    )?;
    let enroll_token = totps.generate_current_token()?;
    admin
        .verify_and_enable_totp(
            ADMIN_REALM,
            APP_REALM_ADMIN_USERNAME,
            &generated.secret_base32,
            &enroll_token,
            None,
        )
        .await?;

    // Try to log in with a deliberately wrong TOTP code
    let fresh_client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });
    let login_result = fresh_client
        .login(ADMIN_REALM, None, Some("000000".to_string()))
        .await;

    assert!(
        login_result.is_err(),
        "Expected an error when TOTP code is invalid"
    );
    let err_str = login_result.unwrap_err().to_string();
    assert!(
        err_str.contains("401") || err_str.to_lowercase().contains("unauthorized"),
        "Expected a 401 Unauthorized, got: {err_str}"
    );

    // Clean up
    admin
        .disable_totp(ADMIN_REALM, APP_REALM_ADMIN_USERNAME)
        .await?;

    ctx.stop_server().await
}

/// Test that after disabling TOTP, logging in without a code works again.
#[actix_web::test]
async fn test_login_after_totp_disabled_succeeds() -> AuthResult<()> {
    // init_test_logging(Some(
    //     "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
    // ));
    let ctx = start_default_test_server().await?;

    let admin = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });

    // Establish admin session and enable TOTP
    admin.login(ADMIN_REALM, None, None).await?;
    let generated = admin
        .generate_totp(ADMIN_REALM, APP_REALM_ADMIN_USERNAME, None)
        .await?;
    let totps = crate::totp::Totps::from_secret(
        &generated.secret_base32,
        None,
        APP_REALM_ADMIN_USERNAME.to_string(),
        None,
    )?;
    let enroll_token = totps.generate_current_token()?;
    admin
        .verify_and_enable_totp(
            ADMIN_REALM,
            APP_REALM_ADMIN_USERNAME,
            &generated.secret_base32,
            &enroll_token,
            None,
        )
        .await?;

    // Verify TOTP is required
    let fresh_client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });
    let (step_check, _) = fresh_client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(step_check.next_step, AuthenticationNextStep::TotpRequired),
        "Expected TotpRequired before disabling, got {:?}",
        step_check.next_step
    );

    // Disable TOTP
    admin
        .disable_totp(ADMIN_REALM, APP_REALM_ADMIN_USERNAME)
        .await?;

    // Now login without TOTP should succeed
    let (result, cookie) = fresh_client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after disabling TOTP, got {:?}",
        result.next_step
    );
    assert!(result.session_id.is_some(), "Expected a session ID");
    assert!(cookie.is_some(), "Expected a session cookie");

    ctx.stop_server().await
}
