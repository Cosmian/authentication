use crate::{
    AuthResult, AuthScheme, AuthenticationNextStep, Realm, RealmAuthParams, UsernamePasswordParams,
    client::AuthClientScheme,
    database::{
        APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME, hash_password_with_argon2,
    },
    models::{ADMIN_REALM, UserPass},
    tests::{init_test_logging, start_default_test_server},
};
use cosmian_logger::info;

#[actix_web::test]
async fn test_valid_basic_auth() -> AuthResult<()> {
    // init_test_logging(Some(
    //     "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
    // ));
    info!("Starting test server...");
    let ctx = start_default_test_server().await?;
    info!("Configuring a test client with UsernamePassword authentication");

    let username = APP_REALM_ADMIN_USERNAME.to_string();
    let password = APP_REALM_ADMIN_INITIAL_PASSWORD.to_string();
    let realm = ADMIN_REALM.to_string();

    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: username.clone(),
        password: password.clone(),
    });

    info!("Making authenticated request to protected endpoint...");
    let (result, cookie) = client.login(&realm, None, None).await?;
    // let username_check: AuthenticatedUser = client.get(&format!("/authenticate/{realm}")).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected authentication next step to be 'Authenticated'"
    );
    assert!(
        result.session_id.is_some(),
        "Expected authentication result to contain a session ID"
    );
    assert!(
        cookie.is_some(),
        "Expected to receive a session cookie from the server"
    );

    let cookie = client.get_cookie(&ctx.get_client_url()).unwrap();
    info!("Received cookie from server: {:?}", cookie);
    assert!(
        cookie.is_some(),
        "Expected to receive a session cookie from the server"
    );
    let cookie = cookie.expect("this should not happen; there must be a cookie");
    assert_eq!(
        cookie.name(),
        "_ea_".to_owned(),
        "Expected session cookie name to be '_ea_'"
    );
    assert!(
        !cookie.is_expired(),
        "Expected session cookie to not be expired"
    );

    let who_am_i = client.whoami(&realm).await?;
    info!("Received 'whoami' response: {:?}", who_am_i);
    assert_eq!(
        who_am_i.registered.sub,
        Some(username.clone()),
        "Expected 'whoami' response to contain the correct username"
    );
    assert_eq!(
        who_am_i.private.auth_scheme,
        Some(AuthScheme::UsernamePassword),
        "Expected 'whoami' response to contain the correct authentication scheme"
    );

    info!("Stopping test server...");
    ctx.stop_server().await?;
    info!("Test server stopped.");
    Ok(())
}

// ── Negative credential tests ────────────────────────────────────────────────

/// Login with a username that does not exist in the database must be rejected with HTTP 401.
#[actix_web::test]
async fn test_invalid_username_returns_401() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: "user_that_does_not_exist".to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });

    let result = client.login(ADMIN_REALM, None, None).await;

    assert!(
        result.is_err(),
        "Expected login to fail with an invalid username"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 in error message, got: {msg}"
    );
    info!("Invalid username correctly rejected with 401");

    ctx.stop_server().await
}

/// Login with the correct username but wrong password must be rejected with HTTP 401.
#[actix_web::test]
async fn test_invalid_password_returns_401() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: "this_is_the_wrong_password".to_string(),
    });

    let result = client.login(ADMIN_REALM, None, None).await;

    assert!(
        result.is_err(),
        "Expected login to fail with an invalid password"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 in error message, got: {msg}"
    );
    info!("Invalid password correctly rejected with 401");

    ctx.stop_server().await
}

/// Login to a realm that does not exist must be rejected (HTTP 404 or similar).
#[actix_web::test]
async fn test_invalid_realm_returns_error() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });

    let result = client.login("realm_that_does_not_exist", None, None).await;

    assert!(
        result.is_err(),
        "Expected login to fail when the realm does not exist"
    );
    info!("Login to non-existent realm correctly rejected with error");

    ctx.stop_server().await
}

/// Login with an empty username and empty password must be rejected with HTTP 401.
#[actix_web::test]
async fn test_empty_credentials_returns_401() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: String::new(),
        password: String::new(),
    });

    let result = client.login(ADMIN_REALM, None, None).await;

    assert!(
        result.is_err(),
        "Expected login to fail with empty credentials"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("401"),
        "Expected 401 in error message, got: {msg}"
    );
    info!("Empty credentials correctly rejected with 401");

    ctx.stop_server().await
}

// ── Expired password (change_password flag) ───────────────────────────────────

/// Build a [`UserPass`] with `change_password: true` (simulates a forced password reset).
fn make_expired_userpass(realm: &str, username: &str, password: &str) -> AuthResult<UserPass> {
    Ok(UserPass {
        realm: realm.to_string(),
        username: username.to_string(),
        password: hash_password_with_argon2(username, password)?,
        change_password: true,
        roles: Vec::new(),
        domain: None,
    })
}

/// Authenticate as the seeded admin, return the ready-to-use client.
async fn authenticate_as_admin_for_up_tests(
    ctx: &crate::tests::TestsContext,
) -> AuthResult<crate::client::AuthClient> {
    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    });
    let (result, cookie) = client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after admin login"
    );
    assert!(
        cookie.is_some(),
        "Expected session cookie after admin login"
    );
    Ok(client)
}

/// When the realm has `allow_expired_passwords: false` and the credential has
/// `change_password: true`, login must be blocked with HTTP 403.
#[actix_web::test]
async fn test_login_with_expired_password_blocked() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin_for_up_tests(&ctx).await?;

    // Create a realm that does NOT allow expired passwords.
    let realm_id = "up_expired_blocked_realm";
    admin
        .create_realm_as_super_admin(&Realm {
            id: realm_id.to_string(),
            auth_params: RealmAuthParams {
                username_password_params: Some(UsernamePasswordParams {
                    allow_expired_passwords: false,
                }),
                ..Default::default()
            },
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
        })
        .await?;

    // Register a credential with change_password: true.
    let username = "expired_user";
    let password = "password123";
    let userpass = make_expired_userpass(realm_id, username, password)?;
    admin
        .create_admin_credentials_in_realm(realm_id, &userpass)
        .await?;

    // Login must fail — the server returns HTTP 403 "Password expired".
    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: username.to_string(),
        password: password.to_string(),
    });
    let result = client.login(realm_id, None, None).await;

    assert!(
        result.is_err(),
        "Expected login to fail when password is expired and allow_expired_passwords is false"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("403"),
        "Expected HTTP 403 for expired password when not allowed, got: {msg}"
    );
    info!("Expired password correctly blocked with 403");

    ctx.stop_server().await
}

/// When the realm has `allow_expired_passwords: true` and the credential has
/// `change_password: true`, login must succeed and the user is fully authenticated.
#[actix_web::test]
async fn test_login_with_expired_password_allowed() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin_for_up_tests(&ctx).await?;

    // Create a realm that allows expired passwords.
    let realm_id = "up_expired_allowed_realm";
    admin
        .create_realm_as_super_admin(&Realm {
            id: realm_id.to_string(),
            auth_params: RealmAuthParams {
                username_password_params: Some(UsernamePasswordParams {
                    allow_expired_passwords: true,
                }),
                ..Default::default()
            },
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
        })
        .await?;

    // Register a credential with change_password: true.
    let username = "expired_user_allowed";
    let password = "password123";
    let userpass = make_expired_userpass(realm_id, username, password)?;
    admin
        .create_admin_credentials_in_realm(realm_id, &userpass)
        .await?;

    // Login must succeed — allow_expired_passwords is true.
    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: username.to_string(),
        password: password.to_string(),
    });
    let (result, cookie) = client.login(realm_id, None, None).await?;

    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated when allow_expired_passwords is true, got {:?}",
        result.next_step
    );
    assert!(result.session_id.is_some(), "Expected a session ID");
    assert!(cookie.is_some(), "Expected a session cookie");
    info!("Expired password allowed: login succeeded as expected");

    ctx.stop_server().await
}

// The following tests were commented out because their API (`/authenticate/{realm}`) no longer
// exists. They have been restored above using the current `client.login(realm, ...)` API.
// See: test_invalid_username_returns_401, test_invalid_password_returns_401,
//      test_invalid_realm_returns_error, test_empty_credentials_returns_401.

// Note: test_authenticate_with_cookie was removed — it logged in and created a realm but
// contained no assertions about cookie authentication. Its intent is covered by
// `cookie_auth_tests.rs`.

// #[actix_web::test]
// async fn test_invalid_username() -> AuthResult<()> {
//     init_test_logging(Some(
//         "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
//     ));
//     let ctx = start_default_test_server().await?;

//     let client = ctx.get_test_client(TestClientAuth::UsernamePassword {
//         username: "invalid_user".to_string(),
//         password: "change_me".to_string(),
//     });

//     let result: Result<AuthenticatedUser, _> = client.get("/authenticate/_").await;
//     assert!(
//         result.is_err(),
//         "Expected authentication to fail with invalid username"
//     );

//     ctx.stop_server().await?;
//     Ok(())
// }

// #[actix_web::test]
// async fn test_invalid_password() -> AuthResult<()> {
//     init_test_logging(Some(
//         "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
//     ));
//     let ctx = start_default_test_server().await?;

//     let client = ctx.get_test_client(TestClientAuth::UsernamePassword {
//         username: "admin".to_string(),
//         password: "wrong_password".to_string(),
//     });

//     let result: Result<AuthenticatedUser, _> = client.get("/authenticate/_").await;
//     assert!(
//         result.is_err(),
//         "Expected authentication to fail with invalid password"
//     );

//     ctx.stop_server().await?;
//     Ok(())
// }

// #[actix_web::test]
// async fn test_invalid_realm() -> AuthResult<()> {
//     init_test_logging(Some(
//         "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
//     ));
//     let ctx = start_default_test_server().await?;

//     let client = ctx.get_test_client(TestClientAuth::UsernamePassword {
//         username: "admin".to_string(),
//         password: "change_me".to_string(),
//     });

//     let result: Result<AuthenticatedUser, _> = client.get("/authenticate/invalid_realm").await;
//     assert!(
//         result.is_err(),
//         "Expected authentication to fail with invalid realm"
//     );

//     ctx.stop_server().await?;
//     Ok(())
// }

// #[actix_web::test]
// async fn test_empty_credentials() -> AuthResult<()> {
//     init_test_logging(Some(
//         "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
//     ));
//     let ctx = start_default_test_server().await?;

//     let client = ctx.get_test_client(TestClientAuth::UsernamePassword {
//         username: "".to_string(),
//         password: "".to_string(),
//     });

//     let result: Result<AuthenticatedUser, _> = client.get("/authenticate/_").await;
//     assert!(
//         result.is_err(),
//         "Expected authentication to fail with empty credentials"
//     );

//     ctx.stop_server().await?;
//     Ok(())
// }

// #[actix_web::test]
// async fn test_valid_credentials_multiple_realms() -> AuthResult<()> {
//     init_test_logging(Some(
//         "warn,h2=warn,actix_server=warn,hyper_util=warn,auth_authentication=debug",
//     ));
//     let ctx = start_default_test_server().await?;

//     let client = ctx.get_test_client(TestClientAuth::UsernamePassword {
//         username: "admin".to_string(),
//         password: "change_me".to_string(),
//     });

//     // Test valid realm
//     let result: AuthResult<AuthenticatedUser> = client.get("/authenticate/_").await;
//     assert!(
//         result.is_ok(),
//         "Expected authentication to succeed with valid realm"
//     );

//     // Test another valid realm if applicable
//     let result2: Result<AuthenticatedUser, _> = client.get("/authenticate/other_realm").await;
//     assert!(
//         result2.is_err(),
//         "Expected authentication to fail for unknown realm"
//     );

//     ctx.stop_server().await?;
//     Ok(())
// }
