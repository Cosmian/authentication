use crate::{
    AuthResult, AuthScheme, AuthenticationNextStep, Realm, RealmAuthParams, UsernamePasswordParams,
    client::AuthClientScheme,
    database::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME},
    models::{ADMIN_REALM, UserPass},
    tests::{
        helpers::{authenticate_as_admin, create_userpass},
        init_test_logging, start_default_test_server,
    },
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
    let (result, cookie) = client.login(&realm, None).await?;
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

    let result = client.login(ADMIN_REALM, None).await;

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

    let result = client.login(ADMIN_REALM, None).await;

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

    let result = client.login("realm_that_does_not_exist", None).await;

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

    let result = client.login(ADMIN_REALM, None).await;

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
/// Sends plaintext password bytes; the server hashes before storage.
fn make_expired_userpass(realm: &str, username: &str, password: &str) -> AuthResult<UserPass> {
    Ok(UserPass {
        realm: realm.to_string(),
        username: username.to_string(),
        password: password.as_bytes().to_vec(),
        change_password: true,
        roles: Vec::new(),
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
    let (result, cookie) = client.login(ADMIN_REALM, None).await?;
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
    let result = client.login(realm_id, None).await;

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
    let (result, cookie) = client.login(realm_id, None).await?;

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

// ── Password hashing regression tests ────────────────────────────────────────

/// Regression: `create_userpass` used to store the plaintext password bytes
/// supplied by the client, while `validate_userpass` compared against an
/// Argon2 hash of the incoming password.  This caused every login to fail.
///
/// This test verifies the full round-trip: create credentials via the HTTP
/// endpoint, then authenticate — login must succeed.
#[actix_web::test]
async fn test_create_userpass_then_authenticate() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let realm_id = "hash_regression_realm_create";
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

    let username = "hash_test_user";
    let password = "supersecret123!";
    // create_userpass sends plaintext bytes; the server must hash before storing.
    let userpass = create_userpass(realm_id, username, password, false)?;
    admin
        .create_admin_credentials_in_realm(realm_id, &userpass)
        .await?;

    // Now attempt to log in with the same plaintext password — must succeed.
    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: username.to_string(),
        password: password.to_string(),
    });
    let (result, cookie) = client.login(realm_id, None).await?;

    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after create_userpass + login, got {:?}",
        result.next_step
    );
    assert!(result.session_id.is_some(), "Expected a session ID");
    assert!(cookie.is_some(), "Expected a session cookie");
    info!("create_userpass → login round-trip succeeded");

    ctx.stop_server().await
}

/// Regression: `update_userpass` used to store the plaintext password bytes
/// supplied by the client, while `validate_userpass` compared against an
/// Argon2 hash.  After a password reset, login with the new password must work.
///
/// Also verifies that sending `password: []` (the GET response pattern) preserves
/// the existing password hash and does not break authentication.
#[actix_web::test]
async fn test_update_userpass_then_authenticate() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let admin = authenticate_as_admin(&ctx).await?;

    let realm_id = "hash_regression_realm_update";
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

    let username = "update_hash_user";
    let initial_password = "initial_pass_42!";
    let new_password = "new_pass_99!";

    // CREATE with plaintext bytes
    let userpass = create_userpass(realm_id, username, initial_password, false)?;
    admin
        .create_admin_credentials_in_realm(realm_id, &userpass)
        .await?;

    // Confirm initial login works.
    let client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: username.to_string(),
        password: initial_password.to_string(),
    });
    let (result, _) = client.login(realm_id, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after initial login, got {:?}",
        result.next_step
    );
    info!("Initial login succeeded");

    // UPDATE with a new plaintext password (simulates password reset).
    let updated = create_userpass(realm_id, username, new_password, false)?;
    admin
        .update_admin_credentials_in_realm(realm_id, username, &updated)
        .await?;

    // Old password must now be rejected.
    let old_client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: username.to_string(),
        password: initial_password.to_string(),
    });
    let result = old_client.login(realm_id, None).await;
    assert!(
        result.is_err(),
        "Expected login to fail with old password after password update"
    );
    info!("Old password correctly rejected after update");

    // New password must be accepted.
    let new_client = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: username.to_string(),
        password: new_password.to_string(),
    });
    let (result, cookie) = new_client.login(realm_id, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after login with new password, got {:?}",
        result.next_step
    );
    assert!(result.session_id.is_some(), "Expected a session ID");
    assert!(cookie.is_some(), "Expected a session cookie");
    info!("New password login succeeded after update");

    // UPDATE with empty password (simulates roles-only update) — password must be preserved.
    let roles_only = UserPass {
        realm: realm_id.to_string(),
        username: username.to_string(),
        password: Vec::new(), // empty — server must keep the existing hash
        change_password: false,
        roles: vec!["Auditor".to_string()],
    };
    admin
        .update_admin_credentials_in_realm(realm_id, username, &roles_only)
        .await?;

    // New password still works after roles-only update.
    let new_client2 = ctx.get_test_client(AuthClientScheme::UsernamePassword {
        username: username.to_string(),
        password: new_password.to_string(),
    });
    let (result, cookie) = new_client2.login(realm_id, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated after roles-only update, got {:?}",
        result.next_step
    );
    assert!(result.session_id.is_some(), "Expected a session ID");
    assert!(cookie.is_some(), "Expected a session cookie");
    info!("Password preserved correctly after roles-only update");

    ctx.stop_server().await
}
