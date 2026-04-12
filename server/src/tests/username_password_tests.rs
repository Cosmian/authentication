use crate::{
    AuthResult, AuthScheme, AuthenticationNextStep, Realm, RealmAuthParams,
    client::AuthClientScheme,
    database::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME},
    models::ADMIN_REALM,
    tests::start_default_test_server,
};
use actix_web::HttpResponse;
use cosmian_logger::info;

async fn test_handler() -> HttpResponse {
    HttpResponse::Ok().body("Success")
}

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

#[actix_web::test]
async fn test_authenticate_with_cookie() -> AuthResult<()> {
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
    let _result = client.login(&realm, None, None).await?;

    // now create a Realm called "test_realm" and a userpass with an expired password
    client
        .create_realm(&Realm {
            id: "test_realm".to_string(),
            auth_params: RealmAuthParams {
                ..Default::default()
            },
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
        })
        .await?;

    info!("Stopping test server...");
    ctx.stop_server().await?;
    info!("Test server stopped.");
    Ok(())
}

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
