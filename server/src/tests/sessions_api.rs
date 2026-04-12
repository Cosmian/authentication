use crate::{
    AuthResult, AuthScheme, AuthenticatedClientScheme, AuthenticationNextStep, SessionsAction,
    client::AuthClientScheme,
    database::{APP_REALM_ADMIN_INITIAL_PASSWORD, APP_REALM_ADMIN_USERNAME},
    models::ADMIN_REALM,
    tests::{init_test_logging, start_default_test_server},
};
use cosmian_logger::info;

fn admin_scheme() -> AuthClientScheme {
    AuthClientScheme::UsernamePassword {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        password: APP_REALM_ADMIN_INITIAL_PASSWORD.to_string(),
    }
}

/// Authenticate as admin and return the issued session ID.
async fn authenticate_admin(ctx: &crate::tests::TestsContext) -> AuthResult<String> {
    let client = ctx.get_test_client(admin_scheme());
    let (result, _cookie) = client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated next step"
    );
    result
        .session_id
        .ok_or_else(|| crate::AuthError::Session("authenticate did not return a session_id".into()))
}

// ── get_session ──────────────────────────────────────────────────────────────

/// A freshly-issued session ID must return a `SessionData` with a non-empty cookie string
/// and fields matching the authenticated client.
#[actix_web::test]
async fn test_get_session_returns_claims() -> AuthResult<()> {
    // init_test_logging(Some("info"));
    let ctx = start_default_test_server().await?;

    let session_id = authenticate_admin(&ctx).await?;
    let client = ctx.get_test_client(admin_scheme());

    let session_data = client.get_session(&session_id).await?;
    assert!(
        session_data.is_some(),
        "Expected session data for a valid session ID"
    );
    let session_data = session_data.unwrap();
    assert!(
        !session_data.cookie_string.is_empty(),
        "Expected a non-empty cookie string"
    );
    assert_eq!(
        session_data.session_id, session_id,
        "session_id field must round-trip"
    );
    assert_eq!(
        session_data.username, APP_REALM_ADMIN_USERNAME,
        "username must match the authenticated client"
    );

    info!("Session data: {session_data:?}");
    ctx.stop_server().await
}

/// Querying a session ID that was never issued must return None (JSON null
/// is returned by the server and deserialised as None by the client).
#[actix_web::test]
async fn test_get_session_not_found_returns_none() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = ctx.get_test_client(admin_scheme());

    let claims = client
        .get_session("00000000-0000-0000-0000-000000000000")
        .await?;
    assert!(
        claims.is_none(),
        "Expected None for a non-existent session ID"
    );

    ctx.stop_server().await
}

// ── get_sessions_for_users ───────────────────────────────────────────────────

/// The session ID returned by `authenticate` must appear in
/// `get_sessions_for_users` for the corresponding user.
#[actix_web::test]
async fn test_get_sessions_for_users_contains_new_session() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let session_id = authenticate_admin(&ctx).await?;
    let client = ctx.get_test_client(admin_scheme());

    let admin_user = AuthenticatedClientScheme {
        username: "admin".to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    };
    let sessions = client
        .get_sessions_for_clients(ADMIN_REALM, &[admin_user])
        .await?;

    assert!(
        sessions.contains(&session_id),
        "Expected the new session ID to be listed for the user"
    );

    ctx.stop_server().await
}

/// `get_sessions_for_users` for a user that has no sessions must return an
/// empty list.
#[actix_web::test]
async fn test_get_sessions_for_users_no_sessions() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = ctx.get_test_client(admin_scheme());

    let ghost_user = AuthenticatedClientScheme {
        username: "ghost_user_that_never_authenticated".to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    };
    let sessions = client
        .get_sessions_for_clients(ADMIN_REALM, &[ghost_user])
        .await?;
    assert!(sessions.is_empty(), "Expected empty list for unknown user");

    ctx.stop_server().await
}

/// Multiple authentications for the same user should all appear in the list.
#[actix_web::test]
async fn test_get_sessions_for_users_multiple_sessions() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // Authenticate twice with independent clients to create two sessions
    let session_a = authenticate_admin(&ctx).await?;
    let session_b = authenticate_admin(&ctx).await?;

    let client = ctx.get_test_client(admin_scheme());
    let admin_user = AuthenticatedClientScheme {
        username: "admin".to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    };
    let sessions = client
        .get_sessions_for_clients(ADMIN_REALM, &[admin_user])
        .await?;

    assert!(
        sessions.contains(&session_a),
        "Expected first session ID in the list"
    );
    assert!(
        sessions.contains(&session_b),
        "Expected second session ID in the list"
    );

    ctx.stop_server().await
}

// ── delete_sessions ──────────────────────────────────────────────────────────

/// Deleting a session by its ID must make it inaccessible via `get_session`.
#[actix_web::test]
async fn test_delete_sessions_removes_session() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let session_id = authenticate_admin(&ctx).await?;
    let client = ctx.get_test_client(admin_scheme());

    // Confirm it is live before deletion
    let claims_before = client.get_session(&session_id).await?;
    assert!(
        claims_before.is_some(),
        "Session should exist before deletion"
    );

    client
        .delete_sessions(std::slice::from_ref(&session_id))
        .await?;

    let claims_after = client.get_session(&session_id).await?;
    assert!(
        claims_after.is_none(),
        "Session should be gone after explicit deletion"
    );

    ctx.stop_server().await
}

/// Deleting a list of session IDs must remove all of them.
#[actix_web::test]
async fn test_delete_sessions_multiple() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let session_a = authenticate_admin(&ctx).await?;
    let session_b = authenticate_admin(&ctx).await?;
    let client = ctx.get_test_client(admin_scheme());

    client
        .delete_sessions(&[session_a.clone(), session_b.clone()])
        .await?;

    assert!(
        client.get_session(&session_a).await?.is_none(),
        "First session should be gone"
    );
    assert!(
        client.get_session(&session_b).await?.is_none(),
        "Second session should be gone"
    );

    ctx.stop_server().await
}

/// Deleting an empty list of session IDs must succeed without error.
#[actix_web::test]
async fn test_delete_sessions_empty_list() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = ctx.get_test_client(admin_scheme());

    client.delete_sessions(&[]).await?;

    ctx.stop_server().await
}

// ── delete_expired_sessions ──────────────────────────────────────────────────

/// Calling `delete_expired_sessions` when all sessions are still fresh must
/// succeed and leave the live sessions intact.
#[actix_web::test]
async fn test_delete_expired_sessions_keeps_live_sessions() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let session_id = authenticate_admin(&ctx).await?;
    let client = ctx.get_test_client(admin_scheme());

    client.delete_expired_sessions().await?;

    // The fresh session must still be accessible
    let claims = client.get_session(&session_id).await?;
    assert!(
        claims.is_some(),
        "Live session must survive delete_expired_sessions"
    );

    ctx.stop_server().await
}

/// Calling `delete_expired_sessions` on an empty store must not error.
#[actix_web::test]
async fn test_delete_expired_sessions_empty_store() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = ctx.get_test_client(admin_scheme());

    client.delete_expired_sessions().await?;

    ctx.stop_server().await
}

// ── delete_sessions_for_realm ────────────────────────────────────────────────

/// After `delete_sessions_for_realm` all sessions in that realm must be gone.
#[actix_web::test]
async fn test_delete_sessions_for_realm_removes_all() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let session_a = authenticate_admin(&ctx).await?;
    let session_b = authenticate_admin(&ctx).await?;
    let client = ctx.get_test_client(admin_scheme());

    client.delete_sessions_for_realm(ADMIN_REALM).await?;

    assert!(
        client.get_session(&session_a).await?.is_none(),
        "First session should be gone after realm wipe"
    );
    assert!(
        client.get_session(&session_b).await?.is_none(),
        "Second session should be gone after realm wipe"
    );

    ctx.stop_server().await
}

/// `delete_sessions_for_realm` on a realm with no sessions must not error.
#[actix_web::test]
async fn test_delete_sessions_for_realm_empty() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let client = ctx.get_test_client(admin_scheme());

    // Use a realm that exists (registered at server start) but has no sessions
    client.delete_sessions_for_realm(ADMIN_REALM).await?;

    ctx.stop_server().await
}

// ── get_session with SessionsAction ─────────────────────────────────────────

/// `LogoutOtherSessions`: calling `get_session_with_action` with this variant
/// must delete all OTHER active sessions for the given clients while keeping
/// the queried session alive.
#[actix_web::test]
async fn test_get_session_logout_other_sessions() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let session_a = authenticate_admin(&ctx).await?;
    let session_b = authenticate_admin(&ctx).await?;
    let session_c = authenticate_admin(&ctx).await?;
    let client = ctx.get_test_client(admin_scheme());

    let admin_user = AuthenticatedClientScheme {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    };

    // Call get_session on session_a with LogoutOtherSessions action
    let session_data = client
        .get_session_with_action(
            &session_a,
            vec![admin_user],
            SessionsAction::LogoutOtherSessions,
        )
        .await?;

    // session_a must still be alive and returned
    assert!(
        session_data.is_some(),
        "Queried session must still be alive"
    );
    assert_eq!(
        session_data.unwrap().session_id,
        session_a,
        "Returned session must be session_a"
    );

    // session_a must still be retrievable
    assert!(
        client.get_session(&session_a).await?.is_some(),
        "session_a must survive LogoutOtherSessions"
    );

    // session_b and session_c must have been deleted
    assert!(
        client.get_session(&session_b).await?.is_none(),
        "session_b must be deleted by LogoutOtherSessions"
    );
    assert!(
        client.get_session(&session_c).await?.is_none(),
        "session_c must be deleted by LogoutOtherSessions"
    );

    ctx.stop_server().await
}

/// `LogoutAllSessions`: calling `get_session_with_action` with this variant
/// must delete ALL active sessions for the given clients, including the
/// queried session itself. The server returns the session data before deleting.
#[actix_web::test]
async fn test_get_session_logout_all_sessions() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    let session_a = authenticate_admin(&ctx).await?;
    let session_b = authenticate_admin(&ctx).await?;
    let session_c = authenticate_admin(&ctx).await?;
    let client = ctx.get_test_client(admin_scheme());

    let admin_user = AuthenticatedClientScheme {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    };

    // Call get_session on session_a with LogoutAllSessions action
    let session_data = client
        .get_session_with_action(
            &session_a,
            vec![admin_user],
            SessionsAction::LogoutAllSessions,
        )
        .await?;

    // Session data is returned even though the session is then deleted
    assert!(
        session_data.is_some(),
        "Session data must be returned before all sessions are wiped"
    );
    assert_eq!(
        session_data.unwrap().session_id,
        session_a,
        "Returned session must be session_a"
    );

    // All three sessions must now be gone
    assert!(
        client.get_session(&session_a).await?.is_none(),
        "session_a must be deleted by LogoutAllSessions"
    );
    assert!(
        client.get_session(&session_b).await?.is_none(),
        "session_b must be deleted by LogoutAllSessions"
    );
    assert!(
        client.get_session(&session_c).await?.is_none(),
        "session_c must be deleted by LogoutAllSessions"
    );

    ctx.stop_server().await
}
