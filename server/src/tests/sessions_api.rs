use crate::{
    AuthResult, AuthScheme, AuthenticatedClientScheme, AuthenticationNextStep, SessionsAction,
    client::{AuthClient, AuthClientScheme},
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

/// Authenticate as admin. Returns `(session_id, authenticated_client)`.
///
/// The returned client retains its `_ea_` session cookie and MUST be used
/// for any subsequent calls to session-protected endpoints.
async fn authenticate_admin(ctx: &crate::tests::TestsContext) -> AuthResult<(String, AuthClient)> {
    let client = ctx.get_test_client(admin_scheme());
    let (result, _cookie) = client.login(ADMIN_REALM, None, None).await?;
    assert!(
        matches!(result.next_step, AuthenticationNextStep::Authenticated),
        "Expected Authenticated next step"
    );
    let session_id = result.session_id.ok_or_else(|| {
        crate::AuthError::Session("authenticate did not return a session_id".into())
    })?;
    Ok((session_id, client))
}

// ── get_session ──────────────────────────────────────────────────────────────

/// A freshly-issued session ID must return a `SessionData` with a non-empty cookie string
/// and fields matching the authenticated client.
#[actix_web::test]
async fn test_get_session_returns_claims() -> AuthResult<()> {
    // init_test_logging(Some("info"));
    let ctx = start_default_test_server().await?;

    let (session_id, client) = authenticate_admin(&ctx).await?;

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
    let (_, client) = authenticate_admin(&ctx).await?;

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

    let (session_id, client) = authenticate_admin(&ctx).await?;

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
    let (_, client) = authenticate_admin(&ctx).await?;

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

    // Authenticate twice with independent clients to create two sessions.
    // Reuse the second client as the management client (its session is independent).
    let (session_a, _) = authenticate_admin(&ctx).await?;
    let (session_b, client) = authenticate_admin(&ctx).await?;
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

    // Create the target session with one client, use a separate management
    // client for deletion so that deleting the target session does not
    // invalidate the management client's own cookie.
    let (session_id, _) = authenticate_admin(&ctx).await?;
    let (_, client) = authenticate_admin(&ctx).await?;

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

    let (session_a, _) = authenticate_admin(&ctx).await?;
    let (session_b, _) = authenticate_admin(&ctx).await?;
    // Separate management client so deleting session_a/session_b does not
    // invalidate the client performing the deletion.
    let (_, client) = authenticate_admin(&ctx).await?;

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
    let (_, client) = authenticate_admin(&ctx).await?;

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

    let (session_id, _) = authenticate_admin(&ctx).await?;
    // Use a separate management client so that the target session and the
    // management session are independent.
    let (_, client) = authenticate_admin(&ctx).await?;

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
    let (_, client) = authenticate_admin(&ctx).await?;

    client.delete_expired_sessions().await?;

    ctx.stop_server().await
}

// ── delete_sessions_for_realm ────────────────────────────────────────────────

/// After `delete_sessions_for_realm` all sessions in that realm must be gone.
///
/// Verification is done via `whoami`, which also requires a valid session
/// cookie: once a session is deleted, `whoami` returns 401.
#[actix_web::test]
async fn test_delete_sessions_for_realm_removes_all() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // Create two sessions that will be wiped by the realm deletion.
    let (_, client_a) = authenticate_admin(&ctx).await?;
    let (_, client_b) = authenticate_admin(&ctx).await?;
    // Management client whose session will also be wiped — its last call
    // (delete_sessions_for_realm) succeeds because auth is checked at
    // request entry, before the handler deletes all sessions.
    let (_, mgmt) = authenticate_admin(&ctx).await?;

    mgmt.delete_sessions_for_realm(ADMIN_REALM).await?;

    // All sessions in the realm are now gone. Any authenticated call from
    // client_a or client_b must fail with 401.
    assert!(
        client_a.whoami(ADMIN_REALM).await.is_err(),
        "client_a's session should be gone after realm wipe"
    );
    assert!(
        client_b.whoami(ADMIN_REALM).await.is_err(),
        "client_b's session should be gone after realm wipe"
    );

    ctx.stop_server().await
}

/// `delete_sessions_for_realm` on a realm with no sessions must not error.
#[actix_web::test]
async fn test_delete_sessions_for_realm_empty() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let (_, client) = authenticate_admin(&ctx).await?;

    // Use a realm that exists (registered at server start) but has no sessions.
    // The management client's own session will be deleted by this call, but
    // no further authenticated calls follow.
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

    // client_a owns session_a; it calls LogoutOtherSessions(session_a), which
    // keeps session_a and deletes every other session for `admin`.  client_a's
    // own cookie is for session_a, so it remains valid after the action.
    let (session_a, client_a) = authenticate_admin(&ctx).await?;
    let (session_b, client_b) = authenticate_admin(&ctx).await?;
    let (session_c, client_c) = authenticate_admin(&ctx).await?;

    let admin_user = AuthenticatedClientScheme {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    };

    // Call get_session on session_a with LogoutOtherSessions action.
    // Uses client_a (session_a owner) so its cookie is for the kept session.
    let session_data = client_a
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

    // session_a must still be retrievable — client_a's session is the kept one
    assert!(
        client_a.get_session(&session_a).await?.is_some(),
        "session_a must survive LogoutOtherSessions"
    );

    // session_b and session_c must have been deleted
    assert!(
        client_a.get_session(&session_b).await?.is_none(),
        "session_b must be deleted by LogoutOtherSessions"
    );
    assert!(
        client_a.get_session(&session_c).await?.is_none(),
        "session_c must be deleted by LogoutOtherSessions"
    );

    // Confirm via whoami: client_b and client_c are now rejected
    assert!(
        client_b.whoami(ADMIN_REALM).await.is_err(),
        "client_b must be rejected after its session was deleted"
    );
    assert!(
        client_c.whoami(ADMIN_REALM).await.is_err(),
        "client_c must be rejected after its session was deleted"
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

    // client_a calls LogoutAllSessions(session_a, [admin]).
    // CookieAuthSameServer validates client_a's cookie at request entry
    // (session_a is still valid then), then the handler deletes ALL admin
    // sessions including session_a itself.  After the response, every client
    // gets 401 on subsequent calls.
    let (session_a, client_a) = authenticate_admin(&ctx).await?;
    let (_, client_b) = authenticate_admin(&ctx).await?;
    let (_, client_c) = authenticate_admin(&ctx).await?;

    let admin_user = AuthenticatedClientScheme {
        username: APP_REALM_ADMIN_USERNAME.to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    };

    // Call get_session on session_a with LogoutAllSessions action.
    let session_data = client_a
        .get_session_with_action(
            &session_a,
            vec![admin_user],
            SessionsAction::LogoutAllSessions,
        )
        .await?;

    // Session data is returned even though the session is then deleted.
    assert!(
        session_data.is_some(),
        "Session data must be returned before all sessions are wiped"
    );
    assert_eq!(
        session_data.unwrap().session_id,
        session_a,
        "Returned session must be session_a"
    );

    // All sessions are now gone — verify via whoami (requires a valid cookie).
    // Each client gets 401 because its session was deleted.
    assert!(
        client_a.whoami(ADMIN_REALM).await.is_err(),
        "client_a must be rejected after LogoutAllSessions"
    );
    assert!(
        client_b.whoami(ADMIN_REALM).await.is_err(),
        "client_b must be rejected after LogoutAllSessions"
    );
    assert!(
        client_c.whoami(ADMIN_REALM).await.is_err(),
        "client_c must be rejected after LogoutAllSessions"
    );

    ctx.stop_server().await
}

// ── Session revocation end-to-end (management API → whoami) ──────────────────

/// After a session is deleted via the management API, the client that holds the
/// corresponding `_ea_` cookie must receive HTTP 401 on the next `whoami` call.
#[actix_web::test]
async fn test_whoami_fails_after_session_deleted() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // Login and keep the client so it retains the _ea_ cookie.
    let logged_in_client = ctx.get_test_client(admin_scheme());
    let (login_result, _) = logged_in_client.login(ADMIN_REALM, None, None).await?;
    let session_id = login_result
        .session_id
        .expect("login must return a session_id");

    // Sanity check: whoami works while the session is alive.
    logged_in_client.whoami(ADMIN_REALM).await?;

    // Delete the session via a separate management client that has its own
    // independent session cookie.
    let (_, mgmt_client) = authenticate_admin(&ctx).await?;
    mgmt_client
        .delete_sessions(std::slice::from_ref(&session_id))
        .await?;

    // Now whoami must fail with 401 — the session no longer exists in the store.
    let err = logged_in_client
        .whoami(ADMIN_REALM)
        .await
        .expect_err("Expected whoami to fail after session deletion");
    let msg = err.to_string();
    assert!(
        msg.contains("401"),
        "Expected HTTP 401 after session deletion, got: {msg}"
    );
    info!("whoami correctly rejected revoked session with 401");

    ctx.stop_server().await
}

/// Revoking one session must not invalidate other active sessions for the same
/// user.  Session B must remain usable after session A is deleted.
#[actix_web::test]
async fn test_revoking_one_session_leaves_other_valid() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;

    // Create two independent sessions for the same user.
    let client_a = ctx.get_test_client(admin_scheme());
    let (result_a, _) = client_a.login(ADMIN_REALM, None, None).await?;
    let session_a_id = result_a
        .session_id
        .expect("login_a must return a session_id");

    let client_b = ctx.get_test_client(admin_scheme());
    client_b.login(ADMIN_REALM, None, None).await?;

    // Delete only session A via a separate management client so that deleting
    // session_a does not invalidate the management client's own cookie.
    let (_, mgmt_client) = authenticate_admin(&ctx).await?;
    mgmt_client
        .delete_sessions(std::slice::from_ref(&session_a_id))
        .await?;

    // Session A must now be rejected.
    let err_a = client_a.whoami(ADMIN_REALM).await;
    assert!(
        err_a.is_err(),
        "client_a whoami must fail after its session was revoked"
    );
    let msg_a = err_a.unwrap_err().to_string();
    assert!(
        msg_a.contains("401"),
        "Expected 401 for revoked client_a, got: {msg_a}"
    );

    // Session B must still succeed.
    let claims_b = client_b.whoami(ADMIN_REALM).await?;
    assert_eq!(
        claims_b.registered.sub.as_deref(),
        Some(APP_REALM_ADMIN_USERNAME),
        "client_b must remain authenticated after client_a was revoked"
    );
    info!("Revoking session A did not affect session B");

    ctx.stop_server().await
}
