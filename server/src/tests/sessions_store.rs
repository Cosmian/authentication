// Running the Tests
// ==================
//
// SQLite only (default, always runs):
//   cargo test --package auth_authentication sessions
//
// With specific session store (requires running database/Redis server):
//   TEST_SESSIONS_STORE="postgresql" TEST_POSTGRES_URL="postgresql://auth:auth@localhost/auth" cargo test --package auth_authentication sessions
//   TEST_SESSIONS_STORE="mysql" TEST_MYSQL_URL="mysql://auth:auth@localhost/auth" cargo test --package auth_authentication sessions
//   TEST_SESSIONS_STORE="redis" TEST_REDIS_URL="redis://localhost:6379" cargo test --package auth_authentication sessions
//
// To create a docker container for testing:
//   PostgreSQL: `docker run --name postgres_auth -e POSTGRES_USER=auth -e POSTGRES_PASSWORD=auth -e POSTGRES_DB=auth -p 5432:5432 -d postgres`
//   MySQL: `docker run --name mysql_auth -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=auth -e MYSQL_USER=auth -e MYSQL_PASSWORD=auth -p 3306:3306 -d mysql`
//   Redis: `docker run --name redis_auth -p 6379:6379 -d redis`
//
// The tests will use in-memory SQLite for the session store by default.
// Set TEST_SESSIONS_STORE environment variable to test other stores.
// Each test uses a unique realm ID to avoid conflicts when running in parallel.

use crate::{
    AuthenticatedClientScheme, DatabaseBackend, DatabaseParams, Realm, RealmAuthParams,
    database::{Database, create_database},
    models::AuthScheme,
    session::{
        MySqlSessionStore, PostgresSessionStore, RedisSessionStore, SessionStore,
        SqliteSessionStore,
    },
};
use std::sync::Arc;
use tokio::time::{Duration, sleep};

// Helper to create an in-memory SQLite database with a test realm
// Each test should use a unique realm_id to avoid conflicts when running in parallel
async fn create_test_database_with_realm(realm_id: &str) -> (Arc<dyn Database>, Realm) {
    let db = create_database(&DatabaseParams {
        backend: DatabaseBackend::SQLite,
        connection_url: "sqlite::memory:".to_string(),
        max_connections: 5,
        min_connections: 1,
        connect_timeout_secs: 30,
        idle_timeout_secs: 300,
        auto_init_schema: true,
    })
    .await
    .expect("Failed to create SQLite database");
    db.init()
        .await
        .expect("Failed to initialize database schema");

    let realm = Realm {
        id: realm_id.to_string(),
        auth_params: RealmAuthParams::default(),
        session_max_age_seconds: 10, // 10 seconds for testing absolute expiration
        session_max_stale_age_seconds: 5, // 5 seconds for testing stale expiration
        certificate_max_age_seconds: 365 * 24 * 3600,
    };

    db.create_realm(&realm)
        .await
        .expect("Failed to create test realm");

    (db, realm)
}

// Helper to create the appropriate session store based on environment variable
async fn create_test_session_store() -> Arc<dyn SessionStore> {
    let store_type = std::env::var("TEST_SESSIONS_STORE").unwrap_or_else(|_| "sqlite".to_string());

    match store_type.as_str() {
        "sqlite" => {
            let url =
                std::env::var("TEST_SQLITE_URL").unwrap_or_else(|_| "sqlite::memory:".to_string());
            let store = SqliteSessionStore::from_url(&url)
                .await
                .expect("Failed to create SQLite session store");
            store
                .init()
                .await
                .expect("Failed to initialize SQLite session store");
            Arc::new(store)
        }
        "postgresql" | "postgres" => {
            let url = std::env::var("TEST_POSTGRES_URL")
                .expect("TEST_POSTGRES_URL must be set when using postgresql store");
            let store = PostgresSessionStore::from_url(&url)
                .await
                .expect("Failed to create PostgreSQL session store");
            store
                .init()
                .await
                .expect("Failed to initialize PostgreSQL session store");
            Arc::new(store)
        }
        "mysql" => {
            let url = std::env::var("TEST_MYSQL_URL")
                .expect("TEST_MYSQL_URL must be set when using mysql store");
            let store = MySqlSessionStore::from_url(&url)
                .await
                .expect("Failed to create MySQL session store");
            store
                .init()
                .await
                .expect("Failed to initialize MySQL session store");
            Arc::new(store)
        }
        "redis" => {
            let url = std::env::var("TEST_REDIS_URL")
                .expect("TEST_REDIS_URL must be set when using redis store");
            let store = RedisSessionStore::from_url(&url)
                .await
                .expect("Failed to create Redis session store");
            Arc::new(store)
        }
        _ => panic!("Unknown TEST_SESSIONS_STORE value: {}", store_type),
    }
}

// Helper to create a test authenticated user
fn create_test_user(username: &str) -> AuthenticatedClientScheme {
    AuthenticatedClientScheme {
        username: username.to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    }
}

// Helper to clean up test data for a realm (for persistent stores like PostgreSQL/MySQL)
async fn cleanup_test_realm(store: &Arc<dyn SessionStore>, realm_id: &str) {
    // Best effort cleanup - ignore errors as the realm might not exist yet
    let _ = store.delete_sessions_for_realm(realm_id).await;
}

#[tokio::test]
async fn test_session_basic_create_and_retrieve() {
    let (_db, realm) = create_test_database_with_realm("test-basic-create").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    let user = create_test_user("alice");
    let encoded_cookie = "test-cookie-data";

    // Create a session
    let session_id = "session-alice".to_string();
    store
        .upsert_session(&session_id, &realm, &user, encoded_cookie)
        .await
        .expect("Failed to create session");

    // Retrieve the session
    let user_claims = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session");

    assert!(user_claims.is_some(), "Session should exist");
    let session_data = user_claims.unwrap();
    assert_eq!(
        session_data.cookie_string,
        "test-cookie-data".to_string(),
        "Cookie value should match"
    );
}

#[tokio::test]
async fn test_session_not_found() {
    let (_db, _realm) = create_test_database_with_realm("test-not-found").await;
    let store = create_test_session_store().await;
    // No cleanup needed - this test doesn't create sessions

    let user_claims = store
        .get_session("non-existent-session-id")
        .await
        .expect("Failed to get session");

    assert!(
        user_claims.is_none(),
        "Non-existent session should return None"
    );
}

#[tokio::test]
async fn test_session_stale_expiration() {
    let (_db, mut realm) = create_test_database_with_realm("test-stale-expiration").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    // Set a very short stale time (2 seconds)
    realm.session_max_stale_age_seconds = 2;
    // Set a longer absolute max time so it doesn't expire first
    realm.session_max_age_seconds = 10;

    let user = create_test_user("bob");
    let encoded_cookie = "test-cookie-data";

    // Create a session
    let session_id = "session-bob".to_string();
    store
        .upsert_session(&session_id, &realm, &user, encoded_cookie)
        .await
        .expect("Failed to create session");

    // Session should exist immediately
    let user_claims = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_some(), "Session should exist initially");

    // Wait for the session to become stale (2 seconds + buffer)
    sleep(Duration::from_secs(3)).await;

    // Session should now be expired and deleted
    let user_claims = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session");
    assert!(
        user_claims.is_none(),
        "Session should be expired and deleted"
    );
}

#[tokio::test]
async fn test_session_absolute_max_age_expiration() {
    let (_db, mut realm) = create_test_database_with_realm("test-absolute-max-age").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    // Set a short absolute max time (2 seconds)
    realm.session_max_age_seconds = 2;
    // Set a longer stale time so it doesn't expire first
    realm.session_max_stale_age_seconds = 10;

    let user = create_test_user("charlie");
    let encoded_cookie = "test-cookie-data";

    // Create a session
    let session_id = "session-charlie".to_string();
    store
        .upsert_session(&session_id, &realm, &user, encoded_cookie)
        .await
        .expect("Failed to create session");

    // Access the session immediately to refresh stale timer
    let user_claims = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_some(), "Session should exist initially");

    // Wait 1 second and access again (should still be valid)
    sleep(Duration::from_secs(1)).await;
    let user_claims = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session");
    assert!(
        user_claims.is_some(),
        "Session should still be valid after 1 second"
    );

    // Wait for the session to reach absolute max age (2 more seconds + buffer)
    sleep(Duration::from_secs(2)).await;

    // Session should now be expired due to absolute max age, even though we accessed it
    let user_claims = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session");
    assert!(
        user_claims.is_none(),
        "Session should be expired due to absolute max age"
    );
}

#[tokio::test]
async fn test_session_stale_timer_refresh_on_access() {
    let (_db, mut realm) = create_test_database_with_realm("test-stale-timer-refresh").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    // Set a short stale time (3 seconds)
    realm.session_max_stale_age_seconds = 3;
    // Set a longer absolute max time
    realm.session_max_age_seconds = 15;

    let user = create_test_user("david");
    let encoded_cookie = "test-cookie-data";

    // Create a session
    let session_id = "session-david".to_string();
    store
        .upsert_session(&session_id, &realm, &user, encoded_cookie)
        .await
        .expect("Failed to create session");

    // Wait 2 seconds and access the session (should refresh the stale timer)
    sleep(Duration::from_secs(2)).await;
    let user_claims = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_some(), "Session should still be valid");

    // Wait another 2 seconds (total 4 seconds from creation, but only 2 from last access)
    sleep(Duration::from_secs(2)).await;
    let user_claims = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session");
    // Session should still be valid because stale timer was refreshed
    assert!(
        user_claims.is_some(),
        "Session should still be valid due to stale timer refresh"
    );

    // Now wait longer than stale time without accessing (4 seconds)
    sleep(Duration::from_secs(4)).await;
    let user_claims = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session");
    // Session should now be stale
    assert!(user_claims.is_none(), "Session should now be stale");
}

#[tokio::test]
async fn test_get_sessions_for_users() {
    let (_db, realm) = create_test_database_with_realm("test-get-sessions-user").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    let user = create_test_user("emma");

    // Create multiple sessions for the same user
    let session_id1 = "session-emma-1".to_string();
    store
        .upsert_session(&session_id1, &realm, &user, "test-cookie-data-1")
        .await
        .expect("Failed to create session 1");

    let session_id2 = "session-emma-2".to_string();
    store
        .upsert_session(&session_id2, &realm, &user, "test-cookie-data-2")
        .await
        .expect("Failed to create session 2");

    let session_id3 = "session-emma-3".to_string();
    store
        .upsert_session(&session_id3, &realm, &user, "test-cookie-data-3")
        .await
        .expect("Failed to create session 3");

    // Get all sessions for the user
    let sessions = store
        .get_sessions_for_clients(&realm.id, &[&user])
        .await
        .expect("Failed to get sessions for user");

    assert_eq!(sessions.len(), 3, "User should have 3 sessions");
    assert!(sessions.iter().any(|s| s.session_id == session_id1));
    assert!(sessions.iter().any(|s| s.session_id == session_id2));
    assert!(sessions.iter().any(|s| s.session_id == session_id3));
}

#[tokio::test]
async fn test_get_sessions_for_users_excludes_expired() {
    let (_db, mut realm) = create_test_database_with_realm("test-excludes-expired").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    // Set short expiration times
    realm.session_max_age_seconds = 3;
    realm.session_max_stale_age_seconds = 2;

    let user = create_test_user("frank");

    // Create multiple sessions
    let _session_id1 = "session-frank-1".to_string();
    store
        .upsert_session(&_session_id1, &realm, &user, "test-cookie-data-1")
        .await
        .expect("Failed to create session 1");

    // Wait for first session to expire
    sleep(Duration::from_secs(3)).await;

    // Create another session
    let session_id2 = "session-frank-2".to_string();
    store
        .upsert_session(&session_id2, &realm, &user, "test-cookie-data-2")
        .await
        .expect("Failed to create session 2");

    // Get all sessions for the user
    let sessions = store
        .get_sessions_for_clients(&realm.id, &[&user])
        .await
        .expect("Failed to get sessions for user");

    // Should only get the non-expired session
    assert_eq!(sessions.len(), 1, "User should have 1 non-expired session");
    assert!(sessions.iter().any(|s| s.session_id == session_id2));
}

#[tokio::test]
async fn test_delete_sessions() {
    let (_db, realm) = create_test_database_with_realm("test-delete-sessions").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    let user = create_test_user("grace");

    // Create multiple sessions
    let session_id1 = "session-grace-1".to_string();
    store
        .upsert_session(&session_id1, &realm, &user, "test-cookie-data-1")
        .await
        .expect("Failed to create session 1");

    let session_id2 = "session-grace-2".to_string();
    store
        .upsert_session(&session_id2, &realm, &user, "test-cookie-data-2")
        .await
        .expect("Failed to create session 2");

    let session_id3 = "session-grace-3".to_string();
    store
        .upsert_session(&session_id3, &realm, &user, "test-cookie-data-3")
        .await
        .expect("Failed to create session 3");

    // Delete two sessions
    store
        .delete_sessions(&[&session_id1, &session_id2])
        .await
        .expect("Failed to delete sessions");

    // Verify deleted sessions don't exist
    let user_claims = store
        .get_session(&session_id1)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_none(), "Session 1 should be deleted");

    let user_claims = store
        .get_session(&session_id2)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_none(), "Session 2 should be deleted");

    // Verify the third session still exists
    let user_claims = store
        .get_session(&session_id3)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_some(), "Session 3 should still exist");
}

#[tokio::test]
async fn test_delete_expired_sessions() {
    let (_db, mut realm) = create_test_database_with_realm("test-delete-expired").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    // Set short expiration times
    realm.session_max_age_seconds = 3;
    realm.session_max_stale_age_seconds = 2;

    let user1 = create_test_user("helen");
    let user2 = create_test_user("ivan");

    // Create sessions for different users
    let session_id1 = "session-helen-1".to_string();
    store
        .upsert_session(&session_id1, &realm, &user1, "test-cookie-data-1")
        .await
        .expect("Failed to create session 1");

    let session_id2 = "session-ivan-1".to_string();
    store
        .upsert_session(&session_id2, &realm, &user2, "test-cookie-data-2")
        .await
        .expect("Failed to create session 2");

    // Wait for sessions to expire
    sleep(Duration::from_secs(3)).await;

    // Create a new session (should not be expired)
    let session_id3 = "session-helen-2".to_string();
    store
        .upsert_session(&session_id3, &realm, &user1, "test-cookie-data-3")
        .await
        .expect("Failed to create session 3");

    // Delete expired sessions
    store
        .delete_expired_sessions()
        .await
        .expect("Failed to delete expired sessions");

    // Verify expired sessions are deleted
    let user_claims = store
        .get_session(&session_id1)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_none(), "Expired session 1 should be deleted");

    let user_claims = store
        .get_session(&session_id2)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_none(), "Expired session 2 should be deleted");

    // Verify non-expired session still exists
    let user_claims = store
        .get_session(&session_id3)
        .await
        .expect("Failed to get session");
    assert!(
        user_claims.is_some(),
        "Non-expired session 3 should still exist"
    );
}

#[tokio::test]
async fn test_delete_sessions_for_realm() {
    let (_db, realm1) = create_test_database_with_realm("test-delete-realm1").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm1.id).await;

    // Create a second realm
    let realm2 = Realm {
        id: "test-delete-realm2".to_string(),
        auth_params: RealmAuthParams::default(),
        session_max_age_seconds: 10,
        session_max_stale_age_seconds: 5,
        certificate_max_age_seconds: 365 * 24 * 3600,
    };
    cleanup_test_realm(&store, &realm2.id).await;

    let user1 = create_test_user("judy");
    let user2 = create_test_user("kevin");

    // Create sessions in realm1
    let session_id1 = "session-judy-1".to_string();
    store
        .upsert_session(&session_id1, &realm1, &user1, "test-cookie-data-1")
        .await
        .expect("Failed to create session 1 in realm1");

    let session_id2 = "session-kevin-1".to_string();
    store
        .upsert_session(&session_id2, &realm1, &user2, "test-cookie-data-2")
        .await
        .expect("Failed to create session 2 in realm1");

    // Create sessions in realm2
    let session_id3 = "session-judy-2".to_string();
    store
        .upsert_session(&session_id3, &realm2, &user1, "test-cookie-data-3")
        .await
        .expect("Failed to create session 3 in realm2");

    let session_id4 = "session-kevin-2".to_string();
    store
        .upsert_session(&session_id4, &realm2, &user2, "test-cookie-data-4")
        .await
        .expect("Failed to create session 4 in realm2");

    // Delete all sessions for realm1
    store
        .delete_sessions_for_realm(&realm1.id)
        .await
        .expect("Failed to delete sessions for realm1");

    // Verify realm1 sessions are deleted
    let user_claims = store
        .get_session(&session_id1)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_none(), "Realm1 session 1 should be deleted");

    let user_claims = store
        .get_session(&session_id2)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_none(), "Realm1 session 2 should be deleted");

    // Verify realm2 sessions still exist
    let user_claims = store
        .get_session(&session_id3)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_some(), "Realm2 session 3 should still exist");

    let user_claims = store
        .get_session(&session_id4)
        .await
        .expect("Failed to get session");
    assert!(user_claims.is_some(), "Realm2 session 4 should still exist");
}

#[tokio::test]
async fn test_multiple_realms_isolated() {
    let (_db, realm1) = create_test_database_with_realm("test-multi-realm1").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm1.id).await;
    cleanup_test_realm(&store, &realm1.id).await;

    // Create a second realm with different expiration times
    let realm2 = Realm {
        id: "test-multi-realm2".to_string(),
        auth_params: RealmAuthParams::default(),
        session_max_age_seconds: 20,
        session_max_stale_age_seconds: 15,
        certificate_max_age_seconds: 365 * 24 * 3600,
    };
    cleanup_test_realm(&store, &realm2.id).await;

    let user = create_test_user("laura");

    // Create sessions in both realms
    let _session_id1 = "session-laura-1".to_string();
    store
        .upsert_session(&_session_id1, &realm1, &user, "test-cookie-data-1")
        .await
        .expect("Failed to create session in realm1");

    let _session_id2 = "session-laura-2".to_string();
    store
        .upsert_session(&_session_id2, &realm2, &user, "test-cookie-data-2")
        .await
        .expect("Failed to create session in realm2");

    // Get sessions for user in realm1
    let realm1_sessions = store
        .get_sessions_for_clients(&realm1.id, &[&user])
        .await
        .expect("Failed to get sessions for realm1");

    // Get sessions for user in realm2
    let realm2_sessions = store
        .get_sessions_for_clients(&realm2.id, &[&user])
        .await
        .expect("Failed to get sessions for realm2");

    // Each realm should have exactly one session
    assert_eq!(realm1_sessions.len(), 1, "Realm1 should have 1 session");
    assert_eq!(realm2_sessions.len(), 1, "Realm2 should have 1 session");

    // Sessions should be different
    assert_ne!(
        realm1_sessions[0].session_id, realm2_sessions[0].session_id,
        "Sessions in different realms should be different"
    );
}

#[tokio::test]
async fn test_concurrent_session_access() {
    let (_db, realm) = create_test_database_with_realm("test-concurrent").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    let user = create_test_user("michael");
    let encoded_cookie = "test-cookie-data";

    // Create a session
    let session_id = "session-michael".to_string();
    store
        .upsert_session(&session_id, &realm, &user, encoded_cookie)
        .await
        .expect("Failed to create session");

    // Access the session concurrently from multiple tasks
    let store1 = store.clone();
    let store2 = store.clone();
    let store3 = store.clone();
    let session_id1 = session_id.clone();
    let session_id2 = session_id.clone();
    let session_id3 = session_id.clone();

    let handle1 = tokio::spawn(async move {
        store1
            .get_session(&session_id1)
            .await
            .expect("Failed to get session")
    });

    let handle2 = tokio::spawn(async move {
        store2
            .get_session(&session_id2)
            .await
            .expect("Failed to get session")
    });

    let handle3 = tokio::spawn(async move {
        store3
            .get_session(&session_id3)
            .await
            .expect("Failed to get session")
    });

    // All accesses should succeed
    let result1 = handle1.await.expect("Task 1 panicked");
    let result2 = handle2.await.expect("Task 2 panicked");
    let result3 = handle3.await.expect("Task 3 panicked");

    assert!(result1.is_some(), "Concurrent access 1 should succeed");
    assert!(result2.is_some(), "Concurrent access 2 should succeed");
    assert!(result3.is_some(), "Concurrent access 3 should succeed");
}

#[tokio::test]
async fn test_edge_case_zero_max_age() {
    let (_db, mut realm) = create_test_database_with_realm("test-zero-max-age").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    // Set max age to 0 (should expire immediately)
    realm.session_max_age_seconds = 0;
    realm.session_max_stale_age_seconds = 10;

    let user = create_test_user("nancy");
    let encoded_cookie = "test-cookie-data";

    // Create a session
    let session_id = "session-nancy".to_string();
    store
        .upsert_session(&session_id, &realm, &user, encoded_cookie)
        .await
        .expect("Failed to create session");

    // Wait at least 1 second to ensure we're past the max age
    sleep(Duration::from_secs(1)).await;

    let user_claims = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session");

    assert!(
        user_claims.is_none(),
        "Session with zero max age should be expired"
    );
}

#[tokio::test]
async fn test_session_data_integrity() {
    let (_db, realm) = create_test_database_with_realm("test-data-integrity").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    let user = create_test_user("oliver@example.com");
    let encoded_cookie = "test-cookie-data";

    // Create a session
    let session_id = "session-oliver".to_string();
    store
        .upsert_session(&session_id, &realm, &user, encoded_cookie)
        .await
        .expect("Failed to create session");

    // Retrieve the session
    let session_data = store
        .get_session(&session_id)
        .await
        .expect("Failed to get session")
        .expect("Session should exist");

    // Verify the data integrity
    assert_eq!(
        session_data.cookie_string, "test-cookie-data",
        "Cookie string should match"
    );
    assert_eq!(
        session_data.session_id, session_id,
        "Session ID should round-trip"
    );
    assert_eq!(
        session_data.username, "oliver@example.com",
        "Username should match"
    );
    assert_eq!(session_data.realm_id, realm.id, "Realm ID should match");
}

#[tokio::test]
async fn test_get_sessions_for_users_with_different_auth_schemes() {
    let (_db, realm) = create_test_database_with_realm("test-auth-scheme-isolation").await;
    let store = create_test_session_store().await;
    cleanup_test_realm(&store, &realm.id).await;

    // Create two users with the SAME username but DIFFERENT auth schemes
    // This tests that (username, auth_scheme) is properly used as a tuple to identify users
    let user_jwt = AuthenticatedClientScheme {
        username: "alice".to_string(),
        auth_scheme: AuthScheme::Jwt,
    };

    let user_password = AuthenticatedClientScheme {
        username: "alice".to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    };

    // Create sessions for user with JWT authentication
    let jwt_session_1 = "session-jwt-1".to_string();
    store
        .upsert_session(&jwt_session_1, &realm, &user_jwt, "test-jwt-cookie-1")
        .await
        .expect("Failed to create JWT session 1");

    let jwt_session_2 = "session-jwt-2".to_string();
    store
        .upsert_session(&jwt_session_2, &realm, &user_jwt, "test-jwt-cookie-2")
        .await
        .expect("Failed to create JWT session 2");

    // Create sessions for user with password authentication
    let password_session_1 = "session-pwd-1".to_string();
    store
        .upsert_session(
            &password_session_1,
            &realm,
            &user_password,
            "test-pwd-cookie-1",
        )
        .await
        .expect("Failed to create password session 1");

    let password_session_2 = "session-pwd-2".to_string();
    store
        .upsert_session(
            &password_session_2,
            &realm,
            &user_password,
            "test-pwd-cookie-2",
        )
        .await
        .expect("Failed to create password session 2");

    let password_session_3 = "session-pwd-3".to_string();
    store
        .upsert_session(
            &password_session_3,
            &realm,
            &user_password,
            "test-pwd-cookie-3",
        )
        .await
        .expect("Failed to create password session 3");

    // Test 1: Get sessions for ONLY the JWT user
    let jwt_sessions = store
        .get_sessions_for_clients(&realm.id, &[&user_jwt])
        .await
        .expect("Failed to get JWT sessions");

    assert_eq!(
        jwt_sessions.len(),
        2,
        "JWT user should have exactly 2 sessions"
    );
    assert!(
        jwt_sessions.iter().any(|s| s.session_id == jwt_session_1),
        "JWT sessions should contain jwt_session_1"
    );
    assert!(
        jwt_sessions.iter().any(|s| s.session_id == jwt_session_2),
        "JWT sessions should contain jwt_session_2"
    );
    assert!(
        !jwt_sessions
            .iter()
            .any(|s| s.session_id == password_session_1),
        "JWT sessions should NOT contain password sessions"
    );
    assert!(
        !jwt_sessions
            .iter()
            .any(|s| s.session_id == password_session_2),
        "JWT sessions should NOT contain password sessions"
    );
    assert!(
        !jwt_sessions
            .iter()
            .any(|s| s.session_id == password_session_3),
        "JWT sessions should NOT contain password sessions"
    );

    // Test 2: Get sessions for ONLY the password user
    let password_sessions = store
        .get_sessions_for_clients(&realm.id, &[&user_password])
        .await
        .expect("Failed to get password sessions");

    assert_eq!(
        password_sessions.len(),
        3,
        "Password user should have exactly 3 sessions"
    );
    assert!(
        password_sessions
            .iter()
            .any(|s| s.session_id == password_session_1),
        "Password sessions should contain password_session_1"
    );
    assert!(
        password_sessions
            .iter()
            .any(|s| s.session_id == password_session_2),
        "Password sessions should contain password_session_2"
    );
    assert!(
        password_sessions
            .iter()
            .any(|s| s.session_id == password_session_3),
        "Password sessions should contain password_session_3"
    );
    assert!(
        !password_sessions
            .iter()
            .any(|s| s.session_id == jwt_session_1),
        "Password sessions should NOT contain JWT sessions"
    );
    assert!(
        !password_sessions
            .iter()
            .any(|s| s.session_id == jwt_session_2),
        "Password sessions should NOT contain JWT sessions"
    );

    // Test 3: Get sessions for BOTH users at once
    let all_sessions = store
        .get_sessions_for_clients(&realm.id, &[&user_jwt, &user_password])
        .await
        .expect("Failed to get sessions for both users");

    assert_eq!(
        all_sessions.len(),
        5,
        "Should have all 5 sessions (2 JWT + 3 password)"
    );
    assert!(
        all_sessions.iter().any(|s| s.session_id == jwt_session_1),
        "All sessions should contain jwt_session_1"
    );
    assert!(
        all_sessions.iter().any(|s| s.session_id == jwt_session_2),
        "All sessions should contain jwt_session_2"
    );
    assert!(
        all_sessions
            .iter()
            .any(|s| s.session_id == password_session_1),
        "All sessions should contain password_session_1"
    );
    assert!(
        all_sessions
            .iter()
            .any(|s| s.session_id == password_session_2),
        "All sessions should contain password_session_2"
    );
    assert!(
        all_sessions
            .iter()
            .any(|s| s.session_id == password_session_3),
        "All sessions should contain password_session_3"
    );

    // Test 4: Get sessions for empty array
    let empty_sessions = store
        .get_sessions_for_clients(&realm.id, &[])
        .await
        .expect("Failed to get sessions for empty array");

    assert_eq!(
        empty_sessions.len(),
        0,
        "Empty user array should return no sessions"
    );
}
