// SAML request store tests, run against the backend selected by the same variables as
// `sessions_store.rs` (in-memory SQLite by default):
//   TEST_SESSIONS_STORE="postgresql" TEST_POSTGRES_URL="postgresql://auth:auth@localhost/auth"
//   TEST_SESSIONS_STORE="mysql"      TEST_MYSQL_URL="mysql://auth:auth@localhost/auth"
//   TEST_SESSIONS_STORE="redis"      TEST_REDIS_URL="redis://localhost:6379"
// Requires `--features auth_verifier/saml`. Every test uses unique IDs so runs can share a
// persistent database and execute in parallel.

use crate::{
    DatabaseBackend, DatabaseParams, PendingSamlRequest, SamlRequestStore,
    create_saml_request_store,
};
use chrono::Utc;
use std::sync::Arc;
use tokio::{
    sync::Mutex,
    time::{Duration, sleep},
};
use uuid::Uuid;

// Concurrent `CREATE TABLE IF NOT EXISTS` can fail on PostgreSQL, so schema init is serialized.
static INIT_LOCK: Mutex<()> = Mutex::const_new(());

async fn store() -> Arc<dyn SamlRequestStore> {
    let selected = std::env::var("TEST_SESSIONS_STORE").unwrap_or_else(|_| "sqlite".to_string());
    let (backend, connection_url, max_connections) = match selected.as_str() {
        // One connection: each `sqlite::memory:` connection is its own separate database.
        "sqlite" => (
            DatabaseBackend::SQLite,
            std::env::var("TEST_SQLITE_URL").unwrap_or_else(|_| "sqlite::memory:".to_string()),
            1,
        ),
        "postgresql" | "postgres" => (
            DatabaseBackend::PostgreSQL,
            std::env::var("TEST_POSTGRES_URL")
                .expect("TEST_POSTGRES_URL must be set when using postgresql store"),
            5,
        ),
        "mysql" => (
            DatabaseBackend::MySQL,
            std::env::var("TEST_MYSQL_URL")
                .expect("TEST_MYSQL_URL must be set when using mysql store"),
            5,
        ),
        "redis" => (
            DatabaseBackend::Redis,
            std::env::var("TEST_REDIS_URL")
                .expect("TEST_REDIS_URL must be set when using redis store"),
            5,
        ),
        other => panic!("Unknown TEST_SESSIONS_STORE value: {other}"),
    };

    let _guard = INIT_LOCK.lock().await;
    create_saml_request_store(&DatabaseParams {
        backend,
        connection_url,
        max_connections,
        min_connections: 1,
        connect_timeout_secs: 30,
        idle_timeout_secs: 300,
        auto_init_schema: true,
    })
    .await
    .expect("Failed to create SAML request store")
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4())
}

fn now() -> i64 {
    Utc::now().timestamp()
}

fn pending(request_id: &str, realm_id: &str, expires_at: i64) -> PendingSamlRequest {
    PendingSamlRequest {
        request_id: request_id.to_string(),
        realm_id: realm_id.to_string(),
        return_url: "https://app.example.com/home".to_string(),
        created_at: now(),
        expires_at,
    }
}

#[tokio::test]
async fn test_take_returns_the_stored_request_then_consumes_it() {
    let store = store().await;
    let (id, realm) = (unique("req"), unique("realm"));
    let request = pending(&id, &realm, now() + 300);
    store
        .store_pending_request(&request)
        .await
        .expect("store request");

    let taken = store.take_pending_request(&id, &realm).await.expect("take");
    assert_eq!(taken, Some(request));

    let again = store.take_pending_request(&id, &realm).await.expect("take");
    assert_eq!(again, None, "a pending request must be single-use");
}

#[tokio::test]
async fn test_take_rejects_a_wrong_realm() {
    let store = store().await;
    let (id, realm, other_realm) = (unique("req"), unique("realm"), unique("realm"));
    store
        .store_pending_request(&pending(&id, &realm, now() + 300))
        .await
        .expect("store request");

    let taken = store
        .take_pending_request(&id, &other_realm)
        .await
        .expect("take");
    assert_eq!(
        taken, None,
        "another realm's ACS must not consume the request"
    );
    assert!(
        store
            .take_pending_request(&id, &realm)
            .await
            .expect("take")
            .is_some(),
        "the wrong-realm attempt must not have consumed it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_takes_consume_a_request_exactly_once() {
    let store = store().await;
    let (id, realm) = (unique("req"), unique("realm"));
    store
        .store_pending_request(&pending(&id, &realm, now() + 300))
        .await
        .expect("store request");

    let takers: Vec<_> = (0..8)
        .map(|_| {
            let (store, id, realm) = (store.clone(), id.clone(), realm.clone());
            tokio::spawn(async move { store.take_pending_request(&id, &realm).await })
        })
        .collect();
    let mut consumed = 0;
    for taker in takers {
        if taker.await.expect("join").expect("take").is_some() {
            consumed += 1;
        }
    }
    assert_eq!(consumed, 1, "exactly one concurrent take must succeed");
}

#[tokio::test]
async fn test_store_refuses_an_already_expired_request() {
    let store = store().await;
    let (id, realm) = (unique("req"), unique("realm"));

    let result = store
        .store_pending_request(&pending(&id, &realm, now() - 1))
        .await;
    assert!(result.is_err(), "an expired request must not be stored");
    assert_eq!(
        store.take_pending_request(&id, &realm).await.expect("take"),
        None
    );
}

#[tokio::test]
async fn test_take_rejects_a_request_that_expired_after_being_stored() {
    let store = store().await;
    let (id, realm) = (unique("req"), unique("realm"));
    // Two seconds, not one: a second boundary between building and storing must not make the
    // initial store see the request as already expired.
    store
        .store_pending_request(&pending(&id, &realm, now() + 2))
        .await
        .expect("store request");

    sleep(Duration::from_secs(3)).await;

    assert_eq!(
        store.take_pending_request(&id, &realm).await.expect("take"),
        None,
        "an expired request must not be returned"
    );
}

#[tokio::test]
async fn test_record_assertion_id_detects_replay() {
    let store = store().await;
    let (id, other_id) = (unique("assertion"), unique("assertion"));

    assert!(
        store
            .record_assertion_id(&id, now() + 300)
            .await
            .expect("record")
    );
    assert!(
        !store
            .record_assertion_id(&id, now() + 300)
            .await
            .expect("record"),
        "the same assertion id seen twice is a replay"
    );
    assert!(
        store
            .record_assertion_id(&other_id, now() + 300)
            .await
            .expect("record")
    );
}

#[tokio::test]
async fn test_record_assertion_id_refuses_an_already_expired_entry() {
    let store = store().await;

    let result = store
        .record_assertion_id(&unique("assertion"), now() - 1)
        .await;
    assert!(
        result.is_err(),
        "an entry that would be forgotten immediately must be refused"
    );
}

#[tokio::test]
async fn test_ids_are_case_sensitive() {
    let store = store().await;
    let (id, realm) = (unique("Req-Mixed"), unique("realm"));
    store
        .store_pending_request(&pending(&id, &realm, now() + 300))
        .await
        .expect("store request");

    assert_eq!(
        store
            .take_pending_request(&id.to_lowercase(), &realm)
            .await
            .expect("take"),
        None,
        "request ids differing only in case are different requests"
    );
    assert!(
        store
            .take_pending_request(&id, &realm)
            .await
            .expect("take")
            .is_some()
    );

    let assertion_id = unique("Assertion-Mixed");
    assert!(
        store
            .record_assertion_id(&assertion_id, now() + 300)
            .await
            .expect("record")
    );
    assert!(
        store
            .record_assertion_id(&assertion_id.to_lowercase(), now() + 300)
            .await
            .expect("record"),
        "assertion ids differing only in case are different assertions"
    );
}

#[tokio::test]
async fn test_long_assertion_ids_sharing_a_prefix_are_distinct() {
    let store = store().await;
    let prefix = format!("{}{}", unique("assertion"), "x".repeat(300));
    let (first, second) = (format!("{prefix}-first"), format!("{prefix}-second"));

    assert!(
        store
            .record_assertion_id(&first, now() + 300)
            .await
            .expect("record")
    );
    assert!(
        store
            .record_assertion_id(&second, now() + 300)
            .await
            .expect("record"),
        "ids that differ only after 255 characters are different assertions"
    );
    assert!(
        !store
            .record_assertion_id(&first, now() + 300)
            .await
            .expect("record"),
        "a long id is still recognized as a replay"
    );
}

#[tokio::test]
async fn test_delete_expired_purges_only_expired_entries() {
    let store = store().await;
    let (fresh_request, realm) = (unique("req"), unique("realm"));
    let (stale_assertion, fresh_assertion) = (unique("assertion"), unique("assertion"));
    store
        .store_pending_request(&pending(&fresh_request, &realm, now() + 300))
        .await
        .expect("store request");
    store
        .record_assertion_id(&stale_assertion, now() + 2)
        .await
        .expect("record");
    store
        .record_assertion_id(&fresh_assertion, now() + 300)
        .await
        .expect("record");

    sleep(Duration::from_secs(3)).await;
    store.delete_expired().await.expect("delete expired");

    assert!(
        store
            .record_assertion_id(&stale_assertion, now() + 300)
            .await
            .expect("record"),
        "the expired entry must have been purged"
    );
    assert!(
        !store
            .record_assertion_id(&fresh_assertion, now() + 300)
            .await
            .expect("record"),
        "an unexpired entry must survive the purge"
    );
    assert!(
        store
            .take_pending_request(&fresh_request, &realm)
            .await
            .expect("take")
            .is_some(),
        "an unexpired pending request must survive the purge"
    );
}
