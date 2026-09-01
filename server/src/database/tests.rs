// Running the Tests
// ==================
//
// SQLite only (always runs):
//   cargo test --package auth_authentication
//
// With PostgreSQL (requires running PostgreSQL server):
//   TEST_POSTGRES_URL="postgresql://user:pass@localhost/test_db" cargo test --package auth_authentication
//
// With MySQL (requires running MySQL server):
//   TEST_MYSQL_URL="mysql://user:pass@localhost/test_db" cargo test --package auth_authentication
//
// All three databases:
//   TEST_POSTGRES_URL="postgresql://user:pass@localhost/test_db" \
//   TEST_MYSQL_URL="mysql://user:pass@localhost/test_db" \
//   cargo test --package auth_authentication
//
// The tests will automatically skip PostgreSQL and MySQL if their environment variables aren't set,
// so SQLite tests will always run without any setup required.

use std::sync::Arc;

use crate::database::{
    APP_REALM_ADMIN_USERNAME, AppRole, AppSecretId, AppToken, Database, K8sRole, create_database,
    hash_password_with_argon2,
};
use crate::models::{ADMIN_REALM, Realm, UserPass};
use crate::{DatabaseBackend, DatabaseParams, RealmAuthParams};

// Helper to create test databases
async fn create_sqlite_db() -> Arc<dyn Database> {
    create_database(&DatabaseParams {
        backend: DatabaseBackend::SQLite,
        connection_url: "sqlite::memory:".to_string(),
        max_connections: 5,
        min_connections: 1,
        connect_timeout_secs: 30,
        idle_timeout_secs: 300,
        auto_init_schema: true,
    })
    .await
    .expect("Failed to create SQLite database")
}

// Note: PostgreSQL and MySQL tests require running database servers
// Set TEST_POSTGRES_URL and TEST_MYSQL_URL environment variables to enable these tests
async fn create_postgres_db() -> Option<Arc<dyn Database>> {
    if let Ok(url) = std::env::var("TEST_POSTGRES_URL") {
        Some(
            create_database(&DatabaseParams {
                backend: DatabaseBackend::PostgreSQL,
                connection_url: url,
                max_connections: 5,
                min_connections: 1,
                connect_timeout_secs: 30,
                idle_timeout_secs: 300,
                auto_init_schema: true,
            })
            .await
            .expect("Failed to create PostgreSQL database"),
        )
    } else {
        None
    }
}

async fn create_mysql_db() -> Option<Arc<dyn Database>> {
    if let Ok(url) = std::env::var("TEST_MYSQL_URL") {
        Some(
            create_database(&DatabaseParams {
                backend: DatabaseBackend::MySQL,
                connection_url: url,
                max_connections: 5,
                min_connections: 1,
                connect_timeout_secs: 30,
                idle_timeout_secs: 300,
                auto_init_schema: true,
            })
            .await
            .expect("Failed to create MySQL database"),
        )
    } else {
        None
    }
}

async fn get_all_test_databases() -> Vec<(&'static str, Arc<dyn Database>)> {
    let mut dbs = vec![("SQLite", create_sqlite_db().await)];

    if let Some(db) = create_postgres_db().await {
        dbs.push(("PostgreSQL", db));
    }

    if let Some(db) = create_mysql_db().await {
        dbs.push(("MySQL", db));
    }

    dbs
}

fn create_user(realm: &str, username: &str, password: &str, change_password: bool) -> UserPass {
    UserPass {
        realm: realm.to_string(),
        username: username.to_string(),
        password: hash_password_with_argon2(password).expect("Failed to hash password"),
        change_password,
        roles: Vec::new(),
        email: None,
    }
}

#[test]
fn test_realm_creation() {
    let realm = Realm {
        id: "test-realm".to_string(),
        auth_params: RealmAuthParams::default(),
        session_max_age_seconds: 3600,
        session_max_stale_age_seconds: 3600,
    };

    assert_eq!(realm.id, "test-realm");
}

#[test]
fn test_userpass_creation() {
    let userpass = create_user("test-realm", "alice", "alice password", false);

    assert_eq!(userpass.realm, "test-realm");
    assert_eq!(userpass.username, "alice");
    assert_ne!(userpass.password, "alice password".as_bytes()); // Password should be hashed
    assert!(!userpass.change_password);
}

#[tokio::test]
async fn test_database_init() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} database initialization");

        // The should be the application realm ADMIN_REALM and the 'APP_REALM_ADMIN_USERNAME' user
        let realm = db
            .get_realm(ADMIN_REALM)
            .await
            .expect("Failed to get realm")
            .expect("Application realm not found");
        assert_eq!(realm.id, ADMIN_REALM);

        // Further checks can be added for the 'APP_REALM_ADMIN_USERNAME' userpass entry
        let user = db
            .get_userpass(ADMIN_REALM, APP_REALM_ADMIN_USERNAME)
            .await
            .expect("Failed to get userpass")
            .unwrap_or_else(|| panic!("{APP_REALM_ADMIN_USERNAME} user not found"));
        assert_eq!(user.username, APP_REALM_ADMIN_USERNAME);
    }
}

#[tokio::test]
async fn test_realm_crud() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} realm CRUD");

        // Create a test realm
        let realm = Realm {
            id: format!("test-{}", name.to_lowercase().replace(' ', "-")),
            auth_params: RealmAuthParams::default(),
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
        };

        db.create_realm(&realm)
            .await
            .expect("Failed to create realm");

        // Retrieve the realm
        let retrieved = db
            .get_realm(&realm.id)
            .await
            .expect("Failed to get realm")
            .expect("Realm not found");

        assert_eq!(retrieved.id, realm.id);

        // Clean up
        db.delete_realm(&realm.id)
            .await
            .expect("Failed to delete realm");
    }
}

#[tokio::test]
async fn test_realm_deletion_cascades_userpass() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} cascade deletion");

        let realm_id = format!("cascade-test-{}", name.to_lowercase().replace(' ', "-"));

        // Create a test realm
        let realm = Realm {
            id: realm_id.clone(),
            auth_params: RealmAuthParams::default(),
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
        };
        db.create_realm(&realm)
            .await
            .expect("Failed to create realm");

        // Create multiple users in the realm
        let user1 = create_user(&realm_id, "alice", "password1", false);
        let user2 = create_user(&realm_id, "bob", "password2", false);

        db.create_userpass(&user1)
            .await
            .expect("Failed to create user1");
        db.create_userpass(&user2)
            .await
            .expect("Failed to create user2");

        // Verify users exist
        assert!(
            db.get_userpass(&realm_id, "alice")
                .await
                .expect("Failed to get user")
                .is_some()
        );
        assert!(
            db.get_userpass(&realm_id, "bob")
                .await
                .expect("Failed to get user")
                .is_some()
        );

        // Delete the realm
        db.delete_realm(&realm_id)
            .await
            .expect("Failed to delete realm");

        // Verify realm is deleted
        assert!(
            db.get_realm(&realm_id)
                .await
                .expect("Failed to get realm")
                .is_none()
        );

        // Verify associated users are also deleted (CASCADE behavior)
        assert!(
            db.get_userpass(&realm_id, "alice")
                .await
                .expect("Failed to get user")
                .is_none(),
            "{name}: alice should be deleted via CASCADE"
        );
        assert!(
            db.get_userpass(&realm_id, "bob")
                .await
                .expect("Failed to get user")
                .is_none(),
            "{name}: bob should be deleted via CASCADE"
        );
    }
}

#[tokio::test]
async fn test_userpass_crud() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} userpass CRUD");

        let realm_id = format!("userpass-test-{}", name.to_lowercase().replace(' ', "-"));

        // Create realm first
        let realm = Realm {
            id: realm_id.clone(),
            auth_params: RealmAuthParams::default(),
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
        };
        db.create_realm(&realm)
            .await
            .expect("Failed to create realm");

        // Create user
        let user = create_user(&realm_id, "alice", "password123", false);
        db.create_userpass(&user)
            .await
            .expect("Failed to create user");

        // Retrieve user
        let retrieved = db
            .get_userpass(&realm_id, "alice")
            .await
            .expect("Failed to get user")
            .expect("User not found");

        assert_eq!(retrieved.username, "alice");
        assert_ne!(retrieved.password, b"password123");

        // Update user
        let updated = create_user(&realm_id, "alice", "new password", false);
        db.update_userpass(&updated)
            .await
            .expect("Failed to update user");

        let retrieved = db
            .get_userpass(&realm_id, "alice")
            .await
            .expect("Failed to get user")
            .expect("User not found");
        assert_ne!(retrieved.password, b"new password");

        // Delete user
        db.delete_userpass(&realm_id, "alice")
            .await
            .expect("Failed to delete user");

        let result = db
            .get_userpass(&realm_id, "alice")
            .await
            .expect("Failed to get user");
        assert!(result.is_none());

        // Clean up
        db.delete_realm(&realm_id)
            .await
            .expect("Failed to delete realm");
    }
}

// ── App token database tests ──────────────────────────────────────────────────

fn make_token(suffix: u8) -> AppToken {
    use sha2::{Digest, Sha256};
    let raw = format!("hvs.test-token-{suffix}");
    let now = chrono::Utc::now().timestamp();
    AppToken {
        token_hash: Sha256::digest(raw.as_bytes()).to_vec(),
        entity: format!("entity-{suffix}"),
        policies: vec!["default".to_string()],
        expiry: now + 3600,
        renewable: true,
        lease_duration_secs: 3600,
        created_at: now,
    }
}

/// Issue a token and look it up — it must be found before it expires.
#[tokio::test]
async fn test_app_token_issue_and_lookup() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} app_token issue + lookup");
        let token = make_token(1);
        db.issue_app_token(&token).await.expect("issue_app_token");
        let found = db
            .lookup_app_token(&token.token_hash)
            .await
            .expect("lookup_app_token")
            .expect("token should be present");
        assert_eq!(found.entity, token.entity);
        assert_eq!(found.policies, token.policies);
    }
}

/// A revoked token must no longer be returned by lookup.
#[tokio::test]
async fn test_app_token_revoke() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} app_token revoke");
        let token = make_token(2);
        db.issue_app_token(&token).await.expect("issue_app_token");
        db.revoke_app_token(&token.token_hash)
            .await
            .expect("revoke_app_token");
        let found = db
            .lookup_app_token(&token.token_hash)
            .await
            .expect("lookup_app_token");
        assert!(found.is_none(), "{name}: revoked token must not be found");
    }
}

/// Renewing a renewable token must succeed and extend its expiry.
#[tokio::test]
async fn test_app_token_renew() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} app_token renew");
        let token = make_token(3);
        db.issue_app_token(&token).await.expect("issue_app_token");

        // Renew must succeed for a token with expiry > 0 and renewable = true
        db.renew_app_token(&token.token_hash)
            .await
            .expect("renew_app_token");

        let renewed = db
            .lookup_app_token(&token.token_hash)
            .await
            .expect("lookup after renew")
            .expect("token must still exist after renew");
        // Expiry must be at least as far as the original
        assert!(
            renewed.expiry >= token.expiry,
            "{name}: expiry must not decrease after renew"
        );
    }
}

/// Renewing a non-renewable token must fail.
#[tokio::test]
async fn test_app_token_renew_non_renewable_fails() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} app_token renew non-renewable");
        let mut token = make_token(4);
        token.renewable = false;
        db.issue_app_token(&token).await.expect("issue_app_token");

        let result = db.renew_app_token(&token.token_hash).await;
        assert!(
            result.is_err(),
            "{name}: renewing a non-renewable token must fail"
        );
    }
}

// ── AppRole database tests ────────────────────────────────────────────────────

fn make_approle(name: &str) -> AppRole {
    AppRole {
        name: name.to_string(),
        role_id: uuid::Uuid::new_v4().to_string(),
        secret_id_ttl_secs: 0,
        token_ttl_secs: 3600,
        bind_secret_id: true,
        token_policies: vec!["default".to_string()],
    }
}

/// Create, lookup by name, lookup by role_id, delete — round-trip.
#[tokio::test]
async fn test_approle_crud() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} AppRole CRUD");
        let role = make_approle("crud-role");
        db.create_approle(&role).await.expect("create_approle");

        // Lookup by name
        let by_name = db
            .get_approle_by_name("crud-role")
            .await
            .expect("get_approle_by_name")
            .expect("role must be found by name");
        assert_eq!(by_name.role_id, role.role_id);

        // Lookup by role_id
        let by_id = db
            .get_approle_by_role_id(&role.role_id)
            .await
            .expect("get_approle_by_role_id")
            .expect("role must be found by role_id");
        assert_eq!(by_id.name, role.name);

        // List
        let keys = db.list_approle_names().await.expect("list_approle_names");
        assert!(keys.contains(&"crud-role".to_string()));

        // Delete
        db.delete_approle("crud-role")
            .await
            .expect("delete_approle");
        assert!(
            db.get_approle_by_name("crud-role")
                .await
                .expect("get after delete")
                .is_none(),
            "{name}: role must be gone after delete"
        );
    }
}

/// Upsert (create_approle on conflict) must preserve role_id and update other fields.
#[tokio::test]
async fn test_approle_upsert_preserves_role_id() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} AppRole upsert");
        let role = make_approle("upsert-role");
        db.create_approle(&role).await.expect("create_approle");

        // Update TTL but keep same name
        let updated = AppRole {
            name: "upsert-role".to_string(),
            role_id: role.role_id.clone(), // same
            token_ttl_secs: 7200,
            secret_id_ttl_secs: 0,
            bind_secret_id: false,
            token_policies: vec![],
        };
        db.create_approle(&updated).await.expect("upsert_approle");

        let found = db
            .get_approle_by_name("upsert-role")
            .await
            .expect("get after upsert")
            .unwrap();
        assert_eq!(
            found.role_id, role.role_id,
            "{name}: role_id must be preserved"
        );
        assert_eq!(found.token_ttl_secs, 7200);

        db.delete_approle("upsert-role").await.ok();
    }
}

/// `consume_secret_id` must succeed once and fail on a second call when `num_uses = 1`.
#[tokio::test]
async fn test_consume_secret_id_single_use() {
    use sha2::{Digest, Sha256};

    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} consume_secret_id single-use");

        let role = make_approle("single-use-role");
        db.create_approle(&role).await.expect("create_approle");

        let raw = "my-secret-id";
        let hash = Sha256::digest(raw.as_bytes()).to_vec();
        let now = chrono::Utc::now().timestamp();
        let secret_rec = AppSecretId {
            accessor: uuid::Uuid::new_v4().to_string(),
            secret_id_hash: hash.clone(),
            role_name: "single-use-role".to_string(),
            expiry: 0,
            num_uses_remaining: 1,
        };
        db.create_secret_id(&secret_rec)
            .await
            .expect("create_secret_id");

        // First consume — must succeed
        let accessor = db
            .consume_secret_id("single-use-role", &hash)
            .await
            .expect("consume_secret_id first call")
            .expect("must return Some on first use");
        assert_eq!(accessor, secret_rec.accessor);

        // Second consume — must return None (record deleted)
        let second = db
            .consume_secret_id("single-use-role", &hash)
            .await
            .expect("consume_secret_id second call");
        assert!(
            second.is_none(),
            "{name}: second consume must return None for single-use secret"
        );

        let _ = now; // suppress unused-variable warning
        db.delete_approle("single-use-role").await.ok();
    }
}

/// `consume_secret_id` with `num_uses = -1` (unlimited) must always succeed.
#[tokio::test]
async fn test_consume_secret_id_unlimited() {
    use sha2::{Digest, Sha256};

    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} consume_secret_id unlimited");

        let role = make_approle("unlimited-role");
        db.create_approle(&role).await.expect("create_approle");

        let raw = "unlimited-secret";
        let hash = Sha256::digest(raw.as_bytes()).to_vec();
        let secret_rec = AppSecretId {
            accessor: uuid::Uuid::new_v4().to_string(),
            secret_id_hash: hash.clone(),
            role_name: "unlimited-role".to_string(),
            expiry: 0,
            num_uses_remaining: -1,
        };
        db.create_secret_id(&secret_rec)
            .await
            .expect("create_secret_id");

        // Must be consumable multiple times
        for _ in 0..3 {
            let result = db
                .consume_secret_id("unlimited-role", &hash)
                .await
                .expect("consume_secret_id unlimited");
            assert!(
                result.is_some(),
                "{name}: unlimited secret must always be consumable"
            );
        }

        db.delete_approle("unlimited-role").await.ok();
    }
}

/// An expired `secret_id` must not be consumable.
#[tokio::test]
async fn test_consume_secret_id_expired() {
    use sha2::{Digest, Sha256};

    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} consume_secret_id expired");

        let role = make_approle("expired-secret-role");
        db.create_approle(&role).await.expect("create_approle");

        let raw = "expired-secret";
        let hash = Sha256::digest(raw.as_bytes()).to_vec();
        // Set expiry to 1 second past Unix epoch — definitely expired
        let secret_rec = AppSecretId {
            accessor: uuid::Uuid::new_v4().to_string(),
            secret_id_hash: hash.clone(),
            role_name: "expired-secret-role".to_string(),
            expiry: 1,
            num_uses_remaining: -1,
        };
        db.create_secret_id(&secret_rec)
            .await
            .expect("create_secret_id");

        let result = db
            .consume_secret_id("expired-secret-role", &hash)
            .await
            .expect("consume_secret_id expired");
        assert!(
            result.is_none(),
            "{name}: expired secret must not be consumable"
        );

        db.delete_approle("expired-secret-role").await.ok();
    }
}

// ── Kubernetes role database tests ────────────────────────────────────────────

fn make_k8s_role(name: &str) -> K8sRole {
    K8sRole {
        name: name.to_string(),
        jwks_url: "https://kubernetes.default.svc/.well-known/openid-configuration".to_string(),
        bound_sa_names: r#"["*"]"#.to_string(),
        bound_sa_namespaces: r#"["*"]"#.to_string(),
        token_ttl_secs: 3600,
        expected_issuer: Some("https://kubernetes.default.svc.cluster.local".to_string()),
        bound_audiences: r#"[]"#.to_string(),
    }
}

/// Create, get, delete K8s role — round-trip.
#[tokio::test]
async fn test_k8s_role_crud() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} K8s role CRUD");
        let role = make_k8s_role("k8s-crud-role");
        db.create_k8s_role(&role).await.expect("create_k8s_role");

        let found = db
            .get_k8s_role("k8s-crud-role")
            .await
            .expect("get_k8s_role")
            .expect("role must be found");
        assert_eq!(found.jwks_url, role.jwks_url);
        assert_eq!(found.token_ttl_secs, 3600);
        assert_eq!(found.expected_issuer, role.expected_issuer);

        db.delete_k8s_role("k8s-crud-role")
            .await
            .expect("delete_k8s_role");
        assert!(
            db.get_k8s_role("k8s-crud-role")
                .await
                .expect("get after delete")
                .is_none(),
            "{name}: K8s role must be gone after delete"
        );
    }
}

/// Upsert on conflict must update fields but not create a duplicate.
#[tokio::test]
async fn test_k8s_role_upsert() {
    for (name, db) in get_all_test_databases().await {
        println!("Testing {name} K8s role upsert");
        let role = make_k8s_role("k8s-upsert-role");
        db.create_k8s_role(&role).await.expect("create_k8s_role");

        let updated = K8sRole {
            name: "k8s-upsert-role".to_string(),
            jwks_url: "https://updated.example.com/jwks".to_string(),
            bound_sa_names: r#"["spire-agent"]"#.to_string(),
            bound_sa_namespaces: r#"["spire"]"#.to_string(),
            token_ttl_secs: 7200,
            expected_issuer: None,
            bound_audiences: r#"["vault"]"#.to_string(),
        };
        db.create_k8s_role(&updated).await.expect("upsert_k8s_role");

        let found = db
            .get_k8s_role("k8s-upsert-role")
            .await
            .expect("get after upsert")
            .unwrap();
        assert_eq!(
            found.token_ttl_secs, 7200,
            "{name}: token_ttl must be updated"
        );
        assert_eq!(
            found.expected_issuer, None,
            "{name}: expected_issuer must be updated"
        );

        db.delete_k8s_role("k8s-upsert-role").await.ok();
    }
}
