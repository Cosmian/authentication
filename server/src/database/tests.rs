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
    APP_REALM_ADMIN_USERNAME, Database, create_database, hash_password_with_argon2,
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
        password: hash_password_with_argon2(username, password).expect("Failed to hash password"),
        change_password,
        roles: Vec::new(),
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
