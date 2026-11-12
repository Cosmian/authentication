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

use std::collections::HashMap;
use std::sync::Arc;

use sqlx::{MySqlPool, PgPool, SqlitePool, sqlite::SqlitePoolOptions};

use crate::database::{
    APP_REALM_ADMIN_USERNAME, AppRole, AppSecretId, AppToken, AuthDbError, Database, K8sRole,
    MySqlDatabase, PostgresDatabase, SqliteDatabase, create_database, hash_password_with_argon2,
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

/// A connection pool on the same database as a [`Database`], to set up legacy schemas.
enum RawPool {
    Sqlite(SqlitePool),
    Postgres(PgPool),
    MySql(MySqlPool),
}

impl RawPool {
    async fn execute(&self, sql: &str) {
        match self {
            Self::Sqlite(pool) => sqlx::query(sql).execute(pool).await.map(|_| ()),
            Self::Postgres(pool) => sqlx::query(sql).execute(pool).await.map(|_| ()),
            Self::MySql(pool) => sqlx::query(sql).execute(pool).await.map(|_| ()),
        }
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
}

/// Every configured backend, initialized, with raw access to its database.
async fn databases_with_raw_access() -> Vec<(&'static str, Arc<dyn Database>, RawPool)> {
    let sqlite = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("SQLite pool");
    let mut dbs: Vec<(&'static str, Arc<dyn Database>, RawPool)> = vec![(
        "SQLite",
        Arc::new(SqliteDatabase::new(sqlite.clone())),
        RawPool::Sqlite(sqlite),
    )];
    if let Ok(url) = std::env::var("TEST_POSTGRES_URL") {
        let pool = PgPool::connect(&url).await.expect("PostgreSQL pool");
        dbs.push((
            "PostgreSQL",
            Arc::new(PostgresDatabase::new(pool.clone())),
            RawPool::Postgres(pool),
        ));
    }
    if let Ok(url) = std::env::var("TEST_MYSQL_URL") {
        let pool = MySqlPool::connect(&url).await.expect("MySQL pool");
        dbs.push((
            "MySQL",
            Arc::new(MySqlDatabase::new(pool.clone())),
            RawPool::MySql(pool),
        ));
    }
    for (name, db, _) in &dbs {
        db.init()
            .await
            .unwrap_or_else(|e| panic!("{name} init: {e}"));
    }
    dbs
}

/// A `_` login with an unusable password hash, for tests that never log in.
fn admin_realm_login(username: &str) -> UserPass {
    UserPass {
        realm: ADMIN_REALM.to_string(),
        username: username.to_string(),
        password_hash: "unused".to_string(),
        password_input: None,
        change_password: false,
        roles: Vec::new(),
        extra_claims: None,
    }
}

/// 2FA is stored on the login: it needs the login, and goes away with it.
#[tokio::test]
async fn test_totp_lives_on_the_login() {
    const SECRET: &str = "JBSWY3DPEHPK3PXP";
    for (name, db) in get_all_test_databases().await {
        let login = "totp_on_login";
        db.delete_userpass(ADMIN_REALM, login)
            .await
            .expect("cleanup");
        assert!(
            !db.enable_totp(ADMIN_REALM, login, SECRET)
                .await
                .expect("enable"),
            "{name}: no login, no 2FA"
        );

        db.create_userpass(&admin_realm_login(login))
            .await
            .expect("login");
        assert!(
            db.enable_totp(ADMIN_REALM, login, SECRET)
                .await
                .expect("enable"),
            "{name}"
        );
        assert_eq!(
            db.get_totp_secret(ADMIN_REALM, login)
                .await
                .expect("get")
                .as_deref(),
            Some(SECRET),
            "{name}"
        );
        db.disable_totp(ADMIN_REALM, login).await.expect("disable");
        assert_eq!(
            db.get_totp_secret(ADMIN_REALM, login).await.expect("get"),
            None,
            "{name}"
        );

        db.enable_totp(ADMIN_REALM, login, SECRET)
            .await
            .expect("enable");
        db.delete_userpass(ADMIN_REALM, login)
            .await
            .expect("delete");
        db.create_userpass(&admin_realm_login(login))
            .await
            .expect("login");
        assert_eq!(
            db.get_totp_secret(ADMIN_REALM, login).await.expect("get"),
            None,
            "{name}: a recreated login starts without 2FA"
        );
        db.delete_userpass(ADMIN_REALM, login)
            .await
            .expect("cleanup");
    }
}

/// Before 0.6.0 the 2FA of an admin lived on its admin record: startup moves it to the admin's
/// `_` login, drops it for an admin without one (a JWT admin), and removes the old columns.
#[tokio::test]
async fn test_admin_2fa_moves_to_the_admin_login() {
    use crate::tests::helpers::test_admin;

    for (name, db, raw) in databases_with_raw_access().await {
        for id in ["mig_linked", "mig_jwt"] {
            db.delete_admin(id).await.expect("cleanup");
        }
        db.delete_userpass(ADMIN_REALM, "mig_login")
            .await
            .expect("cleanup");
        db.create_userpass(&admin_realm_login("mig_login"))
            .await
            .expect("login");
        let mut linked = test_admin("mig_linked");
        linked.userpass = Some("mig_login".to_string());
        db.create_admin(&linked).await.expect("linked admin");
        let mut jwt = test_admin("mig_jwt");
        jwt.jwt = Some("mig-subject".to_string());
        db.create_admin(&jwt).await.expect("JWT admin");
        for sql in [
            "ALTER TABLE admin ADD COLUMN totp_enabled BOOLEAN",
            "ALTER TABLE admin ADD COLUMN totp_secret TEXT",
            "ALTER TABLE admin ADD COLUMN totp_auth_url TEXT",
            "UPDATE admin SET totp_enabled = TRUE, totp_secret = 'JBSWY3DPEHPK3PXP' \
             WHERE id IN ('mig_linked', 'mig_jwt')",
        ] {
            raw.execute(sql).await;
        }

        db.init().await.expect("migrating init");
        db.init().await.expect("init after the migration");

        assert_eq!(
            db.get_totp_secret(ADMIN_REALM, "mig_login")
                .await
                .expect("get")
                .as_deref(),
            Some("JBSWY3DPEHPK3PXP"),
            "{name}"
        );
        let totp_enabled = |admin: Option<crate::models::Admin>| admin.and_then(|a| a.totp_enabled);
        assert_eq!(
            totp_enabled(db.get_admin("mig_linked").await.expect("get")),
            Some(true),
            "{name}"
        );
        assert_eq!(
            totp_enabled(db.get_admin("mig_jwt").await.expect("get")),
            Some(false),
            "{name}"
        );

        for id in ["mig_linked", "mig_jwt"] {
            db.delete_admin(id).await.expect("cleanup");
        }
        db.delete_userpass(ADMIN_REALM, "mig_login")
            .await
            .expect("cleanup");
    }
}

fn create_user(realm: &str, username: &str, password: &str, change_password: bool) -> UserPass {
    UserPass {
        realm: realm.to_string(),
        username: username.to_string(),
        password_hash: hash_password_with_argon2(password).expect("Failed to hash password"),
        password_input: None,
        change_password,
        roles: Vec::new(),
        extra_claims: None,
    }
}

#[test]
fn test_realm_creation() {
    let realm = Realm {
        id: "test-realm".to_string(),
        auth_params: RealmAuthParams::default(),
        session_max_age_seconds: 3600,
        session_max_stale_age_seconds: 3600,
        certificate_max_age_seconds: 365 * 24 * 3600,
    };

    assert_eq!(realm.id, "test-realm");
}

#[test]
fn test_userpass_creation() {
    let userpass = create_user("test-realm", "alice", "alice password", false);

    assert_eq!(userpass.realm, "test-realm");
    assert_eq!(userpass.username, "alice");
    assert_ne!(userpass.password_hash, "alice password"); // Password should be hashed
    assert!(!userpass.change_password);
}

/// Two admins can never share a `userpass` or a `jwt` login; admins without a login are free.
#[tokio::test]
async fn test_admin_logins_are_unique() {
    use crate::tests::helpers::test_admin;

    for (name, db) in get_all_test_databases().await {
        println!("Testing unique admin logins on {name}");
        let ids = ["unique_login_a", "unique_login_b", "unique_login_c"];
        for id in ids {
            db.delete_admin(id).await.expect("cleanup");
        }

        let mut first = test_admin(ids[0]);
        first.userpass = Some("unique_login_user".to_string());
        first.jwt = Some("unique_login_jwt".to_string());
        db.create_admin(&first).await.expect("create first");

        let mut same_userpass = test_admin(ids[1]);
        same_userpass.userpass = first.userpass.clone();
        let result = db.create_admin(&same_userpass).await;
        assert!(
            matches!(result, Err(AuthDbError::Conflict(_))),
            "{name}: {result:?}"
        );

        let mut same_jwt = test_admin(ids[1]);
        same_jwt.jwt = first.jwt.clone();
        let result = db.create_admin(&same_jwt).await;
        assert!(
            matches!(result, Err(AuthDbError::Conflict(_))),
            "{name}: {result:?}"
        );

        db.create_admin(&test_admin(ids[1]))
            .await
            .expect("no login");
        db.create_admin(&test_admin(ids[2]))
            .await
            .expect("no login");

        let mut stolen = test_admin(ids[1]);
        stolen.userpass = first.userpass.clone();
        let result = db.update_admin(&stolen).await;
        assert!(
            matches!(result, Err(AuthDbError::Conflict(_))),
            "{name}: {result:?}"
        );

        for id in ids {
            db.delete_admin(id).await.expect("cleanup");
        }
    }
}

/// An admin with every optional field set reads back unchanged, through `get` and `list`.
#[tokio::test]
async fn test_admin_round_trip() {
    use crate::tests::helpers::test_admin;

    for (name, db) in get_all_test_databases().await {
        let mut admin = test_admin("round_trip_admin");
        db.delete_admin(&admin.id).await.expect("cleanup");
        admin.realms = vec![ADMIN_REALM.to_string()];
        admin.userpass = Some("round_trip_user".to_string());
        admin.jwt = Some("round_trip_jwt".to_string());
        admin.digital_credentials = Some(HashMap::from([(
            "issuer".to_string(),
            "https://issuer.example".to_string(),
        )]));
        db.create_admin(&admin).await.expect("create");

        let listed = db.list_admins().await.expect("list");
        for read in [
            db.get_admin(&admin.id).await.expect("get"),
            listed.into_iter().find(|a| a.id == admin.id),
        ] {
            let read = read.unwrap_or_else(|| panic!("{name}: admin not found"));
            assert_eq!(read.realms, admin.realms, "{name}");
            assert_eq!(read.userpass, admin.userpass, "{name}");
            assert_eq!(read.jwt, admin.jwt, "{name}");
            assert_eq!(
                read.digital_credentials, admin.digital_credentials,
                "{name}"
            );
        }
        db.delete_admin(&admin.id).await.expect("cleanup");
    }
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
            certificate_max_age_seconds: 365 * 24 * 3600,
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
            certificate_max_age_seconds: 365 * 24 * 3600,
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
            certificate_max_age_seconds: 365 * 24 * 3600,
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
        assert_ne!(retrieved.password_hash, "password123");

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
        assert_ne!(retrieved.password_hash, "new password");

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
