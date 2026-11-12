use std::collections::HashMap;

use crate::{
    database::{
        AuthDbError, AuthDbResult,
        r#trait::{AppRole, AppSecretId, AppToken, Database, K8sRole},
    },
    models::{ADMIN_REALM, Admin, AuthScheme, Realm, UserPass},
};
use async_trait::async_trait;
use cosmian_logger::warn;
use sqlx::{Row, SqlitePool};

/// Unique indexes on the admin login columns: (column, shared-values query, create index).
const ADMIN_LOGIN_INDEXES: [(&str, &str, &str); 2] = [
    (
        "userpass",
        "SELECT userpass FROM admin WHERE userpass IS NOT NULL GROUP BY userpass HAVING COUNT(*) > 1",
        "CREATE UNIQUE INDEX IF NOT EXISTS admin_userpass_unique ON admin(userpass)",
    ),
    (
        "jwt",
        "SELECT jwt FROM admin WHERE jwt IS NOT NULL GROUP BY jwt HAVING COUNT(*) > 1",
        "CREATE UNIQUE INDEX IF NOT EXISTS admin_jwt_unique ON admin(jwt)",
    ),
];

/// Admin columns, with `totp_enabled` computed from the 2FA of the admin's `_` login (bind
/// [`ADMIN_REALM`] first).
macro_rules! select_admins {
    ($rest:literal) => {
        concat!(
            "SELECT id, userpass, jwt, fido2, digital_credentials, certificate, ",
            "EXISTS (SELECT 1 FROM userpass u WHERE u.realm = ? AND u.username = admin.userpass ",
            "AND u.totp_secret IS NOT NULL) AS totp_enabled FROM admin ",
            $rest
        )
    };
}

/// SQLite database implementation
pub struct SqliteDatabase {
    pool: SqlitePool,
}

impl SqliteDatabase {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Makes each admin login column unique, so two admins can never share a login. Refuses to
    /// start when admins already share one: each admin must get its own login first.
    async fn ensure_unique_admin_logins(&self) -> AuthDbResult<()> {
        for (column, shared_sql, create_index_sql) in ADMIN_LOGIN_INDEXES {
            let shared: Vec<String> = sqlx::query_scalar(shared_sql).fetch_all(&self.pool).await?;
            if !shared.is_empty() {
                return Err(AuthDbError::Init(format!(
                    "several admins share the {column} login(s) {shared:?}: give each admin its own login"
                )));
            }
            sqlx::query(create_index_sql).execute(&self.pool).await?;
        }
        Ok(())
    }

    /// Moves the 2FA stored on admin records (before 0.6.0) to their `_` login, then drops the
    /// admin 2FA columns. An admin without a `_` login (a JWT admin) loses its 2FA, with a warning.
    async fn migrate_admin_totp(&self) -> AuthDbResult<()> {
        let has_admin_totp: bool = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('admin') WHERE name='totp_secret'",
        )
        .fetch_one(&self.pool)
        .await
        .map(|c: i32| c > 0)?;
        if !has_admin_totp {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT id, userpass, totp_secret FROM admin WHERE totp_secret IS NOT NULL",
        )
        .fetch_all(&mut *tx)
        .await?;
        for row in rows {
            let id: String = row.try_get("id")?;
            let userpass: Option<String> = row.try_get("userpass")?;
            let secret: String = row.try_get("totp_secret")?;
            let moved = match userpass {
                Some(login) => {
                    sqlx::query(
                        "UPDATE userpass SET totp_secret = ? WHERE realm = ? AND username = ?",
                    )
                    .bind(&secret)
                    .bind(ADMIN_REALM)
                    .bind(&login)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                        > 0
                }
                None => false,
            };
            if !moved {
                warn!(
                    "admin '{id}' loses its 2FA: 2FA now protects '{ADMIN_REALM}' username/password logins only, and this admin has none"
                );
            }
        }
        for drop_sql in [
            "ALTER TABLE admin DROP COLUMN totp_enabled",
            "ALTER TABLE admin DROP COLUMN totp_secret",
            "ALTER TABLE admin DROP COLUMN totp_auth_url",
        ] {
            sqlx::query(drop_sql).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Builds an [`Admin`] from a row selected with [`select_admins`].
    async fn row_to_admin(&self, row: &sqlx::sqlite::SqliteRow) -> AuthDbResult<Admin> {
        let id: String = row.try_get("id")?;
        let realms: Vec<String> =
            sqlx::query_scalar("SELECT realm_id FROM admin_realms WHERE admin_id = ?")
                .bind(&id)
                .fetch_all(&self.pool)
                .await?;
        let digital_credentials: Option<HashMap<String, String>> = row
            .try_get::<Option<String>, _>("digital_credentials")?
            .map(|v| {
                serde_json::from_str(&v).map_err(|e| {
                    AuthDbError::Unexpected(format!(
                        "Failed to deserialize the digital credentials: {e}"
                    ))
                })
            })
            .transpose()?;
        Ok(Admin {
            id,
            realms,
            userpass: row.try_get("userpass")?,
            jwt: row.try_get("jwt")?,
            fido2: row.try_get("fido2")?,
            digital_credentials,
            client_certificate: row.try_get("certificate")?,
            totp_enabled: Some(row.try_get::<i64, _>("totp_enabled")? != 0),
        })
    }

    /// Map a query row to a [`AppRole`].
    fn row_to_approle(row: Option<sqlx::sqlite::SqliteRow>) -> AuthDbResult<Option<AppRole>> {
        match row {
            Some(r) => {
                let policies_json: String = r.try_get("token_policies")?;
                Ok(Some(AppRole {
                    name: r.try_get("name")?,
                    role_id: r.try_get("role_id")?,
                    secret_id_ttl_secs: r.try_get("secret_id_ttl_secs")?,
                    token_ttl_secs: r.try_get("token_ttl_secs")?,
                    bind_secret_id: r.try_get::<i64, _>("bind_secret_id")? != 0,
                    token_policies: serde_json::from_str(&policies_json).unwrap_or_default(),
                }))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
impl Database for SqliteDatabase {
    async fn init(&self) -> AuthDbResult<()> {
        // Enable foreign key constraints for SQLite
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&self.pool)
            .await?;

        // Create realm table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS realm (
                id TEXT PRIMARY KEY CHECK (id GLOB '[a-zA-Z0-9_-]*'),
                auth_params TEXT NOT NULL,
                cookie_max_age_seconds INTEGER NOT NULL,
                max_stale_age_seconds INTEGER NOT NULL,
                certificate_max_age_seconds INTEGER NOT NULL DEFAULT 31536000
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Migration: add the column to a realm table created before this field existed.
        // Check first (rather than attempting the ALTER and swallowing any error) so a real
        // failure — permissions, a locked DB, corruption — surfaces instead of silently
        // leaving the schema without this column.
        let has_certificate_max_age_seconds: bool = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('realm') WHERE name='certificate_max_age_seconds'",
        )
        .fetch_one(&self.pool)
        .await
        .map(|c: i32| c > 0)?;
        if !has_certificate_max_age_seconds {
            sqlx::query(
                "ALTER TABLE realm ADD COLUMN certificate_max_age_seconds INTEGER NOT NULL DEFAULT 31536000",
            )
            .execute(&self.pool)
            .await?;
        }

        // Create userpass table with composite primary key and foreign key
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS userpass (
                realm TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                change_password INTEGER NOT NULL DEFAULT 0,
                roles TEXT NOT NULL DEFAULT '[]',
                extra_claims TEXT,
                PRIMARY KEY (realm, username),
                FOREIGN KEY (realm) REFERENCES realm(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Migration: add roles column if missing (existing databases)
        let has_roles: bool = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('userpass') WHERE name='roles'",
        )
        .fetch_one(&self.pool)
        .await
        .map(|c: i32| c > 0)?;
        if !has_roles {
            sqlx::query("ALTER TABLE userpass ADD COLUMN roles TEXT NOT NULL DEFAULT '[]'")
                .execute(&self.pool)
                .await?;
        }

        // Migration: add extra_claims column if missing (existing databases)
        let has_extra_claims: bool = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('userpass') WHERE name='extra_claims'",
        )
        .fetch_one(&self.pool)
        .await
        .map(|c: i32| c > 0)?;
        if !has_extra_claims {
            sqlx::query("ALTER TABLE userpass ADD COLUMN extra_claims TEXT")
                .execute(&self.pool)
                .await?;
        }

        // Migration: 2FA secret of the login (Base32), added in 0.6.0
        let has_totp_secret: bool = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('userpass') WHERE name='totp_secret'",
        )
        .fetch_one(&self.pool)
        .await
        .map(|c: i32| c > 0)?;
        if !has_totp_secret {
            sqlx::query("ALTER TABLE userpass ADD COLUMN totp_secret TEXT")
                .execute(&self.pool)
                .await?;
        }

        // Create admin table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS admin (
                id TEXT PRIMARY KEY,
                userpass TEXT,
                jwt TEXT,
                fido2 TEXT,
                digital_credentials TEXT,
                certificate TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        // Create user_realms join table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS admin_realms (
                admin_id TEXT NOT NULL,
                realm_id TEXT NOT NULL,
                PRIMARY KEY (admin_id, realm_id),
                FOREIGN KEY (admin_id) REFERENCES admin(id) ON DELETE CASCADE,
                FOREIGN KEY (realm_id) REFERENCES realm(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        self.ensure_unique_admin_logins().await?;
        self.migrate_admin_totp().await?;
        // If the realm table is empty, insert the ADMIN_REALM (application) realm
        // and insert a remove_me:remove_me userpass entry for it in the userpass table
        let realm_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM realm")
            .fetch_one(&self.pool)
            .await?;
        if realm_count.0 == 0 {
            self.initialize_db().await?;
        }

        // ── App auth tables ─────────────────────────────────────────────────
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS app_tokens (
                token_hash      BLOB    NOT NULL PRIMARY KEY,
                entity          TEXT    NOT NULL,
                policies        TEXT    NOT NULL DEFAULT '',
                expiry          INTEGER NOT NULL,
                renewable       INTEGER NOT NULL DEFAULT 0,
                lease_duration_secs INTEGER NOT NULL DEFAULT 3600,
                created_at      INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS approle_roles (
                name                TEXT    NOT NULL PRIMARY KEY,
                role_id             TEXT    NOT NULL UNIQUE,
                secret_id_ttl_secs  INTEGER NOT NULL DEFAULT 0,
                token_ttl_secs      INTEGER NOT NULL DEFAULT 3600,
                bind_secret_id      INTEGER NOT NULL DEFAULT 1,
                token_policies      TEXT    NOT NULL DEFAULT '[]'
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS app_secret_ids (
                accessor            TEXT    NOT NULL PRIMARY KEY,
                secret_id_hash      BLOB    NOT NULL,
                role_name           TEXT    NOT NULL,
                expiry              INTEGER NOT NULL DEFAULT 0,
                num_uses_remaining  INTEGER NOT NULL DEFAULT -1,
                FOREIGN KEY (role_name) REFERENCES approle_roles(name) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS k8s_roles (
                name                    TEXT    NOT NULL PRIMARY KEY,
                jwks_url                TEXT    NOT NULL,
                bound_sa_names          TEXT    NOT NULL DEFAULT '["*"]',
                bound_sa_namespaces     TEXT    NOT NULL DEFAULT '["*"]',
                token_ttl_secs          INTEGER NOT NULL DEFAULT 3600,
                expected_issuer         TEXT,
                bound_audiences         TEXT    NOT NULL DEFAULT '[]'
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Add columns to pre-existing tables (no-op if they already exist).
        let _ = sqlx::query("ALTER TABLE k8s_roles ADD COLUMN IF NOT EXISTS expected_issuer TEXT")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query(
            "ALTER TABLE k8s_roles ADD COLUMN IF NOT EXISTS bound_audiences TEXT NOT NULL DEFAULT '[]'",
        )
        .execute(&self.pool)
        .await;

        Ok(())
    }

    // ===== Realm CRUD operations =====

    async fn create_realm(&self, realm: &Realm) -> AuthDbResult<()> {
        let auth_params_json = serde_json::to_string(&realm.auth_params).map_err(|e| {
            crate::database::AuthDbError::Unexpected(format!(
                "Failed to serialize auth_params: {e}"
            ))
        })?;

        sqlx::query(
            r#"
            INSERT INTO realm (id, auth_params, cookie_max_age_seconds, max_stale_age_seconds, certificate_max_age_seconds)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&realm.id)
        .bind(auth_params_json)
        .bind(realm.session_max_age_seconds)
        .bind(realm.session_max_stale_age_seconds)
        .bind(realm.certificate_max_age_seconds)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            crate::database::AuthDbError::from_insert_error(
                e,
                format!("realm '{}' already exists", realm.id),
            )
        })?;

        Ok(())
    }

    async fn get_realm(&self, id: &str) -> AuthDbResult<Option<Realm>> {
        let row = sqlx::query(
            r#"
            SELECT id, auth_params, cookie_max_age_seconds, max_stale_age_seconds, certificate_max_age_seconds
            FROM realm
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let auth_params_str: String = row.try_get("auth_params")?;
                let auth_params = serde_json::from_str(&auth_params_str).map_err(|e| {
                    crate::database::AuthDbError::Unexpected(format!(
                        "Failed to deserialize auth_params: {e}"
                    ))
                })?;

                Ok(Some(Realm {
                    id: row.try_get("id")?,
                    auth_params,
                    session_max_age_seconds: row.try_get::<i64, _>("cookie_max_age_seconds")?,
                    session_max_stale_age_seconds: row
                        .try_get::<i64, _>("max_stale_age_seconds")?,
                    certificate_max_age_seconds: row
                        .try_get::<i64, _>("certificate_max_age_seconds")?,
                }))
            }
            None => Ok(None),
        }
    }

    async fn update_realm(&self, realm: &Realm) -> AuthDbResult<()> {
        let auth_params_json = serde_json::to_string(&realm.auth_params).map_err(|e| {
            crate::database::AuthDbError::Unexpected(format!(
                "Failed to serialize auth_params: {e}"
            ))
        })?;

        sqlx::query(
            r#"
            UPDATE realm
            SET auth_params = ?, cookie_max_age_seconds = ?, max_stale_age_seconds = ?, certificate_max_age_seconds = ?
            WHERE id = ?
            "#,
        )
        .bind(auth_params_json)
        .bind(realm.session_max_age_seconds)
        .bind(realm.session_max_stale_age_seconds)
        .bind(realm.certificate_max_age_seconds)
        .bind(&realm.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_realm(&self, id: &str) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            DELETE FROM realm WHERE id = ?
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_realms(&self) -> AuthDbResult<Vec<Realm>> {
        let rows = sqlx::query(
            r#"
            SELECT id, auth_params, cookie_max_age_seconds, max_stale_age_seconds, certificate_max_age_seconds
            FROM realm
            ORDER BY id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut realms = Vec::new();
        for row in rows {
            let auth_params_str: String = row.try_get("auth_params")?;
            let auth_params = serde_json::from_str(&auth_params_str).map_err(|e| {
                crate::database::AuthDbError::Unexpected(format!(
                    "Failed to deserialize auth_params: {e}"
                ))
            })?;

            realms.push(Realm {
                id: row.try_get("id")?,
                auth_params,
                session_max_age_seconds: row.try_get::<i64, _>("cookie_max_age_seconds")?,
                session_max_stale_age_seconds: row.try_get::<i64, _>("max_stale_age_seconds")?,
                certificate_max_age_seconds: row
                    .try_get::<i64, _>("certificate_max_age_seconds")?,
            });
        }

        Ok(realms)
    }

    // ===== UserPass CRUD operations =====

    async fn create_userpass(&self, userpass: &UserPass) -> AuthDbResult<()> {
        let roles_json = serde_json::to_string(&userpass.roles)
            .map_err(|e| AuthDbError::Unexpected(format!("failed to serialize roles: {e}")))?;
        let extra_claims_json = userpass
            .extra_claims
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| {
                AuthDbError::Unexpected(format!("failed to serialize extra_claims: {e}"))
            })?;
        sqlx::query(
            r#"
            INSERT INTO userpass (realm, username, password, change_password, roles, extra_claims)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&userpass.realm)
        .bind(&userpass.username)
        .bind(userpass.password_hash.as_bytes())
        .bind(userpass.change_password)
        .bind(&roles_json)
        .bind(&extra_claims_json)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthDbError::from_insert_error(
                e,
                format!(
                    "credentials for '{}' already exist in realm '{}'",
                    userpass.username, userpass.realm
                ),
            )
        })?;

        Ok(())
    }

    async fn get_userpass(&self, realm: &str, username: &str) -> AuthDbResult<Option<UserPass>> {
        let row = sqlx::query(
            r#"
            SELECT realm, username, change_password, roles, extra_claims
            FROM userpass
            WHERE realm = ? AND username = ?
            "#,
        )
        .bind(realm)
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let roles_json: String = row.try_get("roles").unwrap_or_default();
                let roles: Vec<String> = serde_json::from_str(&roles_json).map_err(|e| {
                    AuthDbError::Unexpected(format!(
                        "failed to deserialize roles for user '{username}': {e}"
                    ))
                })?;
                let extra_claims_json: Option<String> = row.try_get("extra_claims")?;
                let extra_claims = extra_claims_json
                    .map(|json| serde_json::from_str(&json))
                    .transpose()
                    .map_err(|e| {
                        AuthDbError::Unexpected(format!(
                            "failed to deserialize extra_claims for user '{username}': {e}"
                        ))
                    })?;
                let userpass = UserPass {
                    realm: row.try_get("realm")?,
                    username: row.try_get("username")?,
                    password_hash: String::new(), // do not return the password hash
                    password_input: None,
                    change_password: row.try_get("change_password")?,
                    roles,
                    extra_claims,
                };
                Ok(Some(userpass))
            }
            None => Ok(None),
        }
    }

    async fn update_userpass(&self, userpass: &UserPass) -> AuthDbResult<()> {
        let roles_json = serde_json::to_string(&userpass.roles)
            .map_err(|e| AuthDbError::Unexpected(format!("failed to serialize roles: {e}")))?;
        let extra_claims_json = userpass
            .extra_claims
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| {
                AuthDbError::Unexpected(format!("failed to serialize extra_claims: {e}"))
            })?;
        sqlx::query(
            r#"
            UPDATE userpass
            SET password = ?, change_password = ?, roles = ?, extra_claims = ?
            WHERE realm = ? AND username = ?
            "#,
        )
        .bind(userpass.password_hash.as_bytes())
        .bind(userpass.change_password)
        .bind(&roles_json)
        .bind(&extra_claims_json)
        .bind(&userpass.realm)
        .bind(&userpass.username)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn update_userpass_metadata(
        &self,
        realm: &str,
        username: &str,
        change_password: bool,
        roles: &[String],
    ) -> AuthDbResult<()> {
        let roles_json = serde_json::to_string(roles)
            .map_err(|e| AuthDbError::Unexpected(format!("failed to serialize roles: {e}")))?;
        sqlx::query(
            r#"
            UPDATE userpass
            SET change_password = ?, roles = ?
            WHERE realm = ? AND username = ?
            "#,
        )
        .bind(change_password)
        .bind(&roles_json)
        .bind(realm)
        .bind(username)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_userpass(&self, realm: &str, username: &str) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            DELETE FROM userpass
            WHERE realm = ? AND username = ?
            "#,
        )
        .bind(realm)
        .bind(username)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_userpass_by_realm(&self, realm: &str) -> AuthDbResult<Vec<UserPass>> {
        let rows = sqlx::query(
            r#"
            SELECT realm, username, password, change_password, roles, extra_claims
            FROM userpass
            WHERE realm = ?
            ORDER BY username
            "#,
        )
        .bind(realm)
        .fetch_all(&self.pool)
        .await?;

        let mut userpass_list = Vec::new();
        for row in rows {
            let roles_json: String = row.try_get("roles").unwrap_or_default();
            let roles: Vec<String> = serde_json::from_str(&roles_json).map_err(|e| {
                let username: String = row.try_get("username").unwrap_or_default();
                AuthDbError::Unexpected(format!(
                    "failed to deserialize roles for user '{username}': {e}"
                ))
            })?;
            let extra_claims_json: Option<String> = row.try_get("extra_claims")?;
            let extra_claims = extra_claims_json
                .map(|json| serde_json::from_str(&json))
                .transpose()
                .map_err(|e| {
                    let username: String = row.try_get("username").unwrap_or_default();
                    AuthDbError::Unexpected(format!(
                        "failed to deserialize extra_claims for user '{username}': {e}"
                    ))
                })?;
            let password_hash: Vec<u8> = row.try_get("password")?;
            userpass_list.push(UserPass {
                realm: row.try_get("realm")?,
                username: row.try_get("username")?,
                password_hash: String::from_utf8(password_hash).map_err(|_| {
                    AuthDbError::Unexpected("stored password hash is not valid UTF-8".to_string())
                })?,
                password_input: None,
                change_password: row.try_get("change_password")?,
                roles,
                extra_claims,
            });
        }

        Ok(userpass_list)
    }

    async fn list_all_userpass(&self) -> AuthDbResult<Vec<UserPass>> {
        let rows = sqlx::query(
            r#"
            SELECT realm, username, password, change_password, roles, extra_claims
            FROM userpass
            ORDER BY realm, username
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut userpass_list = Vec::new();
        for row in rows {
            let roles_json: String = row.try_get("roles").unwrap_or_default();
            let roles: Vec<String> = serde_json::from_str(&roles_json).map_err(|e| {
                let username: String = row.try_get("username").unwrap_or_default();
                AuthDbError::Unexpected(format!(
                    "failed to deserialize roles for user '{username}': {e}"
                ))
            })?;
            let extra_claims_json: Option<String> = row.try_get("extra_claims")?;
            let extra_claims = extra_claims_json
                .map(|json| serde_json::from_str(&json))
                .transpose()
                .map_err(|e| {
                    let username: String = row.try_get("username").unwrap_or_default();
                    AuthDbError::Unexpected(format!(
                        "failed to deserialize extra_claims for user '{username}': {e}"
                    ))
                })?;
            let password_hash: Vec<u8> = row.try_get("password")?;
            userpass_list.push(UserPass {
                realm: row.try_get("realm")?,
                username: row.try_get("username")?,
                password_hash: String::from_utf8(password_hash).map_err(|_| {
                    AuthDbError::Unexpected("stored password hash is not valid UTF-8".to_string())
                })?,
                password_input: None,
                change_password: row.try_get("change_password")?,
                roles,
                extra_claims,
            });
        }

        Ok(userpass_list)
    }

    async fn validate_userpass(
        &self,
        realm: &str,
        username: &str,
        password: &str,
    ) -> AuthDbResult<bool> {
        let row = sqlx::query(
            r#"
            SELECT password, change_password
            FROM userpass
            WHERE realm = ? AND username = ?
            "#,
        )
        .bind(realm)
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => {
                let stored_password: Vec<u8> = row.try_get("password")?;
                let stored_password = String::from_utf8(stored_password).map_err(|_| {
                    AuthDbError::Unexpected("stored password hash is not valid UTF-8".to_string())
                })?;
                crate::database::verify_password_argon2(&stored_password, password)
                    .map_err(|_| crate::database::AuthDbError::InvalidCredentials)?;
                let change_password: bool = row.try_get("change_password")?;
                Ok(change_password)
            }
            None => Err(crate::database::AuthDbError::InvalidCredentials),
        }
    }

    // ===== Admin CRUD operations =====

    async fn create_admin(&self, admin: &Admin) -> AuthDbResult<()> {
        let digital_credentials_json = admin
            .digital_credentials
            .as_ref()
            .map(|digital_credentials| {
                serde_json::to_string(digital_credentials).map_err(|e| {
                    crate::database::AuthDbError::Unexpected(format!(
                        "Failed to serialize digital_credentials: {e}"
                    ))
                })
            })
            .transpose()?;

        // Insert into admin table
        sqlx::query(
            r#"
            INSERT INTO admin (id, userpass, jwt, fido2, digital_credentials, certificate)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&admin.id)
        .bind(&admin.userpass)
        .bind(&admin.jwt)
        .bind(&admin.fido2)
        .bind(digital_credentials_json)
        .bind(&admin.client_certificate)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            crate::database::AuthDbError::from_insert_error(
                e,
                format!(
                    "admin '{}' already exists or shares a login with another admin",
                    admin.id
                ),
            )
        })?;

        // Insert into user_realms join table
        for realm_id in &admin.realms {
            sqlx::query(
                r#"
                INSERT INTO admin_realms (admin_id, realm_id)
                VALUES (?, ?)
                "#,
            )
            .bind(&admin.id)
            .bind(realm_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn get_admin(&self, id: &str) -> AuthDbResult<Option<Admin>> {
        let row = sqlx::query(select_admins!("WHERE id = ?"))
            .bind(ADMIN_REALM)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(row) => Ok(Some(self.row_to_admin(&row).await?)),
            None => Ok(None),
        }
    }

    async fn update_admin(&self, admin: &Admin) -> AuthDbResult<()> {
        let digital_credentials_json = admin
            .digital_credentials
            .as_ref()
            .map(|digital_credentials| {
                serde_json::to_string(digital_credentials).map_err(|e| {
                    crate::database::AuthDbError::Unexpected(format!(
                        "Failed to serialize digital_credentials: {e}"
                    ))
                })
            })
            .transpose()?;

        // Update admin table
        sqlx::query(
            r#"
            UPDATE admin
            SET userpass= ?, jwt = ?, fido2 = ?, digital_credentials = ?, certificate = ?
            WHERE id = ?
            "#,
        )
        .bind(&admin.userpass)
        .bind(&admin.jwt)
        .bind(&admin.fido2)
        .bind(digital_credentials_json)
        .bind(&admin.client_certificate)
        .bind(&admin.id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthDbError::from_insert_error(
                e,
                format!("admin '{}' shares a login with another admin", admin.id),
            )
        })?;

        // Delete existing realm associations
        sqlx::query(
            r#"
            DELETE FROM admin_realms WHERE admin_id = ?
            "#,
        )
        .bind(&admin.id)
        .execute(&self.pool)
        .await?;

        // Insert new realm associations
        for realm_id in &admin.realms {
            sqlx::query(
                r#"
                INSERT INTO admin_realms (admin_id, realm_id)
                VALUES (?, ?)
                "#,
            )
            .bind(&admin.id)
            .bind(realm_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn delete_admin(&self, id: &str) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            DELETE FROM admin WHERE id = ?
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_admins(&self) -> AuthDbResult<Vec<Admin>> {
        let rows = sqlx::query(select_admins!("ORDER BY id"))
            .bind(ADMIN_REALM)
            .fetch_all(&self.pool)
            .await?;
        let mut admins = Vec::with_capacity(rows.len());
        for row in &rows {
            admins.push(self.row_to_admin(row).await?);
        }
        Ok(admins)
    }

    // Find Admins by authentication method (e.g. userpass, jwt, fido2, vp, certificate) and value (e.g. username for userpass, subject for jwt, etc.)
    async fn find_admins_by_auth_scheme(
        &self,
        auth_method: AuthScheme,
        value: &str,
    ) -> AuthDbResult<Vec<Admin>> {
        let query = match auth_method {
            AuthScheme::UsernamePassword => "SELECT id FROM admin WHERE userpass = ?",
            AuthScheme::Jwt => "SELECT id FROM admin WHERE jwt = ?",
            AuthScheme::Fido2 => "SELECT id FROM admin WHERE fido2 = ?",
            AuthScheme::DigitalCredentials => "SELECT id FROM admin WHERE digital_credentials =?",
            AuthScheme::ClientCertificate => "SELECT id FROM admin WHERE certificate = ?",
            // SAML is a user-facing realm auth scheme, not an admin credential: no admin
            // authenticates via SAML, so there is never a matching admin row.
            AuthScheme::Saml => return Ok(Vec::new()),
        };

        let rows = sqlx::query(query).bind(value).fetch_all(&self.pool).await?;

        let mut admins = Vec::new();
        for row in rows {
            if let Some(admin) = self.get_admin(row.try_get("id")?).await? {
                admins.push(admin);
            }
        }

        Ok(admins)
    }

    // ===== TOTP/2FA operations =====

    async fn enable_totp(
        &self,
        realm: &str,
        username: &str,
        totp_secret: &str,
    ) -> AuthDbResult<bool> {
        let updated =
            sqlx::query("UPDATE userpass SET totp_secret = ? WHERE realm = ? AND username = ?")
                .bind(totp_secret)
                .bind(realm)
                .bind(username)
                .execute(&self.pool)
                .await?
                .rows_affected();
        Ok(updated > 0)
    }

    async fn disable_totp(&self, realm: &str, username: &str) -> AuthDbResult<()> {
        sqlx::query("UPDATE userpass SET totp_secret = NULL WHERE realm = ? AND username = ?")
            .bind(realm)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_totp_secret(&self, realm: &str, username: &str) -> AuthDbResult<Option<String>> {
        let secret: Option<Option<String>> =
            sqlx::query_scalar("SELECT totp_secret FROM userpass WHERE realm = ? AND username = ?")
                .bind(realm)
                .bind(username)
                .fetch_optional(&self.pool)
                .await?;
        Ok(secret.flatten())
    }

    // ── app token operations ────────────────────────────────────────────────

    async fn issue_app_token(&self, token: &AppToken) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO app_tokens
                (token_hash, entity, policies, expiry, renewable, lease_duration_secs, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&token.token_hash)
        .bind(&token.entity)
        .bind(serde_json::to_string(&token.policies).unwrap_or_else(|_| "[]".to_string()))
        .bind(token.expiry)
        .bind(token.renewable as i64)
        .bind(token.lease_duration_secs)
        .bind(token.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn lookup_app_token(&self, token_hash: &[u8]) -> AuthDbResult<Option<AppToken>> {
        let now = chrono::Utc::now().timestamp();
        let row = sqlx::query(
            r#"
            SELECT token_hash, entity, policies, expiry, renewable, lease_duration_secs, created_at
            FROM app_tokens
            WHERE token_hash = ? AND (expiry = 0 OR expiry > ?)
            "#,
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(AppToken {
                token_hash: r.try_get("token_hash")?,
                entity: r.try_get("entity")?,
                policies: {
                    let s: String = r.try_get("policies")?;
                    serde_json::from_str(&s).unwrap_or_default()
                },
                expiry: r.try_get("expiry")?,
                renewable: r.try_get::<i64, _>("renewable")? != 0,
                lease_duration_secs: r.try_get("lease_duration_secs")?,
                created_at: r.try_get("created_at")?,
            })),
            None => Ok(None),
        }
    }

    async fn renew_app_token(&self, token_hash: &[u8]) -> AuthDbResult<()> {
        let now = chrono::Utc::now().timestamp();
        // Non-expiring tokens (expiry = 0) must be excluded: renewing them would
        // set expiry = now + lease_duration_secs, which collapses to `now` when
        // lease_duration_secs = 0 and immediately expires a previously non-expiring token.
        let rows_affected = sqlx::query(
            r#"
            UPDATE app_tokens
            SET expiry = ? + lease_duration_secs
            WHERE token_hash = ? AND renewable = 1 AND expiry > 0 AND expiry > ?
            "#,
        )
        .bind(now)
        .bind(token_hash)
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if rows_affected == 0 {
            // Renewal is a no-op for non-expiring renewable tokens (expiry = 0).
            let non_expiring: bool = sqlx::query_scalar(
                "SELECT COUNT(*) FROM app_tokens WHERE token_hash = ? AND renewable = 1 AND expiry = 0",
            )
            .bind(token_hash)
            .fetch_one(&self.pool)
            .await
            .map(|n: i64| n > 0)
            .unwrap_or(false);
            if !non_expiring {
                return Err(AuthDbError::Unexpected(
                    "token not found, expired, or not renewable".to_string(),
                ));
            }
        }
        Ok(())
    }

    async fn revoke_app_token(&self, token_hash: &[u8]) -> AuthDbResult<()> {
        sqlx::query("DELETE FROM app_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── AppRole operations ──────────────────────────────────────────────────

    async fn create_approle(&self, role: &AppRole) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO approle_roles
                (name, role_id, secret_id_ttl_secs, token_ttl_secs, bind_secret_id, token_policies)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                role_id             = excluded.role_id,
                secret_id_ttl_secs  = excluded.secret_id_ttl_secs,
                token_ttl_secs      = excluded.token_ttl_secs,
                bind_secret_id      = excluded.bind_secret_id,
                token_policies      = excluded.token_policies
            "#,
        )
        .bind(&role.name)
        .bind(&role.role_id)
        .bind(role.secret_id_ttl_secs)
        .bind(role.token_ttl_secs)
        .bind(role.bind_secret_id as i64)
        .bind(serde_json::to_string(&role.token_policies).unwrap_or_else(|_| "[]".to_string()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_approle_by_role_id(&self, role_id: &str) -> AuthDbResult<Option<AppRole>> {
        let row = sqlx::query(
            r#"
            SELECT name, role_id, secret_id_ttl_secs, token_ttl_secs, bind_secret_id, token_policies
            FROM approle_roles WHERE role_id = ?
            "#,
        )
        .bind(role_id)
        .fetch_optional(&self.pool)
        .await?;
        Self::row_to_approle(row)
    }

    async fn get_approle_by_name(&self, name: &str) -> AuthDbResult<Option<AppRole>> {
        let row = sqlx::query(
            r#"
            SELECT name, role_id, secret_id_ttl_secs, token_ttl_secs, bind_secret_id, token_policies
            FROM approle_roles WHERE name = ?
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        Self::row_to_approle(row)
    }

    async fn delete_approle(&self, name: &str) -> AuthDbResult<()> {
        sqlx::query("DELETE FROM approle_roles WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_approle_names(&self) -> AuthDbResult<Vec<String>> {
        let rows = sqlx::query("SELECT name FROM approle_roles ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.try_get("name").unwrap_or_default())
            .collect())
    }

    async fn create_secret_id(&self, secret_id: &AppSecretId) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO app_secret_ids
                (accessor, secret_id_hash, role_name, expiry, num_uses_remaining)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&secret_id.accessor)
        .bind(&secret_id.secret_id_hash)
        .bind(&secret_id.role_name)
        .bind(secret_id.expiry)
        .bind(secret_id.num_uses_remaining)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn consume_secret_id(
        &self,
        role_name: &str,
        secret_id_hash: &[u8],
    ) -> AuthDbResult<Option<String>> {
        let now = chrono::Utc::now().timestamp();
        // All reads and the subsequent update/delete run inside a single
        // transaction so that concurrent logins cannot both pass the
        // num_uses_remaining check and consume the same secret-ID twice
        // (TOCTOU race condition). Unlike PostgreSQL/MySQL, SQLite has no
        // `SELECT ... FOR UPDATE`, so the transaction is opened with
        // `BEGIN IMMEDIATE` to acquire a write lock up front and serialize
        // concurrent writers. The `rows_affected()` checks below are a
        // second safety net: if another request already consumed the
        // secret-ID, the DELETE/UPDATE affects zero rows and we return
        // `Ok(None)` instead of handing out a stale accessor.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        let row = sqlx::query(
            r#"
            SELECT accessor, num_uses_remaining
            FROM app_secret_ids
            WHERE role_name = ? AND secret_id_hash = ? AND (expiry = 0 OR expiry > ?)
            "#,
        )
        .bind(role_name)
        .bind(secret_id_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let accessor: String = row.try_get("accessor")?;
        let num_uses: i64 = row.try_get("num_uses_remaining")?;

        if num_uses == 1 {
            // Last use — delete the record. If another concurrent request
            // already consumed it, the DELETE affects zero rows.
            let result = sqlx::query("DELETE FROM app_secret_ids WHERE accessor = ?")
                .bind(&accessor)
                .execute(&mut *tx)
                .await?;
            if result.rows_affected() == 0 {
                tx.rollback().await?;
                return Ok(None);
            }
        } else if num_uses > 1 {
            // Decrement uses. If another concurrent request already consumed
            // it, the UPDATE affects zero rows.
            let result = sqlx::query(
                "UPDATE app_secret_ids SET num_uses_remaining = num_uses_remaining - 1 WHERE accessor = ?",
            )
            .bind(&accessor)
            .execute(&mut *tx)
            .await?;
            if result.rows_affected() == 0 {
                tx.rollback().await?;
                return Ok(None);
            }
        }
        // num_uses == -1 or 0 → unlimited, do nothing

        tx.commit().await?;
        Ok(Some(accessor))
    }

    async fn destroy_secret_id(&self, role_name: &str, accessor: &str) -> AuthDbResult<()> {
        sqlx::query("DELETE FROM app_secret_ids WHERE accessor = ? AND role_name = ?")
            .bind(accessor)
            .bind(role_name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Kubernetes role operations ──────────────────────────────────────────

    async fn create_k8s_role(&self, role: &K8sRole) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO k8s_roles
                (name, jwks_url, bound_sa_names, bound_sa_namespaces, token_ttl_secs,
                 expected_issuer, bound_audiences)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                jwks_url                = excluded.jwks_url,
                bound_sa_names          = excluded.bound_sa_names,
                bound_sa_namespaces     = excluded.bound_sa_namespaces,
                token_ttl_secs          = excluded.token_ttl_secs,
                expected_issuer         = excluded.expected_issuer,
                bound_audiences         = excluded.bound_audiences
            "#,
        )
        .bind(&role.name)
        .bind(&role.jwks_url)
        .bind(&role.bound_sa_names)
        .bind(&role.bound_sa_namespaces)
        .bind(role.token_ttl_secs)
        .bind(&role.expected_issuer)
        .bind(&role.bound_audiences)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_k8s_role(&self, name: &str) -> AuthDbResult<Option<K8sRole>> {
        let row = sqlx::query(
            r#"
            SELECT name, jwks_url, bound_sa_names, bound_sa_namespaces, token_ttl_secs
                   , expected_issuer, bound_audiences
            FROM k8s_roles WHERE name = ?
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(K8sRole {
                name: r.try_get("name")?,
                jwks_url: r.try_get("jwks_url")?,
                bound_sa_names: r.try_get("bound_sa_names")?,
                bound_sa_namespaces: r.try_get("bound_sa_namespaces")?,
                token_ttl_secs: r.try_get("token_ttl_secs")?,
                expected_issuer: r.try_get("expected_issuer")?,
                bound_audiences: r
                    .try_get::<String, _>("bound_audiences")
                    .unwrap_or_else(|_| "[]".to_string()),
            })),
            None => Ok(None),
        }
    }

    async fn delete_k8s_role(&self, name: &str) -> AuthDbResult<()> {
        sqlx::query("DELETE FROM k8s_roles WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_k8s_role_names(&self) -> AuthDbResult<Vec<String>> {
        let rows = sqlx::query("SELECT name FROM k8s_roles ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.try_get("name").unwrap_or_default())
            .collect())
    }
}
