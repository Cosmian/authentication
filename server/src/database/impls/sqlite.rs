use std::collections::HashMap;

use crate::{
    database::{
        AuthDbError, AuthDbResult, hash_password_with_argon2,
        r#trait::Database,
        vault_models::{VaultRole, VaultSecretId, VaultToken},
    },
    models::{Admin, AuthScheme, Realm, UserPass},
};
use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

/// SQLite database implementation
pub struct SqliteDatabase {
    pool: SqlitePool,
}

impl SqliteDatabase {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // #[allow(dead_code)]
    // /// Create a new SqliteDatabase from a connection string
    // pub async fn from_url(url: &str) -> AuthDbResult<Self> {
    //     let pool = SqlitePool::connect(url).await?;
    //     Ok(Self::new(pool))
    // }
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
                max_stale_age_seconds INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create userpass table with composite primary key and foreign key
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS userpass (
                realm TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                change_password INTEGER NOT NULL DEFAULT 0,
                roles TEXT NOT NULL DEFAULT '[]',
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
        .map(|c: i32| c > 0)
        .unwrap_or(false);
        if !has_roles {
            sqlx::query("ALTER TABLE userpass ADD COLUMN roles TEXT NOT NULL DEFAULT '[]'")
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
                certificate TEXT,

                -- TOTP/2FA fields
                totp_enabled INTEGER DEFAULT 0,
                totp_secret TEXT,
                totp_auth_url TEXT
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
        // If the realm table is empty, insert the ADMIN_REALM (application) realm
        // and insert a remove_me:remove_me userpass entry for it in the userpass table
        let realm_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM realm")
            .fetch_one(&self.pool)
            .await?;
        if realm_count.0 == 0 {
            self.initialize_db().await?;
        }

        // ── Vault AppRole tables ──────────────────────────────────────────────
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vault_roles (
                role_name       TEXT    PRIMARY KEY NOT NULL,
                role_id         TEXT    NOT NULL UNIQUE,
                token_ttl       INTEGER NOT NULL DEFAULT 3600,
                token_policies  TEXT    NOT NULL DEFAULT '[]',
                secret_id_ttl   INTEGER NOT NULL DEFAULT 0,
                bind_secret_id  INTEGER NOT NULL DEFAULT 1,
                created_at      INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vault_secret_ids (
                secret_id_accessor  TEXT    PRIMARY KEY NOT NULL,
                secret_id_hash      BLOB    NOT NULL,
                role_name           TEXT    NOT NULL,
                expiry_time         INTEGER,
                created_at          INTEGER NOT NULL,
                FOREIGN KEY (role_name) REFERENCES vault_roles(role_name) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS vault_tokens (
                token_hash      BLOB    PRIMARY KEY NOT NULL,
                role_name       TEXT    NOT NULL,
                policies        TEXT    NOT NULL DEFAULT '[]',
                ttl             INTEGER NOT NULL,
                renewable       INTEGER NOT NULL DEFAULT 1,
                expiry_time     INTEGER NOT NULL,
                created_at      INTEGER NOT NULL,
                FOREIGN KEY (role_name) REFERENCES vault_roles(role_name) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

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
            INSERT INTO realm (id, auth_params, cookie_max_age_seconds, max_stale_age_seconds)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&realm.id)
        .bind(auth_params_json)
        .bind(realm.session_max_age_seconds)
        .bind(realm.session_max_stale_age_seconds)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_realm(&self, id: &str) -> AuthDbResult<Option<Realm>> {
        let row = sqlx::query(
            r#"
            SELECT id, auth_params, cookie_max_age_seconds, max_stale_age_seconds
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
            SET auth_params = ?, cookie_max_age_seconds = ?, max_stale_age_seconds = ?
            WHERE id = ?
            "#,
        )
        .bind(auth_params_json)
        .bind(realm.session_max_age_seconds)
        .bind(realm.session_max_stale_age_seconds)
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
            SELECT id, auth_params, cookie_max_age_seconds, max_stale_age_seconds
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
            });
        }

        Ok(realms)
    }

    // ===== UserPass CRUD operations =====

    async fn create_userpass(&self, userpass: &UserPass) -> AuthDbResult<()> {
        let roles_json = serde_json::to_string(&userpass.roles)
            .map_err(|e| AuthDbError::Unexpected(format!("failed to serialize roles: {e}")))?;
        sqlx::query(
            r#"
            INSERT INTO userpass (realm, username, password, change_password, roles)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&userpass.realm)
        .bind(&userpass.username)
        .bind(&userpass.password)
        .bind(userpass.change_password)
        .bind(&roles_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_userpass(&self, realm: &str, username: &str) -> AuthDbResult<Option<UserPass>> {
        let row = sqlx::query(
            r#"
            SELECT realm, username, change_password, roles
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
                let userpass = UserPass {
                    realm: row.try_get("realm")?,
                    username: row.try_get("username")?,
                    password: vec![], // do not return the password hash
                    change_password: row.try_get("change_password")?,
                    roles,
                };
                Ok(Some(userpass))
            }
            None => Ok(None),
        }
    }

    async fn update_userpass(&self, userpass: &UserPass) -> AuthDbResult<()> {
        let roles_json = serde_json::to_string(&userpass.roles)
            .map_err(|e| AuthDbError::Unexpected(format!("failed to serialize roles: {e}")))?;
        sqlx::query(
            r#"
            UPDATE userpass
            SET password = ?, change_password = ?, roles = ?
            WHERE realm = ? AND username = ?
            "#,
        )
        .bind(&userpass.password)
        .bind(userpass.change_password)
        .bind(&roles_json)
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

    async fn delete_userpass_by_username(&self, username: &str) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            DELETE FROM userpass
            WHERE username = ?
            "#,
        )
        .bind(username)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_userpass_by_realm(&self, realm: &str) -> AuthDbResult<Vec<UserPass>> {
        let rows = sqlx::query(
            r#"
            SELECT realm, username, password, change_password, roles
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
            userpass_list.push(UserPass {
                realm: row.try_get("realm")?,
                username: row.try_get("username")?,
                password: row.try_get("password")?,
                change_password: row.try_get("change_password")?,
                roles,
            });
        }

        Ok(userpass_list)
    }

    async fn list_all_userpass(&self) -> AuthDbResult<Vec<UserPass>> {
        let rows = sqlx::query(
            r#"
            SELECT realm, username, password, change_password, roles
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
            userpass_list.push(UserPass {
                realm: row.try_get("realm")?,
                username: row.try_get("username")?,
                password: row.try_get("password")?,
                change_password: row.try_get("change_password")?,
                roles,
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
                if stored_password
                    == hash_password_with_argon2(username, password)
                        .map_err(|e| crate::database::AuthDbError::Unexpected(e.to_string()))?
                {
                    let change_password: bool = row.try_get("change_password")?;
                    Ok(change_password)
                } else {
                    Err(crate::database::AuthDbError::InvalidCredentials)
                }
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
            INSERT INTO admin (id, userpass, jwt, fido2, digital_credentials, certificate, totp_enabled, totp_secret, totp_auth_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&admin.id)
        .bind(&admin.userpass)
        .bind(&admin.jwt)
        .bind(&admin.fido2)
        .bind(digital_credentials_json)
        .bind(&admin.client_certificate)
        .bind(admin.totp_enabled.map(|v| if v { 1 } else { 0 }))
        .bind(&admin.totp_secret)
        .bind(&admin.totp_auth_url)
        .execute(&self.pool)
        .await?;

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
        let row = sqlx::query(
            r#"
            SELECT id, userpass, jwt, fido2, digital_credentials, certificate, totp_enabled, totp_secret, totp_auth_url
            FROM admin
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                // Fetch realms from join table
                let realm_rows = sqlx::query(
                    r#"
                    SELECT realm_id
                    FROM admin_realms
                    WHERE admin_id = ?
                    "#,
                )
                .bind(id)
                .fetch_all(&self.pool)
                .await?;

                let realms: Vec<String> = realm_rows
                    .iter()
                    .map(|r| r.try_get("realm_id"))
                    .collect::<Result<Vec<String>, _>>()?;

                let digital_credentials: Option<HashMap<String, String>> = row
                    .try_get::<Option<String>, _>("digital_credentials")?
                    .map(|v| {
                        serde_json::from_str(&v).map_err(|e| {
                            crate::database::AuthDbError::Unexpected(format!(
                                "Failed to deserialize the digital credentials: {e}"
                            ))
                        })
                    })
                    .transpose()?;

                let admin = Admin {
                    id: row.try_get("id")?,
                    realms,
                    userpass: row.try_get("userpass")?,
                    jwt: row.try_get("jwt")?,
                    fido2: row.try_get("fido2")?,
                    digital_credentials,
                    client_certificate: row.try_get("certificate")?,

                    // TOTP fields (defaults to None if not set)
                    totp_enabled: row
                        .try_get::<Option<i64>, _>("totp_enabled")?
                        .map(|v| v != 0),
                    totp_secret: row.try_get::<Option<String>, _>("totp_secret")?,
                    totp_auth_url: row.try_get::<Option<String>, _>("totp_auth_url")?,
                };
                Ok(Some(admin))
            }
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
            SET userpass= ?, jwt = ?, fido2 = ?, digital_credentials = ?, certificate = ?,
                totp_enabled = ?, totp_secret = ?, totp_auth_url = ?
            WHERE id = ?
            "#,
        )
        .bind(&admin.userpass)
        .bind(&admin.jwt)
        .bind(&admin.fido2)
        .bind(digital_credentials_json)
        .bind(&admin.client_certificate)
        .bind(admin.totp_enabled.map(|v| if v { 1 } else { 0 }))
        .bind(&admin.totp_secret)
        .bind(&admin.totp_auth_url)
        .bind(&admin.id)
        .execute(&self.pool)
        .await?;

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
        let rows = sqlx::query(
            r#"
            SELECT id, userpass, jwt, fido2, digital_credentials, certificate, totp_enabled, totp_secret, totp_auth_url
            FROM admin
            ORDER BY id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut admins = Vec::new();
        for row in rows {
            let admin_id: String = row.try_get("id")?;

            // Fetch realms from join table
            let realm_rows = sqlx::query(
                r#"
                SELECT realm_id
                FROM admin_realms
                WHERE admin_id = ?
                "#,
            )
            .bind(&admin_id)
            .fetch_all(&self.pool)
            .await?;

            let realms: Vec<String> = realm_rows
                .iter()
                .map(|r| r.try_get("realm_id"))
                .collect::<Result<Vec<String>, _>>()?;

            let digital_credentials: Option<HashMap<String, String>> = row
                .try_get::<Option<String>, _>("digital_credentials")?
                .map(|v| {
                    serde_json::from_str(&v).map_err(|e| {
                        crate::database::AuthDbError::Unexpected(format!(
                            "Failed to deserialize the digital credentials: {e}"
                        ))
                    })
                })
                .transpose()?;

            admins.push(Admin {
                id: admin_id,
                realms,
                userpass: row.try_get("userpass")?,
                jwt: row.try_get("jwt")?,
                fido2: row.try_get("fido2")?,
                digital_credentials,
                client_certificate: row.try_get("certificate")?,

                // TOTP fields (defaults to None if not set)
                totp_enabled: row
                    .try_get::<Option<i64>, _>("totp_enabled")?
                    .map(|v| v != 0),
                totp_secret: row.try_get::<Option<String>, _>("totp_secret")?,
                totp_auth_url: row.try_get::<Option<String>, _>("totp_auth_url")?,
            });
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

    async fn generate_totp_secret(&self, realm: &str, username: &str) -> AuthDbResult<String> {
        let totps = crate::totp::Totps::new()
            .map_err(|e| crate::database::AuthDbError::Unexpected(format!("TOTP error: {e}")))?;
        let secret = totps.generate_secret();

        // Debug log (masked in production)
        cosmian_logger::debug!(
            "Generated TOTP secret for user '{}' in realm '{}'",
            username,
            realm
        );

        Ok(secret)
    }

    async fn enable_totp(
        &self,
        realm: &str,
        username: &str,
        totp_secret: &str,
        issuer: &str,
    ) -> AuthDbResult<()> {
        let otpauth_url = crate::totp::Totps::from_secret(
            totp_secret,
            Some(issuer.to_string()),
            username.to_string(),
            None, // use realm-default TOTP params; the canonical URL was already returned at generate time
        )
        .map_err(|e| crate::database::AuthDbError::Unexpected(format!("TOTP error: {e}")))?
        .get_otpauth_url();

        cosmian_logger::debug!("Enabling TOTP for user '{}' in realm '{}'", username, realm);

        sqlx::query(
            r#"
            UPDATE admin
            SET totp_enabled = 1,
                totp_secret = ?,
                totp_auth_url = ?
            WHERE id = ? AND (userpass IS NOT NULL OR jwt IS NOT NULL)
            "#,
        )
        .bind(totp_secret)
        .bind(&otpauth_url)
        .bind(username)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn disable_totp(&self, realm: &str, username: &str) -> AuthDbResult<()> {
        cosmian_logger::debug!(
            "Disabling TOTP for user '{}' in realm '{}'",
            username,
            realm
        );

        sqlx::query(
            r#"
            UPDATE admin
            SET totp_enabled = 0,
                totp_secret = NULL,
                totp_auth_url = NULL
            WHERE id = ? AND (userpass IS NOT NULL OR jwt IS NOT NULL)
            "#,
        )
        .bind(username)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_totp_secret(&self, _realm: &str, username: &str) -> AuthDbResult<Option<String>> {
        let row = sqlx::query(
            r#"
            SELECT totp_secret
            FROM admin
            WHERE id = ? AND (userpass IS NOT NULL OR jwt IS NOT NULL)
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_get("totp_secret")?)),
            None => Ok(None),
        }
    }

    async fn is_totp_enabled(&self, _realm: &str, username: &str) -> AuthDbResult<Option<bool>> {
        let row = sqlx::query(
            r#"
            SELECT totp_enabled
            FROM admin
            WHERE id = ? AND (userpass IS NOT NULL OR jwt IS NOT NULL)
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_get::<i64, _>("totp_enabled")? != 0)),
            None => Ok(None),
        }
    }

    // ===== Vault AppRole operations =====

    async fn create_vault_role(&self, role: &VaultRole) -> AuthDbResult<()> {
        let policies_json = serde_json::to_string(&role.token_policies)
            .map_err(|e| AuthDbError::Unexpected(format!("serialize policies: {e}")))?;
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO vault_roles
                (role_name, role_id, token_ttl, token_policies, secret_id_ttl, bind_secret_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&role.role_name)
        .bind(&role.role_id)
        .bind(role.token_ttl)
        .bind(&policies_json)
        .bind(role.secret_id_ttl)
        .bind(i64::from(role.bind_secret_id))
        .bind(role.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_vault_role(&self, role_name: &str) -> AuthDbResult<Option<VaultRole>> {
        let row = sqlx::query(
            "SELECT role_name, role_id, token_ttl, token_policies, secret_id_ttl, bind_secret_id, created_at FROM vault_roles WHERE role_name = ?",
        )
        .bind(role_name)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| vault_role_from_row(&r)).transpose()
    }

    async fn get_vault_role_by_role_id(&self, role_id: &str) -> AuthDbResult<Option<VaultRole>> {
        let row = sqlx::query(
            "SELECT role_name, role_id, token_ttl, token_policies, secret_id_ttl, bind_secret_id, created_at FROM vault_roles WHERE role_id = ?",
        )
        .bind(role_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| vault_role_from_row(&r)).transpose()
    }

    async fn delete_vault_role(&self, role_name: &str) -> AuthDbResult<()> {
        sqlx::query("DELETE FROM vault_roles WHERE role_name = ?")
            .bind(role_name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_vault_roles(&self) -> AuthDbResult<Vec<String>> {
        let rows = sqlx::query("SELECT role_name FROM vault_roles ORDER BY role_name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| Ok(r.try_get::<String, _>("role_name")?))
            .collect()
    }

    async fn create_vault_secret_id(&self, sid: &VaultSecretId) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO vault_secret_ids
                (secret_id_accessor, secret_id_hash, role_name, expiry_time, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&sid.secret_id_accessor)
        .bind(&sid.secret_id_hash)
        .bind(&sid.role_name)
        .bind(sid.expiry_time)
        .bind(sid.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_vault_secret_id_by_hash(
        &self,
        hash: &[u8],
    ) -> AuthDbResult<Option<VaultSecretId>> {
        let row = sqlx::query(
            "SELECT secret_id_accessor, secret_id_hash, role_name, expiry_time, created_at FROM vault_secret_ids WHERE secret_id_hash = ?",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| VaultSecretId {
            secret_id_accessor: r.try_get("secret_id_accessor").unwrap_or_default(),
            secret_id_hash: r.try_get("secret_id_hash").unwrap_or_default(),
            role_name: r.try_get("role_name").unwrap_or_default(),
            expiry_time: r.try_get("expiry_time").unwrap_or(None),
            created_at: r.try_get("created_at").unwrap_or_default(),
        }))
    }

    async fn destroy_vault_secret_id_by_accessor(&self, accessor: &str) -> AuthDbResult<()> {
        sqlx::query("DELETE FROM vault_secret_ids WHERE secret_id_accessor = ?")
            .bind(accessor)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_vault_token(&self, token: &VaultToken) -> AuthDbResult<()> {
        let policies_json = serde_json::to_string(&token.policies)
            .map_err(|e| AuthDbError::Unexpected(format!("serialize policies: {e}")))?;
        sqlx::query(
            r#"
            INSERT INTO vault_tokens
                (token_hash, role_name, policies, ttl, renewable, expiry_time, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&token.token_hash)
        .bind(&token.role_name)
        .bind(&policies_json)
        .bind(token.ttl)
        .bind(i64::from(token.renewable))
        .bind(token.expiry_time)
        .bind(token.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_vault_token_by_hash(&self, hash: &[u8]) -> AuthDbResult<Option<VaultToken>> {
        let row = sqlx::query(
            "SELECT token_hash, role_name, policies, ttl, renewable, expiry_time, created_at FROM vault_tokens WHERE token_hash = ?",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| vault_token_from_row(&r)).transpose()
    }

    async fn delete_vault_token_by_hash(&self, hash: &[u8]) -> AuthDbResult<()> {
        sqlx::query("DELETE FROM vault_tokens WHERE token_hash = ?")
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn cleanup_expired_vault_entries(&self) -> AuthDbResult<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query("DELETE FROM vault_tokens WHERE expiry_time > 0 AND expiry_time < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "DELETE FROM vault_secret_ids WHERE expiry_time IS NOT NULL AND expiry_time < ?",
        )
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// ── SQLite row helpers ────────────────────────────────────────────────────────

fn vault_role_from_row(r: &sqlx::sqlite::SqliteRow) -> AuthDbResult<VaultRole> {
    use sqlx::Row as _;
    let policies_json: String = r.try_get("token_policies")?;
    let policies: Vec<String> = serde_json::from_str(&policies_json)
        .map_err(|e| AuthDbError::Unexpected(format!("deserialize policies: {e}")))?;
    Ok(VaultRole {
        role_name: r.try_get("role_name")?,
        role_id: r.try_get("role_id")?,
        token_ttl: r.try_get("token_ttl")?,
        token_policies: policies,
        secret_id_ttl: r.try_get("secret_id_ttl")?,
        bind_secret_id: r.try_get::<i64, _>("bind_secret_id")? != 0,
        created_at: r.try_get("created_at")?,
    })
}

fn vault_token_from_row(r: &sqlx::sqlite::SqliteRow) -> AuthDbResult<VaultToken> {
    use sqlx::Row as _;
    let policies_json: String = r.try_get("policies")?;
    let policies: Vec<String> = serde_json::from_str(&policies_json)
        .map_err(|e| AuthDbError::Unexpected(format!("deserialize token policies: {e}")))?;
    Ok(VaultToken {
        token_hash: r.try_get("token_hash")?,
        role_name: r.try_get("role_name")?,
        policies,
        ttl: r.try_get("ttl")?,
        renewable: r.try_get::<i64, _>("renewable")? != 0,
        expiry_time: r.try_get("expiry_time")?,
        created_at: r.try_get("created_at")?,
    })
}
