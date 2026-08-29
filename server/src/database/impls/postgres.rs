use std::collections::HashMap;

use crate::{
    database::{
        AuthDbError, AuthDbResult,
        r#trait::{AppRole, AppSecretId, AppToken, Database, K8sRole},
    },
    models::{Admin, AuthScheme, Realm, UserPass},
};
use async_trait::async_trait;
use sqlx::{PgPool, Row};

/// PostgreSQL database implementation
pub struct PostgresDatabase {
    pool: PgPool,
}

impl PostgresDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl Database for PostgresDatabase {
    async fn init(&self) -> AuthDbResult<()> {
        // Create realm table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS realm (
                id TEXT PRIMARY KEY CHECK (id ~ '^[a-zA-Z0-9_-]+$'),
                auth_params JSONB NOT NULL,
                cookie_max_age_seconds BIGINT NOT NULL,
                max_stale_age_seconds BIGINT NOT NULL,
                certificate_max_age_seconds BIGINT NOT NULL DEFAULT 31536000
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Migration: add the column to a realm table created before this field existed.
        sqlx::query(
            "ALTER TABLE realm ADD COLUMN IF NOT EXISTS certificate_max_age_seconds BIGINT NOT NULL DEFAULT 31536000",
        )
        .execute(&self.pool)
        .await?;

        // Create userpass table with composite primary key and foreign key
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS userpass (
                realm TEXT NOT NULL,
                username TEXT NOT NULL,
                password BYTEA NOT NULL,
                change_password BOOLEAN NOT NULL DEFAULT FALSE,
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
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='userpass' AND column_name='roles')",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false);
        if !has_roles {
            sqlx::query("ALTER TABLE userpass ADD COLUMN roles TEXT NOT NULL DEFAULT '[]'")
                .execute(&self.pool)
                .await?;
        }

        // Migration: add extra_claims column if missing (existing databases)
        let has_extra_claims: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='userpass' AND column_name='extra_claims')",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false);
        if !has_extra_claims {
            sqlx::query("ALTER TABLE userpass ADD COLUMN extra_claims TEXT")
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
                digital_credentials JSONB,
                certificate TEXT,

                -- TOTP/2FA fields
                totp_enabled BOOLEAN DEFAULT FALSE,
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

        // ── App auth tables ─────────────────────────────────────────────────
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS app_tokens (
                token_hash          BYTEA   NOT NULL PRIMARY KEY,
                entity              TEXT    NOT NULL,
                policies            TEXT    NOT NULL DEFAULT '',
                expiry              BIGINT  NOT NULL,
                renewable           BOOLEAN NOT NULL DEFAULT FALSE,
                lease_duration_secs BIGINT  NOT NULL DEFAULT 3600,
                created_at          BIGINT  NOT NULL
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
                secret_id_ttl_secs  BIGINT  NOT NULL DEFAULT 0,
                token_ttl_secs      BIGINT  NOT NULL DEFAULT 3600,
                bind_secret_id      BOOLEAN NOT NULL DEFAULT TRUE,
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
                secret_id_hash      BYTEA   NOT NULL,
                role_name           TEXT    NOT NULL
                    REFERENCES approle_roles(name) ON DELETE CASCADE,
                expiry              BIGINT  NOT NULL DEFAULT 0,
                num_uses_remaining  BIGINT  NOT NULL DEFAULT -1
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
                token_ttl_secs          BIGINT  NOT NULL DEFAULT 3600,
                expected_issuer         TEXT,
                bound_audiences         TEXT    NOT NULL DEFAULT '[]'
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Add columns to pre-existing tables (IF NOT EXISTS is idempotent in PostgreSQL 9.6+).
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
        let auth_params_json = serde_json::to_value(&realm.auth_params).map_err(|e| {
            crate::database::AuthDbError::Unexpected(format!(
                "Failed to serialize auth_params: {e}"
            ))
        })?;

        sqlx::query(
            r#"
            INSERT INTO realm (id, auth_params, cookie_max_age_seconds, max_stale_age_seconds, certificate_max_age_seconds)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(&realm.id)
        .bind(auth_params_json)
        .bind(realm.session_max_age_seconds)
        .bind(realm.session_max_stale_age_seconds)
        .bind(realm.certificate_max_age_seconds)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_realm(&self, id: &str) -> AuthDbResult<Option<Realm>> {
        let row = sqlx::query(
            r#"
            SELECT id, auth_params, cookie_max_age_seconds, max_stale_age_seconds, certificate_max_age_seconds
            FROM realm
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let auth_params_json: serde_json::Value = row.try_get("auth_params")?;
                let auth_params = serde_json::from_value(auth_params_json).map_err(|e| {
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
        let auth_params_json = serde_json::to_value(&realm.auth_params).map_err(|e| {
            crate::database::AuthDbError::Unexpected(format!(
                "Failed to serialize auth_params: {e}"
            ))
        })?;

        sqlx::query(
            r#"
            UPDATE realm
            SET auth_params = $2, cookie_max_age_seconds = $3, max_stale_age_seconds = $4, certificate_max_age_seconds = $5
            WHERE id = $1
            "#,
        )
        .bind(&realm.id)
        .bind(auth_params_json)
        .bind(realm.session_max_age_seconds)
        .bind(realm.session_max_stale_age_seconds)
        .bind(realm.certificate_max_age_seconds)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_realm(&self, id: &str) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            DELETE FROM realm WHERE id = $1
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
            let auth_params_json: serde_json::Value = row.try_get("auth_params")?;
            let auth_params = serde_json::from_value(auth_params_json).map_err(|e| {
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
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(&userpass.realm)
        .bind(&userpass.username)
        .bind(&userpass.password)
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
            WHERE realm = $1 AND username = $2
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
                    password: vec![], // do not return the password hash
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
            SET password = $3, change_password = $4, roles = $5, extra_claims = $6
            WHERE realm = $1 AND username = $2
            "#,
        )
        .bind(&userpass.realm)
        .bind(&userpass.username)
        .bind(&userpass.password)
        .bind(userpass.change_password)
        .bind(&roles_json)
        .bind(&extra_claims_json)
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
            SET change_password = $3, roles = $4
            WHERE realm = $1 AND username = $2
            "#,
        )
        .bind(realm)
        .bind(username)
        .bind(change_password)
        .bind(&roles_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_userpass(&self, realm: &str, username: &str) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            DELETE FROM userpass
            WHERE realm = $1 AND username = $2
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
            WHERE username = $1
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
            SELECT realm, username, password, change_password, roles, extra_claims
            FROM userpass
            WHERE realm = $1
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
            userpass_list.push(UserPass {
                realm: row.try_get("realm")?,
                username: row.try_get("username")?,
                password: row.try_get("password")?,
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
            userpass_list.push(UserPass {
                realm: row.try_get("realm")?,
                username: row.try_get("username")?,
                password: row.try_get("password")?,
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
            WHERE realm = $1 AND username = $2
            "#,
        )
        .bind(realm)
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => {
                let stored_password: Vec<u8> = row.try_get("password")?;
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
                serde_json::to_value(digital_credentials).map_err(|e| {
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
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&admin.id)
        .bind(&admin.userpass)
        .bind(&admin.jwt)
        .bind(&admin.fido2)
        .bind(digital_credentials_json)
        .bind(&admin.client_certificate)
        .bind(admin.totp_enabled)
        .bind(&admin.totp_secret)
        .bind(&admin.totp_auth_url)
        .execute(&self.pool)
        .await?;

        // Insert into user_realms join table
        for realm_id in &admin.realms {
            sqlx::query(
                r#"
                INSERT INTO admin_realms (admin_id, realm_id)
                VALUES ($1, $2)
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
            WHERE id = $1
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
                    WHERE admin_id = $1
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
                    .try_get::<Option<serde_json::Value>, _>("digital_credentials")?
                    .map(|v| {
                        serde_json::from_value(v).map_err(|e| {
                            crate::database::AuthDbError::Unexpected(format!(
                                "Failed to deserialize digital_credentials: {e}"
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
                    totp_enabled: row.try_get("totp_enabled")?,
                    totp_secret: row.try_get("totp_secret")?,
                    totp_auth_url: row.try_get("totp_auth_url")?,
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
            .map(|dc| {
                serde_json::to_value(dc).map_err(|e| {
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
            SET userpass= $2, jwt = $3, fido2 = $4, digital_credentials = $5, certificate = $6,
                totp_enabled = $7, totp_secret = $8, totp_auth_url = $9
            WHERE id = $1
            "#,
        )
        .bind(&admin.id)
        .bind(&admin.userpass)
        .bind(&admin.jwt)
        .bind(&admin.fido2)
        .bind(digital_credentials_json)
        .bind(&admin.client_certificate)
        .bind(admin.totp_enabled)
        .bind(&admin.totp_secret)
        .bind(&admin.totp_auth_url)
        .execute(&self.pool)
        .await?;

        // Delete existing realm associations
        sqlx::query(
            r#"
            DELETE FROM admin_realms WHERE admin_id = $1
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
                VALUES ($1, $2)
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
            DELETE FROM admin WHERE id = $1
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
                WHERE admin_id = $1
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
                .try_get::<Option<serde_json::Value>, _>("digital_credentials")?
                .map(|v| {
                    serde_json::from_value(v).map_err(|e| {
                        crate::database::AuthDbError::Unexpected(format!(
                            "Failed to deserialize digital_credentials: {e}"
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
                totp_enabled: row.try_get("totp_enabled")?,
                totp_secret: row.try_get("totp_secret")?,
                totp_auth_url: row.try_get("totp_auth_url")?,
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
        let (query, bind_value) = match auth_method {
            AuthScheme::UsernamePassword => (
                "SELECT id FROM admin WHERE userpass = $1",
                value.to_string(),
            ),
            AuthScheme::Jwt => ("SELECT id FROM admin WHERE jwt = $1", value.to_string()),
            AuthScheme::Fido2 => ("SELECT id FROM admin WHERE fido2 = $1", value.to_string()),
            AuthScheme::DigitalCredentials => (
                "SELECT id FROM admin WHERE digital_credentials @> $1::jsonb",
                serde_json::to_string(&vec![value]).map_err(|e| {
                    crate::database::AuthDbError::Unexpected(format!(
                        "Failed to serialize VP query value: {e} for value: {value}"
                    ))
                })?,
            ),
            AuthScheme::ClientCertificate => (
                "SELECT id FROM admin WHERE certificate = $1",
                value.to_string(),
            ),
        };

        let rows = sqlx::query(query)
            .bind(bind_value)
            .fetch_all(&self.pool)
            .await?;

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
            SET totp_enabled = true,
                totp_secret = $1,
                totp_auth_url = $2
            WHERE id = $3 AND (userpass IS NOT NULL OR jwt IS NOT NULL)
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
            SET totp_enabled = false,
                totp_secret = NULL,
                totp_auth_url = NULL
            WHERE id = $1 AND (userpass IS NOT NULL OR jwt IS NOT NULL)
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
            WHERE id = $1 AND (userpass IS NOT NULL OR jwt IS NOT NULL)
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(row.try_get("totp_secret")?),
            None => Ok(None),
        }
    }

    async fn is_totp_enabled(&self, _realm: &str, username: &str) -> AuthDbResult<Option<bool>> {
        let row = sqlx::query(
            r#"
            SELECT totp_enabled
            FROM admin
            WHERE id = $1 AND (userpass IS NOT NULL OR jwt IS NOT NULL)
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(row.try_get("totp_enabled")?),
            None => Ok(None),
        }
    }

    // ── app token operations ────────────────────────────────────────────────

    async fn issue_app_token(&self, token: &AppToken) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO app_tokens
                (token_hash, entity, policies, expiry, renewable, lease_duration_secs, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&token.token_hash)
        .bind(&token.entity)
        .bind(serde_json::to_string(&token.policies).unwrap_or_else(|_| "[]".to_string()))
        .bind(token.expiry)
        .bind(token.renewable)
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
            WHERE token_hash = $1 AND (expiry = 0 OR expiry > $2)
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
                renewable: r.try_get("renewable")?,
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
            SET expiry = $1 + lease_duration_secs
            WHERE token_hash = $2 AND renewable = TRUE AND expiry > 0 AND expiry > $3
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
                "SELECT COUNT(*) FROM app_tokens WHERE token_hash = $1 AND renewable = TRUE AND expiry = 0",
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
        sqlx::query("DELETE FROM app_tokens WHERE token_hash = $1")
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
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT(name) DO UPDATE SET
                role_id             = EXCLUDED.role_id,
                secret_id_ttl_secs  = EXCLUDED.secret_id_ttl_secs,
                token_ttl_secs      = EXCLUDED.token_ttl_secs,
                bind_secret_id      = EXCLUDED.bind_secret_id,
                token_policies      = EXCLUDED.token_policies
            "#,
        )
        .bind(&role.name)
        .bind(&role.role_id)
        .bind(role.secret_id_ttl_secs)
        .bind(role.token_ttl_secs)
        .bind(role.bind_secret_id)
        .bind(serde_json::to_string(&role.token_policies).unwrap_or_else(|_| "[]".to_string()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_approle_by_role_id(&self, role_id: &str) -> AuthDbResult<Option<AppRole>> {
        let row = sqlx::query(
            r#"
            SELECT name, role_id, secret_id_ttl_secs, token_ttl_secs, bind_secret_id, token_policies
            FROM approle_roles WHERE role_id = $1
            "#,
        )
        .bind(role_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            let policies_json: String = r.try_get("token_policies").unwrap_or_default();
            AppRole {
                name: r.try_get("name").unwrap_or_default(),
                role_id: r.try_get("role_id").unwrap_or_default(),
                secret_id_ttl_secs: r.try_get("secret_id_ttl_secs").unwrap_or_default(),
                token_ttl_secs: r.try_get("token_ttl_secs").unwrap_or(3600),
                bind_secret_id: r.try_get("bind_secret_id").unwrap_or(true),
                token_policies: serde_json::from_str(&policies_json).unwrap_or_default(),
            }
        }))
    }

    async fn get_approle_by_name(&self, name: &str) -> AuthDbResult<Option<AppRole>> {
        let row = sqlx::query(
            r#"
            SELECT name, role_id, secret_id_ttl_secs, token_ttl_secs, bind_secret_id, token_policies
            FROM approle_roles WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            let policies_json: String = r.try_get("token_policies").unwrap_or_default();
            AppRole {
                name: r.try_get("name").unwrap_or_default(),
                role_id: r.try_get("role_id").unwrap_or_default(),
                secret_id_ttl_secs: r.try_get("secret_id_ttl_secs").unwrap_or_default(),
                token_ttl_secs: r.try_get("token_ttl_secs").unwrap_or(3600),
                bind_secret_id: r.try_get("bind_secret_id").unwrap_or(true),
                token_policies: serde_json::from_str(&policies_json).unwrap_or_default(),
            }
        }))
    }

    async fn delete_approle(&self, name: &str) -> AuthDbResult<()> {
        sqlx::query("DELETE FROM approle_roles WHERE name = $1")
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
            VALUES ($1, $2, $3, $4, $5)
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
        // transaction to prevent concurrent logins from consuming the
        // same secret-ID twice (TOCTOU race condition).
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query(
            r#"
            SELECT accessor, num_uses_remaining
            FROM app_secret_ids
            WHERE role_name = $1 AND secret_id_hash = $2 AND (expiry = 0 OR expiry > $3)
            FOR UPDATE
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
            sqlx::query("DELETE FROM app_secret_ids WHERE accessor = $1")
                .bind(&accessor)
                .execute(&mut *tx)
                .await?;
        } else if num_uses > 1 {
            sqlx::query(
                "UPDATE app_secret_ids SET num_uses_remaining = num_uses_remaining - 1 WHERE accessor = $1",
            )
            .bind(&accessor)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(Some(accessor))
    }

    async fn destroy_secret_id(&self, role_name: &str, accessor: &str) -> AuthDbResult<()> {
        sqlx::query("DELETE FROM app_secret_ids WHERE accessor = $1 AND role_name = $2")
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
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT(name) DO UPDATE SET
                jwks_url                = EXCLUDED.jwks_url,
                bound_sa_names          = EXCLUDED.bound_sa_names,
                bound_sa_namespaces     = EXCLUDED.bound_sa_namespaces,
                token_ttl_secs          = EXCLUDED.token_ttl_secs,
                expected_issuer         = EXCLUDED.expected_issuer,
                bound_audiences         = EXCLUDED.bound_audiences
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
            FROM k8s_roles WHERE name = $1
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
        sqlx::query("DELETE FROM k8s_roles WHERE name = $1")
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
