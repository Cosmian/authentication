use std::collections::HashMap;

use crate::{
    database::{AuthDbResult, hash_password_with_argon2, r#trait::Database},
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
                max_stale_age_seconds BIGINT NOT NULL
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
                password BYTEA NOT NULL,
                change_password BOOLEAN NOT NULL DEFAULT FALSE,
                PRIMARY KEY (realm, username),
                FOREIGN KEY (realm) REFERENCES realm(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

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
            INSERT INTO realm (id, auth_params, cookie_max_age_seconds, max_stale_age_seconds)
            VALUES ($1, $2, $3, $4)
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
            SET auth_params = $2, cookie_max_age_seconds = $3, max_stale_age_seconds = $4
            WHERE id = $1
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
            SELECT id, auth_params, cookie_max_age_seconds, max_stale_age_seconds
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
            });
        }

        Ok(realms)
    }

    // ===== UserPass CRUD operations =====

    async fn create_userpass(&self, userpass: &UserPass) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            INSERT INTO userpass (realm, username, password, change_password)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(&userpass.realm)
        .bind(&userpass.username)
        .bind(&userpass.password)
        .bind(userpass.change_password)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_userpass(&self, realm: &str, username: &str) -> AuthDbResult<Option<UserPass>> {
        let row = sqlx::query(
            r#"
            SELECT realm, username, change_password
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
                let userpass = UserPass {
                    realm: row.try_get("realm")?,
                    username: row.try_get("username")?,
                    password: vec![], // do not return the password hash
                    change_password: row.try_get("change_password")?,
                };
                Ok(Some(userpass))
            }
            None => Ok(None),
        }
    }

    async fn update_userpass(&self, userpass: &UserPass) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            UPDATE userpass
            SET password = $3, change_password = $4
            WHERE realm = $1 AND username = $2
            "#,
        )
        .bind(&userpass.realm)
        .bind(&userpass.username)
        .bind(&userpass.password)
        .bind(userpass.change_password)
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
            SELECT realm, username, password, change_password
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
            userpass_list.push(UserPass {
                realm: row.try_get("realm")?,
                username: row.try_get("username")?,
                password: row.try_get("password")?,
                change_password: row.try_get("change_password")?,
            });
        }

        Ok(userpass_list)
    }

    async fn list_all_userpass(&self) -> AuthDbResult<Vec<UserPass>> {
        let rows = sqlx::query(
            r#"
            SELECT realm, username, password, change_password
            FROM userpass
            ORDER BY realm, username
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut userpass_list = Vec::new();
        for row in rows {
            userpass_list.push(UserPass {
                realm: row.try_get("realm")?,
                username: row.try_get("username")?,
                password: row.try_get("password")?,
                change_password: row.try_get("change_password")?,
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
                    client_certificate: row.try_get("client_certificate")?,
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
                client_certificate: row.try_get("client_certificate")?,
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
}
