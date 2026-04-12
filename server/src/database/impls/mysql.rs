use std::collections::HashMap;

use crate::{
    database::{AuthDbResult, hash_password_with_argon2, r#trait::Database},
    models::{AuthScheme, Realm, User, UserPass},
};
use async_trait::async_trait;
use sqlx::{MySqlPool, Row};

/// MySQL database implementation
pub struct MySqlDatabase {
    pool: MySqlPool,
}

impl MySqlDatabase {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl Database for MySqlDatabase {
    async fn init(&self) -> AuthDbResult<()> {
        // Create realm table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS realm (
                id VARCHAR(255) PRIMARY KEY NOT NULL,
                auth_params JSON NOT NULL,
                cookie_max_age_seconds BIGINT UNSIGNED NOT NULL,
                max_stale_age_seconds BIGINT UNSIGNED NOT NULL,
                CHECK (id REGEXP '^[a-zA-Z0-9_-]+$')
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create userpass table with composite primary key and foreign key
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS userpass (
                realm VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL,
                password BLOB NOT NULL,
                change_password BOOLEAN NOT NULL DEFAULT FALSE,
                PRIMARY KEY (realm, username),
                FOREIGN KEY (realm) REFERENCES realm(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create users table - users in this context are the realms'admins
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user (
                id VARCHAR(255) PRIMARY KEY,
                userpass VARCHAR(255),
                jwt TEXT,
                fido2 TEXT,
                digital_credentials JSON,
                certificate TEXT,

                -- TOTP/2FA fields
                totp_enabled BOOLEAN DEFAULT FALSE,
                totp_secret VARCHAR(4096),
                totp_auth_url TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        // Create user_realms join table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_realms (
                user_id VARCHAR(255) NOT NULL,
                realm_id VARCHAR(255) NOT NULL,
                PRIMARY KEY (user_id, realm_id),
                FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
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
        sqlx::query(
            r#"
            INSERT INTO userpass (realm, username, password, change_password)
            VALUES (?, ?, ?, ?)
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
            WHERE realm = ? AND username = ?
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
            SET password = ?, change_password = ?
            WHERE realm = ? AND username = ?
            "#,
        )
        .bind(&userpass.password)
        .bind(userpass.change_password)
        .bind(&userpass.realm)
        .bind(&userpass.username)
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
            SELECT realm, username, password, change_password
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

    // ===== User CRUD operations =====

    async fn create_user(&self, user: &User) -> AuthDbResult<()> {
        let digital_credentials_json = user
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

        // Insert into user table
        sqlx::query(
            r#"
            INSERT INTO user (id, userpass, jwt, fido2, digital_credentials, certificate, totp_enabled, totp_secret, totp_auth_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&user.id)
        .bind(&user.userpass)
        .bind(&user.jwt)
        .bind(&user.fido2)
        .bind(digital_credentials_json)
        .bind(&user.client_certificate)
        .bind(user.totp_enabled)
        .bind(&user.totp_secret)
        .bind(&user.totp_auth_url)
        .execute(&self.pool)
        .await?;

        // Insert into user_realms join table
        for realm_id in &user.realms {
            sqlx::query(
                r#"
                INSERT INTO user_realms (user_id, realm_id)
                VALUES (?, ?)
                "#,
            )
            .bind(&user.id)
            .bind(realm_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn get_user(&self, id: &str) -> AuthDbResult<Option<User>> {
        let row = sqlx::query(
            r#"
            SELECT id, userpass, jwt, fido2, digital_credentials, certificate, totp_enabled, totp_secret, totp_auth_url
            FROM user
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
                    FROM user_realms
                    WHERE user_id = ?
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
                    .as_ref()
                    .map(|dc_json| {
                        serde_json::from_str(dc_json).map_err(|e| {
                            crate::database::AuthDbError::Unexpected(format!(
                                "Failed to deserialize digital_credentials: {e}"
                            ))
                        })
                    })
                    .transpose()?;

                let user = User {
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
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    async fn update_user(&self, user: &User) -> AuthDbResult<()> {
        let digital_credentials_json = user
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

        // Update user table
        sqlx::query(
            r#"
            UPDATE user
            SET userpass= ?, jwt = ?, fido2 = ?, digital_credentials = ?, certificate = ?,
                totp_enabled = ?, totp_secret = ?, totp_auth_url = ?
            WHERE id = ?
            "#,
        )
        .bind(&user.userpass)
        .bind(&user.jwt)
        .bind(&user.fido2)
        .bind(digital_credentials_json)
        .bind(&user.client_certificate)
        .bind(user.totp_enabled)
        .bind(&user.totp_secret)
        .bind(&user.totp_auth_url)
        .bind(&user.id)
        .execute(&self.pool)
        .await?;

        // Delete existing realm associations
        sqlx::query(
            r#"
            DELETE FROM user_realms WHERE user_id = ?
            "#,
        )
        .bind(&user.id)
        .execute(&self.pool)
        .await?;

        // Insert new realm associations
        for realm_id in &user.realms {
            sqlx::query(
                r#"
                INSERT INTO user_realms (user_id, realm_id)
                VALUES (?, ?)
                "#,
            )
            .bind(&user.id)
            .bind(realm_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn delete_user(&self, id: &str) -> AuthDbResult<()> {
        sqlx::query(
            r#"
            DELETE FROM user WHERE id = ?
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_users(&self) -> AuthDbResult<Vec<User>> {
        let rows = sqlx::query(
            r#"
            SELECT id, userpass, jwt, fido2, digital_credentials, certificate, totp_enabled, totp_secret, totp_auth_url
            FROM user
            ORDER BY id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut users = Vec::new();
        for row in rows {
            let user_id: String = row.try_get("id")?;

            // Fetch realms from join table
            let realm_rows = sqlx::query(
                r#"
                SELECT realm_id
                FROM user_realms
                WHERE user_id = ?
                "#,
            )
            .bind(&user_id)
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
                            "Failed to deserialize digital_credentials: {e}"
                        ))
                    })
                })
                .transpose()?;

            users.push(User {
                id: user_id,
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

        Ok(users)
    }

    // Find Users by authentication method (e.g. userpass, jwt, fido2, vp, certificate) and value (e.g. username for userpass, subject for jwt, etc.)
    async fn find_users_by_auth_scheme(
        &self,
        auth_method: AuthScheme,
        value: &str,
    ) -> AuthDbResult<Vec<User>> {
        let (query, query_value) = match auth_method {
            AuthScheme::UsernamePassword => {
                ("SELECT id FROM user WHERE userpass = ?", value.to_string())
            }
            AuthScheme::Jwt => ("SELECT id FROM user WHERE jwt = ?", value.to_string()),
            AuthScheme::Fido2 => ("SELECT id FROM user WHERE fido2 = ?", value.to_string()),
            AuthScheme::DigitalCredentials => (
                "SELECT id FROM user WHERE digital_credentials LIKE ?",
                serde_json::to_string(&vec![value]).map_err(|e| {
                    crate::database::AuthDbError::Unexpected(format!(
                        "Failed to serialize digital_credentials query value: {e} for value: {value}"
                    ))
                })?,
            ),
            AuthScheme::ClientCertificate => (
                "SELECT id FROM user WHERE certificate = ?",
                value.to_string(),
            ),
        };

        let rows = sqlx::query(query)
            .bind(query_value)
            .fetch_all(&self.pool)
            .await?;

        let mut users = Vec::new();
        for row in rows {
            if let Some(user) = self.get_user(row.try_get("id")?).await? {
                users.push(user);
            }
        }

        Ok(users)
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
            UPDATE user
            SET totp_enabled = true,
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
            UPDATE user
            SET totp_enabled = false,
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
            FROM user
            WHERE id = ? AND (userpass IS NOT NULL OR jwt IS NOT NULL)
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
            FROM user
            WHERE id = ? AND (userpass IS NOT NULL OR jwt IS NOT NULL)
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
