//! Authentication Server HTTP Client
//!
//! This module provides a configurable HTTPS client to interact with the authentication server.
//! It supports three authentication modes:
//! - No authentication
//! - Username and password authentication (using HTTP Basic Auth)
//! - JWT authentication
//! - Client certificate authentication

use crate::{
    AuthError, AuthResult, AuthenticatedClientScheme, AuthenticationResult,
    client::AuthClientCookieStore,
    dto::{
        DeleteSessionsRequest, GetSessionRequest, GetSessionsForClientsRequest,
        GetSessionsForClientsResponse, SessionsAction, TotpGenerateRequest, TotpGenerateResponse,
        TotpVerifyRequest, Version,
    },
    models::{ClientClaims, LoginRequest, Realm, SessionData, User, UserPass},
};
use base64::Engine;
use cookie_store::{Cookie, CookieDomain};
use cosmian_logger::{debug, error, info, trace};
use reqwest::{Certificate, Client, Identity, Response};
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;
use url::Url;

/// Authentication configuration for the test client
#[derive(Debug, Clone)]
pub enum AuthClientScheme {
    /// No authentication
    None,
    /// JWT authentication
    Jwt {
        /// Base64-encoded JWT token
        token: String,
    },
    /// Client certificate authentication using a PKCS#12 archive
    ClientCertificate {
        /// DER-encoded PKCS#12 archive containing the client certificate and private key
        pkcs12_der: Vec<u8>,

        /// Password for the PKCS#12 archive
        password: String,
    },
    /// Username and password authentication
    UsernamePassword {
        /// Username
        username: String,
        /// Password
        password: String,
    },
}

/// Authentication HTTP client with configurable authentication
pub struct AuthClient {
    /// The underlying reqwest client
    client: Client,

    /// Base URL for requests
    base_url: String,

    /// Authentication configuration
    auth: AuthClientScheme,

    /// Cooke store for managing cookies
    cookie_store: Arc<AuthClientCookieStore>,
}

impl AuthClient {
    /// Create a new authentication client with the specified authentication mode
    ///
    /// # Arguments
    /// * `base_url` - The base URL for all requests (e.g., "https://localhost:8443")
    /// * `auth` - The authentication configuration
    ///
    /// # Returns
    /// A configured `AuthClient` ready to make requests
    pub fn new(
        base_url: &str,
        server_ca_cert_pem: &str,
        auth: AuthClientScheme,
    ) -> AuthResult<Self> {
        let cookie_store = Arc::new(AuthClientCookieStore::new());
        let client = Self::build_client(server_ca_cert_pem, &auth, cookie_store.clone())?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth,
            cookie_store,
        })
    }

    /// Build the reqwest client based on authentication configuration
    fn build_client(
        server_ca_cert_pem: &str,
        auth: &AuthClientScheme,
        cookie_store: Arc<AuthClientCookieStore>,
    ) -> AuthResult<Client> {
        // Load the CA certificate for TLS verification
        let ca_cert = Certificate::from_pem(server_ca_cert_pem.as_bytes())
            .map_err(|e| AuthError::Config(format!("Failed to parse CA certificate: {}", e)))?;
        info!("Loaded CA certificate from provided PEM");

        let mut builder = Client::builder()
            .cookie_provider(cookie_store)
            .add_root_certificate(ca_cert)
            .danger_accept_invalid_certs(false);
        info!("Configured client with custom server CA certificate");

        match auth {
            AuthClientScheme::None => {}
            AuthClientScheme::Jwt { token, .. } => {
                builder = builder.default_headers({
                    let mut headers = reqwest::header::HeaderMap::new();
                    let value = format!("Bearer {}", token);
                    headers.insert(
                        reqwest::header::AUTHORIZATION,
                        reqwest::header::HeaderValue::from_str(&value).map_err(|e| {
                            AuthError::Config(format!("Failed to create Bearer auth header: {}", e))
                        })?,
                    );
                    headers
                });
            }
            AuthClientScheme::ClientCertificate {
                pkcs12_der,
                password,
            } => {
                let identity = Identity::from_pkcs12_der(pkcs12_der, password).map_err(|e| {
                    error!("Failed to parse client identity: {}", e);
                    AuthError::Config(format!("Failed to parse client identity: {}", e))
                })?;
                info!("Parsed client identity");

                builder = builder.identity(identity);
            }
            AuthClientScheme::UsernamePassword { username, password } => {
                let credentials = format!("{}:{}", username, password);
                let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
                builder = builder.default_headers({
                    let mut headers = reqwest::header::HeaderMap::new();
                    let value = format!("Basic {}", encoded);
                    headers.insert(
                        reqwest::header::AUTHORIZATION,
                        reqwest::header::HeaderValue::from_str(&value).map_err(|e| {
                            AuthError::Config(format!("Failed to create Basic auth header: {}", e))
                        })?,
                    );
                    headers
                });
            }
        };

        let client = builder
            .build()
            .map_err(|e| AuthError::Config(format!("Failed to build HTTP client: {}", e)))?;

        Ok(client)
    }

    /// Perform an HTTPS GET request and deserialize the JSON response
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> AuthResult<T> {
        debug!("Preparing GET request to {}", path);
        let url = format!("{}{}", self.base_url, path);
        let request = self.client.get(&url);

        let response = request.send().await.map_err(|e| {
            error!("GET request failed: {}", e);
            AuthError::Generic(format!("GET request failed: {}", e))
        })?;

        Self::handle_response(response).await
    }

    /// Perform an HTTPS GET request and return the raw response
    pub async fn get_raw(&self, path: &str) -> AuthResult<Response> {
        debug!("Preparing GET request to {}", path);
        let url = format!("{}{}", self.base_url, path);
        let request = self.client.get(&url);

        request
            .send()
            .await
            .map_err(|e| AuthError::Config(format!("GET request failed: {}", e)))
    }

    /// Perform an HTTPS GET request with a custom header and return the raw response
    pub async fn get_raw_with_header(
        &self,
        path: &str,
        header_name: &str,
        header_value: &str,
    ) -> AuthResult<Response> {
        let url = format!("{}{}", self.base_url, path);
        let request = self.client.get(&url).header(header_name, header_value);

        request
            .send()
            .await
            .map_err(|e| AuthError::Config(format!("GET request failed: {}", e)))
    }

    /// Perform an HTTPS POST request with a JSON body and a custom header, returning the raw response
    pub async fn post_raw_with_header<B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
        header_name: &str,
        header_value: &str,
    ) -> AuthResult<Response> {
        let url = format!("{}{}", self.base_url, path);
        let request = self
            .client
            .post(&url)
            .json(body)
            .header(header_name, header_value);

        request
            .send()
            .await
            .map_err(|e| AuthError::Config(format!("POST request failed: {}", e)))
    }

    /// Perform an HTTPS POST request with a JSON body and deserialize the JSON response
    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> AuthResult<T> {
        debug!("Preparing POST request to {}", path);
        let url = format!("{}{}", self.base_url, path);
        let request = self.client.post(&url).json(body);

        let response = request
            .send()
            .await
            .map_err(|e| AuthError::Config(format!("POST request failed: {}", e)))?;

        Self::handle_response(response).await
    }

    /// Perform an HTTPS PUT request with a JSON body and deserialize the JSON response
    pub async fn put<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> AuthResult<T> {
        debug!("Preparing PUT request to {}", path);
        let url = format!("{}{}", self.base_url, path);
        let request = self.client.put(&url).json(body);

        let response = request
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("PUT request failed: {}", e)))?;

        Self::handle_response(response).await
    }

    /// Perform an HTTPS POST request and return the raw response
    pub async fn post_raw<B: Serialize>(&self, path: &str, body: &B) -> AuthResult<Response> {
        let url = format!("{}{}", self.base_url, path);
        let request = self.client.post(&url).json(body);

        request
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("POST request failed: {}", e)))
    }

    /// Handle the HTTP response, checking for errors and deserializing JSON
    async fn handle_response<T: DeserializeOwned>(response: Response) -> AuthResult<T> {
        let status = response.status();

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AuthError::FailedHttpStatus(format!(
                "Request failed with status {}: {}",
                status, error_text
            )));
        }

        response
            .json()
            .await
            .map_err(|e| AuthError::Config(format!("Failed to deserialize response: {}", e)))
    }

    /// Get the base URL
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the authentication configuration
    pub fn auth(&self) -> &AuthClientScheme {
        &self.auth
    }

    pub fn get_cookie(&self, url: &str) -> AuthResult<Option<Cookie<'_>>> {
        let cookie_store = self
            .cookie_store
            .lock()
            .map_err(|e| AuthError::Config(format!("Failed to lock cookie store: {}", e)))?;
        let host_string = Url::parse(url)
            .map_err(|e| AuthError::Config(format!("Failed to parse URL {}: {}", url, e)))?
            .host_str()
            .ok_or_else(|| AuthError::Config(format!("URL {} has no host", url)))?
            .to_string();
        trace!("Looking for cookies for host: {}", host_string);
        for cookie in cookie_store.iter_any() {
            trace!(
                "Checking cookie: {:?} - domain: {:?}",
                cookie, cookie.domain
            );
            if cookie.domain == CookieDomain::HostOnly(host_string.clone()) {
                debug!("Found matching cookie for host {}", host_string);
                return Ok(Some(cookie.clone()));
            }
        }
        Ok(None)
    }
}

// User API
impl AuthClient {
    /// Call to the /login? realm={realm} endpoint to attempt authenticating the user
    /// and return the authenticated user information and cookie if successful.
    ///
    /// Pass `totp_code` when the server previously returned `TotpRequired` as the next step.
    pub async fn login(
        &self,
        realm: &str,
        public_key_pem: Option<String>,
        totp_code: Option<String>,
    ) -> AuthResult<(AuthenticationResult, Option<Cookie<'_>>)> {
        let user = self
            .post::<LoginRequest, AuthenticationResult>(
                &format!("/login?realm={}", realm),
                &LoginRequest {
                    public_key_pem,
                    totp_code,
                },
            )
            .await?;
        let cookie = self.get_cookie(&self.base_url)?;
        Ok((user, cookie))
    }

    /// Call to the /whoami endpoint to get the authenticated user's claims
    pub async fn whoami(&self, realm: &str) -> AuthResult<ClientClaims> {
        self.get(&format!("/whoami?realm={}", realm)).await
    }

    /// Call to the /public/version endpoint to retrieve the server version string.
    pub async fn get_version(&self) -> AuthResult<String> {
        let v: Version = self.get("/public/version").await?;
        Ok(v.version)
    }
}

// Realm Management API
impl AuthClient {
    /// Create a new realm
    pub async fn create_realm(&self, realm: &Realm) -> AuthResult<()> {
        let path = "/admin/realm".to_string();
        let _realm: Realm = self.post(&path, realm).await?;
        Ok(())
    }

    /// Delete a realm
    pub async fn delete_realm(&self, realm_name: &str) -> AuthResult<()> {
        let url = format!("{}/admin/realm/{}", self.base_url, realm_name);
        let request = self.client.delete(&url);

        let response = request
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("DELETE request failed: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AuthError::FailedHttpStatus(format!(
                "Request failed with status {}: {}",
                status, error_text
            )));
        }

        Ok(())
    }

    /// List all realms
    pub async fn list_realms(&self) -> AuthResult<Vec<String>> {
        self.get("/admin/realm").await
    }
}

// Sessions Management API
impl AuthClient {
    /// Get session information by session ID.
    /// Returns `None` if the session does not exist or has expired.
    pub async fn get_session(&self, session_id: &str) -> AuthResult<Option<SessionData>> {
        let path = format!("/sessions/session/{}", session_id);
        self.get::<Option<SessionData>>(&path).await
    }

    /// Get session information by session ID, and optionally apply a session action.
    pub async fn get_session_with_action(
        &self,
        session_id: &str,
        authenticated_clients: Vec<AuthenticatedClientScheme>,
        sessions_action: SessionsAction,
    ) -> AuthResult<Option<SessionData>> {
        let path = format!("/sessions/session/{}", session_id);
        let payload = GetSessionRequest {
            authenticated_clients,
            sessions_action: Some(sessions_action),
        };
        match self
            .post::<GetSessionRequest, Option<SessionData>>(&path, &payload)
            .await
        {
            Ok(data) => Ok(data),
            Err(AuthError::FailedHttpStatus(ref msg)) if msg.contains("404") => Ok(None),
            Err(e) => Err(e),
        }
    }

    // Get the session IDs for a list of clients in a realm
    pub async fn get_sessions_for_clients(
        &self,
        realm_id: &str,
        authenticated_clients: &[AuthenticatedClientScheme],
    ) -> AuthResult<Vec<String>> {
        let path = format!("/sessions/session/realms/{}/clients", realm_id);
        let payload = GetSessionsForClientsRequest {
            authenticated_clients: authenticated_clients.to_vec(),
        };
        let response: GetSessionsForClientsResponse = self.post(&path, &payload).await?;
        Ok(response.session_ids)
    }

    /// Delete sessions by their session IDs.
    pub async fn delete_sessions(&self, session_ids: &[String]) -> AuthResult<()> {
        let url = format!("{}/sessions/session", self.base_url);
        let payload = DeleteSessionsRequest {
            session_ids: session_ids.to_vec(),
        };
        let request = self.client.delete(&url).json(&payload);
        let response = request
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("DELETE request failed: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AuthError::FailedHttpStatus(format!(
                "Request failed with status {status}: {error_text}"
            )));
        }
        Ok(())
    }

    /// Delete all expired sessions
    pub async fn delete_expired_sessions(&self) -> AuthResult<()> {
        let path = "/sessions/session/expired";
        self.client
            .delete(format!("{}{}", self.base_url, path))
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("DELETE request failed: {}", e)))?
            .error_for_status()
            .map_err(|e| AuthError::FailedHttpStatus(format!("Request failed: {}", e)))?;
        Ok(())
    }

    /// Delete all sessions for a given realm
    pub async fn delete_sessions_for_realm(&self, realm_id: &str) -> AuthResult<()> {
        let path = format!("/sessions/session/realms/{}", realm_id);
        self.client
            .delete(format!("{}{}", self.base_url, path))
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("DELETE request failed: {}", e)))?
            .error_for_status()
            .map_err(|e| AuthError::FailedHttpStatus(format!("Request failed: {}", e)))?;
        Ok(())
    }
}

/// Super Admin API
impl AuthClient {
    /// Create a new realm
    pub async fn create_realm_as_super_admin(&self, realm: &Realm) -> AuthResult<()> {
        let path = "/admin/realm".to_string();
        let _realm: Realm = self.post(&path, realm).await?;
        Ok(())
    }

    /// Get a realm by ID
    pub async fn get_realm_as_super_admin(&self, realm_id: &str) -> AuthResult<Realm> {
        let path = format!("/admin/realm/{}", realm_id);
        self.get(&path).await
    }

    /// Delete a realm by ID
    pub async fn delete_realm_as_super_admin(&self, realm_id: &str) -> AuthResult<()> {
        let url = format!("{}/admin/realm/{}", self.base_url, realm_id);
        let request = self.client.delete(&url);
        let response = request
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("DELETE request failed: {}", e)))?;
        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AuthError::FailedHttpStatus(format!(
                "Request failed with status {}: {}",
                status, error_text
            )));
        }
        Ok(())
    }

    /// Update a realm
    pub async fn update_realm_as_super_admin(
        &self,
        realm_id: &str,
        realm: &Realm,
    ) -> AuthResult<Realm> {
        let path = format!("/admin/realm/{}", realm_id);
        self.put(&path, realm).await
    }

    /// List all realms
    pub async fn list_realms_as_super_admin(&self) -> AuthResult<Vec<Realm>> {
        self.get("/admin/realms").await
    }
}

/// User Management API
impl AuthClient {
    /// Create a new user.
    pub async fn create_user_as_super_admin(&self, user: &User) -> AuthResult<User> {
        self.post("/users/user", user).await
    }

    /// Retrieve a user by ID.
    pub async fn get_user_as_super_admin(&self, user_id: &str) -> AuthResult<User> {
        self.get(&format!("/users/user/{}", user_id)).await
    }

    /// Update an existing user.
    pub async fn update_user_as_super_admin(&self, user_id: &str, user: &User) -> AuthResult<User> {
        self.put(&format!("/users/user/{}", user_id), user).await
    }

    /// Delete a user by ID.
    pub async fn delete_user_as_super_admin(&self, user_id: &str) -> AuthResult<()> {
        let url = format!("{}/users/user/{}", self.base_url, user_id);
        let request = self.client.delete(&url);
        let response = request
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("DELETE request failed: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AuthError::FailedHttpStatus(format!(
                "Request failed with status {status}: {error_text}"
            )));
        }
        Ok(())
    }

    /// List all users.
    pub async fn list_users_as_super_admin(&self) -> AuthResult<Vec<User>> {
        self.get("/users").await
    }

    /// Add a user to a realm.
    pub async fn add_user_to_realm_as_admin(
        &self,
        user_id: &str,
        realm_id: &str,
    ) -> AuthResult<User> {
        self.put(
            &format!("/users/user/{}/realm/{}", user_id, realm_id),
            &serde_json::Value::Null,
        )
        .await
    }

    /// Remove a user from a realm.
    pub async fn remove_user_from_realm_as_admin(
        &self,
        user_id: &str,
        realm_id: &str,
    ) -> AuthResult<User> {
        let url = format!(
            "{}/users/user/{}/realm/{}",
            self.base_url, user_id, realm_id
        );
        let request = self.client.delete(&url);
        let response = request
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("DELETE request failed: {e}")))?;
        Self::handle_response(response).await
    }

    /// Create login credentials for a user in a given realm.
    pub async fn create_user_credentials_in_realm(
        &self,
        realm_id: &str,
        userpass: &UserPass,
    ) -> AuthResult<()> {
        let path = format!("/realms/{}/userpass?realm={}", realm_id, realm_id);
        let _: serde_json::Value = self.post(&path, userpass).await?;
        Ok(())
    }

    /// Retrieve login credentials for a user in a given realm.
    pub async fn get_user_credentials_in_realm(
        &self,
        realm_id: &str,
        username: &str,
    ) -> AuthResult<UserPass> {
        let path = format!(
            "/realms/{}/userpass/{}?realm={}",
            realm_id, username, realm_id
        );
        self.get(&path).await
    }

    /// Update login credentials for a user in a given realm.
    pub async fn update_user_credentials_in_realm(
        &self,
        realm_id: &str,
        username: &str,
        userpass: &UserPass,
    ) -> AuthResult<UserPass> {
        let path = format!(
            "/realms/{}/userpass/{}?realm={}",
            realm_id, username, realm_id
        );
        self.put(&path, userpass).await
    }

    /// Delete login credentials for a user in a given realm.
    pub async fn delete_user_credentials_in_realm(
        &self,
        realm_id: &str,
        username: &str,
    ) -> AuthResult<()> {
        let url = format!(
            "{}/realms/{}/userpass/{}?realm={}",
            self.base_url, realm_id, username, realm_id
        );
        let request = self.client.delete(&url);
        let response = request
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("DELETE request failed: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AuthError::FailedHttpStatus(format!(
                "Request failed with status {status}: {error_text}"
            )));
        }
        Ok(())
    }

    /// List all login credentials for a given realm.
    pub async fn list_user_credentials_in_realm(
        &self,
        realm_id: &str,
    ) -> AuthResult<Vec<UserPass>> {
        let path = format!("/realms/{}/userpass?realm={}", realm_id, realm_id);
        self.get(&path).await
    }

    /// List all userpass credentials across all realms. Super admins only.
    pub async fn list_all_userpass_as_super_admin(&self) -> AuthResult<Vec<UserPass>> {
        self.get("/admin/userpass").await
    }
}

// TOTP Management API
impl AuthClient {
    /// Generate a new TOTP secret for a user in a realm.
    pub async fn generate_totp(
        &self,
        realm_id: &str,
        username: &str,
        issuer: Option<String>,
    ) -> AuthResult<TotpGenerateResponse> {
        let path = format!("/realms/{}/totp/generate?realm={}", realm_id, realm_id);
        self.post(
            &path,
            &TotpGenerateRequest {
                username: username.to_string(),
                issuer,
            },
        )
        .await
    }

    /// Verify a TOTP token against a given secret and — if valid — enable TOTP for the user.
    pub async fn verify_and_enable_totp(
        &self,
        realm_id: &str,
        username: &str,
        secret: &str,
        token: &str,
        issuer: Option<String>,
    ) -> AuthResult<()> {
        let path = format!("/realms/{}/totp/verify?realm={}", realm_id, realm_id);
        let _: serde_json::Value = self
            .post(
                &path,
                &TotpVerifyRequest {
                    username: username.to_string(),
                    token: token.to_string(),
                    secret: secret.to_string(),
                    issuer,
                },
            )
            .await?;
        Ok(())
    }

    /// Disable TOTP for a user, removing their stored secret.
    pub async fn disable_totp(&self, realm_id: &str, username: &str) -> AuthResult<()> {
        let url = format!(
            "{}/realms/{}/totp/{}?realm={}",
            self.base_url, realm_id, username, realm_id
        );
        let request = self.client.delete(&url);
        let response = request
            .send()
            .await
            .map_err(|e| AuthError::Generic(format!("DELETE request failed: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AuthError::FailedHttpStatus(format!(
                "Request failed with status {status}: {error_text}"
            )));
        }
        Ok(())
    }
}
