# Client Library Guide

The `auth_client` crate provides an HTTP client and shared types for interacting with the Authentication Verifier. It is used by:

- **API servers** that need to validate incoming session cookies and manage sessions.
- **Admin tools** that manage realms, users, and credentials.
- The Authentication Verifier itself (internal use).

---

## Table of Contents

- [Installation](#installation)
- [Building a Client](#building-a-client)
- [Authentication Schemes](#authentication-schemes)
- [Session Validation](#session-validation)
- [Session Actions — Log Out Everywhere](#session-actions--log-out-everywhere)
- [Logging In](#logging-in)
- [Realm Management](#realm-management)
- [Admin Management](#admin-management)
- [Credential Management](#credential-management)
- [TOTP Management](#totp-management)
- [Machine Authentication (AppRole / Kubernetes / Token)](#machine-authentication-approle--kubernetes--token)
- [Public Endpoints](#public-endpoints)
- [Error Handling](#error-handling)
- [Types Reference](#types-reference)
  - [`ClientClaims`](#clientclaims)
    - [Reading roles from a validated session](#reading-roles-from-a-validated-session)
- [Actix-web Integration Example](#actix-web-integration-example)

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
auth_client = { path = "../authentication_client" }
```

No Cargo features are required for session validation. The `_server` feature enables additional `actix-web` integrations and is only needed inside the Authentication Verifier crate itself.

---

## Building a Client

All operations go through `AuthClient`. Create one at startup and share it as application state (it is `Clone`-able).

```rust
use auth_client::{AuthClient, AuthClientScheme};
use std::fs;

// Client for session validation — no authentication needed for this role
let client = AuthClient::new(
    "https://auth.example.com",          // base URL
    &fs::read_to_string("ca.cert.pem")?, // PEM of the server CA certificate
    AuthClientScheme::None,
)?;

println!("Base URL: {}", client.base_url());
```

`AuthClient::new` returns `AuthResult<AuthClient>`. It fails if the CA certificate is malformed or the authentication scheme configuration is invalid (e.g., unparsable PKCS#12 archive).

---

## Authentication Schemes

`AuthClientScheme` controls how the client authenticates to the Authentication Verifier crate itself. For simple session validation no authentication is needed; admin operations require a logged-in session.

```rust
use auth_client::AuthClientScheme;

// No authentication — use for session validation and public endpoints
AuthClientScheme::None

// Username/password — use to log in as admin before calling management APIs
AuthClientScheme::UsernamePassword {
    username: "admin".to_string(),
    password: "s3cret".to_string(),
}

// JWT Bearer token — use for machine-to-machine admin access
AuthClientScheme::Jwt {
    token: jwt_string,
}

// Client Certificate (mTLS) — PKCS#12 DER archive + password
AuthClientScheme::ClientCertificate {
    pkcs12_der: fs::read("client.p12")?,
    password: "pkcs12_password".to_string(),
}
```

> **Session cookie management:** After a successful `login()` call the session cookie is stored automatically in the client's built-in cookie jar and sent with all subsequent requests. You do not need to manage cookies manually.

---

## Session Validation

The most common operation: your API server receives a request with an `_ea_` cookie and needs to check whether the session is valid.

```rust
use auth_client::{AuthClient, AuthClientScheme, SessionData};

// Build a shared client at application startup
let auth = AuthClient::new(
    "https://auth.example.com",
    &fs::read_to_string("ca.cert.pem")?,
    AuthClientScheme::None,
)?;

// Later, in a request handler — extract session_id from the _ea_ cookie
let session_id = extract_session_id_from_cookie(&request);

let session: Option<SessionData> = auth.get_session(&session_id).await?;

match session {
    None => {
        // Session not found or expired — return 401
    }
    Some(data) => {
        println!("Authenticated: {} in realm {}", data.username, data.realm_id);
        // data.auth_scheme — "up" | "jwt" | "cc" | "f2" | "dc"
        // data.created_at  — Unix timestamp
    }
}
```

`get_session` maps to `GET /sessions/{session_id}`. It returns `None` — not an error — when the session is not found.

### `SessionData` fields

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | `String` | Unique session identifier (UUID) |
| `realm_id` | `String` | Realm the session belongs to |
| `username` | `String` | Authenticated client identity |
| `auth_scheme` | `String` | `"up"` / `"jwt"` / `"cc"` / `"f2"` / `"dc"` |
| `cookie_string` | `String` | Opaque value from the `_ea_` cookie |
| `max_age_seconds` | `i64` | Maximum absolute session lifetime |
| `max_stale_age_seconds` | `i64` | Idle timeout; any access resets this timer |
| `created_at` | `i64` | Unix timestamp of session creation |

---

## Session Actions — Log Out Everywhere

You can validate a session and perform a bulk logout in a single round-trip. This implements "keep this session, revoke all others" and "log out from every device" patterns.

```rust
use auth_client::{
    AuthClient, AuthClientScheme, AuthenticatedClientScheme, AuthScheme, SessionsAction,
};

let auth = AuthClient::new("https://auth.example.com", &ca_pem, AuthClientScheme::None)?;

let current_session_id = "550e8400-e29b-41d4-a716-446655440000";

// Validate the session AND revoke all other sessions for alice in one call
let session = auth.get_session_with_action(
    current_session_id,
    vec![AuthenticatedClientScheme {
        username: "alice".to_string(),
        auth_scheme: AuthScheme::UsernamePassword,
    }],
    SessionsAction::LogoutOtherSessions,
).await?;
```

| `SessionsAction` | Effect |
|------------------|--------|
| `LogoutOtherSessions` | Deletes all sessions for the given clients **except** the current one. |
| `LogoutAllSessions` | Deletes **all** sessions for the given clients including the current one. Session data is returned before deletion. |

### Look up session IDs across authentication schemes

```rust
use auth_client::{AuthenticatedClientScheme, AuthScheme};

let session_ids = auth.get_sessions_for_clients(
    "my-service",
    &[
        AuthenticatedClientScheme { username: "alice".to_string(), auth_scheme: AuthScheme::UsernamePassword },
        AuthenticatedClientScheme { username: "alice".to_string(), auth_scheme: AuthScheme::Jwt },
        AuthenticatedClientScheme { username: "alice".to_string(), auth_scheme: AuthScheme::ClientCertificate },
    ],
).await?;

// Revoke all found sessions
auth.delete_sessions(&session_ids).await?;
```

### Explicit logout

```rust
// Delete specific sessions
auth.delete_sessions(&[session_id.to_string()]).await?;

// Delete all sessions in a realm
auth.delete_sessions_for_realm("my-service").await?;

// Purge all globally expired sessions (maintenance)
auth.delete_expired_sessions().await?;
```

---

## Logging In

Admin operations require a logged-in session. The `login()` method stores the session cookie automatically.

```rust
use auth_client::{AuthClient, AuthClientScheme, AuthenticationNextStep};

let admin = AuthClient::new(
    "https://auth.example.com",
    &fs::read_to_string("ca.cert.pem")?,
    AuthClientScheme::UsernamePassword {
        username: "admin".to_string(),
        password: "s3cret".to_string(),
    },
)?;

let (result, _cookie) = admin.login("_", None, None).await?;

match result.next_step {
    AuthenticationNextStep::Authenticated => {
        println!("Logged in. Session: {}", result.session_id.unwrap());
    }
    AuthenticationNextStep::TotpRequired => {
        // Prompt for TOTP code then re-login:
        let code = prompt_for_totp_code();
        let (result2, _) = admin.login("_", None, Some(code)).await?;
        assert!(matches!(result2.next_step, AuthenticationNextStep::Authenticated));
    }
    AuthenticationNextStep::ChangePassword => {
        // Handle forced password change
    }
}
```

---

## Realm Management

Realm management requires super admin authentication.

```rust
use auth_client::{Realm, RealmAuthParams};

// List all realms
let realms: Vec<Realm> = admin.list_realms_as_super_admin().await?;

// Create a new realm with username/password authentication
let realm = Realm {
    id: "my-service".to_string(),
    auth_params: serde_json::from_str(r#"{
        "username_password_params": { "allow_expired_passwords": false }
    }"#)?,
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
};
admin.create_realm_as_super_admin(&realm).await?;

// Create a realm with JWT/OIDC authentication (e.g., Google Sign-In)
let jwt_realm = Realm {
    id: "google-login".to_string(),
    auth_params: serde_json::from_str(r#"{
        "jwt_params": {
            "idp_params": [{
                "jwt_issuer_uri": "https://accounts.google.com",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                "jwt_audience": "my-client-id.apps.googleusercontent.com"
            }]
        }
    }"#)?,
    session_max_age_seconds: 28800,
    session_max_stale_age_seconds: 3600,
};
admin.create_realm_as_super_admin(&jwt_realm).await?;

// Retrieve a realm
let r: Realm = admin.get_realm_as_super_admin("my-service").await?;

// Update a realm
admin.update_realm_as_super_admin("my-service", &r).await?;

// Delete a realm
admin.delete_realm_as_super_admin("my-service").await?;
```

---

## Admin Management

```rust
use auth_client::Admin;

// Create a realm admin (can manage "my-service" and "other-service")
let user = Admin {
    id: "bob".to_string(),
    realms: vec!["my-service".to_string(), "other-service".to_string()],
    userpass: Some("bob".to_string()),
    jwt: None,
    fido2: None,
    digital_credentials: None,
    client_certificate: None,
    totp_enabled: Some(false),
    totp_secret: None,
    totp_auth_url: None,
};
let created: Admin = admin.create_admin_as_super_admin(&user).await?;

// Check admin roles
assert!(created.can_administer_realm("my-service"));
assert!(!created.is_super_admin());

// List all users
let all: Vec<Admin> = admin.list_admins_as_super_admin().await?;

// Add / remove realm from user
admin.add_admin_to_realm("bob", "another-realm").await?;
admin.remove_admin_from_realm("bob", "another-realm").await?;

// Delete
admin.delete_admin_as_super_admin("bob").await?;
```

---

## Credential Management

Passwords are hashed with **Argon2id** server-side. Pass the plaintext password as a UTF-8 byte array. The server stores only the hash. When reading back a credential, the `password` field is always empty.

```rust
use auth_client::UserPass;

// Create credentials
admin.create_admin_credentials_in_realm(
    "my-service",
    &UserPass {
        realm: "my-service".to_string(),
        username: "alice".to_string(),
        password: b"hunter2".to_vec(),  // plaintext — server hashes with Argon2id
        change_password: false,
        roles: vec!["CryptoOfficer".to_string()],
    },
).await?;

// Read back — password is always empty
let stored: UserPass = admin.get_admin_credentials_in_realm("my-service", "alice").await?;
assert!(stored.password.is_empty());

// Force password change on next login
admin.update_admin_credentials_in_realm(
    "my-service",
    "alice",
    &UserPass {
        realm: "my-service".to_string(),
        username: "alice".to_string(),
        password: b"new-password".to_vec(),
        change_password: true,
        roles: vec!["CryptoOfficer".to_string()],
    },
).await?;

// List all credentials in a realm
let all: Vec<UserPass> = admin.list_admin_credentials_in_realm("my-service").await?;

// Delete
admin.delete_admin_credentials_in_realm("my-service", "alice").await?;
```

---

## TOTP Management

TOTP enrollment is a two-step process: generate a secret, show the QR code to the user, then verify one code to confirm enrollment.

```rust
use auth_client::TotpGenerateResponse;

// Step 1 — generate a TOTP secret (not stored yet)
let resp: TotpGenerateResponse = admin
    .generate_totp("my-service", "alice", Some("My App".to_string()))
    .await?;

println!("Secret: {}", resp.secret_base32);
println!("QR code URL: {}", resp.otpauth_url);
// Render resp.otpauth_url as a QR code and show it to the user

// Step 2 — user scans the QR code and provides the current code
let totp_code = prompt_user_for_code(); // e.g., "482913"

admin.verify_and_enable_totp(
    "my-service",
    "alice",
    &resp.secret_base32,
    &totp_code,
    Some("My App".to_string()),
).await?;
// TOTP is now active. Alice's next login will return `TotpRequired`.

// Disable TOTP
admin.disable_totp("my-service", "alice").await?;
```

---

## Machine Authentication (AppRole / Kubernetes / Token)

These methods are used by **machine clients** (SPIRE, CI pipelines, Kubernetes workloads). They do not use session cookies — they produce opaque app tokens (`X-Vault-Token`).

### AppRole provisioning (admin operations)

```rust
use auth_client::{AppRoleRequest, AppRoleSecretIdRequest};

// Create or update a role (requires admin session)
client.approle_create_role("spire-server", &AppRoleRequest {
    token_ttl: 3600,
    secret_id_ttl: 86400,
    token_policies: vec!["default".to_string()],
    bind_secret_id: true,
}).await?;

// Read the stable role_id to hand to the service
let role_id_resp = client.approle_get_role_id("spire-server").await?;
let role_id = role_id_resp.data.role_id;
println!("role_id: {role_id}");

// Generate a secret_id (single-use by default)
let secret_resp = client.approle_generate_secret_id("spire-server", &AppRoleSecretIdRequest {
    ttl: 0,
    num_uses: 1,
}).await?;
let secret_id = secret_resp.data.secret_id;
let accessor   = secret_resp.data.secret_id_accessor;
println!("secret_id: {secret_id}  accessor: {accessor}");

// Destroy a secret_id by accessor (without knowing its value)
client.approle_destroy_secret_id("spire-server", &accessor).await?;

// List all role names
let roles = client.approle_list_roles().await?;
println!("roles: {:?}", roles.data.keys);

// Delete a role (cascades to all its secret IDs)
client.approle_delete_role("spire-server").await?;
```

### AppRole login (client operation)

```rust
use auth_client::AppAuthResponse;

// Exchange role_id + secret_id for an app token
let auth: AppAuthResponse = client
    .approle_login(&role_id, Some(&secret_id))
    .await?;

let token = auth.auth.client_token;
println!("app token: {token}");
println!("renewable: {}, ttl: {}s", auth.auth.renewable, auth.auth.lease_duration);
```

### Kubernetes role provisioning (admin operations)

```rust
use auth_client::K8sRoleRequest;

// Create or update a Kubernetes role (requires admin session)
client.k8s_create_role("my-k8s-role", &K8sRoleRequest {
    jwks_url: "https://kubernetes.default.svc/.well-known/jwks.json".to_string(),
    bound_service_account_names: vec!["my-app".to_string()],
    bound_service_account_namespaces: vec!["production".to_string()],
    token_ttl: 3600,
    expected_issuer: None,
    bound_audiences: None,
}).await?;

// Delete a Kubernetes role
client.k8s_delete_role("my-k8s-role").await?;
```

### Kubernetes login (client operation)

```rust
// Read the projected service-account JWT from the pod filesystem
let jwt = std::fs::read_to_string(
    "/var/run/secrets/kubernetes.io/serviceaccount/token"
)?;

let auth = client.k8s_login("my-k8s-role", &jwt).await?;
let token = auth.auth.client_token;
```

### Token self-service

```rust
use auth_client::APP_TOKEN_HEADER;

// Validate a token and read its metadata
let lookup = client.token_lookup_self(&token).await?;
println!("entity: {}, ttl: {}s", lookup.data.entity_id, lookup.data.ttl);

// Renew a token (resets TTL to lease_duration)
let renewed = client.token_renew_self(&token).await?;
println!("new lease_duration: {}s", renewed.auth.lease_duration);

// Revoke a token immediately
client.token_revoke_self(&token).await?;

// The header constant, if you need to set it manually:
println!("Header name: {APP_TOKEN_HEADER}");  // "X-Vault-Token"
```

---

## Public Endpoints

```rust
// Server version — no authentication required
let version: String = client.get_version().await?;
println!("Auth server version: {}", version);

// Current session claims — requires a valid session cookie in the jar
use auth_client::ClientClaims;
let claims: ClientClaims = client.whoami("_").await?;
println!("Logged in as: {}", claims.registered.sub.as_deref().unwrap_or("unknown"));
```

---

## Error Handling

All methods return `AuthResult<T>`, which is `Result<T, AuthError>`.

```rust
use auth_client::AuthError;

match client.get_session("bad-id").await {
    Ok(None)    => { /* session not found — normal path */ }
    Ok(Some(s)) => { /* valid session */ }
    Err(AuthError::FailedHttpStatus(msg)) => eprintln!("Auth server error: {}", msg),
    Err(AuthError::SessionNotFound)       => eprintln!("Session not found"),
    Err(AuthError::Config(msg))           => eprintln!("Client config error: {}", msg),
    Err(AuthError::JWT(msg))              => eprintln!("JWT error: {}", msg),
    Err(e)                                => eprintln!("Unexpected error: {}", e),
}
```

| Variant | Meaning |
|---------|---------|
| `AuthError::FailedHttpStatus(msg)` | Non-2xx response; `msg` contains status code and body |
| `AuthError::SessionNotFound` | `GET /sessions/{id}` returned 404 |
| `AuthError::Config(msg)` | Client misconfiguration (bad URL, certificate parse error, etc.) |
| `AuthError::JWT(msg)` | JWT signing or validation failure |
| `AuthError::Generic(msg)` | Network or serialization error |

---

## Types Reference

### `AuthClientScheme`

```rust
pub enum AuthClientScheme {
    None,
    Jwt         { token: String },
    ClientCertificate { pkcs12_der: Vec<u8>, password: String },
    UsernamePassword  { username: String, password: String },
}
```

### `AuthScheme` (wire format in `AuthenticatedClientScheme`)

| Rust Variant | JSON value |
|---|---|
| `UsernamePassword` | `"up"` |
| `Jwt` | `"jwt"` |
| `ClientCertificate` | `"cc"` |
| `Fido2` | `"f2"` |
| `DigitalCredentials` | `"dc"` |

### `AuthenticationNextStep`

| Variant | Meaning |
|---------|---------|
| `Authenticated` | Login complete; session cookie issued |
| `TotpRequired` | Primary credentials accepted; re-submit with `totp_code` |
| `ChangePassword` | Password has expired; must be changed |

### `ClientClaims`

Returned by `whoami()`. The struct has three flattened sub-structs — the JWT is a
**flat JSON object** on the wire; the sub-struct boundaries exist only in Rust:

```rust
pub struct ClientClaims {
    pub registered:    RegisteredClaims,    // RFC 7519 §4.1
    pub authorization: AuthorizationClaims, // RFC 9068 §2.2.3.1
    pub private:       AuthPrivateClaims,   // Auth-specific
    pub extra:         HashMap<String, Value>,
}

pub struct RegisteredClaims {
    pub iss: Option<String>,      // Issuer
    pub sub: Option<String>,      // Subject (username)
    pub aud: Option<Vec<String>>, // Audience
    pub exp: Option<i64>,         // Expiry (Unix secs)
    pub nbf: Option<i64>,         // Not-before (Unix secs)
    pub iat: Option<i64>,         // Issued-at (Unix secs)
    pub jti: Option<String>,      // JWT ID
}

/// Authorization claims (RFC 9068 §2.2.3.1 / RFC 7643 §4.1.2).
pub struct AuthorizationClaims {
    // "roles" — RBAC roles assigned to the user at credential level.
    // Omitted when empty (fail-closed in OPA and downstream consumers).
    pub roles: Option<Vec<String>>,
}

pub struct AuthPrivateClaims {
    // "as_as" — auth scheme: "up" | "jwt" | "cc" | "f2" | "dc"
    pub auth_scheme: Option<AuthScheme>,
    // "as_pk" — client public key PEM (when using mTLS)
    pub public_key: Option<String>,
    // "as_rid" — realm ID (also used as the OPA domain scope)
    pub realm_id: Option<String>,
}
```

#### Reading roles from a validated session

```rust
let claims: ClientClaims = client.whoami("my-service").await?;

let roles = claims.authorization.roles.as_deref().unwrap_or(&[]);
if roles.contains(&"CryptoOfficer".to_string()) {
    // grant access to crypto operations
}
```

#### Wire format example

A token issued for a user with the `CryptoOfficer` role in realm `acme` looks like:

```json
{
  "sub": "alice",
  "exp": 1893456000,
  "iat": 1893452400,
  "roles": ["CryptoOfficer"],
  "as_as": "up",
  "as_rid": "acme"
}
```

The `roles` claim is absent (not `[]`) when the credential has no roles assigned,
so downstream OPA policies can treat absence as fail-closed without an explicit
empty-array check.

---

## Actix-web Integration Example

A complete pattern for an Actix-web API server that validates sessions via the Authentication Verifier.

```rust
use std::sync::Arc;
use actix_web::{web, HttpRequest, HttpResponse, middleware};
use auth_client::{AuthClient, AuthClientScheme, AuthError, SessionData};

/// Shared application state containing the auth client.
pub struct AppState {
    pub auth: Arc<AuthClient>,
}

/// Extract and validate the _ea_ session cookie.
async fn validate_session(
    state: &AppState,
    req: &HttpRequest,
) -> Result<SessionData, HttpResponse> {
    let cookie = req
        .cookie("_ea_")
        .ok_or_else(|| HttpResponse::Unauthorized().body("Missing _ea_ cookie"))?;

    state
        .auth
        .get_session(cookie.value())
        .await
        .map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?
        .ok_or_else(|| HttpResponse::Unauthorized().body("Session not found or expired"))
}

/// A protected endpoint.
async fn protected_handler(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> HttpResponse {
    let session = match validate_session(&state, &req).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Hello, {}!", session.username),
        "realm": session.realm_id,
    }))
}

/// Build the shared auth client at application startup.
pub fn build_auth_client(
    auth_verifier_url: &str,
    ca_cert_pem: &str,
) -> Arc<AuthClient> {
    Arc::new(
        AuthClient::new(auth_verifier_url, ca_cert_pem, AuthClientScheme::None)
            .expect("Failed to build auth client"),
    )
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use actix_web::{App, HttpServer};

    let ca_pem = std::fs::read_to_string("ca.cert.pem").unwrap();
    let auth = build_auth_client("https://auth.example.com", &ca_pem);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState { auth: auth.clone() }))
            .route("/api/resource", web::get().to(protected_handler))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```
