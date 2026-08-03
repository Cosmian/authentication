# Security Findings — Cosmian Authentication Verifier

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 4 |
| 🔵 LOW | 2 |
| ⚪ INFO | 1 |

---

## Finding Cards

### [F-001] 🔴 CRITICAL — Unauthenticated Session Injection

| Field | Value |
|-------|-------|
| **STRIDE** | Elevation of Privilege |
| **CWE** | CWE-862: Missing Authorization |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 9.3 — AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N |
| **Component** | `/sessions` scope |
| **File** | `server/src/server/auth_verifier.rs:394-403`, `server/src/server/endpoints/sessions_endpoints.rs:17-34` |

**Description**

The `/sessions` scope is mounted with no authentication middleware. Any network-reachable client can call `POST /sessions` to create a session record for an arbitrary user identity, or call `DELETE /sessions` to invalidate all sessions (DoS). The endpoint is designed as an internal server-to-server API (KMS → auth-verifier), but there is no enforcement of this assumption at the application layer.

**Evidence**

```rust
// auth_verifier.rs:394-403
let sessions_scope = web::scope("/sessions")
    .wrap(Cors::permissive())
    .wrap(ExtractRealm::new(database.clone()))
    // ← No CookieAuthSameServer, AdminAuth, or AppTokenExtract here
    .service(upsert_session)
    .service(get_session_by_id)
    .service(get_session)
    .service(get_sessions_for_clients)
    .service(delete_sessions)
    .service(delete_expired_sessions)
    .service(delete_sessions_for_realm);

// sessions_endpoints.rs:17-34 — upsert accepts any JSON payload
pub async fn upsert_session(
    payload: Json<UpsertSessionRequest>,
    session_store: Data<Arc<dyn session::SessionStore>>,
) -> Result<HttpResponse, AuthError> {
    session_store.upsert_session(&payload.session_id, &payload.realm,
        &payload.authenticated_client, &payload.session_value).await?;
    Ok(HttpResponse::NoContent().finish())
}
```

#### Attack Scenario

1. Attacker constructs a self-signed ES256 JWT using a locally generated P-256 key pair:
   `{"sub":"admin","realm_id":"_","auth_scheme":"UsernamePassword","exp":9999999999}`
2. Attacker computes `session_id = hex(SHA256(JWT))` (same as `session_id_from_cookie_value` in `cookies.rs:12-17`).
3. Attacker calls `POST http://<auth-verifier>/sessions` with the fabricated session record (no auth required).
4. Attacker crafts a cookie `_ea_=<forged_JWT>` and sends it to the KMS in a request.
5. The KMS validates the session against auth-verifier: `POST /sessions/{session_id}` returns the injected record.
6. The KMS trusts the session and executes the request as `admin`.

**Proposed Fix** (review before applying)

Add an authentication mechanism to the `/sessions` scope. Two options:

**Option A — Shared secret (simplest):**
```rust
// Add a static bearer token that KMS and auth-verifier share
let sessions_scope = web::scope("/sessions")
    .wrap(AppTokenExtract::new(database.clone()))  // ← requires X-Vault-Token
    .wrap(Cors::permissive())
    // ...
```

**Option B — mTLS (strongest):** require mutual TLS for the KMS→auth-verifier channel, and verify the peer certificate on the `/sessions` scope.

**Option C — IP allowlist (defense-in-depth, not sufficient alone):** configure a reverse proxy (nginx, Envoy) to restrict `/sessions` to the KMS's IP range.

---

### [F-002] 🔴 CRITICAL — Unauthenticated Session JWT Read

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-862: Missing Authorization; CWE-284: Improper Access Control |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 8.7 — AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N |
| **Component** | `GET /sessions/{session_id}` |
| **File** | `server/src/server/endpoints/sessions_endpoints.rs:38-46` |

**Description**

The `GET /sessions/{session_id}` endpoint returns the full session record, which includes `cookie_string` — the raw `_ea_=<JWT>` Set-Cookie value stored at login time. An attacker who learns a valid session ID can retrieve the JWT and use it to authenticate to any relying party (KMS) that trusts auth-verifier-issued tokens. Session IDs are deterministically derived from the JWT value (`SHA256(cookie_value)`), so an attacker who intercepts a cookie in transit (plain HTTP dev mode) can immediately derive the session ID.

**Evidence**

```rust
// sessions_endpoints.rs:38-46
#[get("/{session_id}")]
pub async fn get_session_by_id(
    session_id: Path<String>,
    session_store: Data<Arc<dyn session::SessionStore>>,
) -> Result<HttpResponse, AuthError> {
    let session_id = session_id.into_inner();
    let session_data = session_store.get_session(&session_id).await?;
    Ok(HttpResponse::Ok().json(session_data))  // ← returns cookie_string (raw signed JWT)
}
```

**Proposed Fix** (review before applying)

Apply the same authentication fix as F-001 (shared secret or mTLS). Additionally, consider stripping `cookie_string` from the response object, returning only the `authenticated_client` and `realm_id` fields needed by the KMS.

---

### [F-003] 🟠 HIGH — Permissive CORS on All Scopes Including Admin

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing |
| **CWE** | CWE-942: Permissive Cross-domain Policy with Untrusted Domains |
| **OWASP** | A05:2025 — Security Misconfiguration |
| **CVSS 4.0** | 7.2 — AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N |
| **Component** | All HTTP scopes in `build_app()` |
| **File** | `server/src/server/auth_verifier.rs:325,334,339,347,370,384,395,412,438,443,453,469` |

**Description**

Every route scope including the admin CRUD endpoints (`/admins/realms`, `/admins`, `/realms`) uses `Cors::permissive()`, which responds to any `Origin` with `Access-Control-Allow-Origin: *` and accepts all methods and headers. Combined with `SameSite=Strict` cookies, cross-origin state-changing requests from browser-based attackers are partially mitigated — a `SameSite=Strict` cookie would not be sent from a cross-site context. However:

1. If the auth-verifier is ever deployed on the same origin as the admin UI (same domain), `SameSite=Strict` provides no protection.
2. The permissive policy allows unauthenticated cross-origin reads of the JWKS, version, and roles endpoints, which expands the attack surface for reconnaissance.
3. A TODO comment in the source acknowledges this is a known issue: `// TODO : Remove permissive CORS and replace with more restrictive configuration if needed`.

**Proposed Fix** (review before applying)

```rust
// Replace Cors::permissive() with an explicit allowlist
// Set once at the App level or per-scope
let cors = Cors::default()
    .allowed_origin(&server_params.admin_ui_origin)  // specific UI origin
    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
    .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
    .max_age(3600);
```

For the `/sessions` internal API, CORS should be disabled entirely (it's a server-to-server endpoint).

---

### [F-004] 🟠 HIGH — `no_jwt_validation` Feature Disables All JWT Security

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing |
| **CWE** | CWE-345: Insufficient Verification of Data Authenticity |
| **OWASP** | A07:2025 — Identification and Authentication Failures |
| **CVSS 4.0** | 9.1 (if enabled) — AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N |
| **Component** | JWT authentication middleware |
| **File** | `server/src/middleware/jwt/client_claim.rs:2-7, 85-108` |

**Description**

The `no_jwt_validation` Cargo feature replaces `jsonwebtoken::decode` with `jsonwebtoken::dangerous::insecure_decode`, which skips all signature, expiry, issuer, and audience checks. Any token header+payload combination is accepted. There is no compile-time assertion or runtime panic guard to prevent shipping this feature in a production binary.

**Evidence**

```rust
#[cfg(feature = "no_jwt_validation")]
use jsonwebtoken::dangerous::insecure_decode;

// ...in decode_bearer_header():
#[cfg(feature = "no_jwt_validation")]
let token_data = insecure_decode::<ClientClaims>(token)
    .map_err(|err| AuthError::JWT(format!("Cannot insecurely decode token: {err:?}")))?;
```

**Proposed Fix** (review before applying)

Add a compile-time guard that prevents production builds from enabling this feature:

```rust
// In client_claim.rs or lib.rs
#[cfg(all(feature = "no_jwt_validation", not(test)))]
compile_error!("`no_jwt_validation` must only be enabled in test builds; \
                never use in production");
```

Or in `Cargo.toml`:
```toml
# Prevent accidental production builds
[features]
no_jwt_validation = []  # Only valid in [dev-dependencies] test contexts
```

---

### [F-005] 🟡 MEDIUM — Deterministic Argon2 Salt Derived from Username

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing |
| **CWE** | CWE-760: Use of a One-Way Hash with a Predictable Salt; CWE-916: Use of Password Hash with Insufficient Computational Effort |
| **OWASP** | A02:2025 — Cryptographic Failures |
| **CVSS 4.0** | 5.9 — AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N |
| **Component** | Password hasher |
| **File** | `server/src/database/passwords.rs:8-10` |

**Description**

The Argon2 salt is `SHA-256(username)`, making it fully predictable for any attacker who knows the username. Argon2's salt is meant to be random and unpredictable to prevent targeted precomputation attacks. With a predictable salt, an attacker who knows a target username (`admin`) can pre-hash common passwords against the known salt offline before obtaining the hash from the database, reducing the effective KDF cost.

**Evidence**

```rust
// passwords.rs:8-10
pub fn hash_password_with_argon2(username: &str, password: &str) -> AuthResult<Vec<u8>> {
    let hash = sha2::Sha256::digest(username.as_bytes());
    let salt = SaltString::b64_encode(hash.as_ref())  // deterministic: SHA256(username)
        .map_err(...)?;
    let argon2 = Argon2::default();
    // Argon2id v19 — good KDF, but salt predictability undermines it
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)...
```

**Proposed Fix** (review before applying)

Use a random salt, which is Argon2's default behavior when using `SaltString::generate()`:
```rust
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;

pub fn hash_password_with_argon2(password: &str) -> AuthResult<Vec<u8>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string().into_bytes())
}
```

Note: migration of existing hashes will require a re-hash on next successful login.

---

### [F-006] 🟡 MEDIUM — No Brute-Force Protection on `/login` Endpoint

| Field | Value |
|-------|-------|
| **STRIDE** | Denial of Service / Spoofing |
| **CWE** | CWE-307: Improper Restriction of Excessive Authentication Attempts |
| **OWASP** | A07:2025 — Identification and Authentication Failures |
| **CVSS 4.0** | 6.9 — AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N |
| **Component** | `/login` scope |
| **File** | `server/src/server/auth_verifier.rs:319-326`; `server/src/middleware/username_password.rs` |

**Description**

The `/login` endpoint accepts unlimited credential attempts. There is no per-IP rate limiting, no per-account lockout after N failed attempts, and no exponential backoff. An attacker can perform online brute-force attacks against user accounts at full server speed, limited only by Argon2's cost. Argon2's default parameters (memory=19456 KiB, iterations=2) provide roughly 1-10 ms/attempt on a single server core — an attacker with a botnet can sustain thousands of attempts per second.

**Proposed Fix** (review before applying)

Add a rate-limiting middleware using the `governor` crate (already in workspace dependencies):

```rust
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;

// 5 attempts per IP per 60 seconds
let quota = Quota::per_minute(NonZeroU32::new(5).unwrap());
let limiter = RateLimiter::keyed(quota);

let client_scope = web::scope("/login")
    .wrap(RateLimitMiddleware::new(limiter))
    .wrap(EnsureAuth::new(true, default_username.as_deref()))
    // ...
```

---

### [F-007] 🟡 MEDIUM — SSRF via Kubernetes JWKS URL Fetch

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing / Tampering |
| **CWE** | CWE-918: Server-Side Request Forgery (SSRF) |
| **OWASP** | A10:2025 — Server-Side Request Forgery |
| **CVSS 4.0** | 5.3 — AV:N/AC:H/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N |
| **Component** | Kubernetes auth login |
| **File** | `server/src/server/endpoints/kubernetes.rs:72-79, 318-341` |

**Description**

When an admin creates a Kubernetes auth role (`POST /auth/kubernetes/role/{name}`), they provide a `jwks_url`. The code validates that the URL starts with `https://` but does not restrict private IP ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`, `127.x.x.x`). A malicious admin (or a compromised admin account) can create a role pointing to an internal service, causing the auth-verifier to make HTTPS requests to internal infrastructure.

**Evidence**:

```rust
// kubernetes.rs:173-177
if !payload.jwks_url.starts_with("https://") {
    return Err(AuthError::BadRequest("jwks_url must use the https:// scheme".to_string()));
}
// No private-IP check follows
```

**Proposed Fix** (review before applying)

Parse the URL and reject private IP ranges:

```rust
use std::net::IpAddr;
fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}
// Resolve hostname and reject if private
```

---

### [F-008] 🟡 MEDIUM — No Structured Audit Log for Authentication Events

| Field | Value |
|-------|-------|
| **STRIDE** | Repudiation |
| **CWE** | CWE-778: Insufficient Logging; CWE-223: Omission of Security-relevant Information |
| **OWASP** | A09:2025 — Security Logging and Monitoring Failures |
| **CVSS 4.0** | 4.0 — AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N |
| **Component** | All authentication endpoints |
| **File** | `server/src/server/endpoints/client_endpoints.rs`; `server/src/server/endpoints/approle.rs` |

**Description**

Authentication events (successful login, failed login, AppRole token issuance, admin account creation, realm creation) emit only `info!`/`debug!` log lines via `cosmian_logger`, with no machine-parseable structured format, no persistent audit sink, and no tamper protection. In a security incident, it is impossible to reliably reconstruct which accounts were accessed, from which IPs, and when. The `info!` calls use free-form strings without consistent field names.

**Proposed Fix** (review before applying)

Introduce a structured audit event type and emit it to a separate audit log channel:

```rust
#[derive(Serialize)]
struct AuditEvent {
    timestamp: DateTime<Utc>,
    event_type: &'static str,   // "login_success", "login_failure", "token_issued"
    realm_id: String,
    subject: String,
    remote_addr: Option<String>,
    auth_scheme: String,
}
// Emit to a dedicated audit logger (file, syslog, OpenTelemetry)
```

---

### [F-009] 🔵 LOW — Plaintext Dev Credentials in TOML Config

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure |
| **CWE** | CWE-312: Cleartext Storage of Sensitive Information |
| **OWASP** | A02:2025 — Cryptographic Failures |
| **CVSS 4.0** | 4.0 — AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N |
| **Component** | `DevSeedParams` |
| **File** | `server/src/server/parameters/server_params.rs:59-74` |

**Description**

The `[dev_seed]` TOML configuration block stores `admin_password` and optionally `totp_password` in plaintext. If `auth_verifier.dev.toml` is accidentally committed to a public repository, embedded in a container image, or included in logs, credentials are immediately exposed.

**Proposed Fix** (review before applying)

Accept the password as an environment variable reference:
```toml
[dev_seed]
admin_password_env = "AUTH_ADMIN_PASSWORD"  # reads from env var at startup
```

---

### [F-010] 🔵 LOW — `Secure` Cookie Always Set, Including in Plain-HTTP Dev Mode

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure (indirect) |
| **CWE** | CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute (inverse: `Secure` flag set on HTTP) |
| **OWASP** | A05:2025 — Security Misconfiguration |
| **CVSS 4.0** | 2.0 — AV:L/AC:H/AT:N/PR:L/UI:A/VC:N/VI:N/VA:L |
| **Component** | Cookie construction |
| **File** | `server/src/session/cookies.rs:22` |

**Description**

`build_cookie()` unconditionally sets `Secure=true`. When the auth-verifier runs in plain-HTTP dev mode (no TLS), browsers correctly refuse to send the `_ea_` cookie back on subsequent requests, silently breaking the login flow for browser users. The issue is masked in automated tests because `reqwest` does not enforce the `Secure` attribute on non-HTTPS connections.

**Proposed Fix** (review before applying)

Pass TLS-awareness to `build_cookie()`:
```rust
pub fn build_cookie(value: &str, max_age_seconds: i64, is_https: bool) -> Result<Cookie<'static>, AuthError> {
    cookie.set_secure(is_https);
    // ...
}
```

---

### [F-011] ⚪ INFO — `EnsureAuth` Allows Unauthenticated Access with `default_username`

| Field | Value |
|-------|-------|
| **STRIDE** | Elevation of Privilege |
| **CWE** | CWE-285: Improper Authorization |
| **OWASP** | A01:2025 — Broken Access Control |
| **CVSS 4.0** | 8.2 (if misconfigured) |
| **Component** | EnsureAuth middleware |
| **File** | `server/src/middleware/ensure_auth.rs:144-152` |

**Description**

If `default_username` is set and `auth_is_configured = false`, all requests receive that username as identity without credentials. This is an intentional dev shortcut, but there is no documentation warning against using this in internet-reachable deployments. A misconfigured production server could grant any client admin-level access. This is classified INFO because the standard production config (`auth_is_configured = true`) prevents this path entirely.

**Proposed Fix** (review before applying)

Emit a startup warning when `default_username` is configured:
```rust
if server_params.default_username.is_some() {
    warn!("⚠ default_username is set — all unauthenticated requests \
           will be granted access as '{}'. \
           Do NOT use in production.", default_username);
}
```
