# STRIDE-A Analysis — Cosmian Authentication Verifier

## Analysis Matrix

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
|----|----------------------|-------------|-------------------|----------|----------|-----|--------|
| T-001 | `/sessions` scope | **Elevation of Privilege** | Unauthenticated session injection — attacker can create arbitrary sessions for any user identity | `auth_verifier.rs:394-403` — no auth middleware on sessions scope | 9.3 | CWE-862 | **Confirmed** |
| T-002 | `/sessions/{id}` GET | **Information Disclosure** | Unauthenticated session read — returns `cookie_string` (embedded JWT) for any valid session ID | `sessions_endpoints.rs:38-46`; `auth_verifier.rs:394-403` | 8.7 | CWE-862, CWE-284 | **Confirmed** |
| T-003 | CORS on all scopes | **Spoofing / Tampering** | `Cors::permissive()` on every scope including admin — any origin can make credentialed requests | `auth_verifier.rs:325,334,339,347,370,384,395,412,438,443,453,469` | 7.2 | CWE-942 | **Confirmed** |
| T-004 | Argon2 salt derivation | **Spoofing** | Salt derived deterministically from username (`SHA-256(username)`) — attacker can precompute targeted rainbow tables for known usernames | `passwords.rs:8-10` | 5.9 | CWE-916, CWE-760 | **Confirmed** |
| T-005 | `/login` endpoint | **Denial of Service** | No brute-force protection — unlimited credential attempts, no lockout, no rate limiting, no exponential backoff | `username_password.rs` — no attempt counter; `auth_verifier.rs:319-326` — no rate-limit middleware | 6.9 | CWE-307 | **Confirmed** |
| T-006 | `UsernamePasswordAuth` pass-through | **Spoofing** | When `ExtractRealm` injects no realm (realm not found in DB), middleware passes request through to the service without authentication, propagating to `EnsureAuth` with `auth_is_configured=true` | `username_password.rs:130-137`; however `EnsureAuth` with `auth_is_configured=true` then blocks | `username_password.rs:130-137` | 3.1 | CWE-287 | Confirmed — mitigated by EnsureAuth in production config |
| T-007 | `no_jwt_validation` feature | **Spoofing** | Feature flag that disables all JWT signature and expiry validation — any crafted JWT accepted | `client_claim.rs:2-7, 105-107` | 9.1 | CWE-345 | Confirmed — currently only triggered by opt-in compile flag; no guard prevents accidental production use |
| T-008 | Kubernetes JWKS fetch | **Spoofing / SSRF** | K8s login fetches an attacker-controlled JWKS URL over HTTPS — partial SSRF to HTTPS-capable internal services; no private-IP exclusion | `kubernetes.rs:72-79, 318-341` | 5.3 | CWE-918, CWE-441 | **Confirmed** |
| T-009 | `dev_seed` plaintext credentials | **Information Disclosure** | `DevSeedParams.admin_password` stored as plain text in TOML config file | `server_params.rs:63-68`; `auth_verifier.dev.toml` | 4.0 | CWE-312 | Confirmed — dev-only config; severity depends on file storage security |
| T-010 | Session ID derivation | **Spoofing** | `session_id = SHA256(JWT cookie value)` — deterministic; party possessing the JWT can compute the session ID and enumerate the `/sessions/{id}` endpoint | `cookies.rs:12-17` | 5.3 | CWE-330 | Confirmed — exploitable only because of T-002 |
| T-011 | `EnsureAuth` default_username | **Elevation of Privilege** | When `auth_is_configured=false` AND `default_username` set, all requests unauthenticated are granted access as the default user without any credential check | `ensure_auth.rs:144-152` | 8.2 | CWE-285 | Confirmed — only exploitable when misconfigured (not in default prod config) |
| T-012 | `audit log` absence | **Repudiation** | No structured audit trail for authentication events (successful login, failed login, AppRole token issuance, admin operations) — only operational `info!`/`debug!` logs | Search across `server/src/server/endpoints/` — only `cosmian_logger::info!` calls, no structured audit sink | 4.0 | CWE-778 | **Confirmed** |
| T-013 | `Secure` cookie over plain HTTP dev | **Information Disclosure** | In dev mode (no TLS), `build_cookie()` always sets `Secure=true`. Browsers will refuse to send the cookie back. Test suites pass because `reqwest` ignores the `Secure` flag. Real users cannot authenticate in plain-HTTP dev deployments. | `cookies.rs:22`; `auth_verifier.rs:247,263,270` (plain HTTP path) | 2.0 | CWE-614 | Confirmed — functional gap in dev mode, not a production vulnerability |
| T-014 | Secret ID SHA-256 hash strength | **Spoofing** | Secret IDs are SHA-256-hashed for storage — acceptable, but collision-resistance only; unlike passwords, no KDF (Argon2) is used. Secret IDs are random UUIDs (128-bit entropy), so brute force is infeasible. | `approle.rs:68-72`; `passwords.rs` not used here | 1.5 | CWE-916 | No evidence of exploit — UUID entropy is sufficient for SHA-256; no finding raised |
| T-015 | `PayloadConfig` 1 MB limit | **Denial of Service** | Payload capped at 1 MB; attacker could spray 1 MB requests at unauthenticated endpoints (`/auth/approle/login`, `/auth/kubernetes/login`) | `auth_verifier.rs:307-308` | 4.3 | CWE-400 | Confirmed — 1 MB limit present; no per-IP rate limit |

---

## Threat Narratives (CRITICAL and HIGH)

### T-001: Unauthenticated Session Injection via `/sessions` API

**Attack scenario**:
1. Attacker sends `POST /sessions` to auth-verifier with arbitrary `session_id`, `realm`, `authenticated_client` (`username: "admin"`, `auth_scheme: "UsernamePassword"`), and a crafted `session_value` (cookie string containing a self-signed JWT).
2. The session is stored in the session store associated with the attacker-chosen session ID.
3. The attacker crafts a cookie `_ea_=<forged_JWT>` and sends it to the KMS.
4. The KMS calls the auth-verifier's `POST /sessions/{session_id}` with the session ID derived from `SHA256(forged_JWT)` — this matches the injected record.
5. The KMS trusts the session and treats the request as authenticated with `username=admin`.

**Pre-conditions**: Network access to auth-verifier's HTTP port. Knowledge of the expected JWT structure (obtainable by inspecting any valid JWT issued by the server, or from the JWKS endpoint).

**Impact**: Full authentication bypass — attacker can impersonate any user including admin, gaining access to all KMS operations including key export, deletion, and grant.

**Evidence**:
```rust
// auth_verifier.rs:394-403 — /sessions scope: only Cors::permissive() + ExtractRealm, NO auth
let sessions_scope = web::scope("/sessions")
    .wrap(Cors::permissive())
    .wrap(ExtractRealm::new(database.clone()))
    .service(upsert_session)      // ← unauthenticated POST to create sessions
    .service(get_session_by_id)   // ← unauthenticated GET to read sessions
    .service(get_session)
    .service(get_sessions_for_clients)
    .service(delete_sessions)
    .service(delete_expired_sessions)
    .service(delete_sessions_for_realm);
```

**Mitigations present**: None in application code. Relies entirely on network isolation.

**Gaps**: No `CookieAuthSameServer`, `AdminAuth`, or any token-based middleware on the `/sessions` scope. No IP allowlist. The service is meant to be called by the KMS, but any network-reachable client can call it.

---

### T-002: Unauthenticated Session Read — JWT Token Exfiltration

**Attack scenario**:
1. Attacker learns or guesses a session ID (e.g., by observing `SHA256(cookie_value)` when sniffing plain HTTP traffic in dev mode, or by brute-forcing valid UUIDs in the session table).
2. Attacker calls `GET /sessions/{session_id}`.
3. Response includes the full `session_data` struct which contains `cookie_string` — the raw `_ea_=<JWT>` cookie with the signed JWT token.
4. Attacker uses the JWT directly to authenticate to KMS.

**Pre-conditions**: Network access to auth-verifier + ability to obtain or derive a valid session ID.

**Impact**: Session hijacking without needing a victim's password.

**Evidence**:
```rust
// sessions_endpoints.rs:38-46
#[get("/{session_id}")]
pub async fn get_session_by_id(
    session_id: Path<String>,
    session_store: Data<Arc<dyn session::SessionStore>>,
) -> Result<HttpResponse, AuthError> {
    let session_id = session_id.into_inner();
    let session_data = session_store.get_session(&session_id).await?;
    Ok(HttpResponse::Ok().json(session_data)) // ← returns cookie_string (raw JWT)
}
```

---

### T-003: Permissive CORS on All Scopes (Including Admin)

**Attack scenario**:
1. A victim admin logs into the auth-verifier admin UI from their browser (obtaining a valid `_ea_` admin session cookie).
2. Attacker tricks the victim into visiting `https://attacker.example.com` which contains JavaScript that makes credentialed requests to the auth-verifier (using `credentials: 'include'`).
3. Because `Cors::permissive()` allows all origins, the attacker's origin is accepted, and the browser sends the admin cookie along.
4. Attacker JavaScript can create realms, users, and admin accounts, or read admin data.

**Pre-conditions**: Admin user visits attacker-controlled page while having an active admin session.

**Impact**: Full admin account takeover; realm manipulation; new backdoor accounts.

**Evidence**: `auth_verifier.rs:325, 370, 384, 395, 412` — every scope including `/admins/realms`, `/admins`, `/realms`, `/sessions` uses `Cors::permissive()`. There is a TODO comment at line 324: `// TODO : Remove permissive CORS and replace with more restrictive configuration if needed`.

---

### T-007: `no_jwt_validation` Feature — Complete JWT Bypass

**Attack scenario**:
1. A production binary is accidentally compiled with `--features no_jwt_validation` (e.g., a CI pipeline passes feature flags incorrectly, or a developer tests with this flag and ships the binary).
2. Any client presenting any Bearer token (even a hand-crafted unsigned one) is accepted as authenticated.
3. Attacker constructs `{"alg":"none","typ":"JWT"}.{"sub":"admin","realm_id":"_","exp":9999999999}.` (unsigned JWT) and sends it in the Authorization header.
4. The server accepts it as a valid JWT for `admin` in realm `_`.

**Pre-conditions**: Binary compiled with `no_jwt_validation` feature (not the default).

**Impact**: Full authentication bypass for any JWT-protected scope.

**Evidence**:
```rust
// client_claim.rs:105-107
#[cfg(feature = "no_jwt_validation")]
let token_data = insecure_decode::<ClientClaims>(token)
    .map_err(|err| AuthError::JWT(format!("Cannot insecurely decode token: {err:?}")))?;
```

**Mitigations present**: Feature is not in `default` features. Comment says "only useful for tests." Cargo.toml reads: `# no_jwt_validation: only useful for tests, do not enable in production`.

**Gaps**: No compile-time `cfg!(debug_assertions)` guard or `panic!` to prevent production use. No CI check that the release binary was not compiled with this feature.

---

### T-011: EnsureAuth Default Username Bypass

**Attack scenario**:
1. Auth-verifier is deployed with `default_username = "admin"` in config (e.g., for testing).
2. No other auth method is configured (`auth_is_configured = false`).
3. Any unauthenticated request is injected with `AuthenticatedClientScheme { username: "admin", auth_scheme: UsernamePassword }`.
4. Attacker without any credentials is treated as the admin user.

**Pre-conditions**: Server deployed with `default_username` set and no auth methods configured.

**Impact**: Complete authentication bypass — all requests treated as the default user.

**Evidence**:
```rust
// ensure_auth.rs:144-152
if let Some(ref username) = self.default_username {
    req.extensions_mut().insert(AuthenticatedClientScheme {
        username: username.clone(),
        auth_scheme: AuthScheme::UsernamePassword,
    });
}
// No Unauthorized returned — request continues
```

**Mitigations present**: In the standard production flow, `auth_is_configured = true` causes EnsureAuth to return 401. This bypass only occurs if someone explicitly sets `default_username` without configuring any auth method.
