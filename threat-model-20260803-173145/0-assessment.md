# Threat Model Assessment — Cosmian Authentication Verifier

**Date**: 2026-08-03
**Scope**: `authentication/` git submodule — server crate, client crate, middleware stack, session management
**Overall Risk Posture**: 🔴 **CRITICAL**
**Commit**: HEAD of `spire` branch

---

## Comparison with Prior Analysis

_First analysis for this component — no baseline to compare._

---

## Key Findings

1. **🔴 The `/sessions` API is unauthenticated** — any network client can inject arbitrary sessions, fabricating identities including `admin`. This is the most severe finding and directly enables full authentication bypass on the Cosmian KMS.

2. **🔴 Session JWT tokens are readable by unauthenticated clients** — `GET /sessions/{id}` returns the raw signed JWT cookie string without any credential check, enabling session hijacking for anyone who can derive or guess a session ID.

3. **🟠 CORS is permissive on all scopes** — including admin endpoints (`/admins/realms`, `/admins`), enabling cross-origin attacks when an admin visits an attacker-controlled page.

4. **🟠 `no_jwt_validation` compile flag has no production guard** — if accidentally enabled, all JWT verification is skipped. A `compile_error!` guard is needed.

5. **🟡 Argon2 salt is deterministic** — derived from `SHA-256(username)` rather than a random value, enabling targeted precomputation for known usernames.

---

## Risk Summary

| Category | Risk Level | Notes |
|----------|------------|-------|
| Authentication — Session API | 🔴 CRITICAL | `/sessions` scope completely unauthenticated |
| Authentication — Login endpoint | 🟡 MEDIUM | No brute-force protection; Argon2 with predictable salt |
| JWT security | 🟠 HIGH | `no_jwt_validation` flag exists without production guard |
| CORS policy | 🟠 HIGH | Permissive on all scopes; admin API exploitable via CSRF |
| Kubernetes JWKS SSRF | 🟡 MEDIUM | HTTPS-only but no private-IP restriction |
| Audit / Repudiation | 🟡 MEDIUM | No structured audit log; free-form `info!` only |
| Cryptographic (password hashing) | 🟡 MEDIUM | Argon2id used (good) but deterministic salt (bad) |
| Secret management | 🔵 LOW | Dev seed credentials in plaintext TOML |
| Dependency supply chain | ⚪ INFO | Not analyzed (out of scope for this run) |

---

## Recommended Actions (Priority Order)

1. **[IMMEDIATE — CRITICAL]** Add authentication to the `/sessions` scope (F-001, F-002).
   Either share a static server-to-server token (quick win) or enforce mTLS between KMS and auth-verifier. Without this fix, the entire authentication chain is bypassable by any network-adjacent attacker.

2. **[URGENT — HIGH]** Add a `compile_error!` guard to the `no_jwt_validation` feature so it cannot be compiled outside test builds (F-004).
   ```rust
   #[cfg(all(feature = "no_jwt_validation", not(test)))]
   compile_error!("no_jwt_validation must only be used in tests");
   ```

3. **[HIGH]** Replace `Cors::permissive()` with an origin allowlist on admin-facing scopes (F-003). At minimum, use `Cors::default()` on `/admins/*` and `/sessions` endpoints.

4. **[MEDIUM]** Fix Argon2 salt to use `SaltString::generate(&mut OsRng)` instead of `SHA-256(username)` (F-005). Plan a migration strategy for existing hashes.

5. **[MEDIUM]** Add rate limiting to the `/login` endpoint — 5 attempts/IP/minute is a reasonable starting point using the `governor` crate already in the workspace (F-006).

6. **[MEDIUM]** Introduce a structured audit event type for login success/failure and token issuance; emit to a dedicated audit log channel (F-008).

7. **[MEDIUM]** Add private-IP blocking to Kubernetes JWKS URL validation to prevent SSRF to internal services (F-007).

8. **[LOW]** Emit a loud startup warning when `default_username` is configured, to prevent accidental exposure (F-011).

9. **[LOW]** Accept dev seed credentials from environment variables rather than plaintext TOML fields (F-009).

---

## Scope Limitations

- **Dependency vulnerability scan** (cargo-audit) was not run. Known CVEs in transitive dependencies are not covered.
- **Database SQL injection** was examined at the code level; no raw SQL string formatting was found. Full SQL injection audit against the ORM/query layer (SQLx, diesel, etc.) is out of scope.
- **Admin UI** (`admin-ui/`) was not analyzed — it is a separate frontend application.
- **Network topology** is unknown. If auth-verifier is deployed behind a firewall that restricts `/sessions` to KMS-only traffic, F-001/F-002 severity is reduced from CRITICAL to HIGH.
- **mTLS peer certificate handling** (`tls/openssl_config.rs`, `tls/rustls_config.rs`) was not deeply audited.
- **Redis session backend** (`session/impls/redis.rs`) was not analyzed for session fixation or key collision.
- **TOTP implementation** (`totp.rs`) was not audited against RFC 6238 timing attack requirements.

---

## Finding Quick Reference

| ID | Severity | Title | File |
|----|----------|-------|------|
| F-001 | 🔴 CRITICAL | Unauthenticated Session Injection | `server/auth_verifier.rs:394-403` |
| F-002 | 🔴 CRITICAL | Unauthenticated Session JWT Read | `sessions_endpoints.rs:38-46` |
| F-003 | 🟠 HIGH | Permissive CORS on All Scopes | `auth_verifier.rs:325+` |
| F-004 | 🟠 HIGH | `no_jwt_validation` Lacks Production Guard | `client_claim.rs:105-107` |
| F-005 | 🟡 MEDIUM | Deterministic Argon2 Salt | `passwords.rs:8-10` |
| F-006 | 🟡 MEDIUM | No Brute-Force Protection on `/login` | `auth_verifier.rs:319-326` |
| F-007 | 🟡 MEDIUM | SSRF via Kubernetes JWKS URL | `kubernetes.rs:72-79` |
| F-008 | 🟡 MEDIUM | No Structured Audit Log | `client_endpoints.rs` |
| F-009 | 🔵 LOW | Plaintext Dev Credentials in Config | `server_params.rs:63-68` |
| F-010 | 🔵 LOW | `Secure` Cookie in Plain-HTTP Mode | `cookies.rs:22` |
| F-011 | ⚪ INFO | `EnsureAuth` Default-Username Bypass | `ensure_auth.rs:144-152` |

---

*Generated by AI Threat Model Analyst. All findings require human review before remediation.*
