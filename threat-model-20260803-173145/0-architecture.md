# Architecture Overview — Cosmian Authentication Verifier

**Analysis date**: 2026-08-03
**Scope**: `authentication/` git submodule (server crate + client crate)
**Analyst**: AI Threat Model Analyst

---

## System Description

The Cosmian Authentication Verifier (`auth_verifier`) is a standalone HTTP/HTTPS service that authenticates users and machines for downstream services (primarily the Cosmian KMS). It issues short-lived JWT session tokens stored as `SameSite=Strict; Secure; HttpOnly` cookies, validates credentials against a relational database (SQLite / PostgreSQL / MySQL), and exposes a JWKS endpoint so relying parties can verify issued tokens. It also acts as a Vault-compatible AppRole and Kubernetes JWT authentication gateway for machine-to-machine workloads (e.g., SPIRE).

---

## Component Inventory

| Component | Location | Purpose | Trust Level |
|-----------|----------|---------|-------------|
| Actix-web HTTP/TLS layer | `server/src/server/auth_verifier.rs` | HTTP binding (plain or TLS), request routing | Untrusted boundary |
| ExtractRealm middleware | `server/src/middleware/extract_realm.rs` | Looks up realm from DB, injects into extensions | Semi-trusted |
| UsernamePasswordAuth middleware | `server/src/middleware/username_password.rs` | HTTP Basic Auth credential validation | Semi-trusted |
| JwtAuth middleware | `server/src/middleware/jwt/jwt_middleware.rs` | External JWT validation via cached JWKS | Semi-trusted |
| CookieAuthSameServer middleware | `server/src/middleware/cookie_auth.rs` | Session cookie validation against session store + JWT verify | Semi-trusted |
| AdminAuth middleware | `server/src/middleware/admin_auth.rs` | Maps authenticated session subject → Admin entity in DB | Trusted |
| AppTokenExtract middleware | `server/src/middleware/app_token_extract.rs` | `X-Vault-Token` header lookup and hash validation | Semi-trusted |
| EnsureAuth middleware | `server/src/middleware/ensure_auth.rs` | Enforces at least one auth method; fallback to `default_username` | Semi-trusted |
| Login endpoint | `server/src/server/endpoints/client_endpoints.rs` | Issues JWT session token after successful auth | Trusted |
| Sessions API | `server/src/server/endpoints/sessions_endpoints.rs` | CRUD for session records (server-to-server internal API) | **Unauthenticated** |
| Admin CRUD API | `server/src/server/endpoints/realms_endpoints.rs`, `super_admins_endpoints.rs` | Realm/admin management (admin-auth required) | Trusted |
| AppRole API | `server/src/server/endpoints/approle.rs` | Vault-compatible AppRole login and admin CRUD | Trusted (login: unauthenticated) |
| Kubernetes Auth API | `server/src/server/endpoints/kubernetes.rs` | K8s service-account JWT login and role admin CRUD | Trusted (login: unauthenticated) |
| Session store | `server/src/session/` | JWT issuance, cookie construction, session CRUD | Trusted |
| Database backends | `server/src/database/impls/` | SQLite / PostgreSQL / MySQL credential and session storage | Trusted (local) |
| Password hasher | `server/src/database/passwords.rs` | Argon2id credential hashing | Trusted |
| JWKS manager | `server/src/middleware/jwt/jwks.rs` | Remote JWKS caching with auto-refresh | Semi-trusted |
| TLS layer (openssl / rustls) | `server/src/tls/` | TLS termination and mTLS peer cert extraction | Trusted |

---

## Asset Inventory

| Asset | Location | Sensitivity | Protection |
|-------|----------|-------------|-----------|
| Argon2-hashed passwords | Database `userpass` table | CRITICAL | Argon2id at rest; never returned by API |
| JWT session tokens (embedded in `_ea_` cookie) | Session store cookie string | CRITICAL | `Secure; HttpOnly; SameSite=Strict`; 1-second JWT leeway |
| JWT EC P-256 signing key pair | `session_jwt_params.jwt_ec_private_key` file | CRITICAL | File system ACL; never exposed via API |
| AppRole secret IDs | Database `app_secret_ids` table (SHA-256 hash only) | HIGH | Only hash stored; raw secret returned once on creation |
| AppRole tokens | Database `app_tokens` table (SHA-256 hash only) | HIGH | Only hash stored; raw token returned once on issuance |
| Admin session cookies | Session store | HIGH | Same protections as user session tokens |
| TOTP secrets | Database `totp_secrets` table | HIGH | Access-controlled by realm; never returned plaintext |
| Dev seed credentials | `auth_verifier.dev.toml` config file | MEDIUM | Plain text in config; intended for dev only |
| Server TLS private key | `tls_params.server_private_key` file | CRITICAL | File system ACL |
| Database connection URL | `database_params.connection_url` config | HIGH | Config file ACL; contains credentials |

---

## Trust Boundary Summary

| Boundary | What crosses it | Controls |
|----------|-----------------|----------|
| Network → auth-verifier HTTP | Login requests, JWT tokens, AppRole credentials | TLS (optional in dev), CORS headers |
| auth-verifier → database | Argon2 hashes, session records, AppRole data | Connection-level credentials; no network restriction in code |
| auth-verifier → external JWKS URIs | JWKS public-key material | HTTPS required (for K8s JWKS), 5s timeout, redirect disabled |
| KMS → auth-verifier `/sessions` | Session creation, lookup, deletion | **No authentication** — assumed internal network isolation |
| Admin browser → auth-verifier admin scopes | Realm/admin/role management | `CookieAuthSameServer` + `AdminAuth`; requires valid admin session |

---

## Deployment Modes

| Mode | TLS | Auth | Salt | Notes |
|------|-----|------|------|-------|
| Dev (`auth_verifier.dev.toml`) | Plain HTTP | `no_jwt_validation` off; username/password with seeded `admin`/`change_me` | Argon2 with username-derived salt | SQLite in-memory; permissive CORS; intended for local dev/CI only |
| Production (`auth_verifier.toml`) | TLS via OpenSSL or rustls | Username/password + optional JWT/mTLS | Same Argon2 config | PostgreSQL/MySQL recommended |
