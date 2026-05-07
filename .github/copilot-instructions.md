# Authentication Server — Copilot Instructions

## Project Structure

Rust workspace with two crates:

- `client/` (`auth_client`) — HTTP client, shared models, DTOs, error types, and params. This is the contract surface used by both the server and external API servers.
- `server/` (`auth_server`) — Actix-web HTTPS server: middleware pipeline, endpoints, database layer, session store, TOTP, and TLS configuration.

Project documentation lives in `server/documentation/`. Start with `server/documentation/index.md`.

## Architecture

The server has two independent storage abstractions:

- **Database** (`server/src/database/trait.rs`) — long-lived auth data: realms, users, userpass credentials, TOTP state. Implementations: SQLite, PostgreSQL, MySQL.
- **SessionStore** (`server/src/session/session_store.rs`) — live sessions with lookup, revocation, and expiry. Implementations: SQLite, PostgreSQL, MySQL, Redis.

The HTTP layer is organized as Actix scopes with layered middleware, assembled in `server/src/server/auth_server.rs`:

| Scope | Purpose | Key middleware |
|-------|---------|----------------|
| `/public` | Unauthenticated (version, JWKS) | None |
| `/login` | Credential authentication | `ExtractRealm` → `UsernamePasswordAuth` → `JwtAuth` → `EnsureAuth` |
| `/whoami` | Session introspection | `ExtractRealm` → `CookieAuthSameServer` |
| `/sessions` | Session validation/revocation API | `ExtractRealm` |
| `/realms` | Realm-scoped credentials and TOTP | `ExtractRealm` → `CookieAuthSameServer` → `AdminAuth` |
| `/admins` | Admin CRUD | `InjectAdminRealm` → `CookieAuthSameServer` → `AdminAuth` |
| `/admins/realms` | Realm management (super admin) | `InjectAdminRealm` → `CookieAuthSameServer` → `AdminAuth` |

Middleware runs bottom-to-top in each scope (last `.wrap()` runs first).

## Key Domain Concepts

- **Realm** — isolated auth domain with its own allowed auth methods and session lifetime. The special `_` realm is the admin realm.
- **Admin** — an *administrator* record, not a generic account. Every `Admin` has a `realms` list determining what they may administer.
- **Super admin** — `Admin` with `"_"` in `realms`. Can administer everything.
- **Realm admin** — `Admin` with specific realm IDs (not `"_"`). Scoped to those realms only.
- **Session** — server-side record. The `_ea_` cookie is an opaque lookup key, not a JWT. All session state is in the store.
- **AuthenticatedClientScheme** — inserted into request extensions by auth middleware; carries `username` and `auth_scheme`.
- **ClientClaims** — JWT claims extracted from the session cookie by `CookieAuthSameServer`.

## Authentication Schemes

| Scheme | Middleware | Credential source |
|--------|-----------|-------------------|
| Username/password | `UsernamePasswordAuth` | `Authorization: Basic` header, Argon2id hash |
| JWT/OIDC | `JwtAuth` | `Authorization: Bearer` header, JWKS validation |
| mTLS client cert | OpenSSL `on_connect` callback | TLS handshake, EC P-256 |
| TOTP (2FA) | Checked in `/login` handler | `totp_code` field in `LoginRequest` body |

## Authorization Model

Two-tier: super admin vs realm admin. Authorization is enforced in endpoint handlers, not middleware. Key rules:

- `Admin::is_super_admin()` — `realms` contains `"_"`
- `Admin::can_administer_realm(r)` — is super admin OR `realms` contains `r`
- **Exclusive-ownership rule** — realm admin can only CRUD an `Admin` if *every* realm in that admin's `realms` list is one they administer
- PUT endpoints run the ownership check twice: once on current state, once on incoming body (prevents privilege escalation)

See `server/documentation/authorization_and_administration.md`.

## Conventions

- Shared types (models, DTOs, params, errors) live in `client/`, not `server/`. The server re-exports them.
- Error types use `thiserror`. The client crate provides `AuthError`, `AuthResult`, `auth_bail!`, `auth_ensure!`, `auth_error!`.
- Database implementations use `sqlx` with raw SQL, not an ORM.
- Session cookie name is `_ea_` (constant `COOKIE_NAME`).
- Passwords are hashed: `salt = SHA-256(lowercase(username))`, `hash = Argon2id(password, salt)`.
- Test harness spins up a real HTTPS server per test with in-memory SQLite. See `server/src/tests/test_server.rs`.

## Build & Test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check