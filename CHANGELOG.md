# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] - 2026-07-16

## Bug Fixes

- **`create_userpass` endpoint now hashes the password before storage**: previously the
  plaintext password bytes sent by the client were stored verbatim in the database, while
  `validate_userpass` compared the stored value against an Argon2 hash of the incoming
  password — causing all username/password logins for API-created credentials to fail.
  The endpoint now calls `hash_password_with_argon2` before passing the record to the
  database layer.

- **`update_userpass` endpoint now hashes the new password before storage**: same root
  cause as above. If the client sends non-empty password bytes (password reset), they are
  hashed before storage. If the client sends `password: []` (roles/flags-only update, the
  common case since GET always returns an empty password field), the existing hash is
  preserved so that authentication continues to work.

## Testing

- Added `test_create_userpass_then_authenticate` regression test: creates credentials via
  the HTTP endpoint with plaintext password bytes and asserts that a subsequent login with
  the same password succeeds.

- Added `test_update_userpass_then_authenticate` regression test: covers password update
  (old password rejected, new password accepted) and roles-only update (empty password
  field preserves existing hash and authentication continues to work).

- Updated all test helpers that built `UserPass` structs for HTTP API calls
  (`helpers::create_userpass`, `make_expired_userpass`) to send plaintext bytes instead of
  pre-hashed values, matching the intended client contract.

## [0.2.0] - 2026-07-14

### Bug Fixes

- `server/src/database/impls/{postgres,mysql}.rs`: fix a column-name mismatch in
  `get_admin` and `list_admins` where the row was read with
  `try_get("client_certificate")` while the `SELECT` projects the `certificate`
  column, causing a runtime "column not found" error that blocked admin lookups
  and session validation on PostgreSQL and MySQL backends (SQLite was unaffected).

## [0.1.0] - 2026-07-10

### 🚀 Features

- Add first version of the Cosmian Authentication Verifier with main features:
  - **Realm management** — isolated authentication domains, each with its own allowed
    auth methods, session lifetime, and TOTP configuration
  - **Username / password authentication** — Argon2id password hashing, per-realm
    allow-expired-passwords policy
  - **JWT / OIDC authentication** — JWKS validation against multiple IdPs per realm,
    configurable audience and auto-refreshing key cache
  - **mTLS client-certificate authentication** — EC P-256 client certificates verified
    during TLS handshake
  - **Two-factor authentication (TOTP)** — per-realm TOTP configuration (algorithm,
    time step), generate / verify / disable enrollment flow, TOTP challenge step in
    the login flow
  - **Server-side session management** — opaque `_ea_` session cookie, session
    validation endpoint (`GET /sessions/{id}`), per-realm and per-user bulk revocation,
    stale-session background collector
  - **Role-based claims** — roles stored per user credential, surfaced in the JWT
    issued at login
  - **Two-tier administration model** — super admins administer all realms; realm
    admins are scoped to their own realms with exclusive-ownership enforcement
  - **Multiple database backends** — SQLite, PostgreSQL, MySQL (runtime selection via
    configuration)
  - **Multiple session-store backends** — SQLite, PostgreSQL, MySQL, Redis
  - **Admin UI** — React / Ant Design web application for managing realms, credentials,
    admins, and sessions
