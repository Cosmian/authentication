# Changelog

All notable changes to this project will be documented in this file.

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
