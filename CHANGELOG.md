# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-08-06

### Features

- **AppRole / Kubernetes / Token machine-auth API** (SPIRE/SPIFFE support): new database tables (`app_tokens`, `approle_roles`, `app_secret_ids`, `k8s_roles`); endpoints under `/auth/approle/`, `/auth/kubernetes/`, and `/auth/token/`; tokens stored as `SHA-256(hvs.<random>)`, never persisted raw; token-validation middleware inserts authenticated entity into request extensions.
- Kubernetes JWT validation: explicit algorithm allowlist (`RS256/RS384/RS512/ES256/ES384`), `nbf` claim validation, `kid`-based key pre-selection per RFC 7517 §4.5.
- **Machine Credentials admin UI page** (AppRole, Kubernetes, token self-service tabs) backed by new admin read endpoints; client DTOs and `openapi.yaml` updated.
- **Configurable log level** via optional `[log]` section in server TOML (`level`, defaults to `"info"`, overridable by `RUST_LOG`).
- **Admin-ui Nix derivation** (`nix/admin-ui.nix`) using `pnpm_9.fetchDeps` for hermetic builds; static assets bundled into Docker image (`/srv/admin-ui/`) and DEB/RPM packages (`/usr/share/auth_verifier/admin-ui/`).
- Docker image entrypoint generates self-signed TLS certificates at runtime; no private key baked into the image.

### Bug Fixes

- **Admin userpass auto-link**: server now auto-links/unlinks `admin.userpass` on `POST`/`DELETE /realms/_/userpass`; admin UI gained a "Credential" button and optional password fields in the "New Admin" drawer.
- **`create_userpass` / `update_userpass` now hash passwords before storage**: plaintext bytes were previously stored verbatim, breaking all logins for API-created credentials; empty `password: []` on update preserves the existing hash.
- **TOCTOU race in SQLite secret-ID consumption**: `consume_secret_id` now uses `BEGIN IMMEDIATE` + `rows_affected()` check to prevent two concurrent AppRole logins both succeeding against a single-use secret ID.
- Fixed `AppRoleLoginRequest.secret_id` as required `String` (broke `bind_secret_id: false` login); changed to `Option<String>` with `#[serde(default)]`.
- Removed fragile RS256 fallback loop in `validate_k8s_jwt` that silently accepted weak-algorithm tokens.
- Test harness: replaced fixed `AtomicU16` port counter with OS-assigned ephemeral ports; changed `host_name` to `"127.0.0.1"`; added `Drop` on `TestsContext` to stop server on panic.
- Resolved three Dependabot security advisories via pnpm overrides (`js-yaml@5.2.2`, `postcss@8.5.25`, `brace-expansion@5.0.9`); migrated to `react-router` v8.3.0 (GHSA-qwww-vcr4-c8h2); bumped `react`/`react-dom` to 19.2.8.
- Miscellaneous: fixed clippy `unnecessary_unwrap`, packaging `chown root:root`, admin-ui `chmod -R u+w` before cleanup, `/etc/cosmian/dev/` creation moved to `fakeRootCommands`.

### Refactor

- `auth_verifier.service` now runs as `root`, uses `StateDirectory=cosmian-auth` and `WorkingDirectory=/var/lib/cosmian-auth`; `postinst` simplified (no cosmian user/group creation).
- Docker image default port changed from `8443` to `8080`.

### Tests

- 17 integration tests (`app_auth_tests.rs`) covering AppRole, Kubernetes, and token self-service workflows.
- 13 database unit tests for all new machine-auth tables.
- Regression tests for password-hashing fix (`test_create/update_userpass_then_authenticate`); test helpers updated to send plaintext bytes.

### Docs

- `server/documentation/` restructured as an mdBook (pages under `docs/`, `nav.yml`, `book.toml`, `SUMMARY.md`, `doc-theme` submodule).
- Authentication flows doc extended to cover AppRole (Flow 5), Kubernetes (Flow 6), and token self-service (Flow 7).
- OpenAPI fixes: `secret_id` removed from `AppRoleLoginRequest.required`; `expected_issuer`/`bound_audiences` added to `K8sRoleRequest`; `/v1/auth/` paths corrected to `/auth/`.

### CI

- Added `.github/dependabot.yml` for weekly admin-ui npm updates.
- Added `verify_running_ui.sh`, admin-UI verification steps in `packaging-tests.yml`, and asset checks in DEB/RPM smoke tests.
- Added `build_admin_ui()` to `package_common.sh`; updated pnpm store hashes for all platforms; improved `test_docker_image.sh`.

### Security

- Ephemeral TLS certificate generation at container startup removes the private key that was previously baked into the Docker image.

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
