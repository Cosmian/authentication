# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-09-05

### Features

- **`POST /certify`**: a new authenticated (session-cookie) endpoint that certifies a caller-supplied verification key under the caller's own `realm_id`/`sub`/`auth_scheme`, returning a long-lived, ES256-signed certificate. It is signed with a dedicated certificate signing key (`certificate_jwt_params`), entirely separate from the session JWT key, so it can never be presented back as a session cookie/token even if algorithms collide.
- Added `GET /.well-known/certificate-jwks.json`, a JWKS document for the new certificate signing key, kept separate from the existing session `/.well-known/jwks.json` for the same isolation reason.
- Added a per-realm `certificate_max_age_seconds` field controlling how long issued certificates remain valid (defaults to one year), following the same pattern as the existing `session_max_age_seconds`.
- `POST /login`'s per-IP rate limiter is now configurable via `ServerParams::login_rate_limit_per_second` / `login_rate_limit_burst` (both optional, default to the previous hardcoded values: 5 req/s, burst of 10).
- `UserPass` gained `extra_claims`, arbitrary claims a realm admin sets at enrollment that are merged into the session JWT on username/password login (rejected with `400` on collision with a typed claim or if serialized size exceeds 4 KiB), and `POST /certify` gained a `claims` field (plus `exclude_sub`) to selectively copy a session's extra claims into an isolated, separately-signed certificate.
- `UserPass` gained `password_input`, a `PasswordInput` enum (`Plaintext(String)` or `Hashed(String)`) letting a caller provision a credential either from a plaintext password or from an already-computed Argon2id PHC string without ever sending its plaintext to this server; the latter is rejected with `400` unless it uses exactly this server's own algorithm/version/cost parameters.
- `CredentialModal` (create mode): added a plaintext/pre-hashed password toggle (`PasswordFields`) so an admin can provision a credential from an already-computed Argon2 PHC string instead of a plaintext password, and a key/value extra-claims editor (`ExtraClaimsEditor`) for `UserPass.extra_claims`, matching the new server-side `password_input`/`extra_claims` fields.

### Bug Fixes

- `POST /admins`, `POST /admins/realms`, and `POST /realms/{realm_id}/userpass` used to leak a raw `500` with database internals on a duplicate ID/username; all three now return a clean `409 Conflict` (the `userpass` case unconditionally, since distinguishing a genuine conflict from a byte-for-byte resubmission would require checking the submitted password against the stored hash on this unrate-limited, admin-authenticated endpoint, turning it into a password-guessing oracle).
- `CredentialModal`'s roles-fetch effect had no unmount guard: if the `list()` call resolved after the modal/component was torn down, the resulting `setAvailableRoles` call could fire against a dead environment. Added the same `cancelled` guard already used by the form-validity effect right below it.
- Column migrations (e.g. `userpass.roles`) now use the same atomic `ADD COLUMN IF NOT EXISTS` on PostgreSQL as other columns instead of a `SELECT`-then-`ALTER` check missing a schema filter, and all three backends (PostgreSQL, MySQL, SQLite) now propagate a failure of that check instead of silently treating it as "column missing".
- Plaintext passwords are now wrapped in `Zeroizing` through the HTTP Basic Auth extraction path and the `userpass` create/update handlers, reducing how long they remain in cleartext in application-held memory.
- Raised the server's Argon2id parameters to RFC 9106 §4's recommended `t=3, m=64 MiB (65536), p=4` (was `t=3, m=4 MiB (4096), p=1`, a wrongly-documented value inherited from the crate's own default) and now pin/validate the algorithm version (`v=19`) in addition to the variant and cost parameters when accepting a pre-hashed `password_input: { hashed: ... }`.
- Bumped `h2` from 0.4.13 to 0.4.16 (hyper/reqwest instance) to fix `RUSTSEC-2026-0258` (unbounded empty DATA frames, low severity); the other instance, pulled in transitively via `actix-http` 3.13.1 (pinned to `h2 ^0.3`, no patched 0.3.x release exists), is now explicitly ignored in `deny.toml`. Also removed a stale `RUSTSEC-2023-0071` ignore entry.
- Bumped eight `admin-ui` dependencies flagged by Dependabot to pick up upstream fixes: `antd`, `react-router`, `@testing-library/react`, `@types/react-dom`, `@types/node`, `eslint`, `eslint-plugin-react-refresh`, and `typescript-eslint`.

### Refactor

- Removed `public_key_pem` from `POST /login` and the `as_pk` private claim it populated on the session JWT: this was dead weight (no caller ever set it) and the wrong shape for the job — VELO, the intended consumer, now uses `/certify` instead, which produces a purpose-built, long-lived, cryptographically isolated certificate rather than piggybacking on the short-lived session token.
- `UserPass.password`/`hashed_password` (two separate, manually-mutually-exclusive fields) replaced by a single `password_input: Option<PasswordInput>` field, enforcing the plaintext-vs-pre-hashed exclusivity at the type level instead of at runtime — a request providing both is now structurally impossible rather than a `400` caught after the fact.
- Renamed `UserPass.password` to `password_hash` and changed its type from `Vec<u8>` to `String`: the stored value has always been the full Argon2id PHC string, so the old name/type obscured what it actually holds and forced an unnecessary byte/string round-trip. The three database backends still store it as a binary column (`BYTEA`/`BLOB`, unchanged — no migration needed) and convert at the Rust boundary.

### Tests

- Added `certify_tests.rs`: session requirement, empty-key rejection (400), missing server configuration (500), certificate JWKS availability, and cryptographic isolation (a certificate signed with the certificate key is rejected by the session JWT decoding key).
- Added a userpass duplicate-creation regression test and renamed a misleading pre-existing duplicate-admin test for clarity.
- Fixed a flaky `admin-ui` unit test (`window is not defined`, `RealmContext.test.tsx`) by guarding `RealmContext`'s `fetchRealms` against post-unmount `setState` and extending the scheduler-drain loop in `afterEach`.

### Docs

- Added `SECURITY.md`, a hand-maintained security policy and vulnerability-disclosure ledger, so the auth server has the same advisory-tracking surface as the KMS repository.
- Documented the advisory-ledger lifecycle in AGENTS.md §11 and mirrored a short pointer in `.github/copilot-instructions.md`, defining the `COSMIAN-AUTH-<YYYY>-NNN` ID scheme, the released-vs-unreleased rule, and the three-part internal-consistency requirement.

### CI

- Regenerated the Nix `admin-ui` pnpm dependencies hash (`nix/expected-hashes/admin-ui.pnpm.*.sha256`) for all three platforms after several Dependabot bumps to `admin-ui/pnpm-lock.yaml` went unmatched by a hash regeneration, breaking the Nix `Packaging` CI job; also corrected a stale `darwin` hash.
- Fixed the `admin-ui` package-update pipeline: regenerated `pnpm-lock.yaml` to record the `pnpm.overrides` block (was causing `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`), added a browser `User-Agent` to Nix's `fetchurl`/`importCargoLock` calls to stop crates.io HTTP 403s, and pinned `npm_config_node_version=22.12.0` so pnpm's engine check picks up the `@rolldown/binding-linux-x64-gnu` optional dependency.

### Security

- Recorded previously shipped and fixed vulnerabilities in `SECURITY.md`: COSMIAN-AUTH-2026-001 and COSMIAN-AUTH-2026-002 (plaintext password storage via the `create_userpass`/`update_userpass` endpoints), COSMIAN-AUTH-2026-003 (TLS private key baked into the Docker image), and COSMIAN-AUTH-2026-004 (vulnerable admin UI transitive dependencies).

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
