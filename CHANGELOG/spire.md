## Features

- **AppRole-compatible authentication API** for SPIRE/SPIFFE support:
  - Added `app_tokens` database table to store AppRole-compatible tokens with
    TTL, revocation, and entity binding (SQLite, PostgreSQL, MySQL backends).
  - Added `approle_roles` and `app_secret_ids` tables for AppRole role management
    with configurable `bind_secret_id`, `token_policies`, and per-role / per-secret TTL.
  - Added `k8s_roles` table for Kubernetes auth with JWKS-based JWT validation and
    bound service-account name/namespace filters.
  - **Token endpoints** under `/auth/token/`: `GET /lookup-self` (validate a token
    and return entity + policies), `POST /renew-self` (extend a renewable token's TTL),
    `POST /revoke-self` (immediately invalidate a token).
  - **AppRole endpoints** under `/auth/approle/`: `POST /login`
    (exchange `role_id` + `secret_id` for an app token), `POST /role/{name}` (admin,
    create or update a role), `GET /role/{name}/role-id` (admin), `POST /role/{name}/secret-id`
    (admin, generate a single/limited-use secret ID), `POST /role/{name}/secret-id/destroy`
    (admin), `DELETE /role/{name}` (admin), `GET /role?list=true` (admin, list roles).
  - **Kubernetes auth endpoints** under `/auth/kubernetes/`: `POST /login`
    (authenticate with a Kubernetes service-account JWT), `POST /role/{name}` (admin),
    `DELETE /role/{name}` (admin).
  - App token format: `hvs.<base64url(32 random bytes)>`; stored as `SHA-256(token)`
    — the raw token is never persisted.
  - Token validation middleware (`app_token_extract.rs`) inserts the authenticated
    entity into request extensions for use by admin endpoints. Admin endpoints require
    an active auth-verifier admin session (`CookieAuthSameServer` + `AdminAuth`).
- Added an explicit algorithm allowlist (`RS256/RS384/RS512/ES256/ES384`) in
  `server/src/server/endpoints/kubernetes.rs`; Kubernetes JWTs with any other algorithm
  (e.g. `HS256`) are now rejected immediately with a clear error, aligning with RFC 7518.
- Enabled `validate_nbf = true` in `build_validation` so the RFC 7519 §4.1.5 "Not Before"
  claim is now validated for all Kubernetes service-account JWTs.
- Added `kid`-based key pre-selection in `validate_k8s_jwt` per RFC 7517 §4.5: when the
  JWT header carries a `kid`, only JWKS keys whose `kid` matches are tried first, falling
  back to all keys only when no `kid` is present or no key declares one.
- **Machine-credential admin UI + read endpoints**: added a super-admin "Machine
  Credentials" page to `admin-ui` with AppRole, Kubernetes, and token self-service tabs,
  backed by three new admin read endpoints — `GET /auth/approle/role/{name}` (role
  config), `GET /auth/kubernetes/role?list=true` (list roles) and
  `GET /auth/kubernetes/role/{name}` (role config, with stored JSON fields parsed back to
  arrays). Kubernetes role listing is backed by a new `list_k8s_role_names()` database
  method (SQLite, PostgreSQL, MySQL). Client DTOs and `openapi.yaml` updated to match.

## Bug Fixes

- Fixed a `clippy::unnecessary_unwrap` warning in `server/src/server/auth_verifier.rs` by replacing `is_some()` + `.unwrap()` with `if let Some(tls_params)` for both the OpenSSL and Rustls TLS bind branches.

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
- **Fixed a TOCTOU race in single/limited-use secret-ID consumption on SQLite.**
  `consume_secret_id` now opens its transaction with `BEGIN IMMEDIATE` to serialize
  concurrent writers (SQLite has no `SELECT ... FOR UPDATE`) and checks `rows_affected()`
  on the `DELETE`/`UPDATE`, returning `Ok(None)` when another concurrent login already
  consumed the secret ID. This prevents two simultaneous AppRole logins from both
  succeeding against a `num_uses_remaining = 1` secret ID. PostgreSQL and MySQL were
  already safe via `SELECT ... FOR UPDATE`.
- Fixed `AppRoleLoginRequest.secret_id` being a required `String` field, which caused login
  with `bind_secret_id: false` to fail at JSON deserialization before the handler could skip
  the secret-ID check; changed the field to `Option<String>` with `#[serde(default)]` in
  `client/src/dto/app_auth.rs` and updated the handler in
  `server/src/server/endpoints/approle.rs` to return a clear error when `bind_secret_id = true`
  but `secret_id` is absent.
- Removed the fragile RS256 fallback loop in `validate_k8s_jwt` that was silently retried
  only when the JWT header algorithm was not RS256 or ES256, leading to unexpected behaviour
  for tokens with other (including weak) algorithms.
- Replaced the fixed `AtomicU16` port counter (starting at 49998) in the test harness with
  OS-assigned ephemeral ports (`TcpListener::bind("127.0.0.1:0")`), eliminating sporadic
  test failures when ports in the counter range happen to be in use by other processes.
- Changed the test server `host_name` from `"localhost"` to `"127.0.0.1"` to avoid
  dual-stack ambiguity where `localhost` may resolve to `::1` (IPv6) while the TLS client
  URL is always forced to `127.0.0.1` (IPv4), which would cause the readiness probe to
  succeed against the wrong listener.

## Tests

- Added `server/src/tests/app_auth_tests.rs` with 17 integration tests covering the full
  AppRole workflow (create, list, login, destroy, delete), `bind_secret_id = false` login,
  single-use secret-ID invalidation, the full Kubernetes auth workflow (valid SA JWT,
  wrong SA name, wrong namespace, wildcard allowlist, expired JWT, issuer mismatch), and
  all three token self-service endpoints (`lookup-self`, `renew-self`, `revoke-self`).
- Added 13 database unit tests in `server/src/database/tests.rs` for `app_tokens`
  (issue, revoke, renew, renew-non-renewable), `approle_roles` (CRUD, upsert),
  `app_secret_ids` (single-use, unlimited, expired), and `k8s_roles` (CRUD, upsert).
- Added `APP_TOKEN_HEADER` and AppRole/Kubernetes/Token self-service client methods to
  `client/src/client/auth_client.rs` so integration tests can call these endpoints without
  raw HTTP.
- Added `test_create_userpass_then_authenticate` and `test_update_userpass_then_authenticate`
  regression tests for the password-hashing fix, and updated all test helpers that built
  `UserPass` structs for HTTP API calls (`helpers::create_userpass`, `make_expired_userpass`)
  to send plaintext bytes instead of pre-hashed values, matching the intended client contract.

## Docs

- Restructured `server/documentation/` into an mdBook section so it can be built standalone
  and aggregated into the combined Cosmian documentation: moved all pages under
  `server/documentation/docs/`, added `nav.yml`, `book.toml`, a generated `docs/SUMMARY.md`,
  a `README.md`, and the shared `doc-theme` submodule at `server/documentation/theme`.
  `openapi.yaml` was kept at `server/documentation/openapi.yaml` (it is `include_str!`'d by
  the server) and internal doc links were updated to the new `docs/` paths.
- Rewrote `server/documentation/authentication_flows.md` to cover all seven authentication
  flows: added Flow 5 (AppRole with full sequence diagram and secret-ID consumption warning),
  Flow 6 (Kubernetes service-account with JWKS validation steps), and Flow 7 (token
  self-service with state diagram for token lifecycle); expanded the API endpoint reference
  table to include all 13 machine authentication endpoints; updated the request-authentication
  decision flowchart to add the `X-Vault-Token` → `AppTokenExtract` branch.
- Added `Machine Authentication (AppRole / Kubernetes / Token)` sections to
  `server/documentation/api_reference.md` (full request/response docs for all 13 new
  endpoints) and `server/documentation/client_library.md` (Rust code examples for AppRole
  provisioning and login, Kubernetes role provisioning and login, and all three token
  self-service operations), each with a Table of Contents entry.
- Added a table of contents to `server/documentation/app_auth_api.md`; the document is kept
  as a single file since the three auth methods share the token table, token format, token
  self-service protocol, database schema, and KMS integration sections.
- Added a "Standards and Protocol References" section to `server/documentation/app_auth_api.md`
  listing the authoritative references for AppRole (AppRole auth API specification, SPIRE,
  RFC 4648, RFC 4086, FIPS 180-4), Kubernetes auth (RFC 7519, RFC 7517, RFC 7518, Kubernetes
  SA token docs, OpenID Connect Discovery 1.0), and Token self-service.
- Updated `server/documentation/index.md` and `server/documentation/getting_started.md` to
  reference Token self-service and AppRole/Kubernetes machine auth.
- Corrected all `/v1/auth/...` path references in
  `server/documentation/adr/2026-07-26-app-auth-api-for-spire.md` to `/auth/...` to match
  the actual implementation and openapi.yaml (the `/v1/` prefix was dropped during
  implementation to avoid Actix-web FIFO routing conflicts).
- Fixed the OpenAPI `AppRoleLoginRequest` schema (removed `secret_id` from the `required`
  array, consistent with the `bind_secret_id = false` use-case) and added the
  `expected_issuer` and `bound_audiences` fields to the OpenAPI `K8sRoleRequest` schema,
  which were present in the Rust DTO but missing from the specification.
