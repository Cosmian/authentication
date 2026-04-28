# Test Coverage Reference

This document catalogs every integration test in the `auth_authentication` crate, describes what it verifies
in functional terms, then identifies scenarios and attack vectors that are not yet covered.

---

## Test Modules

### `cookie_auth_tests` — Session & Cookie Lifecycle

| Test | What it verifies |
|------|------------------|
| `test_login_and_whoami_success` | A valid username/password login on realm `_` issues a signed session cookie; the same cookie can immediately be used to call `/whoami` and retrieve the correct user identity. |
| `test_whoami_without_cookie_fails` | A client that never authenticated receives HTTP 401 on `/whoami`. |
| `test_whoami_with_invalid_cookie_fails` | A client that sends a syntactically valid but cryptographically forged cookie is rejected with HTTP 401. |
| `test_whoami_after_session_deleted_fails` | Even with a valid cookie, if the server-side session has been explicitly deleted the request is rejected with HTTP 401. |
| `test_whoami_after_session_expired_fails` | An expired session (past `session_max_age_seconds`) is rejected with HTTP 401. |
| `test_stale_session_collector_removes_expired_sessions` | The background stale-session collector removes sessions whose `max_stale_age` has passed so they are no longer retrievable. |
| `test_login_wrong_password_returns_401` | Submitting a valid username with an incorrect password returns HTTP 401 and does not issue a session cookie. |
| `test_login_unknown_username_returns_401` | Submitting a username that does not exist returns HTTP 401 — same response shape as wrong-password to avoid leaking username existence. |

---

### `jwt_tests` — JWT Bearer Authentication

| Test | What it verifies |
|------|------------------|
| `test_jwt_auth_valid_token` | A well-formed RS256 JWT with the correct issuer and audience grants access. |
| `test_jwt_auth_no_token` | A request with no `Authorization` header is rejected (401 or falls through to cookie path). |
| `test_jwt_auth_malformed_token` | A `Bearer` header containing random bytes is rejected. |
| `test_jwt_auth_wrong_audience` | A token signed for a different audience is rejected. |
| `test_jwt_auth_expired_token` | An expired token (past `exp`) is rejected. |
| `test_jwt_auth_multiple_requests_same_token` | The same valid token can be reused across multiple requests within its lifetime. |
| `test_jwt_auth_different_users` | Two distinct tokens for two different users each authenticate independently. |
| `test_jwt_auth_session_persistence` | A session created via JWT login persists and can be retrieved via the session store. |
| `test_jwt_auth_without_bearer_prefix` | A token value submitted without the `Bearer` prefix is rejected. |

---

### `username_password_tests` — HTTP Basic Auth Middleware

| Test | What it verifies |
|------|------------------|
| `test_valid_basic_auth` | A request with a correct `Authorization: Basic <base64>` header passes the `UsernamePasswordAuth` middleware. |
| `test_authenticate_with_cookie` | A client that already has a valid session cookie does not need to re-present credentials; the cookie path authorises the request. |

---

### `sessions_api` — Session Store CRUD

| Test | What it verifies |
|------|------------------|
| `test_get_session_returns_claims` | After login, fetching the session by its ID returns the stored claims. |
| `test_get_session_not_found_returns_none` | Fetching a non-existent session ID returns `None` (no error, no data). |
| `test_get_sessions_for_users_contains_new_session` | After one login, the session appears in the user-scoped session list. |
| `test_get_sessions_for_users_no_sessions` | A user that has never logged in has an empty session list. |
| `test_get_sessions_for_users_multiple_sessions` | Multiple concurrent logins each produce a separate session that all appear in the list. |
| `test_delete_sessions_removes_session` | Explicitly deleting a session by ID makes it unretrievable. |
| `test_delete_sessions_multiple` | Deleting a list of session IDs removes all of them atomically. |
| `test_delete_sessions_empty_list` | Deleting an empty list is a no-op (no error). |
| `test_delete_expired_sessions_keeps_live_sessions` | The expired-session purge only removes sessions past their TTL; live sessions are untouched. |
| `test_delete_expired_sessions_empty_store` | Purging an already-empty store is a no-op. |
| `test_delete_sessions_for_realm_removes_all` | Deleting all sessions for a realm removes every session bound to that realm. |
| `test_delete_sessions_for_realm_empty` | Deleting sessions for a realm with no sessions is a no-op. |

---

### `super_admin_api` — Realm Management & Credential Management

#### Realm CRUD

| Test | What it verifies |
|------|------------------|
| `test_list_realms` | A super admin sees at least the seeded `_` realm in `GET /admin/realms`. |
| `test_get_realm` | Fetching the `_` realm by ID returns the expected object. |
| `test_get_realm_not_found` | Fetching a non-existent realm ID returns an error. |
| `test_update_realm` | Updating `session_max_age_seconds` on a realm persists and is visible on a subsequent GET. |
| `test_delete_realm_nonexistent_is_idempotent` | Deleting a realm that never existed returns HTTP 204 (no error). |
| `test_create_realm` | Creating a new realm with a valid `Realm` payload succeeds. |

#### Realm Authorization Enforcement

| Test | What it verifies |
|------|------------------|
| `test_update_realm_requires_super_admin` | A realm admin attempting `PUT /admin/realm/{id}` receives HTTP 403. |
| `test_delete_realm_requires_super_admin` | A realm admin attempting `DELETE /admin/realm/{id}` receives HTTP 403. |
| `test_list_realms_filtered_for_realm_admin` | A realm admin only sees the realms they administer; realms belonging to other admins and `_` are hidden. |

#### Credential (UserPass) Management

| Test | What it verifies |
|------|------------------|
| `test_userpass_endpoints_require_realm_admin` | A realm admin for realm `X` cannot create credentials in realm `_` (403), even though their cookie decrypts via `_`'s key. |
| `test_userpass_crud_by_super_admin` | A super admin can create, retrieve, update, delete, list-by-realm, and list-all credentials in `_`. Exercises every CRUD endpoint including the previously-fixed `update_userpass` path. |
| `test_list_all_userpass_requires_super_admin` | A realm admin calling `GET /admin/userpass` receives HTTP 403. |

#### Unauthenticated Access

| Test | What it verifies |
|------|------------------|
| `test_unauthenticated_access_to_admin_endpoints` | `GET /admin/realm/_`, `GET /admin/realms`, and `GET /admin/userpass` all return HTTP 401 for a client that has never authenticated. |
| `test_unauthenticated_access_to_realms_endpoints` | `GET /realms/_/userpass/…` and `GET /realms/_/userpass` return HTTP 401 for an unauthenticated client. |

#### Security Properties

| Test | What it verifies |
|------|------------------|
| `test_update_userpass_cannot_change_realm` | Even if the PUT body contains a different `realm` value, the handler overwrites it with the realm from the URL path — a credential cannot be silently moved to a different realm. |
| `test_realm_admin_cannot_operate_on_other_realms` | A realm admin cannot create, update, or delete credentials in a realm they do not administer; the server returns HTTP 403. |

---

### `admin_api` — Admin CRUD & Realm Membership

#### Basic CRUD (super admin)

| Test | What it verifies |
|------|------------------|
| `test_list_users_contains_admin` | `GET /admins` returns at least the seeded `admin` user. |
| `test_create_user` | A valid `POST /admins/admin` creates the user and a subsequent GET returns it. |
| `test_create_duplicate_user_fails` | Creating a user whose ID already exists returns an error. |
| `test_get_user_existing` | Fetching the seeded `admin` user by ID succeeds. |
| `test_get_user_not_found` | Fetching a non-existent user ID returns an error. |
| `test_update_user` | Updating a user's realm list persists and is visible on a subsequent GET. |
| `test_update_user_path_id_is_authoritative` | If the JSON body contains a different `id` than the URL, the URL wins. |
| `test_delete_user` | Deleting a user removes it; a subsequent GET returns an error. |
| `test_delete_nonexistent_user_is_idempotent` | Deleting a user that never existed is a no-op. |
| `test_admin_endpoints_require_authentication` | An unauthenticated client receives HTTP 401 on any `/admins` endpoint. |

#### Authorization Enforcement

| Test | What it verifies |
|------|------------------|
| `test_get_user_requires_super_admin` | A realm admin cannot GET a user with `realms=["_"]` (doesn't administer `_`). HTTP 403. |
| `test_update_user_requires_super_admin` | A realm admin cannot update a user with an empty `realms` list (ownership check fails). HTTP 403. |
| `test_delete_user_requires_super_admin` | A realm admin cannot delete a user with an empty `realms` list. HTTP 403. |
| `test_list_users_requires_super_admin` | A realm admin calling `GET /admins` receives HTTP 403. |

#### Realm Admin — create_user

| Test | What it verifies |
|------|------------------|
| `test_create_user_by_realm_admin` | A realm admin can create a user whose `realms` list contains only their own realm. |
| `test_create_user_by_realm_admin_forbidden_no_realm` | A realm admin cannot create a user with an empty `realms` list. HTTP 403. |
| `test_create_user_by_realm_admin_forbidden_other_realm` | A realm admin cannot create a user assigned to a realm they do not administer. HTTP 403. |

#### Realm Admin — get_user

| Test | What it verifies |
|------|------------------|
| `test_get_user_by_realm_admin` | A realm admin can retrieve a user that belongs exclusively to their realm. |
| `test_get_user_by_realm_admin_forbidden_multi_realm` | A realm admin cannot retrieve a user that also belongs to a realm outside their authority. HTTP 403. |

#### Realm Admin — update_user

| Test | What it verifies |
|------|------------------|
| `test_update_user_by_realm_admin` | A realm admin can update a user that belongs exclusively to their realm; the body must also contain only realms they administer. |
| `test_update_user_by_realm_admin_forbidden_multi_realm` | A realm admin cannot update a user that also belongs to another realm (fails current-state check). HTTP 403. |

#### Realm Admin — delete_user

| Test | What it verifies |
|------|------------------|
| `test_delete_user_by_realm_admin` | A realm admin can delete a user that belongs exclusively to their realm. |
| `test_delete_user_by_realm_admin_forbidden_multi_realm` | A realm admin cannot delete a user that also belongs to another realm. HTTP 403. |

#### Realm Membership Management

| Test | What it verifies |
|------|------------------|
| `test_add_user_to_realm_by_realm_admin` | A realm admin can add an existing user to their own realm. |
| `test_remove_user_from_realm_by_realm_admin` | A realm admin can remove a user from their own realm. |
| `test_add_user_to_realm_unauthorized` | A realm admin cannot add a user to a realm they do not administer. HTTP 403. |
| `test_add_user_to_realm_idempotent` | Adding a user who is already a realm member is a no-op; the realm appears exactly once. |

#### Privilege Escalation Prevention

| Test | What it verifies |
|------|------------------|
| `test_add_user_to_realm_prevents_super_admin_escalation` | A realm admin cannot call `add_user_to_realm(user, "_")` to grant super-admin rights; `can_administer_realm("_")` is false → HTTP 403. |
| `test_create_user_with_super_admin_realm_forbidden` | A realm admin cannot create a user whose `realms` list includes `"_"`. The exclusive-ownership check blocks it → HTTP 403. |
| `test_update_user_cannot_escalate_via_body` | A realm admin cannot use the `update_admin` body to inject `"_"` into a user's `realms` list. The **body-realms check** (added to the endpoint) rejects this → HTTP 403. |
| `test_update_user_cannot_add_foreign_realm_via_body` | A realm admin cannot silently extend a user's realm membership to a foreign realm via the update body. HTTP 403. |

#### Security Properties

| Test | What it verifies |
|------|------------------|
| `test_realm_admin_self_removal_revokes_access` | After a realm admin removes themselves from their own realm, subsequent calls requiring realm-admin rights for that realm are rejected with HTTP 403. |
| `test_session_invalidated_after_user_deletion` | Deleting a user's record immediately invalidates their ability to call any `AdminAuth`-guarded endpoint. The `AdminAuth` middleware does a live DB lookup (`find_admins_by_auth_scheme`) on every request, so no session-store wipe is needed. HTTP 401 after deletion. |
| `test_delete_admin_cascades_credentials` | Deleting an Admin whose `userpass` is set also removes the corresponding `UserPass` credential row from the database. Verifies the cascade-delete added to `delete_admin`. |
| `test_session_replay_after_logout` | After a user's session is explicitly deleted, presenting the old session ID to `GET /sessions/{id}` returns `None`. Confirms the session store does not retain the entry and that the cookie cannot be replayed. |
| `test_oversized_user_id_rejected` | A 1 000-character user ID submitted in a URL path does not cause an HTTP 500. The server handles it gracefully (404 or 400). |
| `test_realm_id_with_special_characters` | A realm ID containing `..%2F_` (URL-encoded path traversal attempt) does not cause an HTTP 500. The router's `Path` extractor handles it gracefully. |

---

### `totp::tests` — TOTP Unit Tests (`src/totp/mod.rs`)

These are in-module unit tests; they do not require a database or HTTP stack.

| Test | What it verifies |
|------|------------------|
| `test_generate_secret` | `Totps::generate_secret_and_totps` returns a non-empty Base32 secret and a `Totps` instance. |
| `test_otpauth_url` | The generated `otpauth://` URL contains the issuer and account name. |
| `test_from_known_secret` | `Totps::from_secret` accepts a known valid Base32 secret and constructs a `Totps` instance. |
| `test_validate_own_token` | A token generated by the server validates successfully against the same secret. |
| `test_invalid_token_rejected` | A token with all wrong digits returns `false` (no error, just invalid). |
| `test_malformed_token_rejected` | A non-numeric token (e.g. `"abcdef"`) is rejected. |
| `test_wrong_length_token_rejected` | A 5-digit or 7-digit token is rejected for a 6-digit TOTP configuration. |
| `test_empty_token_rejected` | An empty string token is rejected. |
| `test_from_invalid_base32_secret_fails` | Passing an invalid Base32 string to `from_secret` returns an `Err`. |
| `test_two_independent_secrets_differ` | Two independently generated secrets are not equal. |
| `test_different_accounts_same_secret_produce_same_token` | Two `Totps` instances sharing the same secret produce identical tokens regardless of their account names. |
| `test_create_totp_secret_convenience` | `create_totp_secret` returns a non-empty secret and an `otpauth://` URL containing the issuer. |
| `test_default_params` | `TotpParams::default()` has `digits=6`, `skew=1`, `step=30`. |
| `test_totp_realm_params_sha256` | `TotpRealmParams { algorithm: "SHA256", step: 60 }` produces a `TotpParams` with `step=60`; two `Totps` built from the same secret and SHA-256 params generate equal tokens. |
| `test_totp_realm_params_invalid_algorithm` | `TotpRealmParams { algorithm: "MD5", … }.to_totp_params()` returns `Err` — unsupported algorithms are rejected at config time. |

---

### `tests::totp_tests` — TOTP HTTP and Login Integration Tests (`src/tests/totp_tests.rs`)

End-to-end integration tests using a real in-memory-SQLite test server.

| Test | What it covers |
|------|-----------------|
| `test_login_without_totp_succeeds_normally` | When TOTP is not enabled, login returns `Authenticated` with a session cookie in the first attempt (no behavior change for TOTP-disabled accounts). |
| `test_login_totp_required_when_no_code` | After enabling TOTP via `POST /totp/generate` + `POST /totp/verify`, a login attempt without a `totp_code` returns HTTP 200 with `next_step: TotpRequired` and no session cookie. |
| `test_login_with_valid_totp_succeeds` | A second login attempt including the correct current TOTP code returns `Authenticated` with a full session cookie. |
| `test_login_with_invalid_totp_returns_error` | Submitting `"000000"` as a TOTP code results in HTTP 401 Unauthorized. |
| `test_login_after_totp_disabled_succeeds` | After calling `DELETE /totp/{username}`, a login attempt without any TOTP code succeeds normally. |

---

## Architecture Notes

### `/admins` scope uses `InjectAdminRealm`

The `/admins` scope (which hosts the user CRUD and realm-membership endpoints) uses `InjectAdminRealm`, not `ExtractRealm`. This means the scope always authenticates callers using the `_` (admin) realm's cookie key. All administrators — both super admins and realm admins — log into `_` and receive a `_`-encrypted session cookie. This design intentionally centralises authentication for all administrative operations through the admin realm.

### `whoami` has no `AdminAuth` layer

The `/whoami` endpoint uses only `CookieAuthSameServer` + `ExtractRealm`. It does **not** include `AdminAuth`, so it reflects the session cookie's claims without performing a database lookup. Consequently, a deleted user's `/whoami` request still succeeds (the session claims are intact). Only `AdminAuth`-guarded endpoints (`/admins`, `/admin`, `/realms`) properly reject requests from deleted users.

### `AuthError::Cookie` returns HTTP 401

A cookie decryption failure (e.g., presenting a `_`-realm cookie to a `/realms/other_realm/…` endpoint) is classified as `AuthError::Cookie` and returns **HTTP 401**.

---

## Remaining Coverage Gaps

### Low Priority / Hardening

| Scenario | Status | Why it matters |
|----------|--------|----------------|
| **Concurrent realm admin creation** | Open | Race condition — not deterministically testable without a concurrency harness. The DB unique constraint on `userpass(username)` is the only safeguard. |
