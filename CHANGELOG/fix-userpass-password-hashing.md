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
