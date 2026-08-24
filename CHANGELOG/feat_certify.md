## Features

- Added `POST /certify`: an authenticated (session-cookie) endpoint that certifies a caller-supplied verification key under the caller's own `realm_id`/`sub`/`auth_scheme`, returning a long-lived, ES256-signed certificate. The certificate is signed with a dedicated certificate signing key (`certificate_jwt_params`), entirely separate from the session JWT key, so it can never be presented back as a session cookie/token even if algorithms collide.
- Added `GET /.well-known/certificate-jwks.json`, a JWKS document for the new certificate signing key, kept separate from the existing session `/.well-known/jwks.json` for the same isolation reason.
- Added a per-realm `certificate_max_age_seconds` field controlling how long issued certificates remain valid (defaults to one year), following the same pattern as the existing `session_max_age_seconds`.

## Refactor

- Removed `public_key_pem` from `POST /login` and the `as_pk` private claim it populated on the session JWT: this was dead weight (no caller ever set it) and the wrong shape for the job — VELO, the intended consumer, now uses `/certify` instead, which produces a purpose-built, long-lived, cryptographically isolated certificate rather than piggybacking on the short-lived session token.

## Tests

- Added `certify_tests.rs`: session requirement, empty-key rejection (400), missing server configuration (500), certificate JWKS availability, and — most importantly — cryptographic isolation (a certificate signed with the certificate key is rejected by the session JWT decoding key).
