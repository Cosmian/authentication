## Features

- Add the SAML 2.0 contract types to the client crate — `SamlParams`, `RealmAuthParams.saml_params` and `AuthScheme::Saml` (`"sa"`) — mirrored in the admin-ui TypeScript types and `openapi.yaml`, so realms can carry per-realm SAML Service Provider configuration for the upcoming SP-initiated Web Browser SSO login.
- Make `find_admins_by_auth_scheme` return no admin for `AuthScheme::Saml` on SQLite, PostgreSQL and MySQL, because SAML is a user-facing realm login method and never an administrator credential.
- Add a `SamlRequestStore` (pending `AuthnRequest`s for `InResponseTo` correlation plus a consumed-assertion replay cache) with SQLite, PostgreSQL, MySQL and Redis backends and a `create_saml_request_store` factory, each enforcing single-use atomically in its native primitive, refusing already-expired entries so no backend can return an expired request or forget a consumed assertion early, and keeping IDs exact-match on MySQL (binary collation, SHA-256 replay keys) where the default collation ignores case and `INSERT IGNORE` truncates long IDs.
- Add an optional `saml` Cargo feature (off by default) that pulls in `samael` and gates the server-side SAML module, so default builds, plain `cargo` and existing CI stay free of the new C dependencies.
- Refuse realm create/update requests that carry `saml_params` on servers built without the `saml` feature (HTTP 400), so unusable and unvalidated SAML configuration is never stored.
- Bundle a static, OpenSSL-only xmlsec 1.3.5 and libxml2 2.13.4 (`nix/xmlsec-static.nix`, built with the glibc-2.34 toolchain, XSLT and runtime crypto loading disabled) and wire it plus the libclang/bindgen setup into `shell.nix`, so `--features saml` links xmlsec statically against the server's vendored OpenSSL with no new runtime library dependency.

## Tests

- Add a SAML request store test suite that runs against in-memory SQLite by default and against PostgreSQL, MySQL or Redis through the same `TEST_SESSIONS_STORE` switch as the session-store tests (single-use and concurrent takes, realm scoping, expiry on write and on read, replay detection, case-sensitive and long IDs, expiry purge), an xmlsec smoke test that exercises libxml2, xmlsec and its OpenSSL backend end to end, and an API test checking that SAML settings are refused without the `saml` feature.

## CI

- Add a Nix-based `cargo-saml` job that runs clippy and the unit tests with `--features saml` inside `nix-shell`, since that feature needs the bundled xmlsec and libclang that the plain-cargo jobs don't have.
