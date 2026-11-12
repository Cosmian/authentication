## Features

- **Breaking: 2FA is stored on the login.** The TOTP secret moves from the admin record to the username/password login of the admin realm `_` (`userpass.totp_secret`), so it follows the login: login checks it directly, and deleting a login deletes its 2FA. At startup the server moves existing admin 2FA to the admin's `_` login and drops the `admin.totp_*` columns; JWT admins lose their 2FA (with a warning) and rely on their identity provider's MFA.
- **Breaking: `Admin` no longer has `totp_secret` and `totp_auth_url`.** `totp_enabled` stays, read-only: the server computes it from the admin's `_` login and ignores it in request bodies.
- **Breaking: the server refuses to start when admins share a login.** Startup now fails, naming the shared `userpass` or `jwt` values, instead of warning; the unique indexes on those columns therefore always exist.
- The admin UI shows the TOTP action only for admins with a `_` username/password login, the only ones that can have 2FA.

## Refactor

- Removed the unused `TotpMiddleware` and the `generate_totp_secret` and `is_totp_enabled` database methods; `enable_totp` takes no issuer and reports whether the login exists.

## Tests

- Database tests on SQLite, PostgreSQL and MySQL for 2FA on the login (needs the login, removed with it) and for the migration of pre-0.6.0 admin 2FA; the shared-login test now expects startup to fail.

## Docs

- 2FA guide, API reference, OpenAPI, authorization guide and client library describe 2FA on the `_` login, the migration and the startup refusal.
