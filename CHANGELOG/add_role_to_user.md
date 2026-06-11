## Features

- Add `roles: Vec<String>` field to `UserPass` model for RBAC
- Emit `roles` claim and `as_domain` private claim (= realm) in JWT tokens issued during login
- Add `AuthorizationClaims` struct for JWT role propagation to downstream services (KMS OPA)
- Schema migration: add `roles TEXT NOT NULL DEFAULT '[]'` column to `userpass` table across SQLite, PostgreSQL, and MySQL backends
- Update all CRUD operations (create, get, update, list) to persist and retrieve roles
- Update OpenAPI schema with roles property on UserPass
- Add `roles` config field to `ServerParams` (TOML): declares available RBAC role names
- Add `GET /public/roles` endpoint: returns the configured role list (no auth required)
- Admin UI: `CreateCredentialModal` multi-select Roles field populated from `GET /public/roles`
- Admin UI: `EditCredentialModal` for updating roles of an existing credential (Edit button)
- Admin UI: `CredentialsPage` credentials table with Roles column (blue tags); wire Edit modal in both single-realm and super-admin views

## Refactor

- Update `issue_token()` signature to accept `roles` parameter only (no `domain`); `as_domain` JWT private claim is now derived from `realm_id` (the authenticated realm), unifying the two concepts
- Remove `domain` field from `UserPass` model, all three database backends (SQLite, PostgreSQL, MySQL), and admin UI — domain identity is the realm
- Remove `domain TEXT` column from `userpass` DDL and all related migration blocks; existing databases retain the column but queries no longer select or bind it

## Bug Fixes

- Fix `scheduleExpiry` in `AuthContext` to cap `setTimeout` delay to `2^31 - 1` ms (~24.85 days) to prevent 32-bit integer overflow in browser timers; tokens with `exp` more than ~24.85 days in the future would previously reset auth state immediately

## Testing

- Fix E2E navigation and realms tests: `exp: 9999999999` in mock JWT claims caused a 32-bit `setTimeout` overflow that fired immediately and reset auth state, redirecting to the login page on every test
- Fix E2E navigation tests: `page.goto("/")` with `baseURL = "http://localhost:4173/admin-ui/"` navigated to the origin root (nothing served); changed to `page.goto("")` to navigate to the app root
