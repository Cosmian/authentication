## Features

- Add `roles: Vec<String>` and `domain: Option<String>` fields to `UserPass` model for RBAC
- Emit `roles` claim and `as_domain` private claim in JWT tokens issued during login
- Add `AuthorizationClaims` struct for JWT role propagation to downstream services (KMS OPA)
- Schema migration: add `roles TEXT NOT NULL DEFAULT '[]'` and `domain TEXT` columns to `userpass` table across SQLite, PostgreSQL, and MySQL backends
- Update all CRUD operations (create, get, update, list) to persist and retrieve roles/domain
- Update OpenAPI schema with roles and domain properties on UserPass

## Refactor

- Update `issue_token()` signature to accept `roles` and `domain` parameters
- Add `AuthorizationClaims` to public exports from `auth_client` and server `models` module
