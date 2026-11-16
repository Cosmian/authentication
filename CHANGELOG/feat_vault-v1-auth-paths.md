## Breaking Changes

- Vault client routes (`approle/login`, `kubernetes/login`, `token/*`) are now served only under `/v1/auth/*`; the unprefixed paths return `404`. Requires Eviden KMS ≥ the release that calls `/v1/auth/token/lookup-self`. Admin CRUD routes (`/auth/approle/role/...`, `/auth/kubernetes/role/...`) are unchanged.

## Features

### Vault userpass login

- Add `POST/PUT /v1/auth/userpass/login/{username}` (`bao login -method=userpass`), backed by the userpass accounts of the realm named by the new `vault_userpass_realm` setting; disabled when unset.
- Add `AuthClient::vault_userpass_login` and the `/v1/auth/userpass/login/{username}` path to `openapi.yaml`.

## Bug Fixes

- Declare the admin-ui pnpm `overrides` in `admin-ui/pnpm-workspace.yaml` as well as `package.json`, so a lockfile written by Dependabot's newer pnpm keeps its `overrides:` block and no longer fails the frozen install in CI (`ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`).
