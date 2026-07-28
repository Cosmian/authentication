## Bug Fixes

- Fix `create_vault_role` in SQLite backend to use `ON CONFLICT (role_name) DO UPDATE SET` instead of `INSERT OR REPLACE`, preventing cascade deletion of `vault_secret_ids` and `vault_tokens` when a role is updated.
