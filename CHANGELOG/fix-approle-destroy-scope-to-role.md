## Bug Fixes

- Scope `destroy_secret_id` deletion to `(role_name, accessor)` across all database backends (SQLite, PostgreSQL, MySQL) to prevent cross-role accessor revocation (IDOR / CWE-639): a request to `/role/{name}/secret-id/destroy` can now only delete an accessor that belongs to the named role.
