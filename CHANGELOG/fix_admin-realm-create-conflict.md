## Bug Fixes

- `POST /admins` and `POST /admins/realms` used to leak a raw `500` with database internals when creating an admin or realm whose ID already existed; they now return a clean `409 Conflict`, matching the fix already applied to `POST /realms/{realm_id}/userpass`.
