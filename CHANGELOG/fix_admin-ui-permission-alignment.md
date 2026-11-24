## Features

- `GET /admins` is now open to realm admins, who get the admins whose realms they all administer (themselves included), so the admin UI can show them the admins they can already read, edit and delete one by one; super admins still get every admin.

## Refactor

- Admin UI: `isSuperAdmin` (the Super-Admin view is selected in the header) is renamed `isSuperAdminMode`, and `isGlobalAdmin` (the logged-in admin is a super admin) is renamed `isSuperAdmin`, so the flags match the server's `Admin::is_super_admin`.

## Tests

- `test_list_admins_requires_super_admin` is replaced by a test that a realm admin lists only the admins it owns, not multi-realm, unaffiliated, foreign-realm or super admins.
