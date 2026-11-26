## Features

- `GET /admins` is now open to realm admins, who get the admins whose realms they all administer (themselves included), so the admin UI can show them the admins they can already read, edit and delete one by one; super admins still get every admin.
- Admin UI: `RealmContext` gains `canManageRealm(realmId)`, true for a realm admin's own realms and, for a super admin, for realm `_` and the realms that have no admin of their own yet (claimed realms come from `GET /admins`), so pages can stop offering changes the server refuses.
- Admin UI: the Realms page is open to realm admins, who can edit and delete their own realms but not create realms; for a super admin, a realm that has admins of its own is tagged "Claimed" with Edit disabled (the server refuses it) while Delete stays available, and deleting a realm that has admins warns that they are left without a realm.
- Admin UI: the Admins page lists the admins of the selected realm to its own admins, with Edit, TOTP, Credential and Delete, and the same drawer as the Super-Admin view to add one (the realm is preselected), instead of a create-only form; a super admin sees the admins of a claimed realm without any action (the server refuses them), and no New Admin button there.

## Bug Fixes

- Admin UI: a realm admin no longer gets "Access Denied" on the Realms page and the sidebar shows it the Realms entry, matching the server rules since the realm-claim change (#89) that let a realm's own admins edit and delete it; a save the server refuses with 403 now refreshes the claimed state.

## Refactor

- Admin UI: `isSuperAdmin` (the Super-Admin view is selected in the header) is renamed `isSuperAdminMode`, and `isGlobalAdmin` (the logged-in admin is a super admin) is renamed `isSuperAdmin`, so the flags match the server's `Admin::is_super_admin`.

## Tests

- `test_list_admins_requires_super_admin` is replaced by a test that a realm admin lists only the admins it owns, not multi-realm, unaffiliated, foreign-realm or super admins.
- Admin UI unit and Playwright tests cover a realm admin editing its realm (SAML metadata included) without being offered realm creation, and a super admin seeing a claimed realm as read-only while still able to delete it.
- Admin UI unit tests for the Admins page (Super-Admin view, realm view, claimed realm, empty, error and loading states) and a Playwright spec where a realm admin lists and deletes an admin of its realm.
