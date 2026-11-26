## Features

- `GET /admins` is now open to realm admins, who get the admins whose realms they all administer (themselves included), so the admin UI can show them the admins they can already read, edit and delete one by one; super admins still get every admin.
- Admin UI: `RealmContext` gains `canManageRealm(realmId)`, true for a realm admin's own realms and, for a super admin, for realm `_` and the realms that have no admin of their own yet (claimed realms come from `GET /admins`), so pages can stop offering changes the server refuses.
- Admin UI: the Realms page is open to realm admins, who can edit and delete their own realms but not create realms; for a super admin, a realm that has admins of its own is tagged "Claimed" with Edit disabled (the server refuses it) while Delete stays available, and deleting a realm that has admins warns that they are left without a realm.
- Admin UI: the Admins page lists the admins of the selected realm to its own admins, with Edit, TOTP, Credential and Delete, and the same drawer as the Super-Admin view to add one (the realm is preselected), instead of a create-only form; a super admin sees the admins of a claimed realm without any action (the server refuses them), and no New Admin button there.
- Admin UI: creating, editing or deleting an admin refreshes which realms are claimed, since a realm's first admin claims it and its last one releases it, so the Realms, Credentials and Sessions pages reflect the change without a reload.
- Admin UI: the admin form's realm picker lists realms that have admins of their own as disabled (the server refuses new admins there from a super admin), and the sidebar decides whether to show Admins with the same `canManageRealm` check as the pages instead of its own copy of the rule.
- Admin UI: the Credentials page no longer loads or offers actions on a realm that has its own admins (the server answers 403 for a super admin): the overview shows a note in place of that realm's panel and its New Credential button, and the single-realm view shows the same note.
- Admin UI: the Sessions page hides "Revoke All Sessions" on a realm that has its own admins, where the server now refuses a super admin, and says why.
- Admin UI: the realm form offers the TOTP settings only for the admin realm `_`, the only realm where 2FA exists, and keeps the stored TOTP settings of other realms unchanged when saving them; it used to let any realm enable a 2FA that nothing enforces.

## Bug Fixes

- Admin UI: a realm admin whose last realm is gone (e.g. it deleted it) is no longer sent to the Super-Admin view: with no realm left the selection stays empty instead of falling back to realm `_`, which showed the red super-admin banner and super-admin pages to someone who is not a super admin.
- Admin UI: a super admin creating the first admin of a realm with a password got the admin but not its password (`403`), leaving an admin that could not log in in a realm the super admin could no longer fix; the form now creates the login before the admin for a super admin (the admin claims the realm, after which only the realm's admins may manage the login), keeps the admin-first order for realm admins, and removes the login again if the admin cannot be created.

- Admin UI: a realm admin no longer gets "Access Denied" on the Realms page and the sidebar shows it the Realms entry, matching the server rules since the realm-claim change (#89) that let a realm's own admins edit and delete it; a save the server refuses with 403 now refreshes the claimed state.

## Refactor

- Admin UI: `isSuperAdmin` (the Super-Admin view is selected in the header) is renamed `isSuperAdminMode`, and `isGlobalAdmin` (the logged-in admin is a super admin) is renamed `isSuperAdmin`, so the flags match the server's `Admin::is_super_admin`.

## Tests

- `test_list_admins_requires_super_admin` is replaced by a test that a realm admin lists only the admins it owns, not multi-realm, unaffiliated, foreign-realm or super admins.
- Admin UI unit and Playwright tests cover a realm admin editing its realm (SAML metadata included) without being offered realm creation, and a super admin seeing a claimed realm as read-only while still able to delete it.
- Admin UI unit tests for the Admins page (Super-Admin view, realm view, claimed realm, empty, error and loading states) and a Playwright spec where a realm admin lists and deletes an admin of its realm.
- The SAML realm form tests wait up to 10 s instead of 5 s for slow validation, since the save test failed commit hooks on a loaded machine while taking 0.3 s alone.

## Docs

- Realm permissions described as they are since the realm-claim change: the `can_manage_realm` doc comment no longer says a super admin loses read access, `server/authorization.md`, the API reference, the client guide, the overview and `.github/copilot-instructions.md` no longer call realm update and delete super-admin only, and `can_administer_realm` is documented as a UI hint rather than an authorization decision.
- `AGENTS.md` §4a adds the admin UI as a layer to keep in sync and a rule for authorization changes: state the admin UI impact (or "No admin UI impact") in the PR and the changelog, with the UI update optional; `admin-ui/AGENTS.md` states that the UI permission checks mirror the server rules and that unavailable actions are hidden.

## Security

- Update `actix-http` to 3.22.1 (RUSTSEC-2026-0552, -0553, -0554), `url` to 2.5.9 (RUSTSEC-2026-0592) and `cookie` 0.18 to 0.18.3 (RUSTSEC-2026-0594), plus `actix-web` 4.20.0, so `cargo deny` passes again.
- Accept RUSTSEC-2026-0594 for the `cookie` 0.16.2 copy pinned by `actix-web` (private cookies are not compiled in or used) and RUSTSEC-2026-0543 (`chrono` unmaintained, no patched version) in `deny.toml`, each with its reason; revisit when `actix-web` moves to `cookie` >= 0.18.3 and when `chrono` is migrated.
