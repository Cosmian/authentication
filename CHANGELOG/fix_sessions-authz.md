## Bug Fixes

- **Security: admin endpoints accepted sessions of any realm.** `AdminAuth` matched a session's username and login scheme against admin logins without checking the realm, so a user of any realm named like an admin acted as that admin on `/admins`, `/realms` and the machine-auth endpoints. It now maps only sessions opened on the admin realm `_` (`401` otherwise).
- **Security: `/sessions/*` had no authorization (breaking).** Any valid session could read, list and delete any other session and read its `cookie_string`, the session credential. A caller now acts on its own sessions (same realm and username, any login scheme); admins also on those of the realms they may manage (`can_manage_realm`, so the super admin loses sessions of claimed realms); `DELETE /sessions/expired` is for super admins. A session the caller may not access is reported as not found, and `DELETE /sessions` is refused as a whole if one session is not the caller's to delete.
- **Security: session responses leaked the session credential (breaking).** `/sessions` now returns `SessionInfo`, without `cookie_string`; `AuthClient::get_session` and `get_session_with_action` return it instead of `SessionData`.
- **Security: any admin could manage global machine roles.** `/auth/approle/*` and `/auth/kubernetes/*` role management (including secret IDs) is now limited to super admins through a `require_super_admin` scope guard; the login endpoints stay unauthenticated.

## Refactor

- **Breaking:** removed `POST /sessions` (create or update a session) and `UpsertSessionRequest`: nothing called them, and they let any caller write a session.

## Tests

- New `sessions_authz_tests` covering admin endpoints with a foreign-realm session, `/sessions` for realm users, realm admins, the super admin on unclaimed and claimed realms, `cookie_string` absence, the removed `POST /sessions`, and AppRole/Kubernetes management by a realm admin.

## Docs

- Authorization guide, API reference, OpenAPI, session management, client library, getting started and flows now describe the `/sessions` access rules, that a backend forwards the user's own cookie (`session_id` is the SHA-256 hex of the cookie value), and that admin sessions come from `_`; fixed the wrong "Cookie-Realm Constraint" text.
- The admin UI `SessionData` type, unused but copying the leaked field, is now `SessionInfo` without `cookie_string`.
