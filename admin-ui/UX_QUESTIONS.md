# Admin UI — UX Design Questions

Running interview to reach a shared understanding of the correct UX for the admin UI.
Each question includes a recommended answer. Answer each one before the next is asked.

## Status

| Q | Topic | Status |
|---|-------|--------|
| Q0 | API design conflict: high-volume vs admin-UI endpoints | ⏸ Skipped — revisit when missing endpoints are prioritised |
| Q1 | Primary persona | ✅ Answered |
| Q2 | Typical realm count in production | ✅ Answered |
| Q3 | Realm selector scope and visibility | ✅ Answered |
| Q4 | Admins page: two modes | ✅ Answered |
| Q5 | Dashboard content | ✅ Answered |
| Q6 | Dashboard purpose | ✅ Answered |
| Q7 | Realms management page layout | ✅ Answered |
| Q8 | Credentials page | ✅ Answered |
| Q9 | Sessions page | ✅ Answered — placeholder until `GET /sessions/realms/{id}` safe list endpoint added |
| Q10 | TOTP page | ✅ Answered — placeholder until API reworked |
| Q11 | Login page and AuthContext | ✅ Answered |
| Q12 | Admin form fields | ✅ Answered |
| Q13 | Route guards | ✅ Answered |

**Next action:** Answer Q12 (`fido2`/`digital_credentials`/`client_certificate` — Advanced section or omit?), then Q13 (route guards), then the interview is complete.

---

## Q0 — API design conflict: high-volume vs admin-UI endpoints

This is a foundational architectural tension that underlies every page in this UI.

The current server API was designed primarily for **server-to-server use** at high volume:
- Session lookup and validation must be sub-millisecond under load
- Credential hash verification must resist timing attacks
- No expensive cross-table aggregations at authentication time

Admin UI endpoints have **opposite requirements**:
- Low frequency (human-speed interactions, not per-request)
- Read-heavy aggregated views: "all sessions for realm X", "all users with TOTP enabled"
- Safe schemas that strip sensitive fields (`cookie_string`, raw session keys)
- Pagination or full-list semantics (humans browse, servers lookup)

The conflict surfaces concretely in three places already identified in this interview:

| Gap | Blocked UI | Required endpoint |
|-----|-----------|-------------------|
| No session list | Sessions page | `GET /sessions/realms/{realm_id}` returning `SessionSummary[]` |
| No TOTP status on userpass | TOTP page | `totp_enabled` on `UserPass` or `GET /realms/{realm_id}/clients` |
| Admin's own 2FA mixed with realm management | Admins page TOTP flow | Possibly split `Admin.totp_enabled` concern from realm-client TOTP |

**The fundamental decision:** should admin-UI endpoints live in the same server binary
(added as new routes) or should there be a deliberate API split — performance-critical
routes unchanged, admin-UI routes clearly marked as low-frequency and allowed to be more
expensive?

**Recommendation:** Keep a single binary but adopt a naming/tagging convention that
distinguishes admin-UI routes from operational routes. Use an `/admin/` prefix or an
OpenAPI tag (`admin-ui`) to signal that these endpoints are not on the hot path and
may perform heavier queries. This prevents accidental use of expensive endpoints in
high-frequency contexts while allowing the UI to get the data shapes it needs.

**Question:** Should admin-UI-oriented endpoints be distinguished from operational
endpoints by convention (prefix, tag) or by a separate API surface? And is it acceptable
to add new heavier endpoints to the current server to unblock the UI?

**Answer:** _Skipped for now — to be revisited when the missing endpoints are prioritised._

---

## Q1 — Primary persona

The current design has a flat sidebar (Dashboard, Realms, Admins, Credentials, Sessions, TOTP)
with a global realm selector in the header that silently scopes Credentials, TOTP, and Sessions.
This "ambient filter" pattern is functional but creates a classic confusion risk: the user operates
on the wrong realm without noticing.

Classic IdPs like Keycloak resolve this by making the realm the **primary navigation axis** —
you select a realm first, and the entire sub-navigation is scoped to it. Realm *management*
(CRUD) lives separately at the global level.

Whether that's the right call here depends heavily on who is sitting in front of this UI.

**Recommendation:** A super admin who juggles many realms benefits most from the realm-as-axis
model. A realm admin who only ever sees 1–2 realms finds it adds indirection for no gain.

**Question:** Who is the expected primary user of this admin UI — a super admin managing the
full system (many realms, many admins), a realm admin scoped to a handful of realms, or both
equally?

**Answer:** Both, but the typical deployment has only a few realms (see Q2). The current flat
sidebar with a header realm selector works for this scenario.

---

## Q2 — Typical realm count in production

This determines whether the realm-as-axis tree model is practical or introduces unnecessary
indirection.

With the realm-as-axis model a sidebar for a user with `finance` and `hr` would look like:

```
Dashboard
▼ finance
    Credentials
    Sessions
    TOTP
▼ hr
    Credentials
    Sessions
    TOTP
Admins
```

This is strictly faster to navigate when there are 2–10 realms: one click reaches any
realm-scoped resource with no context-switch. The cost only appears above ~20 realms where
the tree becomes a long scrollable list and a search/filter affordance would be needed.

**Recommendation:** If deployments stay in the 2–10 range, the tree model is the better long-term
choice. If 50+ realms are plausible, the ambient header selector (current approach) scales better
without additional work.

**Question:** How many realms does a typical production deployment have?

**Answer:** Only a few realms (roughly 2–10). The current header-selector model is sufficient
and there is no need to switch to the realm-as-axis tree model at this time.

---

## Q3 — Realm selector scope and visibility

With the header-selector confirmed, the question is what it scopes and whether it should
always be visible. Realm-scoped pages are clear (Credentials, TOTP, Sessions). Two pages
are ambiguous:

- **Admins** — no realm filter param in the API; super admins see all, realm admins are
  scoped server-side. The selector has no meaningful effect.
- **Realms** — the management page for realm objects; showing a selector here risks
  confusion about what is being edited.

The risk with a global selector that is always visible is that users learn to ignore it on
pages where it does nothing, which undermines its value on pages where it matters.

**Recommendation:** Make the selector contextual — hide or disable it on pages where it
has no effect, and show it prominently only on Credentials, Sessions, and TOTP.

**Question:** Should the realm selector be a global header control (always visible) or
a contextual page-level control shown only where it applies?

**Answer:** Keep the global header selector. Three refinements resolve the ambiguity:

1. The selector already has a special `_` value (displayed as "Admin") that signals
   super-admin mode. A warning banner is shown when operating in that mode.
2. The **Admins** menu item is visible to all users, including realm admins, because the
   exclusive-ownership rule means any realm admin can always administer admins scoped
   exclusively to their realms. The Admins page filters the displayed list server-side to
   only admins the current user can touch — no client-side ownership check needed.
   The item is only meaningfully "different" for super admins (they see all admins).
3. The **Realms** management page ambiguity is already resolved by the header selector:
   the active realm context is always visible.

> **Note:** The selector has no effect on the Admins page (server enforces scoping).
> The warning banner on `_` mode is the only visual cue that the admin list is unfiltered.

---

## Q4 — Admins page: two modes

`GET /admins` is super-admin only. Realm admins have no list endpoint; they can only
create, get by ID, update, and delete admins they exclusively own. A single Admins page
with a conditional list risks an empty/broken state for realm admins.

**Recommendation:** The Admins page has two distinct modes driven by the selected realm:

- **Super-admin mode** (`_` selected): full list of all admins + CRUD.
- **Realm-admin mode** (specific realm selected): create-only form scoped to that realm.
  No list is shown — there is no API to back it. The exclusive-ownership rule is satisfied
  by the realm selector already constraining the scope.

The Admins menu item is always visible (both modes provide a meaningful action). No
client-side ownership-rule evaluation is needed to decide visibility.

**Question:** Should the Admins page render differently for super-admin vs realm-admin mode,
or should it always attempt a list and degrade gracefully?

**Answer:** Yes — two explicit modes driven by the selected realm, with conditional menu
visibility:

- **Super-admin mode** (`_` selected): Admins item always visible. Page shows the full
  list of all admins + full CRUD.
- **Realm-admin mode** (specific realm selected): Admins item visible only when the
  exclusive-ownership rule is satisfied for the selected realm (the current user administers
  that realm — determinable from the realm list already held in `RealmContext`, no extra
  fetch needed). Page shows a create form scoped to that realm; no list is shown because
  `GET /admins` is super-admin only and no realm-scoped list endpoint exists.

The page renders differently in each mode. Menu visibility is driven by the realm selector
state and the user's realm list, not by a separate API call.

---

## Q5 — Dashboard content

The Dashboard is already implemented as a navigation shortcut card grid (quick-access cards
to each section). It currently filters out the Realms card for non-super-admins using a
`superAdminOnly` flag.

Three open questions arise from the decisions made in Q3 and Q4:

1. **Stats vs shortcuts** — the API has no aggregate endpoint (`/public/version` aside).
   Any counts (admin count, credential count, session count) would require N fetches.
   Is a stats layer desired, or is the shortcut grid sufficient?

2. **Admins card visibility consistency** — the Admins sidebar item follows the
   exclusive-ownership rule (Q4). The Admins card on the Dashboard should match. Currently
   it has no visibility guard. Should it use the same rule?

3. **Super-admin warning banner** — Q3 established a warning banner when `_` is selected.
   Should it appear on the Dashboard as well, or only on the scoped pages (Credentials,
   Sessions, TOTP)?

**Recommendation:**
1. Keep shortcuts only — no stats. The API cost is too high for a landing page.
2. Yes — the Admins card should follow the same exclusive-ownership visibility rule as the
   sidebar item for consistency.
3. The banner should appear globally (including Dashboard) whenever `_` is selected, since
   all actions from that point carry super-admin scope.

**Question:** Should the Dashboard show stats (requires N API calls), and should the Admins
card and super-admin warning banner follow the same rules established in Q3/Q4?

**Answer:**
1. No stats for now — the required endpoints don't exist and are not currently planned.
   The shortcut grid is sufficient. Stats may be revisited if aggregate endpoints are added.
2. Yes — the Admins card follows the same exclusive-ownership visibility rule as the
   sidebar item. However, the purpose of the Dashboard itself is under discussion (see Q6).
3. The super-admin warning banner appears globally on every page whenever `_` is selected.

---

## Q6 — Dashboard purpose

The Dashboard currently acts as a secondary navigation menu (shortcut cards to each
section). This is a common pattern but it means the landing page has no unique value —
it duplicates the sidebar and becomes a page users pass through rather than stop at.

Alternative uses for the dashboard real estate, given the current API capabilities:

**A — Keep as shortcut grid (current)**
Pro: zero additional API calls, always fast, works offline from nav.
Con: redundant with the sidebar, users quickly learn to bypass it.

**B — Server status / health summary**
Show server version (`GET /public/version`), realm count, and connectivity state.
Realm count requires `GET /admins/realms` which is already fetched by `RealmContext`.
Pro: gives instant orientation on server state with only one extra fetch already in flight.
Con: limited data — no session counts, no credential counts without new endpoints.

**C — Realm overview cards**
Each realm the current user administers gets a card showing its config summary
(auth methods enabled, session TTL). Clicking a card deep-links into Credentials or
Sessions scoped to that realm.
Pro: makes the realm selector concept tangible at a glance; useful for multi-realm admins.
Con: requires `GET /admins/realms` (already fetched) + per-realm detail reads if config
is shown beyond what the list returns.

**D — Activity / audit log feed**
A recent-events list. Not feasible — no audit log endpoint exists.

**E — Getting started / onboarding flow**
Detect empty state (no realms other than `_`, or no credentials) and show a step-by-step
setup guide. Useful for first-run experience.
Pro: high value for new deployments.
Con: adds conditional logic; becomes useless for established deployments.

**Recommendation:** Option B + C combined — server status bar at the top, realm overview
cards below. Both are achievable with data already fetched or planned. The shortcut grid
is retired; navigation stays in the sidebar.

**Question:** What should the Dashboard's primary purpose be — secondary navigation (current),
server/realm status overview, realm overview cards, onboarding flow, or some combination?

**Answer:** A is dropped — it is redundant with the sidebar and adds no value.

The Dashboard has two modes based on deployment state:

- **Empty state** (no realms beyond `_`, or no credentials exist): show an onboarding
  flow (E) with a step-by-step setup guide to orient new deployments.
- **Established state**: show server status bar (B) — server version and connectivity
  from `GET /public/version` and realm count from the already-fetched `RealmContext` data
  — followed by realm overview cards (C), one per administered realm, showing auth config
  summary and deep-linking into Credentials/Sessions scoped to that realm.

The shortcut card grid is retired. Navigation stays in the sidebar.

> **Implementation note:** `GET /admins/realms` is not super-admin only — realm admins
> receive a filtered list of their administered realms from the same endpoint. `RealmContext`
> already calls it. However, `RealmEntry` currently only stores `id` and `label`; the full
> `Realm` payload (`auth_params`, `session_max_age_seconds`, `session_max_stale_age_seconds`)
> is discarded on parse. This is not a deliberate design decision — it was sufficient for the
> realm selector dropdown and nothing downstream needed more. `RealmEntry` must be extended to
> carry the full realm shape before Dashboard realm cards or the Realms page can render config
> details. No new API calls are needed.

---

## Q7 — Realms management page

The Realms page (`/realms`) is currently a placeholder. It is super-admin only for write
operations; realm admins can read realms they administer but cannot create, update, or delete.

The full `Realm` object (once `RealmContext` carries it) contains:

- `id` — immutable identifier
- `auth_params.username_password_params.allow_expired_passwords` — bool
- `session_max_age_seconds` — session lifetime
- `session_max_stale_age_seconds` — sliding window

Three layout options:

**A — Table with inline edit**
Rows per realm, columns for each config field, edit in-place. Fast to scan; compact.
Works well for few realms. Creates/deletes via toolbar buttons.

**B — Cards with drawer/modal edit**
One card per realm (mirrors the Dashboard). Clicking opens a side drawer with a form.
Consistent with the Dashboard realm card metaphor; softer learning curve.

**C — Master/detail split**
Left: realm list. Right: full config form for selected realm. Classic admin panel pattern.
Works well when realm config grows complex over time.

**Recommendation:** Option B — cards + drawer. The small realm count (2–10) doesn't justify
a table, and the card metaphor is already established on the Dashboard. The drawer keeps
the user in context while editing.

**Question:** Which layout for the Realms management page — table (A), cards + drawer (B),
or master/detail split (C)?

**Answer:** Option B — cards + drawer. The card metaphor is consistent with the Dashboard
realm overview cards and the small realm count (2–10) makes a table unnecessary.

> **Note:** If the realm count hypothesis changes (more than ~15 realms becomes common),
> Option C (master/detail split) is the natural migration path — it handles long lists
> better and the drawer form content maps directly to the detail panel with no redesign.

---

## Q8 — Credentials page

The Credentials page lists username/password credentials for the selected realm
(`GET /realms/{realm_id}/userpass`). Operations: create, update password, toggle
`change_password`, delete.

Three non-obvious design constraints from the API:

1. **Password is write-only.** The server always returns `password: []`. The UI can never
   show the current password. On update, sending `password: []` would overwrite the hash
   with an empty-bytes hash — the UI must distinguish "not changed" from "set to empty".
2. **Password is `Vec<u8>` on the wire** — UTF-8 bytes of the plaintext. The UI must
   encode the string entered by the admin as a byte array before sending. Sending a JSON
   string instead of an array will be rejected.
3. **`change_password` flag** — signals that the credential holder must change their
   password on next login. This is a first-class toggle, not just a display field.

Layout options:

**A — Table with action buttons**
Rows: username, change_password badge, action buttons (edit password, toggle flag, delete).
Password column omitted (always empty). Edit opens a modal with a password field + confirm.

**B — Table with inline drawer**
Same table, but "Edit" opens a side drawer with the full form (password reset + flag toggle).
Consistent with the Realms page pattern (Q7 answer: cards + drawer → here: table + drawer).

**Recommendation:** Option A — the credential list is purely tabular (username + flag),
modal for password reset is lighter than a drawer for a two-field form. The drawer pattern
suits complex forms; a password reset is not complex.

For the "not changed" problem: the password field in the edit modal is always blank. If the
admin submits without typing a new password, the UI sends the current PUT with `password: []`
omitted or the field is required — forcing an explicit new value prevents accidental overwrites.
Making the password field required on update is the safest default.

**Question:** Table + modal (A) or table + drawer (B) for Credentials? And should the
password field be required on update (preventing accidental empty-password submissions)?

**Answer:** Option A — table + modal. The credential list is tabular (username +
`change_password` badge + action buttons). Password reset opens a lightweight modal with
a required password field + confirm field. The password field is required on update to
prevent accidental empty-password submissions — the admin must explicitly type a new value.

> **Implementation note:** On submit, the UI encodes the password string as UTF-8 bytes
> (`Array.from(new TextEncoder().encode(password))`) before sending. The `change_password`
> toggle is a separate action button in the table row, not part of the password modal.

---

## Q9 — Sessions page

The Sessions API is primarily designed for server-to-server use. Before deciding on layout,
it is important to understand what the admin UI can actually do:

| What | Endpoint | Notes |
|------|----------|-------|
| List all sessions for a realm | — | **Does not exist.** No browsable session list. |
| Look up a session by ID | `GET /sessions/{session_id}` | Requires knowing the ID. |
| Look up sessions by username | `POST /sessions/realms/{realm_id}/clients` | Returns IDs for given usernames. |
| Revoke sessions by ID | `DELETE /sessions` | Requires knowing the IDs. |
| Bulk revoke all sessions for a realm | `DELETE /sessions/realms/{realm_id}` | Destructive. |
| Purge all expired sessions globally | `DELETE /sessions/expired` | No realm scope. Super-admin action. |

The Sessions page therefore **cannot be a browsable list** — it is an administrative
action page. The meaningful actions available are:

1. **Revoke all sessions for the selected realm** — one-click bulk logout for the realm.
   Requires confirmation dialog (destructive, irreversible).
2. **Look up and revoke sessions by username** — enter a username, fetch their session IDs
   via `POST /sessions/realms/{realm_id}/clients`, display results, offer per-session or
   bulk revoke via `DELETE /sessions`.
3. **Purge expired sessions** — global cleanup button (super-admin only, no realm scope).

**Recommendation:** The page renders as an action panel, not a data table. Three sections:
- A prominent "Revoke all sessions" danger button (with confirmation) for the selected realm.
- A username lookup form → results list with revoke buttons per session.
- A "Purge expired sessions" button visible only in super-admin mode (`_` selected).

**Question:** Is the action-panel approach acceptable, or should a list-of-sessions view
be added as a future server endpoint to unlock a proper browsable sessions page?

**Answer:** The action-panel approach is not acceptable as a final design — directly
manipulating session IDs and JWTs on the frontend is a security anti-pattern. The Sessions
page does not make sense without a safe list endpoint. The page remains a placeholder until
that endpoint exists.

Requirements for the server-side list endpoint:

1. **New safe schema required** — `SessionData` must never be returned by a list endpoint.
   A new `SessionSummary` DTO must be defined omitting `cookie_string` and `session_id`.
   Fields: `username`, `auth_scheme`, `realm_id`, `created_at`, expiry indicator.
   An opaque revocation handle (not the raw session key) may be included if targeted
   revoke-from-list is needed.
2. **Endpoint:** `GET /sessions/realms/{realm_id}` returning `SessionSummary[]`.
   Realm-scoped; super admins may query any realm.
3. **Server-side pagination required** — the endpoint must accept `page`/`limit` (or
   cursor-based) parameters. Returning the full list in one response risks server load on
   long session tables. Ant Design Table pagination maps directly to server-side params.
4. **Redis backend:** requires a secondary index (e.g. a Redis Set per realm tracking
   session keys) to avoid an O(N) `SCAN` against the full keyspace.
   > ⚠️ **Do not implement the Redis secondary index yet.** Design it alongside the
   > endpoint when the Sessions page is prioritised. SQL backends (SQLite, PostgreSQL,
   > MySQL) can implement the endpoint with a simple indexed `SELECT` immediately.

---

## Q10 — TOTP page and admin 2FA

TOTP is a property of `Admin` accounts (the administrators themselves), not a feature for
realm users. The Admin schema includes:

- `totp_enabled` — boolean
- `totp_secret` — Base32-encoded secret (read-only on GET, omitted on PUT)
- `totp_auth_url` — otpauth:// URL for QR code (read-only on GET, omitted on PUT)

The TOTP endpoints are realm-scoped operations for admins who authenticate via
`userpass` in that realm. Three operations per realm:

| Operation | Endpoint | Trigger |
|-----------|----------|---------|
| Generate | `POST /realms/{realm_id}/totp/generate` | Admin initiates TOTP enrollment for themselves |
| Verify + enable | `POST /realms/{realm_id}/totp/verify` | Admin confirms they scanned the QR code |
| Disable | `DELETE /realms/{realm_id}/totp/{username}` | Admin removes their own 2FA (or another admin they administer removes it) |

Key constraints:
1. **No list endpoint.** No way to browse who has TOTP enabled. Status is only visible on
   the Admins page as a badge/indicator on the admin row.
2. **Two-step enrollment.** Generate returns secret + URL. Verify requires a TOTP code.
   The flow must be managed in a modal or inline without page reload.
3. **Scope:** TOTP actions for a specific admin are available in the Admins page context
   (edit an admin, toggle TOTP). The realm selector determines which realm's TOTP endpoints
   are called (the realm where the admin has a `userpass` credential).

Given these constraints, the TOTP page as a standalone destination is redundant with the
Admins page. TOTP management should be inline with admin management.

**Option A — TOTP on the Admins page**
Add a "TOTP" column/badge to the admin list. Clicking "Enable" on an admin row opens a
modal for the two-step generate → verify flow. "Disable" is an action button.
Pro: TOTP status is visible alongside admins; no separate navigation.
Con: the Admins page becomes more complex.

**Option B — Keep a dedicated TOTP page**
The TOTP sidebar item remains. The page has a username input to select an admin, shows
their TOTP status, and offers enable/disable buttons with the flow modal.
Pro: clear separation of admin CRUD from TOTP management.
Con: requires an extra admin fetch just to look up TOTP status; feels thin.

**Recommendation:** Option A — TOTP actions belong on the Admins page. The TOTP sidebar
item should be removed; the page is redundant once Admins is fully implemented.

**Question:** Should TOTP management be inline on the Admins page (A) or on a separate TOTP
page (B)?

**Answer:** TOTP page stays as a placeholder. The current API lacks the necessary endpoints
to build a proper client-facing TOTP management page (`totp_enabled` is not on `UserPass`,
no client list with TOTP status exists). The admin's own `totp_enabled` field (on `Admin`)
is handled as part of the Admins page (see Q12). The TOTP sidebar item remains a placeholder
until the API is reworked to expose per-realm client TOTP status.

---

## Q11 — Login page and AuthContext

The `AuthContext` is currently a stub: `isAuthenticated` is hardcoded to `true`, `username`
is hardcoded to `"admin"`, and `login`/`logout` are no-ops. The app has no login page.

The authentication flow against the server is:

1. `POST /login?realm=_` with `Authorization: Basic <base64(username:password)>`
2. Response is `AuthenticationResult` with `next_step`:
   - `Authenticated` — session cookie `_ea_` is set, `session_id` present. Done.
   - `TotpRequired` — re-submit the same request with `totp_code` filled in.
   - `ChangePassword` — login succeeded but password has expired. Admin must change it
     before proceeding (no dedicated change-password endpoint currently exists — see note).
3. Session is stored server-side. The `_ea_` cookie is HttpOnly/Secure/SameSite=Strict —
   the UI never sees its value. Logout is handled by revoking the session server-side.

Key UX decisions:

1. **Login page route** — `/login` should be a public route (no auth required), redirecting
   to `/` on success. All other routes redirect to `/login` when unauthenticated.

2. **TOTP challenge** — when `next_step: TotpRequired`, the login form stays open and reveals
   a 6-digit code input inline. No page navigation. Re-submits to the same endpoint with
   `totp_code` populated.

3. **`ChangePassword` state** — no `PUT /admins/{id}/password` endpoint exists. The only
   way to change a password is `PUT /admins/{admin_id}` (full replace) or
   `PUT /realms/{realm_id}/userpass/{username}`. The UI cannot complete a change-password
   flow without knowing the admin's `id`. A dedicated endpoint would be cleaner — flag
   as a server-side gap, block the flow with a message for now.

4. **Session persistence** — the `_ea_` cookie is HttpOnly so JS cannot read it. The UI
   cannot verify session validity on page load by inspecting the cookie. Instead, call
   `GET /whoami?realm=_` on mount: a 200 means authenticated (use the returned claims to
   populate `AuthContext`), a 401 means redirect to login.

5. **Logout** — call `DELETE /sessions` with the current session ID, then clear local
   state and redirect to `/login`. The `session_id` is returned in `AuthenticationResult`
   on login and must be stored in `AuthContext` state.

   > **`session_id` is safe to store in JS:** it is `hex(SHA-256(cookie_value))` — a hash
   > of the JWT, not the JWT itself. It cannot be replayed as a Bearer token. It is purely
   > a lookup handle for the session store. XSS reading it from memory is the only residual
   > risk, which is unavoidable for any JS state.

6. **Session expiry tracking** — `GET /whoami?realm=_` returns JWT claims including `exp`
   (Unix timestamp). Store `exp` in `AuthContext` on login/mount. A client-side timer can
   redirect to `/login` when `Date.now()/1000 >= exp`. Forced server-side revocations are
   caught by 401 responses from any subsequent API call — no polling needed.

**Recommendation:**
- Add a `/login` page with username + password fields, an inline TOTP code step, and an
  error state for invalid credentials.
- `AuthContext` stores `{ isAuthenticated, username, sessionId }`. Populated from
  `GET /whoami` on mount or from the login response.
- `ChangePassword` renders an error message pointing the admin to the Credentials page
  as a workaround until a dedicated endpoint exists.
- A `ProtectedRoute` wrapper redirects unauthenticated users to `/login`.

**Question:** Is the `ChangePassword` workaround acceptable for now, and should the login
page be a full-page route or a modal overlay?

**Answer:** `ChangePassword` workaround is acceptable for now — display an error message
pointing the admin to the Credentials page. Full-page route for `/login` (not a modal).

> **Dev mode workaround:** When `VITE_USE_MOCKS=true` (already used by MSW), `AuthContext`
> bypasses the login flow entirely and injects hardcoded values. The mock admin must be a
> **super-admin with access to at least one concrete realm** to exercise all UI branches:
>
> ```ts
> // Injected AuthContext in mock mode
> {
>   isAuthenticated: true,
>   username: "admin",
>   sessionId: "dev-session-id",
>   exp: Math.floor(Date.now() / 1000) + 86400, // 24h from now
>   realms: ["_", "my-realm"],  // super-admin + realm-admin branch
> }
> ```
>
> This allows testing:
> - Super-admin mode (`_` selected): full admin list, Realms management, unfiltered sessions
> - Realm-admin mode (`my-realm` selected): Admins create form, Credentials, TOTP placeholder
> - Exclusive-ownership rule satisfied for `my-realm`: Admins item visible in realm-admin mode
>
> The `/login` route redirects immediately to `/` in mock mode. MSW handlers mock
> `GET /whoami` and `GET /admins/realms` to return matching data.

---

## Q12 — Admin form fields

The `Admin` schema has the following fields:

| Field | Type | Notes |
|-------|------|-------|
| `id` | `string` | Immutable after creation |
| `realms` | `string[]` | Realms this admin manages; `["_"]` = super admin |
| `userpass` | `string \| null` | FK into userpass table (username, not password) |
| `jwt` | `string \| null` | JWT subject claim for JWT auth |
| `fido2` | `string \| null` | FIDO2 credential identifier |
| `digital_credentials` | `object \| null` | Map of credential identifiers |
| `client_certificate` | `string \| null` | mTLS certificate fingerprint |
| `totp_enabled` | `boolean \| null` | Whether TOTP 2FA is active |
| `totp_secret` | `string \| null` | Read-only; base32 secret |
| `totp_auth_url` | `string \| null` | Read-only; otpauth:// URL |

**Key questions for the create/edit form:**

1. **Which auth method fields to expose?** The UI targets super admins. All auth methods
   are plausible, but `fido2`, `digital_credentials`, and `client_certificate` require
   infrastructure (hardware keys, mTLS certs) that is hard to manage via a web form.
   `userpass` and `jwt` are string fields that can be typed directly.

2. **`realms` field:** A multi-select from the realms the current admin can administer.
   Super admins see all realms + the `_` option. Realm admins see only their realms.

3. **`totp_enabled` on the form:** Read-only status badge in the admin list; enable/disable
   actions handled via the TOTP flow modal (see Q10). Not a direct form toggle.

4. **`totp_secret` / `totp_auth_url`:** Read-only, shown in a TOTP enrollment modal only.
   Never editable directly.

**Recommendation:**
- **Create form:** `id` (text), `realms` (multi-select), `userpass` (text, optional),
  `jwt` (text, optional). `fido2`, `digital_credentials`, `client_certificate` hidden
  behind an "Advanced" expandable section — present but not prominent.
- **Edit form:** Same fields. `id` is read-only. `totp_enabled` shown as a status badge
  with a separate "Manage TOTP" action button.
- `totp_secret` and `totp_auth_url` never appear in the form directly.

**Question:** Should `fido2`, `digital_credentials`, and `client_certificate` be in the
form at all (hidden in Advanced), or omitted entirely as out-of-scope for now?

**Answer:** Omit `fido2`, `digital_credentials`, and `client_certificate` from the form
entirely — these require dedicated enrollment flows (hardware interaction for FIDO2, mTLS
cert provisioning for client certificates) that a web form cannot facilitate. They may be
added later if needed.

On PUT, the form must **silently preserve** these fields — read the full `Admin` object on
load, hold `fido2`, `digital_credentials`, and `client_certificate` in local state, and
include them unchanged in the PUT body to avoid data loss. The visible form only exposes:
`id` (read-only on edit), `realms` (multi-select), `userpass` (text, optional), `jwt`
(text, optional), `totp_enabled` (read-only badge with Manage TOTP action).

---

## Q13 — Route guards

Three access scenarios require handling:

1. **Unauthenticated user** hits any protected route.
2. **Authenticated realm admin** hits `/realms` (super-admin only for writes).
3. **Authenticated realm admin** hits `/admins` when exclusive-ownership rule is not
   satisfied for the current realm (no admins to manage there).

**Option A — Silent redirect** to `/` or `/login`. No explanation.
**Option B — Inline 403 result page** using Ant Design `<Result status="403" />` with a
   message and a back button. URL stays unchanged.
**Option C — Redirect with toast notification** explaining why access was denied.

**Recommendation:**
- Unauthenticated → silent redirect to `/login` (A). Standard, expected behaviour.
- Authenticated but unauthorized → inline `<Result status="403" />` (B). URL remains
  meaningful, message is clear, no redirect logic needed to guess a destination.

**Question:** For unauthorized-but-authenticated access, silent redirect (A), 403 result
page (B), or redirect with toast (C)?

**Answer:** Split approach:
- **Unauthenticated:** redirect to `/login` (A).
- **Authenticated but unauthorized:** render inline `<Result status="403" />` (B) —
  the URL stays, the reason is explicit, and no destination-guessing logic is needed.

> **Implementation note:** A `ProtectedRoute` wrapper handles unauthenticated redirects.
> Per-page authorization (e.g. `/realms` super-admin check, `/admins` ownership check)
> is evaluated inside the page component using `RealmContext` and renders the 403 result
> in place of the page content when access is denied. No separate route-level guard needed
> for authorization — only for authentication.

---

## Interview complete

All questions answered. The full design is captured above. Refer to
`/memories/repo/admin-ui-ux-decisions.md` for the decision summary.
