# Authentication Admin UI — Agent Instructions

## Quick Reference

```sh
cd authentication/admin-ui
pnpm install          # Install dependencies
pnpm dev              # Dev server at http://localhost:5173/admin-ui/
pnpm build            # tsc -b && vite build
pnpm lint             # eslint . --fix
pnpm format           # prettier . --write
pnpm test:unit        # vitest --run -c tests/vitest.unit.config.ts
pnpm test:integration # vitest --run -c tests/vitest.int.config.ts
pnpm test:e2e         # playwright test
```

## Stack

React 19 · TypeScript 5.8 · Vite 7 · Ant Design 5 · Tailwind CSS 4 · React Router 7 · Vitest 4 · Playwright 1.59 · pnpm

## Project Structure

```
src/
├── main.tsx              # Entry: createRoot, StrictMode, BrowserRouter
├── App.tsx               # ConfigProvider, providers, routes
├── styles.css            # Tailwind + globals
├── menuItems.tsx         # Navigation tree (no realm — realm is in Header)
├── constants/apiPaths.ts # API path constants (never hardcode paths)
├── contexts/             # AuthContext (stub), RealmContext (global realm selector)
├── components/layout/    # MainLayout, Header, Sidebar, Footer
└── pages/                # DashboardPage, PlaceholderPage, NotFoundPage
tests/
├── unit/                 # Vitest + @testing-library/react (jsdom)
├── integration/          # Vitest (node env), real server
└── e2e/                  # Playwright (chromium)
```

## TDD Workflow (mandatory for all new features)

1. Write failing test (red) — include error/edge cases, not just happy path
2. Implement minimal code (green)
3. Refactor, re-run tests
4. Add E2E test after unit tests pass

## Coding Rules

- Max **80 lines per function**
- No `any` — use `unknown` + type guards
- No `console.log` in committed code
- One component per file, props interface exported
- Default exports for pages only; named exports for everything else
- Import order: react → third-party → local absolute → relative
- **Avoid use of `useMemo`** — performance is not a concern for this app, and memoising async side-effects (e.g. `validateFields`) causes hard-to-diagnose stale-value bugs. Use plain variables or `useEffect` instead.

## Error Handling

- **Transient** (network, timeout, 5xx): `message.error("...")` toast
- **Persistent** (no data, 4xx, permission denied): inline `<Alert type="error" />`
- Never swallow errors silently

## Key Domain Concepts

- **Realm `_`** = Admin realm, always present, displayed as "Admin"
- **Super admin** = Admin with `"_"` in realms list
- **Session** = server-side, `_ea_` cookie is opaque lookup key
- All realm-scoped API paths include `/realms/{realm_id}/...`

## Auth Server Proxy (dev)

Target: `https://localhost:8443`
Proxied paths: `/login`, `/whoami`, `/sessions`, `/realms`, `/admins`, `/public`
Options: `secure: false`, `changeOrigin: true`

## Test Regression Policy

Per component, always test:

- ✅ Happy path (valid props/data)
- ❌ Error state (API failure, network error)
- 🈳 Empty state (no data)

## Changelog & Formatting (mandatory after every change)

### Changelog

Every agent-driven change **must** be recorded in the **single per-branch** changelog file
under `CHANGELOG/` at the **workspace root** (not inside `admin-ui/`).

- **File name**: `CHANGELOG/<branch-name>.md` — one file per branch, named after the current
  git branch with any `/` replaced by `_` (e.g. branch `spire` → `CHANGELOG/spire.md`).
  **Never** create a new file per change (no `<short_slug>.md` files).
- **Append, don't proliferate**: add each new entry as a bullet under the appropriate
  category heading in the existing branch file. Create the file only if it does not yet exist.
- **Format**: one or more category headings (`## Features`, `## Bug Fixes`, `## Refactor`,
  `## CI`, `## Docs`, `## Tests`) with bullet points. Keep the file clear and compact:
  merge related bullets, avoid duplication, and group same-category changes together.
- Each bullet must be a single complete sentence summarising **what** changed and **why**, sufficient for a human to understand without reading the diff.
- Do not add a changelog entry for pure formatting/linting-only commits.

### Formatting (frontend)

After every edit to `.ts` / `.tsx` files in `admin-ui/`, run from the `admin-ui/` directory:

```bash
pnpm lint      # eslint --fix
pnpm format    # prettier --write
```

Both commands auto-fix issues in place. Re-check for any remaining ESLint errors that cannot be auto-fixed and resolve them manually.

- ⏳ Loading state (spinner/skeleton)
- 🚫 Boundary (long strings, special chars, max items)
- 🔄 State transition (e.g., realm switch triggers refresh)

Coverage target: statements ≥80%, branches ≥75%

## Dark Mode

- Always pair `darkTheme` in `theme.ts` with `algorithm: theme.darkAlgorithm`. Never override tokens alone — derived tokens (`colorTextSecondary`, status/alert palette) are only computed correctly when the dark algorithm runs.
- Never hardcode `theme="light"` on Ant Design components (e.g., `Sider`, `Menu`). Derive from the app's `isDarkMode` prop/state: `theme={isDarkMode ? "dark" : "light"}`.
- Never use bare light-only Tailwind color utilities (e.g., `border-gray-300`, `bg-yellow-100`, `text-gray-500`) without providing a dark counterpart via a conditional className based on `isDarkMode`: e.g., `` `${isDarkMode ? "border-gray-600" : "border-gray-300"}` ``.
- Prefer Ant Design theme tokens over Tailwind color utilities for any color that must adapt to the theme.
- Do NOT use Tailwind's `dark:` prefix — the app does not add a `dark` class to `<html>`; theme is controlled via Ant Design's `ConfigProvider`.

## Backlog / Technical Debt

- **Remove remaining `useMemo` calls** — the following files still use `useMemo` for API factory instances and derived lists; replace with plain variable declarations on the next pass:
    - `src/pages/RealmsPage.tsx` — `const api = useMemo(...)`
    - `src/pages/AdminsPage.tsx` — `const api = useMemo(...)`
    - `src/pages/CredentialsPage.tsx` — `const api = useMemo(...)`
    - `src/pages/SessionsPage.tsx` — `const api = useMemo(...)`
    - `src/components/realms/RealmFormDrawer.tsx` — `const api = useMemo(...)`
    - `src/components/layout/Sidebar.tsx` — `const filteredItems = useMemo(...)`
