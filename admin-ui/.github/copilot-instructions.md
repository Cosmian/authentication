# Authentication Admin UI — Copilot Instructions

## Project Overview

React 19 + TypeScript SPA for administering the Authentication Server.
Super-admin audience only. The `_` realm (labeled "Admin") is always present and is the default selection.

Stack: React 19, Vite 7, Ant Design 5, Tailwind CSS 4, React Router 7, pnpm.

## Project Structure

```
admin-ui/
├── src/
│   ├── main.tsx                  # Entry point: createRoot, StrictMode, BrowserRouter
│   ├── App.tsx                   # ConfigProvider, Providers, Routes, MainLayout
│   ├── styles.css                # Tailwind import + global styles
│   ├── menuItems.tsx             # Sidebar navigation definitions
│   ├── constants/
│   │   └── apiPaths.ts           # Centralized API path constants
│   ├── contexts/
│   │   ├── AuthContext.tsx        # Authentication state (stub for now)
│   │   └── RealmContext.tsx       # Global realm selector state
│   ├── components/
│   │   └── layout/
│   │       ├── MainLayout.tsx     # Layout shell: Header + Sidebar + Content + Footer
│   │       ├── Header.tsx         # Title, realm selector, dark mode toggle
│   │       ├── Sidebar.tsx        # Ant Design Menu, collapsible
│   │       └── Footer.tsx         # Server version
│   └── pages/
│       ├── DashboardPage.tsx      # Landing page
│       ├── PlaceholderPage.tsx    # Reusable "Coming soon"
│       └── NotFoundPage.tsx       # 404
├── tests/
│   ├── unit/                     # Vitest + Testing Library (jsdom)
│   │   ├── setup.ts
│   │   ├── contexts/
│   │   ├── components/
│   │   └── pages/
│   ├── integration/              # Vitest (node env), real API
│   └── e2e/                      # Playwright
├── vitest.unit.config.ts         # (in tests/)
├── vitest.int.config.ts          # (in tests/)
└── playwright.config.ts
```

## TDD Workflow (mandatory)

1. **Write the test first** describing desired behavior. Include at least one error/edge case.
2. **Run the test** — confirm it fails (red).
3. **Implement** minimal code to pass.
4. **Run the test** — confirm it passes (green).
5. **Refactor** if needed, re-run tests.

## Coding Rules

- **Max 80 lines per function**. Split into helpers if exceeded.
- **No `any` type**. Use `unknown` + type guards when the type is genuinely unknown.
- **No `console.log`** in committed code. Use `console.error` for caught exceptions only in development.
- **All errors must be handled**. Never swallow errors silently.
- **One component per file**. File name matches the exported component name.
- **Props interfaces exported** alongside the component. Default exports for page components only; named exports for everything else.
- **Import order**: react → third-party → local absolute → relative. Enforced by ESLint.
- **No hardcoded API paths**. Use `constants/apiPaths.ts`.

## State Management

- **React Context** for global state: realm selection (`RealmContext`), authentication (`AuthContext`).
- **Local `useState`/`useReducer`** for component-specific state.
- No Redux, Zustand, or other state libraries.

## Error Handling Strategy

- **Transient errors** (network failures, timeouts, 5xx): Use `message.error("...")` from Ant Design. These are toast-style notifications that auto-dismiss.
- **Persistent state errors** (no data, permission denied, 4xx): Use inline `<Alert type="error" />` from Ant Design. These remain visible until the user takes action.
- **Never swallow errors silently**. Every `catch` block must either display feedback to the user or re-throw.

## Ant Design Usage

- Use **theme tokens** via `ConfigProvider`. No inline color values.
- Use `<Form>` component for all user input.
- Use `<Spin>` for loading states.
- Use `<Result>` for empty/error states on full pages.

## Naming Conventions

- **PascalCase**: Components, types, interfaces (`RealmContext`, `DashboardPage`)
- **camelCase**: Functions, variables, hooks (`useRealm`, `fetchRealms`)
- **kebab-case**: Route paths (`/credentials`, `/admin-ui`)
- **SCREAMING_SNAKE**: Constants (`API_REALMS`, `API_VERSION`)

## Test Rules

- Every component **must** have a corresponding test file.
- Every test **must** assert at least one error or edge case (not just happy path).
- Test naming: `describe("ComponentName") > it("should [behavior] when [condition]")`
- Mock API calls with `vi.fn()` / `vi.spyOn()` — never hit real servers in unit tests.
- Use `@testing-library/react` for rendering and assertions.
- Prefer `getByRole`, `getByText`, `getByTestId` over CSS selectors.

## Build & Test Commands

```sh
pnpm install          # Install dependencies
pnpm dev              # Start dev server (port 5173)
pnpm build            # Type-check + production build
pnpm preview          # Serve production build locally
pnpm lint             # ESLint
pnpm format           # Prettier
pnpm test:unit        # Vitest unit tests (jsdom)
pnpm test:integration # Vitest integration tests (node)
pnpm test:e2e         # Playwright E2E tests
pnpm test             # Alias for test:unit
```

## Key Domain Concepts

- **Realm**: Isolated auth domain. The `_` realm is the admin realm, always present, displayed as "Admin".
- **User**: An administrator record. Users have a `realms` list determining what they may administer.
- **Super admin**: User with `"_"` in their realms list. Can administer everything.
- **Session**: Server-side record. The `_ea_` cookie is an opaque lookup key.
- **UserPass**: Username/password credential scoped to a realm.
- **TOTP**: Time-based one-time password (2FA) per user per realm.

## Auth Server Endpoints (for proxy config and API calls)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/login?realm={id}` | Authenticate |
| GET | `/whoami?realm={id}` | Session introspection |
| GET/POST/DELETE | `/sessions/session/...` | Session management |
| POST/GET/PUT/DELETE | `/admin/realm/...` | Realm CRUD |
| POST/GET/PUT/DELETE | `/users/user/...` | User CRUD |
| POST/GET/PUT/DELETE | `/realms/{realm}/userpass/...` | Credential CRUD |
| POST/DELETE | `/realms/{realm}/totp/...` | TOTP management |
| GET | `/public/version` | Server version |
