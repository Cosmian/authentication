## Refactor

- Remove MSW-based mock mode (`pnpm dev:mock`) from the admin-ui: delete `src/mocks/` directory (handlers, fixtures, browser worker, init logic), `public/mockServiceWorker.js`, `.env.mock`, and the unit test that only covered the mock bootstrap, because the real auth server can be started trivially via `cargo run -p auth_server -- server/auth_server.dev.toml` and the test suites (unit + e2e) never relied on MSW.
- Remove `isMockMode()`, `MOCK_STATE`, and all `VITE_USE_MOCKS`/`VITE_MOCK_USER` branches from `AuthContext.tsx` and `vite.config.ts` to simplify the auth bootstrapping path to a single real-server flow.
- Remove `msw` from `devDependencies` and the `"msw": { "workerDirectory": [...] }` config block from `package.json`; remove `dev:mock` script.
- Update `README.md` and `DEV_GUIDE.md` to remove all mock mode documentation.
