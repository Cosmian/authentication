# Authentication Admin UI

## Development

- `pnpm dev` starts the SPA against a live auth server proxied by Vite. By default, the proxy target is `https://localhost:8443`.
- `pnpm dev:mock` starts the SPA with browser-side mocked responses for the current shell endpoints, so no auth server is required.

## Mock Mode

Mock mode is intentionally limited to local development.

- It intercepts `GET /admin/realms` and `GET /public/version` with MSW.
- It does not replace the normal real-backend development flow.
- The worker is registered from `/mockServiceWorker.js` so it can intercept the root-relative API paths used by the app.

If the worker script changes, refresh it with `pnpm msw init public --no-interactive`.