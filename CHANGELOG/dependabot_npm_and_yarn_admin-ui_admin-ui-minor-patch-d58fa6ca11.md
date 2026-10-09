## Bug Fixes

- Bumped 16 `admin-ui` minor/patch dependencies (React 19.3, react-router 8.4, antd 6.6.5, Vite 8.3.3, Vitest 5.0.3, ESLint 10.12, Prettier 3.9.9 and others) and restored the `overrides:` block that Dependabot dropped from `pnpm-lock.yaml`, so the `ws`/`esbuild`/`js-yaml`/`postcss` security floors stay enforced and `pnpm install --frozen-lockfile` no longer fails.
- Updated the `admin-ui` pnpm dependency hashes in `nix/expected-hashes/` so the Nix build matches the new lockfile.
