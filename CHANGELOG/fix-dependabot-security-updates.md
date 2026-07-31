## Bug Fixes

- **Added pnpm overrides to resolve three Dependabot security advisories that blocked automatic security updates**: `js-yaml` was pinned to the deprecated v5.2.1 which could not reach the patched v5.2.2; `postcss` was constrained to v8.5.10 by vite; `brace-expansion` v1.1.14 was pulled in by minimatch@3 via eslint. All three are now resolved to patched versions (`js-yaml@5.2.2`, `postcss@8.5.25`, `brace-expansion@5.0.9`) via `pnpm.overrides`.

## CI

- **Created `.github/dependabot.yml`** to enable weekly Dependabot version updates for the `admin-ui` npm workspace with proper labels.
