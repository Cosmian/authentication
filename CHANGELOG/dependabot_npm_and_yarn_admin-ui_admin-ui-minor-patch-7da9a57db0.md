## Bug Fixes

- Restore the `overrides` block (`ws`, `esbuild`, `js-yaml`, `postcss` security pins) that Dependabot dropped from `admin-ui/pnpm-lock.yaml` while bumping the admin-ui minor/patch group, which made every Admin UI CI job fail its frozen install with `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH` and would have unpinned those packages.
- Regenerate the `admin-ui.pnpm.*` Nix hashes for the updated lockfile, which Dependabot left stale and would have broken the Nix admin-ui build and packaging.

## CI

- Add an `admin-ui-lockfile` pre-commit hook running a frozen, lockfile-only `pnpm install` when admin-ui's `package.json`, `pnpm-lock.yaml` or `pnpm-workspace.yaml` change, and document the check in the admin-ui agent instructions, so a lockfile out of sync with `package.json` is caught before commit instead of failing every Admin UI CI job.
- Exclude `pnpm-lock.yaml` from the `yamlfmt` pre-commit hook, which rewrote pnpm's long keys into explicit `? :` form that pnpm reverts on every install, and flatten the nested backlog list in the admin-ui agent instructions, on whose indentation markdownlint and prettier disagreed so no commit touching that file could pass both hooks.
- Label admin-ui Dependabot PRs with the existing `frontend` label instead of `admin-ui`, which does not exist in the repository and made Dependabot post a warning on every PR.

## Docs

- Document how to regenerate the `admin-ui.pnpm.*` Nix hashes after a lockfile change in `AGENTS.md`, the expected-hashes README and the admin-ui agent instructions, since they were missing from all of them and Dependabot lockfile bumps leave them stale.
