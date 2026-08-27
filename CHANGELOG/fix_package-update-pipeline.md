# Bug Fixes

- Regenerated `admin-ui/pnpm-lock.yaml` so the `pnpm.overrides` block declared in `package.json` is recorded in the lockfile, fixing the `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH` failure in the `pnpm install --frozen-lockfile` CI job.
