# Bug Fixes

- Regenerated `admin-ui/pnpm-lock.yaml` so the `pnpm.overrides` block declared in `package.json` is recorded in the lockfile, fixing the `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH` failure in the `pnpm install --frozen-lockfile` CI job.
- Set `NIX_CURL_FLAGS` with a standard browser User-Agent in packaging workflow steps to prevent HTTP 403 errors when Nix's `fetchurl` downloads crates from crates.io CDN during `nix-build`.
- Wrapped `fetchurl` in `importCargoLock` with `curlOptsList` to inject a browser User-Agent at the curl command level inside the Nix builder, fixing crates.io HTTP 403 errors that blocked all Packaging jobs.
- Updated expected pnpm deps hashes for Linux x86_64 and aarch64 platforms to match the regenerated `pnpm-lock.yaml`.
