## CI

- Add `nix/admin-ui.nix`: a reproducible Nix derivation that builds the
  `admin-ui/` React/TypeScript/Vite frontend using `pnpm_9.fetchDeps` for
  hermetic offline dependency fetching and `stdenv.mkDerivation` to run
  `pnpm run build`, producing a `dist/` output.
- Add real pnpm store hash `nix/expected-hashes/admin-ui.pnpm.darwin.sha256`
  (`sha256-YvJWPL8Pyfybw4dh+GuWjpe8xOtaR0WUfTTR75910Oo=`) obtained by
  bootstrapping `nix-build -A admin-ui`; the Linux hash remains a placeholder
  to be bootstrapped on a Linux builder.
- Add placeholder hash file `nix/expected-hashes/admin-ui.pnpm.linux.sha256`
  to be bootstrapped on a Linux CI runner.

## Features

- Expose `admin-ui` as a top-level attribute in `default.nix` so it can be
  built independently with `nix-build -A admin-ui`.
- Bundle the admin-ui static assets into the Docker image at `/srv/admin-ui/`
  by adding an optional `adminUi` parameter to `nix/docker.nix`; existing
  callers that omit the parameter are unaffected.
- Add a Docker image build-time check in `nix/docker.nix` `extraCommands` that
  fails the build if `/srv/admin-ui/index.html` is missing when `adminUi` is
  provided, and prints the file count on success.
