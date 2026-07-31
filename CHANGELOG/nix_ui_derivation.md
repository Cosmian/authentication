## Features

- Add `nix/admin-ui.nix`: a reproducible Nix derivation that builds the `admin-ui/` React/TypeScript/Vite frontend using `pnpm_9.fetchDeps` for hermetic offline dependency fetching, producing a `dist/` output that can be built independently with `nix-build -A admin-ui`.
- Bundle the admin-ui static assets into the Docker image at `/srv/admin-ui/` by adding an optional `adminUi` parameter to `nix/docker.nix`; a build-time check in `extraCommands` fails the build if `/srv/admin-ui/index.html` is missing.
- Bundle the pre-built admin UI in DEB and RPM packages under `/usr/share/auth_verifier/admin-ui/` so the installed server can serve it out of the box; previously the UI was only available in the Docker image.
- Implement AppRole authentication endpoints (role CRUD, secret-id generation/destruction, token generation) and remove the Nginx reverse-proxy layer; the server now directly serves all auth endpoints.
- The Docker image entrypoint now generates self-signed TLS certificates at container startup (instead of embedding a pre-generated private key at build time), using a writable `/etc/cosmian/dev/` directory created in `extraCommands`.
- Docker image default port changed from HTTPS 8443 to HTTPS 8080 with runtime-generated self-signed certs; `ExposedPorts` metadata updated accordingly.
- Added `openssl` to the Docker image runtime environment to support certificate generation at startup.

## Bug Fixes

- Scope `destroy_secret_id` deletion to `(role_name, accessor)` across all database backends (SQLite, PostgreSQL, MySQL) to prevent cross-role accessor revocation (IDOR / CWE-639).
- Fix `create_vault_role` in SQLite backend to use `ON CONFLICT (role_name) DO UPDATE SET` instead of `INSERT OR REPLACE`, preventing cascade deletion of `vault_secret_ids` and `vault_tokens` when a role is updated.
- Set binary permissions to `0755` (from `0500`) in DEB and RPM packaging metadata so the `auth_verifier` binary is executable by the service user.
- Remove `actions/checkout@v6` step from Docker-container packaging-test jobs; Docker containers lack a git binary and the REST API fallback does not support submodules, causing the checkout step to fail.
- Move `/etc/cosmian/dev/` directory creation from Nix `buildEnv` (read-only) to `extraCommands` (writable image layer) so the Docker entrypoint can write runtime-generated TLS certificates.
- Fix `chown root:cosmian` in systemd packaging test to `chown root:root` since the `cosmian` group does not exist on GitHub runners.
- Make staged admin-ui files writable via `chmod -R u+w` before `rm -rf` in packaging scripts, handling Nix store read-only permissions.

## Refactor

- Simplified `pkg/deb/postinst`: removed cosmian user/group creation and data directory setup; the service now runs as `root` with systemd-managed directories.
- Changed `pkg/auth_verifier.service`: run as `root` (was `cosmian`), replaced `ReadWritePaths` with `StateDirectory=cosmian-auth`, added `WorkingDirectory=/var/lib/cosmian-auth`.

## CI

- Add pnpm store hashes for admin-ui on all platforms (`admin-ui.pnpm.darwin.sha256`, `admin-ui.pnpm.linux-x86_64.sha256`, `admin-ui.pnpm.linux-aarch64.sha256`).
- Add `verify_running_ui.sh`: a CI helper script that checks a running auth_verifier serves `/admin-ui/index.html`, a hashed JS/CSS asset, and `/public/version` — used by both systemd and Docker-container test jobs.
- Add systemd service start + admin UI verification step in `packaging-tests.yml` with TLS cert generation at `/etc/cosmian/`.
- Add Docker-container admin UI verification step in `packaging-tests.yml` for all distros (Ubuntu, Debian, Rocky Linux) with in-container TLS cert generation.
- Add admin UI asset presence checks to DEB and RPM smoke tests (`smoke_test_deb.sh`, `smoke_test_rpm.sh`).
- Add `build_admin_ui()` to `package_common.sh` that builds the admin-ui Nix derivation and stages its output where `cargo-deb` and `cargo-generate-rpm` resolve asset globs.
- Update `test_docker_image.sh`: auto-detect HTTPS vs HTTP mode, detect premature container exit, and use `docker rm -f` for cleanup.
- Add `[tls_params]` and self-signed cert generation to all CI test configurations (systemd and Docker-container jobs) so the server can start with TLS in CI.

## Security

- Removed the self-signed TLS certificate and private key that were baked into the Docker image at build time; TLS certs are now generated ephemerally at container startup so no private key is ever embedded in the public image.
