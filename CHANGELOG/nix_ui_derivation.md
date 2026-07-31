## Features

- Add `nix/admin-ui.nix`: a reproducible Nix derivation that builds the `admin-ui/` React/TypeScript/Vite frontend using `pnpm_9.fetchDeps` for hermetic offline dependency fetching, producing a `dist/` output; expose it as a top-level `admin-ui` attribute in `default.nix`.
- Bundle admin-ui static assets into the Docker image at `/srv/admin-ui/` by adding an optional `adminUi` parameter to `nix/docker.nix`; a build-time check in `fakeRootCommands` verifies `/srv/admin-ui/index.html` is present.
- Bundle the pre-built admin UI in DEB and RPM packages under `/usr/share/auth_verifier/admin-ui/` by adding asset path entries to `server/Cargo.toml`.
- Docker image entrypoint now generates self-signed TLS certificates at container startup instead of baking a pre-generated private key into the image at build time; `openssl` is added to the runtime environment and `/etc/cosmian/dev/` is created as a writable directory via `fakeRootCommands`.

## Bug Fixes

- Use OS-assigned port (`TcpListener::bind("127.0.0.1:0")`) in test server setup instead of an atomic counter, preventing port conflicts and "Address already in use" failures in parallel or panicked tests.
- Add `Drop` implementation for `TestsContext` that stops the test server on panic, preventing port leaks that would cause subsequent tests to fail.
- Change `test_server` host binding from `"localhost"` to `"127.0.0.1"` to avoid IPv6 resolution issues on some CI runners.
- Move `/etc/cosmian/dev/` directory creation from Nix `buildEnv` (read-only) to `fakeRootCommands` (fakeroot-writable layer) so the Docker entrypoint can write runtime-generated TLS certificates.
- Fix `chown root:cosmian` in systemd packaging test to `chown root:root` since the `cosmian` group does not exist on GitHub runners.
- Make staged admin-ui files writable via `chmod -R u+w` before `rm -rf` in packaging scripts, handling read-only Nix store permissions.

## Refactor

- Change `pkg/auth_verifier.service` to run as `root` (was `cosmian`), replace `ReadWritePaths` with `StateDirectory=cosmian-auth`, and add `WorkingDirectory=/var/lib/cosmian-auth`.
- Simplify `pkg/deb/postinst`: remove cosmian user/group creation and data directory setup; only run `systemctl daemon-reload` when systemd is detected.
- Docker image default port changed from `8443/tcp` to `8080/tcp`.

## CI

- Add pnpm store hashes for admin-ui on all platforms (`admin-ui.pnpm.darwin.sha256`, `admin-ui.pnpm.linux-x86_64.sha256`, `admin-ui.pnpm.linux-aarch64.sha256`).
- Add `verify_running_ui.sh`: a CI helper that checks a running auth_verifier serves `/admin-ui/index.html`, a hashed JS/CSS asset, and `/public/version` — used by both systemd and Docker-container test jobs.
- Add systemd service start + admin UI verification step in `packaging-tests.yml` with TLS cert generation at `/etc/cosmian/`.
- Add Docker-container admin UI verification step in `packaging-tests.yml` for all distros (Ubuntu, Debian, Rocky Linux) with in-container TLS cert generation.
- Add admin UI asset presence checks to DEB and RPM smoke tests (`smoke_test_deb.sh`, `smoke_test_rpm.sh`).
- Add `build_admin_ui()` to `package_common.sh` that builds the admin-ui Nix derivation and stages its output for `cargo-deb` and `cargo-generate-rpm` asset resolution.
- Update `test_docker_image.sh`: auto-detect HTTPS vs HTTP, detect premature container exit, use `docker rm -f` for cleanup.

## Security

- Remove the self-signed TLS certificate and private key that were baked into the Docker image at build time; TLS certs are now generated ephemerally at container startup so no private key is ever embedded in the public image.
