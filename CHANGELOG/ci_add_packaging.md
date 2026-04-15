## Bug Fixes

- Remove unused `tokio` dev-dependency from `auth_client` and unused `base32` dependency from `auth_server` (cargo-machete)
- Add `.cargo/audit.toml` ignoring RUSTSEC-2023-0071 (`rsa` Marvin Attack — transitive via `sqlx-mysql`, no upstream fix available)
- Add `.github/reusable_scripts/get_openssl_binaries.sh` stub so the shared `clippy.yml` reusable workflow passes; `auth_server` uses vendored OpenSSL and does not need pre-built binaries
- Fix `packaging.yml` job `if` conditions: remove `github.event_name == 'workflow_call'` guards (inside a reusable workflow `github.event_name` reflects the caller's original event, not `workflow_call`); `publish-release` now only runs on tag pushes
- Fix GPG signing failure in all packaging jobs: `build_deb`/`build_rpm`/`package_dmg.sh` set `export HOME="${TMPDIR}"` for Cargo, causing GPG to use a fresh empty keyring; fix by re-importing the key from `$GPG_SIGNING_KEY` with passphrase in `gpg_sign_file()` and the DMG inline signing block
- Fix `aws-lc-sys v0.39.1` build failure on aarch64 Linux: `pkgs234` (nixpkgs 22.05) defaults to gcc-9.3.0 on aarch64 which is rejected due to a memcmp bug ([GCC PR#95189](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189)); use `platform.gcc11` instead in `nix/auth-server.nix` buildPhase CC/CXX exports on aarch64

## CI

- Add Nix-based CI/CD infrastructure for Cosmian Authentication Server: `default.nix`, `shell.nix`, `nix/auth-server.nix`, `nix/docker.nix`, pinned nixpkgs (glibc 2.34, Rocky Linux 9 compatibility) and rust-overlay (Rust 1.94.1)
- Add packaging scripts: `nix.sh` (main CI entrypoint), `package_common.sh`, `package_deb.sh`, `package_rpm.sh`, `package_dmg.sh` with GPG signing support
- Add smoke test scripts for DEB, RPM, DMG packages; add Docker image test script
- Add packaging workflows: `.github/workflows/packaging.yml` (DEB/RPM/DMG/Docker, Linux AMD64/ARM, macOS) and `.github/workflows/packaging-tests.yml` (install tests across Ubuntu/Debian/Rocky Linux containers)
- Add `.github/workflows/main_base.yml` reusable workflow: clippy, cargo-deny, cargo-machete, cargo test matrix, packaging
- Add `[package.metadata.deb]`, `[package.metadata.generate-rpm]`, and `[package.metadata.packager]` to `server/Cargo.toml` for DEB, RPM, and DMG packaging
- Add `pkg/auth_server.service` systemd unit and `pkg/deb/postinst` install script
- Add `.pre-commit-config.yaml` (mirrors KMS repo) and install pre-commit hooks on `ci/add_packaging` branch
- Add `AGENTS.md` following the KMS repository structure
- Pin rust-overlay to commit `a313afc` (Rust 1.94.1); use `cargoLock.lockFile` with `outputHashes` for `cosmian_logger` git dependency; set `auditable = false` to bypass cargo-auditable Rust 2024 edition limitation
- Record darwin arm64 static binary hash in `nix/expected-hashes/auth-server.static.arm64.darwin.sha256`
