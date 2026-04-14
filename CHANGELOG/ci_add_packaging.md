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
