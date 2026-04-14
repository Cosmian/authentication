# Cosmian Authentication Server — AI Agent Instructions

> **Purpose of this file**: Single source of truth for any AI agent
> (Copilot, Cursor, Cline, Claude Code, etc.) working on the Cosmian Authentication
> Server codebase. It explains project structure, build commands, CI workflows,
> coding conventions, and troubleshooting steps.

Cosmian Authentication Server is a high-performance authentication and session
management server written in **Rust**. It supports multiple database backends
(SQLite, PostgreSQL, MySQL), TOTP two-factor authentication, JWT-based sessions,
and a Redis session store.

---

## 1. Build & test cheatsheet

```bash
# ── Build ────────────────────────────────────────────────────────────────
cargo build                          # default features (OpenSSL, database)
cargo build --features rustls        # use rustls instead of OpenSSL

# ── Test ─────────────────────────────────────────────────────────────────
cargo test --workspace --lib         # run all library tests
cargo test -p auth_server            # single crate

# ── Lint ─────────────────────────────────────────────────────────────────
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# ── Run locally ──────────────────────────────────────────────────────────
cargo run --bin auth_server -- auth_server.toml

# ── Smoke-test (expect 200 or 404, not 500) ─────────────────────────────
curl -s http://localhost:9005/health
```

### Pre-commit hooks

Always install and never bypass pre-commit hooks:

```sh
pip install pre-commit conventional-pre-commit
pre-commit install
pre-commit install --install-hooks -t commit-msg
```

Never use `git commit --no-verify` or `SKIP=...` to bypass hooks. Fix the
underlying issues instead.

---

## 2. Workspace layout

```text
client/             auth_client  — authentication client library
server/             auth_server  — server binary + lib
  src/
    main.rs         — binary entry point
    lib.rs          — library root
    database/       — database trait and backends (SQLite, PostgreSQL, MySQL)
    middleware/     — auth/JWT/session middleware
    response/       — HTTP response types
    server/         — server startup and config
    session/        — session management
    tests/          — integration tests
    tls/            — TLS helpers

nix/                Nix build expressions and expected vendor hashes
  auth-server.nix   — Nix derivation for auth_server binary
  docker.nix        — Docker image derivation
  expected-hashes/  — expected sha256 hashes for reproducible builds
  signing-keys/     — GPG public keys for package verification

.github/
  scripts/          — CI and packaging scripts
    common.sh       — shared bash helpers
    nix.sh          — unified entrypoint for CI commands
    release/        — version extraction and hash update scripts
    package/        — DEB / RPM / DMG packaging scripts
    test/           — test scripts (sqlite, psql, docker)
  workflows/        — GitHub Actions workflows
  reusable_scripts/ — git submodule: shared scripts with Cosmian/reusable_scripts

default.nix         — top-level Nix derivation (pins nixpkgs, builds auth-server)
shell.nix           — Nix development shell
Cargo.toml          — workspace manifest
```

---

## 3. Crate features

| Feature            | Default | Effect                                                      |
| ------------------ | ------- | ----------------------------------------------------------- |
| `openssl`          | **on**  | Use OpenSSL (vendored) for TLS; required for most deploys   |
| `rustls`           | off     | Use rustls instead of OpenSSL                               |
| `database`         | **on**  | Compile all database backends (SQLite, PostgreSQL, MySQL)   |
| `no_jwt_validation`| off     | Skip JWT expiry/issuer checks — **dev/test only**           |

---

## 4. Key file map

| Intent                          | File(s)                                      |
| ------------------------------- | -------------------------------------------- |
| Server startup                  | `server/src/main.rs`, `server/src/lib.rs`    |
| Server config struct            | `server/src/server/`                         |
| HTTP routes & handlers          | `server/src/server/`                         |
| Auth middleware (JWT, session)  | `server/src/middleware/`                     |
| Database trait & backends       | `server/src/database/`                       |
| Session management              | `server/src/session/`                        |
| TOTP support                    | `server/src/totp.rs`                         |
| Nix derivation                  | `nix/auth-server.nix`                        |
| Nix top-level                   | `default.nix`                                |
| CI/packaging entrypoint         | `.github/scripts/nix.sh`                     |
| Packaging scripts (DEB/RPM/DMG) | `.github/scripts/package/`                  |
| Test scripts                    | `.github/scripts/test/`                      |

---

## 5. Nix derivation

`nix/auth-server.nix` builds the `auth_server` binary targeting glibc 2.34
(Rocky Linux 9 compatibility) on Linux. It uses:

- **Pinned nixpkgs** `8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296` (matches KMS repo)
- **nixpkgs 22.05** (glibc 2.34) as the Linux stdenv
- **Rust 1.86.0** via rust-overlay
- **Vendored OpenSSL** (compiled during cargo build, no external OpenSSL needed)
- `cmake` and `perl` as native build inputs (required by `aws-lc-sys` and openssl crate)

No FIPS / non-FIPS variants — the auth server has a single build variant.

```bash
# Build static binary
nix-build -A auth-server-static

# Build dynamic binary
nix-build -A auth-server-dynamic

# Build Docker image (Linux only)
nix-build -A docker-image
```

---

## 6. Packaging

```bash
# Full packaging via nix.sh:
bash .github/scripts/nix.sh --link static package       # DEB + RPM on Linux, DMG on macOS
bash .github/scripts/nix.sh --link static package deb   # DEB only
bash .github/scripts/nix.sh --link static package rpm   # RPM only
bash .github/scripts/nix.sh --link static package dmg   # DMG only (macOS)

# Docker (Linux only):
bash .github/scripts/nix.sh docker --load
```

### Expected hashes (`nix/expected-hashes/`)

| File                                        | Purpose                                    |
| ------------------------------------------- | ------------------------------------------ |
| `server.vendor.static.sha256`               | Cargo vendor hash for static builds        |
| `server.vendor.dynamic.sha256`              | Cargo vendor hash for dynamic builds       |
| `auth-server.<link>.<arch>.<os>.sha256`     | Expected binary hash for determinism check |

When `Cargo.lock` changes, the vendor hashes become stale. Regenerate:

```bash
# Put fake hash, run build, read "got:" error, paste correct hash
echo "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" > nix/expected-hashes/server.vendor.static.sha256
nix-build -A auth-server-static 2>&1 | grep "got:"
```

---

## 7. CI overview

All CI runs go through `.github/scripts/nix.sh`:

```bash
bash .github/scripts/nix.sh [--link static|dynamic] COMMAND [args]
```

| Command              | Description                                     |
| -------------------- | ----------------------------------------------- |
| `test`               | Run all tests in nix-shell                      |
| `test sqlite`        | SQLite backend tests only                       |
| `test psql`          | PostgreSQL backend tests (requires server)      |
| `package`            | Build all packages for this platform            |
| `package deb`        | Build Debian package                            |
| `package rpm`        | Build RPM package                               |
| `package dmg`        | Build macOS DMG (macOS only)                    |
| `docker [opts]`      | Build Docker image tarball (Linux only)         |
| `update-hashes`      | Regenerate expected binary hashes               |

### Workflow files

| Workflow                  | Purpose                                              |
| ------------------------- | ---------------------------------------------------- |
| `main.yml`                | Push/PR trigger; calls `main_base.yml`               |
| `main_base.yml`           | clippy, cargo-deny, cargo-test, packaging            |
| `packaging.yml`           | Multi-platform packaging (Linux/ARM/macOS) + Docker  |
| `packaging-tests.yml`     | Install packages in Docker containers and verify     |

### Database test environment

For PostgreSQL tests:

| Variable         | Value                                      |
| ---------------- | ------------------------------------------ |
| `POSTGRES_HOST`  | `127.0.0.1`                                |
| `POSTGRES_PORT`  | `5432`                                     |

---

## 8. GitHub CLI — reading issues, PRs, and CI failures

**Always use `GH_PAGER=cat`** to prevent interactive pager. The repository is
`Cosmian/authentication`.

```bash
GH_PAGER=cat gh issue view <number> --repo Cosmian/authentication
GH_PAGER=cat gh pr view <number> --repo Cosmian/authentication
GH_PAGER=cat gh pr checks <number> --repo Cosmian/authentication
GH_PAGER=cat gh run view <run-id> --repo Cosmian/authentication --log-failed
```

---

## 9. Coding rules

- **Function length**: keep functions under 100 lines; extract helpers for longer ones.
- **Imports**: Rust `use` statements go at the top of each file, never inline.
- **Error handling**: never ignore or skip errors in tests or builds — investigate and fix.
- **Commit scope**: minimal, focused changes. Do not refactor surrounding code alongside a bug fix.

---

## 10. Common issues

| Symptom                                                  | Cause                                              | Fix                                                  |
| -------------------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------- |
| `aws-lc-sys` / `cmake` build failure                     | Missing cmake/go in build env                      | Add `cmake` and `go` to nativeBuildInputs / shell.nix |
| Stale Nix vendor hashes after `Cargo.lock` change        | Expected hash is outdated                          | Regenerate with fake-hash trick (see §6)             |
| `tokenExpired` / JWT validation error                    | Feature `no_jwt_validation` disabled in prod       | Check configuration; check token TTL                 |
| `gh` command hangs                                       | Interactive pager opened                           | Use `GH_PAGER=cat gh ...`                            |
| Rocky Linux GLIBC compatibility error                    | Binary compiled against glibc > 2.34               | Ensure pkgs234 (glibc 2.34) stdenv is used in Nix   |
