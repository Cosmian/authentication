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
cargo test -p auth_verifier            # single crate

# ── Lint ─────────────────────────────────────────────────────────────────
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# ── Run locally ──────────────────────────────────────────────────────────
cargo run --bin auth_verifier -- auth_verifier.toml

# ── Smoke-test (expect 200 or 404, not 500) ─────────────────────────────
curl -s http://localhost:8443/health
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
server/             auth_verifier  — server binary + lib
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
  auth-verifier.nix   — Nix derivation for auth_verifier binary
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

default.nix         — top-level Nix derivation (pins nixpkgs, builds auth-verifier)
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
| **OpenAPI schema**              | **`server/documentation/openapi.yaml`**      |
| Nix derivation                  | `nix/auth-verifier.nix`                        |
| Nix top-level                   | `default.nix`                                |
| CI/packaging entrypoint         | `.github/scripts/nix.sh`                     |
| Packaging scripts (DEB/RPM/DMG) | `.github/scripts/package/`                  |
| Test scripts                    | `.github/scripts/test/`                      |

---

## 4a. API contract — keeping server, client and OpenAPI schema in sync

`server/documentation/openapi.yaml` is the **authoritative API contract**. Every
change that touches a route, request body, response body, or authentication
requirement **must** be reflected in all three layers at the same time:

```text
server/src/server/endpoints/   ←→   client/src/   ←→   server/documentation/openapi.yaml
```

### What must stay in sync

| Layer | What to check |
| ----- | ------------- |
| **Server routes** (`server/src/server/endpoints/*.rs`) | HTTP method, URL path, path parameters, query parameters, request body type, response status codes |
| **Server app** (`server/src/server/auth_verifier.rs`) | Scope prefix + middleware stack (which routes require `cookieAuth`) |
| **Client DTOs** (`client/src/dto/`, `client/src/models/`) | Struct field names and types that are serialized/deserialized over the wire |
| **Client methods** (`client/src/client/auth_client.rs`) | URL format strings, HTTP methods, request/response types |
| **OpenAPI schema** (`server/documentation/openapi.yaml`) | Paths, parameter names, schema component field names, security requirements, examples |

### Rules for agents

1. **Route change** (add, rename, remove a path or HTTP method):
   - Update the actix-web `#[get/post/put/delete("...")]` macro in the endpoint file.
   - Update `auth_verifier.rs` scope registration if the path prefix changes.
   - Update the matching URL format string in `auth_client.rs`.
   - Add/rename/delete the corresponding path entry in `openapi.yaml`.

2. **Request or response body change** (add, rename, or remove a field):
   - Update the Rust struct in `client/src/dto/` or `client/src/models/`.
   - Update the matching `components/schemas/` entry in `openapi.yaml`.
   - Update any inline examples in `openapi.yaml` that use the changed field.

3. **Authentication change** (a route gains or loses an auth requirement):
   - Update the middleware wrap chain in `auth_verifier.rs`.
   - Update the `security:` list on the corresponding path in `openapi.yaml`.

4. **New endpoint**:
   - Add the handler in the appropriate `*_endpoints.rs` file.
   - Register it in `auth_verifier.rs`.
   - Add the client method in `auth_client.rs`.
   - Add the full path entry (summary, operationId, parameters, requestBody,
     responses, security, example) in `openapi.yaml`.

### Schema field naming conventions

- Path parameter names in route macros (`/{realm_id}/`) must match the
  `name:` of the corresponding `$ref: '#/components/parameters/...'` entry.
- Rust struct field names are serialized as-is (no `#[serde(rename)]` unless
  explicitly needed). OpenAPI `properties` keys must match exactly.
- `password` in `UserPass` is always a `Vec<u8>` / integer array on the wire —
  returned as `[]` on reads; never echoed back.

### Verification checklist (run after any API change)

```bash
# 1. Build compiles cleanly
cargo build --workspace

# 2. All tests pass
cargo test --workspace --lib

# 3. No clippy warnings
cargo clippy --workspace --all-targets -- -D warnings

# 4. Manually cross-check openapi.yaml against the endpoint files:
grep -r '#\[get\|#\[post\|#\[put\|#\[delete' server/src/server/endpoints/
#    Every route macro must have a matching path in openapi.yaml.
```

---

## 5. Nix derivation

`nix/auth-verifier.nix` builds the `auth_verifier` binary targeting glibc 2.34
(Rocky Linux 9 compatibility) on Linux. It uses:

- **Pinned nixpkgs** `8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296` (matches KMS repo)
- **nixpkgs 22.05** (glibc 2.34) as the Linux stdenv
- **Rust 1.86.0** via rust-overlay
- **Vendored OpenSSL** (compiled during cargo build, no external OpenSSL needed)
- `cmake` and `perl` as native build inputs (required by `aws-lc-sys` and openssl crate)

No FIPS / non-FIPS variants — the auth server has a single build variant.

```bash
# Build static binary
nix-build -A auth-verifier-static

# Build dynamic binary
nix-build -A auth-verifier-dynamic

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
| `auth-verifier.<link>.<arch>.<os>.sha256`     | Expected binary hash for determinism check |

When `Cargo.lock` changes, the vendor hashes become stale. Regenerate:

```bash
# Put fake hash, run build, read "got:" error, paste correct hash
echo "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" > nix/expected-hashes/server.vendor.static.sha256
nix-build -A auth-verifier-static 2>&1 | grep "got:"
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

## 9. Changelog & formatting (mandatory after every change)

### Changelog

Every agent-driven change **must** be recorded in the **single per-branch** changelog file.

- **File name**: `CHANGELOG/<branch-name>.md` — one file per branch, named after the current
  git branch with any `/` replaced by `_` (e.g. branch `spire` → `CHANGELOG/spire.md`,
  branch `fix/user-to-admin` → `CHANGELOG/fix_user-to-admin.md`). **Never** create a new
  file per change (no `<short_slug>.md` files).
- **Append, don't proliferate**: add each new entry as a bullet under the appropriate
  category heading in the existing branch file. Create the file only if it does not yet exist.
- **Format**: one or more category headings (`## Features`, `## Bug Fixes`, `## Refactor`,
  `## CI`, `## Docs`, `## Tests`) with bullet points beneath. Keep the file clear and compact:
  merge related bullets, avoid duplication, and group all changes of the same category together.
- Each bullet must be a single complete sentence summarising **what** changed and **why**,
  sufficient for a human to understand without reading the diff.
- Do not add a changelog entry for pure formatting/linting-only commits.

```text
CHANGELOG/<branch_name>.md
```

### Formatting (Rust)

After every edit to `.rs` files, run:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

Fix all clippy warnings before considering the task complete.

---

## 10. Coding rules

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
