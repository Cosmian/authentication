# Expected Hashes

This directory stores expected SHA-256 hashes for deterministic build verification.

## Files

### Cargo vendor hashes

Used by `nix/auth-verifier.nix` to verify reproducible Cargo vendoring:

- `server.vendor.static.sha256` — Cargo vendor hash for static builds
- `server.vendor.dynamic.sha256` — Cargo vendor hash for dynamic builds

### Admin UI pnpm hashes

Used by `nix/admin-ui.nix` to verify the pnpm dependency fetch:

- `admin-ui.pnpm.<linux-x86_64|linux-aarch64|darwin>.sha256` — always the same
  value on all three platforms, because `fetchDeps` fetches every platform's packages

### Binary hashes

Generated after a successful build and used for cross-run determinism checks:

- `auth-verifier.<static|dynamic>.<arch>.<os>.sha256`

## How to update

When `Cargo.lock` changes (new or updated dependency), the vendor hashes become
stale. To regenerate:

```bash
# 1. Put a fake hash to trigger hash mismatch error
echo "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" > nix/expected-hashes/server.vendor.static.sha256

# 2. Run nix-build; it will fail with: got: sha256-...
nix-build -I nixpkgs="$(grep url default.nix | head -1 | sed 's/.*"\(.*\)".*/\1/')" -A auth-verifier-static 2>&1 | grep "got:"

# 3. Copy the correct hash into the file
```

Repeat for `server.vendor.dynamic.sha256`.

When `admin-ui/pnpm-lock.yaml` changes (including Dependabot PRs), regenerate
the admin UI hash once and write it to all three files, without a trailing newline:

```bash
printf 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' > nix/expected-hashes/admin-ui.pnpm.linux-x86_64.sha256
nix-build -A admin-ui --no-out-link 2>&1 | grep "got:"
for p in linux-x86_64 linux-aarch64 darwin; do printf '<got hash>' > nix/expected-hashes/admin-ui.pnpm.$p.sha256; done
```
