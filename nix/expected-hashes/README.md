# Expected Hashes

This directory stores expected SHA-256 hashes for deterministic build verification.

## Files

### Cargo vendor hashes

Used by `nix/auth-verifier.nix` to verify reproducible Cargo vendoring:

- `server.vendor.static.sha256` — Cargo vendor hash for static builds
- `server.vendor.dynamic.sha256` — Cargo vendor hash for dynamic builds

### Binary hashes

Generated after a successful build and used for cross-run determinism checks:

- `auth-verifier.<static|dynamic|static-saml>.<arch>.<os>.sha256`

`static-saml` is the SAML build (`auth-verifier-static-saml`); it shares the Cargo vendor
hash of the static build because `Cargo.lock` is the same.

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
