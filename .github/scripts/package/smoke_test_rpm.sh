#!/usr/bin/env bash
# Smoke-test for the auth_verifier RPM package
set -euo pipefail

RPM_FILE="${1:-}"
if [ -z "$RPM_FILE" ] || [ ! -f "$RPM_FILE" ]; then
  echo "Usage: $0 <path/to/auth_verifier.rpm>" >&2
  exit 1
fi

TMPDIR_EXTRACT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_EXTRACT"' EXIT

echo "==========================================="
echo "Smoke-testing RPM: $RPM_FILE"
echo "==========================================="

# Extract RPM
rpm2cpio "$RPM_FILE" | cpio -idmv -D "$TMPDIR_EXTRACT" 2>/dev/null || true
BIN=$(find "$TMPDIR_EXTRACT" -type f -name 'auth_verifier' | head -1)
if [ -z "$BIN" ]; then
  echo "ERROR: auth_verifier binary not found inside $RPM_FILE" >&2
  exit 1
fi
echo "Binary: $BIN"

file "$BIN"
readelf -h "$BIN" | head -20 || true

MAX_GLIBC=$(readelf -sW "$BIN" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -V | tail -n1 || true)
if [ -n "$MAX_GLIBC" ]; then
  echo "Max GLIBC: GLIBC_$MAX_GLIBC"
  if [ "$(printf '%s\n' "$MAX_GLIBC" "2.34" | sort -V | tail -n1)" != "2.34" ]; then
    echo "ERROR: GLIBC $MAX_GLIBC > 2.34 — not compatible with Rocky Linux 9" >&2
    exit 1
  fi
  echo "GLIBC version check PASSED ($MAX_GLIBC <= 2.34)"
fi

INTERP=$(readelf -l "$BIN" | sed -n 's/^.*interpreter: \(.*\)]$/\1/p' || true)
if echo "$INTERP" | grep -q "/nix/store/"; then
  echo "ERROR: ELF interpreter is in Nix store: $INTERP" >&2
  exit 1
fi
echo "ELF interpreter: ${INTERP:-<none / statically linked>}"

# Admin UI check: the pre-built UI must be bundled at /usr/share/auth_verifier/admin-ui
UI_INDEX=$(find "$TMPDIR_EXTRACT" -type f -path '*/usr/share/auth_verifier/admin-ui/index.html' | head -1)
if [ -z "$UI_INDEX" ]; then
  echo "ERROR: admin UI index.html not found under usr/share/auth_verifier/admin-ui in $RPM_FILE" >&2
  exit 1
fi
UI_FILES=$(find "$(dirname "$UI_INDEX")" -type f | wc -l)
echo "Admin UI check PASSED ($UI_FILES files at usr/share/auth_verifier/admin-ui/)"

echo "==========================================="
echo "Smoke test PASSED for $RPM_FILE"
echo "==========================================="
