#!/usr/bin/env bash
# Smoke-test for the macOS DMG package
set -euo pipefail

DMG_FILE="${1:-}"
if [ -z "$DMG_FILE" ] || [ ! -f "$DMG_FILE" ]; then
  echo "Usage: $0 <path/to/auth_server.dmg>" >&2
  exit 1
fi

echo "==========================================="
echo "Smoke-testing DMG: $DMG_FILE"
echo "==========================================="

MOUNT_POINT=$(mktemp -d)
trap 'hdiutil detach "$MOUNT_POINT" 2>/dev/null || true; rm -rf "$MOUNT_POINT"' EXIT

hdiutil attach "$DMG_FILE" -mountpoint "$MOUNT_POINT" -nobrowse -quiet

BIN=$(find "$MOUNT_POINT" -type f -name 'auth_server' | head -1)
if [ -z "$BIN" ]; then
  echo "ERROR: auth_server binary not found in DMG $DMG_FILE" >&2
  exit 1
fi
echo "Binary: $BIN"

file "$BIN"
otool -L "$BIN" || true

echo "==========================================="
echo "Smoke test PASSED for $DMG_FILE"
echo "==========================================="
