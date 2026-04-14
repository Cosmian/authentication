#!/usr/bin/env bash
# Build macOS DMG for Cosmian Authentication Server via cargo-packager inside nix-shell.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
cd "$REPO_ROOT"
source "$REPO_ROOT/.github/scripts/common.sh"

LINK="static"
while [ $# -gt 0 ]; do
  case "$1" in
  -l | --link)
    LINK="${2:-}"
    shift 2 || true
    ;;
  *) shift ;;
  esac
done

# Only supported on macOS
if [ "$(uname)" != "Darwin" ]; then
  echo "Error: DMG packaging is only supported on macOS." >&2
  exit 1
fi

ensure_macos_sdk_env
ensure_macos_frameworks_ldflags

VERSION_STR=$(bash "$REPO_ROOT/.github/scripts/release/get_version.sh")

# Build or reuse server binary via Nix
if [ "$LINK" = "dynamic" ]; then
  ATTR="auth-server-dynamic-openssl"
else
  ATTR="auth-server-static-openssl"
fi
OUT_LINK="$REPO_ROOT/result-server-${LINK}"
nix-build -I "nixpkgs=${PIN_URL}" -A "$ATTR" -o "$OUT_LINK"
REAL_OUT=$(readlink -f "$OUT_LINK" || echo "$OUT_LINK")
BIN_OUT="$REAL_OUT/bin/auth_server"

# Stage binary
HOST_TRIPLE=$(rustc -vV 2>/dev/null | awk '/host:/ {print $2}' || echo "")
mkdir -p "server/target/release" "target/release"
[ -n "$HOST_TRIPLE" ] && mkdir -p "server/target/$HOST_TRIPLE/release" && cp -f "$BIN_OUT" "server/target/$HOST_TRIPLE/release/auth_server"
cp -f "$BIN_OUT" "server/target/release/auth_server"
cp -f "$BIN_OUT" "target/release/auth_server"

export HOME="${TMPDIR:-/tmp}"
export CARGO_HOME="$HOME/cargo-home"
mkdir -p "$CARGO_HOME"
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

echo "Building DMG for auth_server v${VERSION_STR} (link=${LINK})…"

# Use cargo-packager if available
if command -v cargo-packager >/dev/null 2>&1; then
  PACKAGER="cargo-packager"
else
  echo "cargo-packager not found; install it first or add it to nix shell" >&2
  exit 1
fi

$PACKAGER \
  --manifest-path server/Cargo.toml \
  --release \
  --formats dmg

OUT_DIR="$REPO_ROOT/result-dmg-${LINK}"
mkdir -p "$OUT_DIR"
find "$REPO_ROOT" -maxdepth 4 -name '*.dmg' -newer "$REPO_ROOT/Cargo.toml" 2>/dev/null | while IFS= read -r dmg; do
  cp -f "$dmg" "$OUT_DIR/"
  sum=$(shasum -a 256 "$dmg" | awk '{print $1}')
  echo "$sum  $(basename "$dmg")" >"$OUT_DIR/$(basename "$dmg").sha256"
  echo "Built DMG: $dmg (sha256: $sum)"
done

# GPG sign
if [ -n "${GPG_SIGNING_KEY:-}" ] && command -v gpg >/dev/null 2>&1; then
  find "$OUT_DIR" -name '*.dmg' | while IFS= read -r dmg; do
    gpg --batch --yes --detach-sign --armor "$dmg"
  done
fi
