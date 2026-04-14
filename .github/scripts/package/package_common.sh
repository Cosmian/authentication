#!/usr/bin/env bash
# Common packaging logic for Cosmian Authentication Server
# Builds auth_server via Nix and packages it with cargo-deb / cargo-generate-rpm.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
source "$REPO_ROOT/.github/scripts/common.sh"
cd "$REPO_ROOT"

FORMAT=""
LINK="static"

usage() {
  echo "Usage: $0 --format deb|rpm [--link static|dynamic]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
  -f | --format)
    FORMAT="${2:-}"
    shift 2 || true
    ;;
  -l | --link)
    LINK="${2:-}"
    shift 2 || true
    ;;
  -h | --help) usage ;;
  *) shift ;;
  esac
done

case "$FORMAT" in
deb | rpm) : ;;
*)
  echo "Error: --format must be 'deb' or 'rpm'" >&2
  usage
  ;;
esac
case "$LINK" in
static | dynamic) : ;;
*)
  echo "Error: --link must be 'static' or 'dynamic'" >&2
  exit 1
  ;;
esac

# Persistent Cargo cache for offline runs
OFFLINE_CARGO_HOME="$REPO_ROOT/target/cargo-offline-home"

# ── Pre-warm Cargo registry ─────────────────────────────────────────────────

prewarm_cargo_registry() {
  if [ -n "${NO_PREWARM:-}" ]; then return; fi
  ensure_modern_rust
  mkdir -p "$OFFLINE_CARGO_HOME"
  export CARGO_HOME="$OFFLINE_CARGO_HOME"
  echo "Prewarming Cargo registry…"
  cargo fetch --locked || true
}

# ── Build server via Nix ────────────────────────────────────────────────────

build_or_reuse_server() {
  local attr
  if [ "$LINK" = "dynamic" ]; then
    attr="auth-server-dynamic-openssl"
  else
    attr="auth-server-static-openssl"
  fi

  OUT_LINK="$REPO_ROOT/result-server-${LINK}"

  nix-build -I "nixpkgs=${PIN_URL}" "$REPO_ROOT/default.nix" -A "$attr" -o "$OUT_LINK"
  REAL_SERVER=$(readlink -f "$OUT_LINK" || echo "$OUT_LINK")
  BIN_OUT="$REAL_SERVER/bin/auth_server"

  if [ ! -f "$BIN_OUT" ]; then
    echo "ERROR: auth_server binary not found at $BIN_OUT" >&2
    exit 1
  fi
  echo "Server binary: $BIN_OUT"
}

# ── Stage binary where cargo-deb/rpm expect it ─────────────────────────────

stage_binary() {
  local host_triple
  host_triple=$(rustc -vV 2>/dev/null | awk '/host:/ {print $2}' || echo "")
  mkdir -p "server/target/release" "target/release"
  if [ -n "$host_triple" ]; then
    mkdir -p "server/target/${host_triple}/release"
    cp -f "$BIN_OUT" "server/target/${host_triple}/release/auth_server"
  fi
  cp -f "$BIN_OUT" "server/target/release/auth_server"
  cp -f "$BIN_OUT" "target/release/auth_server"
}

# ── GPG signing ────────────────────────────────────────────────────────────

gpg_sign_file() {
  local file="$1"
  if [ -n "${GPG_SIGNING_KEY:-}" ] && command -v gpg >/dev/null 2>&1; then
    echo "GPG-signing: $file"
    gpg --batch --yes --detach-sign --armor "$file"
  fi
}

# ── DEB packaging ───────────────────────────────────────────────────────────

build_deb() {
  export HOME="${TMPDIR:-/tmp}"
  export CARGO_HOME="$HOME/cargo-home"
  mkdir -p "$CARGO_HOME"

  if command -v cargo-deb >/dev/null 2>&1; then
    CARGO_DEB="cargo-deb"
  else
    ensure_modern_rust
    cargo install cargo-deb --locked || true
    CARGO_DEB="cargo deb"
  fi

  VERSION_STR=$(bash "$REPO_ROOT/.github/scripts/release/get_version.sh")
  OUT_DIR="$REPO_ROOT/result-deb-${LINK}"
  mkdir -p "$OUT_DIR"

  echo "Building DEB for auth_server v${VERSION_STR} (link=$LINK)…"
  pushd "$REPO_ROOT/server" >/dev/null

  # shellcheck disable=SC2086
  $CARGO_DEB \
    --no-build \
    --target "$(rustc -vV 2>/dev/null | awk '/host:/ {print $2}')" \
    -p auth_server \
    --output "$OUT_DIR/"

  popd >/dev/null

  DEB_FILE=$(find "$OUT_DIR" -maxdepth 1 -name '*.deb' | head -1)
  if [ -z "$DEB_FILE" ]; then
    echo "ERROR: DEB file not found in $OUT_DIR" >&2
    exit 1
  fi

  # Compute SHA256
  sum=$(sha256sum "$DEB_FILE" | awk '{print $1}')
  echo "$sum  $(basename "$DEB_FILE")" >"$DEB_FILE.sha256"
  echo "Built DEB: $DEB_FILE (sha256: $sum)"

  gpg_sign_file "$DEB_FILE"
}

# ── RPM packaging ───────────────────────────────────────────────────────────

build_rpm() {
  export HOME="${TMPDIR:-/tmp}"
  export CARGO_HOME="$HOME/cargo-home"
  mkdir -p "$CARGO_HOME"

  VERSION_STR=$(bash "$REPO_ROOT/.github/scripts/release/get_version.sh")
  OUT_DIR="$REPO_ROOT/result-rpm-${LINK}"
  mkdir -p "$OUT_DIR"

  echo "Building RPM for auth_server v${VERSION_STR} (link=$LINK)…"
  pushd "$REPO_ROOT" >/dev/null

  # Use cargo-generate-rpm from Nix derivation
  CARGO_GENERATE_RPM_BIN=""
  if command -v cargo-generate-rpm >/dev/null 2>&1; then
    CARGO_GENERATE_RPM_BIN="cargo-generate-rpm"
  else
    RPM_FROM_NIX=$(nix-build -I "nixpkgs=${PIN_URL}" --option substituters "" "$REPO_ROOT/default.nix" -A cargoGenerateRpmTool --no-out-link 2>/dev/null || true)
    if [ -n "$RPM_FROM_NIX" ] && [ -x "$RPM_FROM_NIX/bin/cargo-generate-rpm" ]; then
      CARGO_GENERATE_RPM_BIN="$RPM_FROM_NIX/bin/cargo-generate-rpm"
    else
      ensure_modern_rust
      cargo install cargo-generate-rpm --version "0.16.0" --locked || true
      CARGO_GENERATE_RPM_BIN="cargo-generate-rpm"
    fi
  fi

  "$CARGO_GENERATE_RPM_BIN" \
    -p server \
    -o "$OUT_DIR/"

  popd >/dev/null

  RPM_FILE=$(find "$OUT_DIR" -maxdepth 1 -name '*.rpm' | head -1)
  if [ -z "$RPM_FILE" ]; then
    echo "ERROR: RPM file not found in $OUT_DIR" >&2
    exit 1
  fi

  sum=$(sha256sum "$RPM_FILE" | awk '{print $1}')
  echo "$sum  $(basename "$RPM_FILE")" >"$RPM_FILE.sha256"
  echo "Built RPM: $RPM_FILE (sha256: $sum)"

  gpg_sign_file "$RPM_FILE"
}

# ── Main ─────────────────────────────────────────────────────────────────────

prewarm_cargo_registry || true
build_or_reuse_server
stage_binary

if [ "$FORMAT" = "deb" ]; then
  build_deb
elif [ "$FORMAT" = "rpm" ]; then
  build_rpm
fi
