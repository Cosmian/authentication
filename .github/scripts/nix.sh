#!/usr/bin/env bash
# Unified entrypoint for authentication server CI: test and packaging workflows.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=.github/scripts/common.sh
source "$SCRIPT_DIR/common.sh"

# ── Usage ────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF

  Commands:
    docker [--force] [--load] [--test]
                       Build Docker image tarball (always static)
                       --force: Force rebuild, ignore cached result
                       --load:  Load image into Docker daemon
                       --test:  Run smoke-test after loading
    test [type]        Run tests inside nix-shell
      all              Run all available tests (default)
      sqlite           Run SQLite backend tests
      psql             Run PostgreSQL backend tests (requires running server)
    package [type]     Build packages via Nix
      deb              Build Debian package
      rpm              Build RPM package
      dmg              Build macOS DMG package
      (no type)        Build all supported packages for this platform
    update-hashes      Update expected binary hashes (release build)

  Global options:
    -l, --link <static|dynamic>   OpenSSL linkage (default: static)
                    static:  statically link OpenSSL (vendored in Rust crate)
                    dynamic: dynamically link system OpenSSL

  Examples:
    $0 test                           # all tests
    $0 test sqlite
    $0 test psql
    $0 --link static package
    $0 --link static package deb
    $0 --link dynamic package rpm
    $0 --link static package dmg     # macOS only
    $0 docker --load
    $0 docker --load --test
    $0 update-hashes
EOF
  exit 1
}

# ── Helpers ──────────────────────────────────────────────────────────────────

compute_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

resolve_pinned_nixpkgs_store() {
  local path
  if path=$(nix eval --raw "(builtins.fetchTarball \"${PINNED_NIXPKGS_URL}\")" 2>/dev/null); then
    :
  else
    path=$(nix-instantiate --eval -E "builtins.fetchTarball { url = \"${PINNED_NIXPKGS_URL}\"; }" | sed -e 's/\"//g') || path=""
  fi
  if [ -n "$path" ] && [ -e "$path" ]; then
    echo "$path"
    return 0
  fi
  return 1
}

prewarm_nixpkgs_and_tools() {
  if [ -n "${NO_PREWARM:-}" ]; then
    echo "Skipping prewarm (NO_PREWARM set)"
    return 0
  fi
  echo "Prewarming pinned nixpkgs into the store…"
  if ! resolve_pinned_nixpkgs_store >/dev/null; then
    nix-instantiate --eval -E "builtins.fetchTarball { url = \"${PINNED_NIXPKGS_URL}\"; }" >/dev/null
  fi
  local NIXPKGS_STORE
  NIXPKGS_STORE=$(resolve_pinned_nixpkgs_store || true)
  if [ -n "$NIXPKGS_STORE" ]; then
    export NIXPKGS_STORE
    echo "Pinned nixpkgs realized at: $NIXPKGS_STORE"
    if [ "$(uname)" = "Linux" ]; then
      nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; dpkg' --no-out-link >/dev/null 2>/dev/null || true
      nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; rpm' --no-out-link >/dev/null 2>/dev/null || true
      nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; cpio' --no-out-link >/dev/null 2>/dev/null || true
    fi
  fi
}

set_repo_root() {
  REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
  cd "$REPO_ROOT"
}

ensure_nix_path() {
  PINNED_NIXPKGS_URL="$PIN_URL"
  if [ -z "${NIX_PATH:-}" ]; then
    export NIX_PATH="nixpkgs=${PINNED_NIXPKGS_URL}"
  fi
}

# ── Argument parsing ─────────────────────────────────────────────────────────

parse_global_options() {
  LINK="static"
  COMMAND=""

  while [ $# -gt 0 ]; do
    case "$1" in
    -l | --link)
      LINK="${2:-}"
      shift 2 || true
      ;;
    docker | test | package | update-hashes)
      COMMAND="$1"
      shift
      break
      ;;
    -h | --help)
      usage
      ;;
    *)
      if [ -n "${COMMAND:-}" ]; then
        break
      fi
      echo "Unknown option: $1" >&2
      usage
      ;;
    esac
  done

  [ -z "${COMMAND:-}" ] && usage

  if [ "$COMMAND" = "package" ]; then
    RELEASE_FLAG="--release"
    BUILD_PROFILE="release"
  else
    RELEASE_FLAG=""
    BUILD_PROFILE="debug"
  fi

  export LINK RELEASE_FLAG BUILD_PROFILE
  REMAINING_ARGS=("$@")
}

resolve_command_args() {
  local -a args=()
  args=("$@")
  COMMAND_ARGS=()

  TEST_TYPE=""
  if [ "$COMMAND" = "test" ]; then
    if [ ${#args[@]} -eq 0 ]; then
      TEST_TYPE="all"
    else
      TEST_TYPE="${args[0]}"
      args=("${args[@]:1}")
    fi
  fi

  PACKAGE_TYPE=""
  if [ "$COMMAND" = "package" ]; then
    if [ ${#args[@]} -ge 1 ]; then
      PACKAGE_TYPE="${args[0]}"
      args=("${args[@]:1}")
    fi
  fi

  if [ "$COMMAND" = "test" ]; then
    export WITH_WGET=1
  fi

  COMMAND_ARGS=("${args[@]+"${args[@]}"}")
}

dispatch_command() {
  parse_global_options "$@"
  resolve_command_args ${REMAINING_ARGS[@]+"${REMAINING_ARGS[@]}"}

  case "$COMMAND" in
  docker)
    docker_command ${COMMAND_ARGS[@]+"${COMMAND_ARGS[@]}"}
    ;;
  test)
    test_command ${COMMAND_ARGS[@]+"${COMMAND_ARGS[@]}"}
    ;;
  package)
    package_command ${COMMAND_ARGS[@]+"${COMMAND_ARGS[@]}"}
    ;;
  update-hashes)
    update_hashes_command ${COMMAND_ARGS[@]+"${COMMAND_ARGS[@]}"}
    ;;
  *)
    echo "Error: Unknown command '$COMMAND'" >&2
    usage
    ;;
  esac
}

# ── Docker command ────────────────────────────────────────────────────────────

docker_command() {
  DOCKER_LOAD=false
  DOCKER_TEST=false
  DOCKER_FORCE=false
  while [ $# -gt 0 ]; do
    case "$1" in
    --force)
      DOCKER_FORCE=true
      shift
      ;;
    --load)
      DOCKER_LOAD=true
      shift
      ;;
    --test)
      DOCKER_TEST=true
      DOCKER_LOAD=true
      shift
      ;;
    --)
      shift
      break
      ;;
    *) break ;;
    esac
  done

  if [ "$(uname)" = "Darwin" ]; then
    echo "Error: Docker image builds require a Linux builder." >&2
    exit 1
  fi

  ATTR="docker-image"
  VERSION=$(bash "$REPO_ROOT/.github/scripts/release/get_version.sh")
  OUT_LINK="$REPO_ROOT/result-docker-static"

  if [ -n "${FORCE_REBUILD:-}" ]; then
    DOCKER_FORCE=true
  fi

  if [ "$DOCKER_FORCE" != true ] && [ -L "$OUT_LINK" ] && REAL_OUT=$(readlink -f "$OUT_LINK" || true) && [ -f "$REAL_OUT" ]; then
    echo "Reusing existing Docker image tarball at: $REAL_OUT (use --force to rebuild)"
  else
    echo "Building Docker image: attr=$ATTR -> $OUT_LINK"
    nix-build -I "nixpkgs=${PIN_URL}" -A "$ATTR" -o "$OUT_LINK"
    REAL_OUT=$(readlink -f "$OUT_LINK" || echo "$OUT_LINK")
    echo "Built Docker image tarball: $REAL_OUT"
  fi

  if [ "$DOCKER_LOAD" = true ]; then
    if command -v docker >/dev/null 2>&1; then
      echo "Loading image into Docker (from $REAL_OUT)…"
      docker load <"$REAL_OUT"

      if [ "$DOCKER_TEST" = true ]; then
        echo "Running Docker image tests..."
        DOCKER_IMAGE_NAME="cosmian-auth-verifier:${VERSION}"
        export DOCKER_IMAGE_NAME
        bash "$REPO_ROOT/.github/scripts/test/test_docker_image.sh"
      fi
    else
      echo "Warning: docker CLI not found; skipping --load" >&2
    fi
  fi

  exit 0
}

# ── Test command ─────────────────────────────────────────────────────────────

test_command() {
  case "$TEST_TYPE" in
  all)
    SCRIPT="$REPO_ROOT/.github/scripts/test/test_all.sh"
    ;;
  sqlite)
    SCRIPT="$REPO_ROOT/.github/scripts/test/test_sqlite.sh"
    ;;
  psql | postgres)
    SCRIPT="$REPO_ROOT/.github/scripts/test/test_psql.sh"
    ;;
  *)
    echo "Error: Unknown test type '$TEST_TYPE'" >&2
    echo "Valid types: all, sqlite, psql" >&2
    usage
    ;;
  esac

  export WITH_CURL=1

  KEEP_VARS=" \
    --keep POSTGRES_HOST --keep POSTGRES_PORT \
    --keep AUTH_DATABASE_URL \
    --keep WITH_WGET \
    --keep WITH_CURL \
    --keep LINK \
    --keep RELEASE_FLAG \
    --keep BUILD_PROFILE"

  # Run inside nix-shell
  # shellcheck disable=SC2086
  nix-shell -I "nixpkgs=${PIN_URL}" $KEEP_VARS "$REPO_ROOT/shell.nix" \
    --run "bash '$SCRIPT'"
}

# ── Package command ───────────────────────────────────────────────────────────

package_command() {
  case "$PACKAGE_TYPE" in
  "" | deb | rpm | dmg) : ;;
  *)
    echo "Error: Unknown package type '$PACKAGE_TYPE'" >&2
    usage
    ;;
  esac

  # macOS: DMG only via nix-shell (needs system tools: hdiutil, osascript)
  if [ "$(uname)" = "Darwin" ]; then
    local pkg_type="${PACKAGE_TYPE:-dmg}"
    if [ "$pkg_type" = "dmg" ]; then
      SCRIPT="$REPO_ROOT/.github/scripts/package/package_dmg.sh"
      nix-shell -I "nixpkgs=${PIN_URL}" --argstr variant "default" "$REPO_ROOT/shell.nix" \
        --run "bash '$SCRIPT' --link '$LINK'"
      OUT_DIR="$REPO_ROOT/result-dmg-$LINK"
      dmg_file=$(find "$OUT_DIR" -maxdepth 1 -type f -name '*.dmg' 2>/dev/null | head -n1 || true)
      if [ -n "${dmg_file:-}" ] && [ -f "$dmg_file" ]; then
        sum=$(compute_sha256 "$dmg_file")
        echo "$sum  $(basename "$dmg_file")" >"$dmg_file.sha256"
        echo "Wrote checksum: $dmg_file.sha256 ($sum)"
      fi
      exit 0
    fi
  fi

  ensure_nix_path
  prewarm_nixpkgs_and_tools || true

  NIXPKGS_STORE="${NIXPKGS_STORE:-}"
  NIXPKGS_ARG="$PINNED_NIXPKGS_URL"
  if [ -n "$NIXPKGS_STORE" ] && [ -e "$NIXPKGS_STORE" ]; then
    NIXPKGS_ARG="$NIXPKGS_STORE"
  fi

  # Determine which package types to build
  if [ -z "$PACKAGE_TYPE" ]; then
    TYPES="deb rpm"
  else
    TYPES="$PACKAGE_TYPE"
  fi

  for TYPE in $TYPES; do
    case "$TYPE" in
    deb)
      if [ "$(uname)" = "Linux" ]; then
        SCRIPT_LINUX="$REPO_ROOT/.github/scripts/package/package_deb.sh"
        nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p curl --run "bash '$SCRIPT_LINUX' --link '$LINK'"
        REAL_OUT="$REPO_ROOT/result-deb-$LINK"
        echo "Built deb ($LINK): $REAL_OUT"

        # Smoke test
        SMOKE_TEST="$REPO_ROOT/.github/scripts/package/smoke_test_deb.sh"
        DEB_FILE=$(find "$REAL_OUT" -maxdepth 1 -type f -name '*.deb' 2>/dev/null | head -n1 || true)
        if [ -n "${DEB_FILE:-}" ] && [ -f "$DEB_FILE" ] && [ -f "$SMOKE_TEST" ]; then
          nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p binutils file coreutils --run "bash '$SMOKE_TEST' '$DEB_FILE'" || {
            echo "ERROR: Smoke test failed for $DEB_FILE" >&2
            exit 1
          }
        fi
      else
        echo "DEB packaging is only supported on Linux." >&2
        exit 1
      fi
      ;;
    rpm)
      if [ "$(uname)" = "Linux" ]; then
        SCRIPT_LINUX="$REPO_ROOT/.github/scripts/package/package_rpm.sh"
        nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p curl --run "bash '$SCRIPT_LINUX' --link '$LINK'"
        REAL_OUT="$REPO_ROOT/result-rpm-$LINK"
        echo "Built rpm ($LINK): $REAL_OUT"

        SMOKE_TEST="$REPO_ROOT/.github/scripts/package/smoke_test_rpm.sh"
        RPM_FILE=$(find "$REAL_OUT" -maxdepth 1 -type f -name '*.rpm' 2>/dev/null | head -n1 || true)
        if [ -n "${RPM_FILE:-}" ] && [ -f "$RPM_FILE" ] && [ -f "$SMOKE_TEST" ]; then
          nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p binutils file coreutils rpm cpio --run "bash '$SMOKE_TEST' '$RPM_FILE'" || {
            echo "ERROR: Smoke test failed for $RPM_FILE" >&2
            exit 1
          }
        fi
      else
        echo "RPM packaging is only supported on Linux." >&2
        exit 1
      fi
      ;;
    dmg)
      if [ "$(uname)" = "Darwin" ]; then
        SCRIPT_DARWIN="$REPO_ROOT/.github/scripts/package/package_dmg.sh"
        nix-shell -I "nixpkgs=${NIXPKGS_ARG}" --argstr variant "default" "$REPO_ROOT/shell.nix" \
          --run "bash '$SCRIPT_DARWIN' --link '$LINK'"
        echo "Built dmg ($LINK): $REPO_ROOT/result-dmg-$LINK"
      else
        echo "DMG packaging is only supported on macOS." >&2
        exit 1
      fi
      ;;
    esac
  done
}

# ── Update-hashes command ─────────────────────────────────────────────────────

update_hashes_command() {
  SCRIPT="$REPO_ROOT/.github/scripts/release/update_hashes.sh"
  if [ -f "$SCRIPT" ]; then
    bash "$SCRIPT" "$@"
  else
    echo "Building auth-verifier (static) to capture hashes..."
    ATTR="auth-verifier-static"
    OUT_LINK="$REPO_ROOT/result-server-static"
    nix-build -I "nixpkgs=${PIN_URL}" "$REPO_ROOT/default.nix" -A "$ATTR" -o "$OUT_LINK"
    REAL_OUT=$(readlink -f "$OUT_LINK")

    # Copy generated hash file from derivation output
    HASHES_DIR="$REPO_ROOT/nix/expected-hashes"
    mkdir -p "$HASHES_DIR"
    find "$REAL_OUT/bin" -name 'auth-verifier.*.sha256' 2>/dev/null | while IFS= read -r src; do
      fname=$(basename "$src")
      cp -f "$src" "$HASHES_DIR/$fname"
      echo "Updated: nix/expected-hashes/$fname"
    done
    echo "Done. Run the same for --link dynamic if needed."
  fi
  exit 0
}

# ── Main ─────────────────────────────────────────────────────────────────────

set_repo_root
ensure_nix_path
dispatch_command "$@"
