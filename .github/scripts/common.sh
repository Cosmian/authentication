#!/usr/bin/env bash
# Minimal shared helpers for authentication server CI scripts
# Source this file from other scripts: source "$(dirname "$0")/../scripts/common.sh"

set -euo pipefail

# ── macOS SDK helpers ────────────────────────────────────────────────────────

# Ensure macOS SDK path is available for the linker.
ensure_macos_sdk_env() {
  if [ "$(uname -s)" != "Darwin" ]; then
    return 0
  fi

  : "${DEVELOPER_DIR:=/Library/Developer/CommandLineTools}"
  export DEVELOPER_DIR
  if [ -d "${DEVELOPER_DIR}/usr/bin" ]; then
    case ":${PATH}:" in
    *":${DEVELOPER_DIR}/usr/bin:"*) : ;;
    *) export PATH="${DEVELOPER_DIR}/usr/bin:${PATH}" ;;
    esac
  fi

  if [ -n "${SDKROOT:-}" ] && [ -d "${SDKROOT}" ]; then
    :
  else
    if command -v xcrun >/dev/null 2>&1; then
      local sdk
      sdk="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
      if [ -n "$sdk" ] && [ -d "$sdk" ]; then
        export SDKROOT="$sdk"
      fi
    fi

    if [ -z "${SDKROOT:-}" ]; then
      local clt_sdk="/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"
      if [ -d "$clt_sdk" ]; then
        export SDKROOT="$clt_sdk"
      fi
    fi
  fi

  if [ -n "${SDKROOT:-}" ] && [ -d "${SDKROOT}" ]; then
    unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH
    unset NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS

    local sysroot_flag="-isysroot ${SDKROOT}"
    local framework_dir="${SDKROOT}/System/Library/Frameworks"
    local framework_flags=""
    if [ -d "${framework_dir}" ]; then
      framework_flags="-F${framework_dir} -iframework ${framework_dir}"
    fi

    export CFLAGS="${sysroot_flag} ${framework_flags} ${CFLAGS:-}"
    export CPPFLAGS="${sysroot_flag} ${framework_flags} ${CPPFLAGS:-}"
    export CXXFLAGS="${sysroot_flag} ${framework_flags} ${CXXFLAGS:-}"
  fi
}

ensure_macos_frameworks_ldflags() {
  if [ "$(uname -s)" != "Darwin" ]; then
    return 0
  fi

  if [ -z "${SDKROOT:-}" ] || [ ! -d "${SDKROOT}" ]; then
    ensure_macos_sdk_env || true
  fi

  if [ -z "${SDKROOT:-}" ] || [ ! -d "${SDKROOT}" ]; then
    return 0
  fi

  local frameworks_dir="${SDKROOT}/System/Library/Frameworks"
  if [ ! -d "${frameworks_dir}" ]; then
    return 0
  fi

  local fw_ldflags="-F${frameworks_dir} -Wl,-F,${frameworks_dir}"
  export LDFLAGS="${fw_ldflags} ${LDFLAGS:-}"
  export RUSTFLAGS="-C link-arg=-F${frameworks_dir} -C link-arg=-Wl,-F,${frameworks_dir} ${RUSTFLAGS:-}"
}

# ── Pinned nixpkgs ────────────────────────────────────────────────────────────

# Single source of truth for the pinned nixpkgs URL.
# IMPORTANT: Use an immutable commit tarball for deterministic builds.
export PIN_URL="https://package.cosmian.com/nixpkgs/8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296.tar.gz"
export PINNED_NIXPKGS_URL="$PIN_URL"

# ── Build environment ────────────────────────────────────────────────────────

# Initialize build/test configuration from CLI args
# Exports: LINK (static|dynamic), BUILD_PROFILE
init_build_env() {
  local link="static"
  local link_set=0

  local i=1
  while [ $i -le $# ]; do
    case "${!i}" in
    --link)
      link_set=1
      i=$((i + 1))
      link="${!i:-}"
      ;;
    esac
    i=$((i + 1))
  done

  if [ $link_set -eq 0 ] && [ -n "${LINK:-}" ]; then
    case "${LINK}" in
    static | dynamic) link="${LINK}" ;;
    esac
  fi

  case "$link" in
  static | dynamic) : ;;
  *)
    echo "Error: --link must be 'static' or 'dynamic'" >&2
    exit 1
    ;;
  esac

  export LINK="$link"
}

# Ensure a modern Rust toolchain is available on PATH
ensure_modern_rust() {
  if command -v rustup >/dev/null 2>&1; then
    if ! rustup which cargo >/dev/null 2>&1; then
      rustup default stable
    fi
  fi
}
