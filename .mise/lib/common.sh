#!/usr/bin/env bash
# Shared helpers for .mise/tasks/**. Source via:
#   source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
# Guarded against multiple sourcing since several tasks may load it.

[ -n "${_MISE_COMMON_SH_LOADED:-}" ] && return 0
_MISE_COMMON_SH_LOADED=1

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[mise]${NC} $*"; }
print_error() { echo -e "${RED}[mise][error]${NC} $*" >&2; }

# Split leading --link/--variant pairs of "$@" into NIX_GLOBAL_ARGS (they must precede the
# nix.sh command word); the remaining arguments go to NIX_REST_ARGS.
split_nix_global_args() {
  NIX_GLOBAL_ARGS=()
  while [ "${1:-}" = "--link" ] || [ "${1:-}" = "-l" ] || [ "${1:-}" = "--variant" ]; do
    NIX_GLOBAL_ARGS+=("$1" "${2:?missing value for $1}")
    shift 2
  done
  # shellcheck disable=SC2034 # read by the sourcing task
  NIX_REST_ARGS=("$@")
}
