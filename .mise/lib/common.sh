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
