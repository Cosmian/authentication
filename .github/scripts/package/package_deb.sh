#!/usr/bin/env bash
# Build Debian package for Cosmian Authentication Server
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
"$SCRIPT_DIR/package_common.sh" --format deb "$@"
