#!/usr/bin/env bash
# Run all authentication server tests
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
source "$REPO_ROOT/.github/scripts/common.sh"
cd "$REPO_ROOT"

echo "Running all authentication server tests…"

# SQLite tests
bash "$SCRIPT_DIR/test_sqlite.sh"

echo "All tests completed successfully."
