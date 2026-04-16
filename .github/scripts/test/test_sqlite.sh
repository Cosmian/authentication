#!/usr/bin/env bash
# Run authentication server tests with SQLite backend
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
source "$REPO_ROOT/.github/scripts/common.sh"
cd "$REPO_ROOT"

echo "=========================================="
echo "Running SQLite backend tests"
echo "=========================================="

cargo test --workspace --lib -- --nocapture

echo "SQLite tests completed."
