#!/usr/bin/env bash
# Run authentication server tests with PostgreSQL backend
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
source "$REPO_ROOT/.github/scripts/common.sh"
cd "$REPO_ROOT"

POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"

echo "=========================================="
echo "Running PostgreSQL backend tests"
echo "  Host: $POSTGRES_HOST:$POSTGRES_PORT"
echo "=========================================="

export TEST_POSTGRES_URL="postgresql://auth:auth@${POSTGRES_HOST}:${POSTGRES_PORT}/auth"

cargo test --workspace --lib -- --nocapture

echo "PostgreSQL tests completed."
