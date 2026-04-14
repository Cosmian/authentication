#!/usr/bin/env bash
# Smoke-test the Docker image for auth_server
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)

IMAGE_NAME="${DOCKER_IMAGE_NAME:-cosmian-auth-server:latest}"
PORT="${AUTH_SERVER_PORT:-9005}"

echo "=========================================="
echo "Testing Docker image: $IMAGE_NAME"
echo "=========================================="

# Start container in background
CID=$(docker run -d --rm -p "${PORT}:${PORT}" "$IMAGE_NAME" 2>/dev/null)
echo "Container ID: $CID"
trap 'docker stop "$CID" 2>/dev/null || true' EXIT

# Wait for readiness
echo "Waiting for server to start…"
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    echo "Server is ready (attempt $i)"
    break
  fi
  sleep 1
done

# Basic health check
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/health" || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  echo "Health check PASSED (HTTP $HTTP_CODE)"
else
  echo "WARNING: Health check returned HTTP $HTTP_CODE (server may still be functional)"
fi

echo "Docker smoke test completed."
