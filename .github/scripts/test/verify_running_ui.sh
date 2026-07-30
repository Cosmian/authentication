#!/usr/bin/env bash
# Verify a running auth_verifier server serves a functional admin UI over HTTP.
#
# Usage: verify_running_ui.sh [BASE_URL]
#   BASE_URL defaults to http://127.0.0.1:8080
#
# Checks (all must pass):
#   1. GET /admin-ui/index.html            -> 2xx and looks like HTML
#   2. GET the first /admin-ui/assets/*    -> 2xx (proves JS/CSS bundle is served)
#   3. GET /public/version                 -> 2xx (unauthenticated liveness endpoint)
#
# Requires curl. Exits non-zero on the first failed check.
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8080}"
BASE_URL="${BASE_URL%/}"

if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl is required but not installed" >&2
  exit 1
fi

# Detect HTTPS and add -k (skip cert verification) for self-signed certs
CURL_OPTS=""
case "$BASE_URL" in
  https://*) CURL_OPTS="-k" ;;
esac

echo "==========================================="
echo "Verifying admin UI at $BASE_URL"
echo "==========================================="

# ── 1. index.html ──────────────────────────────────────────────────────────
index_url="$BASE_URL/admin-ui/index.html"
echo "GET $index_url"
index_body=$(mktemp)
trap 'rm -f "$index_body"' EXIT
http_code=$(curl $CURL_OPTS -fsSL -o "$index_body" -w '%{http_code}' "$index_url")
echo "  -> HTTP $http_code"
if ! grep -qiE '<html|<!doctype html|<div id="root"' "$index_body"; then
  echo "ERROR: /admin-ui/index.html does not look like the UI HTML document" >&2
  head -20 "$index_body" >&2 || true
  exit 1
fi
echo "  index.html check PASSED"

# ── 2. hashed asset (JS or CSS) ────────────────────────────────────────────
# index.html references assets as /admin-ui/assets/index-XXXX.{js,css}
asset_path=$(grep -oE '/admin-ui/assets/[A-Za-z0-9._-]+\.(js|css)' "$index_body" | head -1 || true)
if [ -z "$asset_path" ]; then
  echo "ERROR: no /admin-ui/assets/*.{js,css} reference found in index.html" >&2
  exit 1
fi
asset_url="$BASE_URL$asset_path"
echo "GET $asset_url"
asset_code=$(curl $CURL_OPTS -fsSL -o /dev/null -w '%{http_code}' "$asset_url")
echo "  -> HTTP $asset_code"
echo "  asset check PASSED ($asset_path)"

# ── 3. public API endpoint ─────────────────────────────────────────────────
version_url="$BASE_URL/public/version"
echo "GET $version_url"
version_code=$(curl $CURL_OPTS -fsSL -o /dev/null -w '%{http_code}' "$version_url")
echo "  -> HTTP $version_code"
echo "  /public/version check PASSED"

echo "==========================================="
echo "Admin UI verification PASSED for $BASE_URL"
echo "==========================================="
