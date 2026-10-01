#!/usr/bin/env bash
# Functional tests for the auth_verifier Docker image.
# The container is expected to expose the auth server over HTTP on PORT (default 8080)
# when running with the built-in development configuration (no TLS).
# To supply a custom config with TLS, set AUTH_SERVER_CONF inside the container or
# mount a TOML at /etc/cosmian/auth_verifier.toml and set AUTH_SERVER_HTTPS=true.
set -euo pipefail

IMAGE_NAME="${DOCKER_IMAGE_NAME:-cosmian-auth-verifier:latest}"
PORT="${AUTH_SERVER_PORT:-8080}"
HTTPS="${AUTH_SERVER_HTTPS:-true}"
if [ "$HTTPS" = "true" ]; then
  BASE_URL="https://127.0.0.1:${PORT}"
else
  BASE_URL="http://127.0.0.1:${PORT}"
fi

# Default admin credentials seeded on first start (username=admin, password=change_me)
ADMIN_BASIC=$(printf 'admin:change_me' | base64)

PASS=0
FAIL=0

echo "=========================================="
echo "Testing Docker image: $IMAGE_NAME"
echo "Base URL : $BASE_URL"
echo "=========================================="

# ── Helpers ────────────────────────────────────────────────────────────────

# curl wrapper: works for both plain HTTP and HTTPS (--insecure for self-signed certs)
ca_curl() {
  curl --insecure --silent --show-error "$@"
}

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  PASS  $label (got: $actual)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $label (expected: $expected, got: $actual)"
    FAIL=$((FAIL + 1))
  fi
}

assert_contains() {
  local label="$1" needle="$2" haystack="$3"
  if echo "$haystack" | grep -qF "$needle"; then
    echo "  PASS  $label (contains: $needle)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $label (expected to contain '$needle', got: $haystack)"
    FAIL=$((FAIL + 1))
  fi
}

# ── Start container ────────────────────────────────────────────────────────

CID=$(docker run -d -p "${PORT}:${PORT}" "$IMAGE_NAME" 2>/dev/null)
echo "Container ID: $CID"
trap 'echo "Stopping container…"; docker stop "$CID" 2>/dev/null || true; docker rm -f "$CID" 2>/dev/null || true' EXIT

# ── Wait for readiness ─────────────────────────────────────────────────────

echo "Waiting for server to start (${BASE_URL})…"
READY=false
for i in $(seq 1 30); do
  if ca_curl -o /dev/null -w '' "$BASE_URL/public/version" 2>/dev/null; then
    echo "Server is ready (attempt $i)"
    READY=true
    break
  fi
  # Check if container is still running
  if ! docker inspect -f '{{.State.Running}}' "$CID" 2>/dev/null | grep -q true; then
    echo "ERROR: Container exited prematurely"
    docker logs "$CID" 2>&1 || true
    exit 1
  fi
  sleep 1
done

if [ "$READY" != true ]; then
  echo "ERROR: Server did not become ready within 30 seconds"
  docker logs "$CID" 2>&1 || true
  exit 1
fi

echo ""
echo "── Public endpoints ──────────────────────────────────────────────────"

# ── GET /public/version ────────────────────────────────────────────────────

echo "Test: GET /public/version"
HTTP_CODE=$(ca_curl -o /tmp/auth_version.json -w '%{http_code}' "$BASE_URL/public/version")
assert_eq "HTTP 200" "200" "$HTTP_CODE"
VERSION_BODY=$(cat /tmp/auth_version.json)
assert_contains "version field present" '"version"' "$VERSION_BODY"

# ── GET /public/roles ──────────────────────────────────────────────────────

echo "Test: GET /public/roles"
HTTP_CODE=$(ca_curl -o /tmp/auth_roles.json -w '%{http_code}' "$BASE_URL/public/roles")
assert_eq "HTTP 200" "200" "$HTTP_CODE"
ROLES_BODY=$(cat /tmp/auth_roles.json)
assert_contains "roles is JSON array" '["' "$ROLES_BODY"

# ── GET /.well-known/jwks.json ─────────────────────────────────────────────

echo "Test: GET /.well-known/jwks.json"
HTTP_CODE=$(ca_curl -o /tmp/auth_jwks.json -w '%{http_code}' "$BASE_URL/.well-known/jwks.json")
assert_eq "HTTP 200" "200" "$HTTP_CODE"
JWKS_BODY=$(cat /tmp/auth_jwks.json)
assert_contains "JWKS keys field present" '"keys"' "$JWKS_BODY"

echo ""
echo "── Authentication ────────────────────────────────────────────────────"

# ── POST /login — wrong password → 401 ────────────────────────────────────

echo "Test: POST /login?realm=_ with wrong password → 401"
WRONG_BASIC=$(printf 'admin:wrongpassword' | base64)
HTTP_CODE=$(ca_curl -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "Authorization: Basic ${WRONG_BASIC}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "$BASE_URL/login?realm=_")
assert_eq "HTTP 401" "401" "$HTTP_CODE"

# ── POST /login — unknown realm → 404 ─────────────────────────────────────

echo "Test: POST /login?realm=nonexistent → 401"
HTTP_CODE=$(ca_curl -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "Authorization: Basic ${ADMIN_BASIC}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "$BASE_URL/login?realm=nonexistent")
# The server returns 401 (not 404) for unknown realms — realm existence is not
# disclosed to unauthenticated callers.
assert_eq "HTTP 401" "401" "$HTTP_CODE"

# ── POST /login — valid admin credentials → 200 + session cookie ──────────

echo "Test: POST /login?realm=_ with valid admin credentials → 200 + cookie"
HTTP_CODE=$(ca_curl -o /tmp/auth_login.json -w '%{http_code}' \
  -c /tmp/auth_cookies.txt \
  -X POST \
  -H "Authorization: Basic ${ADMIN_BASIC}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "$BASE_URL/login?realm=_")
assert_eq "HTTP 200" "200" "$HTTP_CODE"
LOGIN_BODY=$(cat /tmp/auth_login.json)
assert_contains "next_step present" '"next_step"' "$LOGIN_BODY"
assert_contains "session_id present" '"session_id"' "$LOGIN_BODY"
# The seeded admin has change_password=true; the server issues a session
# and returns Authenticated (password change is enforced at the UI level).
assert_contains "authenticated" '"Authenticated"' "$LOGIN_BODY"
COOKIE_LINE=$(grep -i "_ea_" /tmp/auth_cookies.txt 2>/dev/null || true)
if [ -n "$COOKIE_LINE" ]; then
  echo "  PASS  session cookie (_ea_) set"
  PASS=$((PASS + 1))
else
  echo "  FAIL  session cookie (_ea_) not found in Set-Cookie"
  FAIL=$((FAIL + 1))
fi

# ── GET /whoami — with session cookie → 200 ───────────────────────────────

echo "Test: GET /whoami?realm=_ with valid session cookie → 200"
HTTP_CODE=$(ca_curl -o /tmp/auth_whoami.json -w '%{http_code}' \
  -b /tmp/auth_cookies.txt \
  "$BASE_URL/whoami?realm=_")
assert_eq "HTTP 200" "200" "$HTTP_CODE"
WHOAMI_BODY=$(cat /tmp/auth_whoami.json)
assert_contains "sub (username) in whoami" '"sub"' "$WHOAMI_BODY"

# ── GET /whoami — without cookie → 401 ────────────────────────────────────

echo "Test: GET /whoami?realm=_ without cookie → 401"
HTTP_CODE=$(ca_curl -o /dev/null -w '%{http_code}' \
  "$BASE_URL/whoami?realm=_")
assert_eq "HTTP 401" "401" "$HTTP_CODE"

# ── SAML build check (EXPECT_SAML=1) ───────────────────────────────────────
# A server built without the `saml` feature refuses to start when [saml_sp_params]
# is configured, so a successful start proves the feature is compiled in.

if [ "${EXPECT_SAML:-}" = "1" ]; then
  echo ""
  echo "── SAML build ────────────────────────────────────────────────────────"
  SAML_PORT="${AUTH_SERVER_SAML_PORT:-8081}"
  SAML_DIR=$(mktemp -d)
  # The container runs as uid 1000 and must be able to read the (throw-away) keys.
  chmod 755 "$SAML_DIR"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$SAML_DIR/tls.key.pem"
  openssl req -new -x509 -key "$SAML_DIR/tls.key.pem" -out "$SAML_DIR/tls.cert.pem" -days 1 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  openssl req -x509 -newkey rsa:3072 -sha256 -days 1 -nodes -subj "/CN=saml-sp-test" \
    -keyout "$SAML_DIR/saml-sp.key.pem" -out "$SAML_DIR/saml-sp.cert.pem" 2>/dev/null
  cat >"$SAML_DIR/auth_verifier.toml" <<'TOML'
host_name = "0.0.0.0"
host_port = 8080
roles = ["Admin", "User"]

[tls_params]
server_private_key = "/conf/tls.key.pem"
server_certificate = "/conf/tls.cert.pem"
server_ca_chain = "/conf/tls.cert.pem"

[database_params]
backend = "sqlite"
connection_url = "sqlite::memory:"

[saml_sp_params]
saml_rsa_private_key = "/conf/saml-sp.key.pem"
saml_certificate = "/conf/saml-sp.cert.pem"
TOML
  chmod 644 "$SAML_DIR"/*

  SAML_CID=$(docker run -d -p "${SAML_PORT}:8080" -v "$SAML_DIR:/conf:ro" \
    -e AUTH_SERVER_CONF=/conf/auth_verifier.toml "$IMAGE_NAME" 2>/dev/null)
  trap 'echo "Stopping containers…"; docker rm -f "$CID" "$SAML_CID" >/dev/null 2>&1 || true; rm -rf "$SAML_DIR"' EXIT

  echo "Test: server starts with [saml_sp_params] (saml feature compiled in)"
  SAML_UP=false
  for _ in $(seq 1 30); do
    if ca_curl -o /dev/null "https://127.0.0.1:${SAML_PORT}/public/version" 2>/dev/null; then
      SAML_UP=true
      break
    fi
    docker inspect -f '{{.State.Running}}' "$SAML_CID" 2>/dev/null | grep -q true || break
    sleep 1
  done
  if [ "$SAML_UP" = true ]; then
    echo "  PASS  server started with [saml_sp_params]"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  server did not start with [saml_sp_params]"
    docker logs "$SAML_CID" 2>&1 || true
    FAIL=$((FAIL + 1))
  fi
fi

echo ""
echo "=========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
  echo "Docker image test FAILED"
  docker logs "$CID" || true
  exit 1
fi

echo "Docker image test PASSED"
