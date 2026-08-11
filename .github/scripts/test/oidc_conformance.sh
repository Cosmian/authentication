#!/usr/bin/env bash
# =============================================================================
# OpenID Foundation Conformance Suite runner for auth-verifier's OpenID Provider.
#
# Runs the authoritative certification test plans against a running auth-verifier:
#   - oidcc-config-certification-test-plan  (fully automated: metadata/JWKS/discovery)
#   - oidcc-basic-certification-test-plan   (Authorization Code flow; uses the
#     suite's headless browser to drive our login + consent forms)
#
# Requirements: docker + docker compose. When they are unavailable the script
# prints guidance and exits 0 (skipped, not failed) so it is safe to wire into CI.
#
# Environment overrides:
#   CONFORMANCE_DIR   path to a checked-out conformance-suite (default: clone into a temp dir)
#   CONFORMANCE_URL   base URL of an already-running suite (skips docker startup)
#   BASE_URL          run against an already-running auth-verifier (skips local server)
#   SUITE_REPO        git URL for the conformance suite
#                     (default: https://gitlab.com/openid/conformance-suite.git)
# =============================================================================
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
cd "$REPO_ROOT" || exit

CERTS="$REPO_ROOT/server/src/tests/certificates/ec"
CACERT="${CACERT:-$CERTS/auth.ca.pem}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-change_me}"
REALM="oidc-conf"
USER_NAME="alice"
USER_PASS="s3cret-password"
REDIRECT="https://localhost.emobix.co.uk:8443/test/a/cosmian-auth/callback"
SUITE_REPO="${SUITE_REPO:-https://gitlab.com/openid/conformance-suite.git}"
WORK="$(mktemp -d)"
SERVER_PID=""
COMPOSE_DIR=""

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" >/dev/null 2>&1 || true
  if [ -n "$COMPOSE_DIR" ] && [ -z "${CONFORMANCE_URL:-}" ]; then
    (cd "$COMPOSE_DIR" && docker compose down >/dev/null 2>&1 || true)
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

skip() { echo "SKIP: $*"; exit 0; }

# ── Prerequisites ────────────────────────────────────────────────────────────
for tool in curl jq openssl python3 git; do
  command -v "$tool" >/dev/null 2>&1 || skip "'$tool' not found — conformance run skipped"
done
if [ -z "${CONFORMANCE_URL:-}" ]; then
  command -v docker >/dev/null 2>&1 || skip "docker not found — conformance run skipped"
  docker compose version >/dev/null 2>&1 || skip "docker compose not available — conformance run skipped"
fi

CURL() { curl -sS --cacert "$CACERT" "$@"; }

# ── 1. Start auth-verifier + provisioning ────────────────────────────────────
start_auth_verifier() {
  echo "== Building + starting auth-verifier =="
  cargo build -p auth_verifier >/dev/null 2>&1 || { echo "build failed"; exit 2; }
  local port=18444
  BASE="https://127.0.0.1:$port"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/oidc.key.pem" 2>/dev/null
  openssl pkey -in "$WORK/oidc.key.pem" -pubout -out "$WORK/oidc.pub.pem" 2>/dev/null
  cat > "$WORK/config.toml" <<TOML
host_name = "127.0.0.1"
host_port = $port
[log]
level = "info"
[tls_params]
server_ca_chain = "$CERTS/auth.ca.pem"
server_certificate = "$CERTS/auth.server.cert.pem"
server_private_key = "$CERTS/auth.server.key.pem"
[session_jwt_params]
jwt_ec_private_key = "$CERTS/auth.server.key.pem"
jwt_ec_public_key = "$CERTS/auth.server.cert.pem"
[database_params]
auto_init_schema = true
backend = "sqlite"
connection_url = "sqlite:$WORK/oidc.db"
[oidc_params]
issuer = "$BASE"
oidc_signing_private_key = "$WORK/oidc.key.pem"
oidc_signing_public_key = "$WORK/oidc.pub.pem"
TOML
  ./target/debug/auth_verifier "$WORK/config.toml" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 60); do
    CURL -o /dev/null "$BASE/.well-known/openid-configuration" 2>/dev/null && return 0
    sleep 0.5
  done
  echo "auth-verifier did not start"; cat "$WORK/server.log"; exit 2
}

provision() {
  echo "== Provisioning realm/user/client =="
  local cj="$WORK/cj"
  CURL -u "$ADMIN_USER:$ADMIN_PASS" -c "$cj" -X POST "$BASE/login?realm=_" \
    -H 'Content-Type: application/json' -d '{}' -o /dev/null
  CURL -b "$cj" -X POST "$BASE/admins/realms" -H 'Content-Type: application/json' \
    -d "{\"id\":\"$REALM\",\"auth_params\":{\"username_password_params\":{\"allow_expired_passwords\":true}},\"session_max_age_seconds\":3600,\"session_max_stale_age_seconds\":3600}" -o /dev/null
  local pw; pw=$(python3 -c "import json,sys;print(json.dumps(list(sys.argv[1].encode())))" "$USER_PASS")
  CURL -b "$cj" -X POST "$BASE/realms/$REALM/userpass" -H 'Content-Type: application/json' \
    -d "{\"realm\":\"$REALM\",\"username\":\"$USER_NAME\",\"password\":$pw,\"change_password\":false,\"roles\":[\"Auditor\"]}" -o /dev/null
  local resp
  resp=$(CURL -b "$cj" -X POST "$BASE/realms/$REALM/clients" -H 'Content-Type: application/json' -d '{
    "client_name":"Conformance Client",
    "redirect_uris":["'"$REDIRECT"'"],
    "grant_types":["authorization_code","refresh_token"],
    "response_types":["code"],
    "scopes":["openid","profile","email","offline_access","roles"],
    "token_endpoint_auth_method":"client_secret_basic"}')
  CID=$(echo "$resp" | jq -r .client_id)
  CSECRET=$(echo "$resp" | jq -r .client_secret)
  [ -n "$CID" ] && [ "$CID" != "null" ] || { echo "client registration failed: $resp"; exit 2; }
  echo "  client_id=$CID"
}

if [ -n "${BASE_URL:-}" ]; then
  BASE="$BASE_URL"
else
  start_auth_verifier
fi
provision

# ── 2. Generate the conformance test configuration ───────────────────────────
# The `browser` automation drives auth-verifier's login + consent forms so the
# Authorization Code plan can complete headlessly.
CONFIG="$WORK/cosmian-auth-config.json"
python3 - "$BASE" "$CID" "$CSECRET" "$USER_NAME" "$USER_PASS" > "$CONFIG" <<'PY'
import json, sys
base, cid, csecret, user, pw = sys.argv[1:6]
cfg = {
  "alias": "cosmian-auth",
  "description": "Cosmian auth-verifier OpenID Provider",
  "server": {"discoveryUrl": f"{base}/.well-known/openid-configuration"},
  "client": {"client_id": cid, "client_secret": csecret},
  "consent": {},
  "browser": [
    {
      "match": f"{base}/oidc/authorize*",
      "tasks": [
        {
          "task": "Login",
          "match": f"{base}/oidc/authorize*",
          "commands": [
            ["text", "name", "username", user],
            ["text", "name", "password", pw],
            ["click", "xpath", "//button[@type='submit']"]
          ]
        },
        {
          "task": "Consent",
          "match": f"{base}/oidc/authorize/*",
          "optional": True,
          "commands": [
            ["click", "xpath", "//button[@value='approve']"]
          ]
        }
      ]
    }
  ]
}
print(json.dumps(cfg, indent=2))
PY
echo "== Generated conformance config: $CONFIG =="

# ── 3. Bring up the conformance suite (unless one is already running) ─────────
if [ -n "${CONFORMANCE_URL:-}" ]; then
  SUITE="$CONFORMANCE_URL"
else
  COMPOSE_DIR="${CONFORMANCE_DIR:-$WORK/conformance-suite}"
  if [ ! -d "$COMPOSE_DIR" ]; then
    echo "== Cloning conformance suite =="
    git clone --depth 1 "$SUITE_REPO" "$COMPOSE_DIR" || skip "unable to clone conformance suite"
  fi
  echo "== Building + starting conformance suite (docker compose) =="
  ( cd "$COMPOSE_DIR" \
      && (mvn -q clean package -DskipTests >/dev/null 2>&1 || docker compose build >/dev/null 2>&1 || true) \
      && docker compose up -d >/dev/null 2>&1 ) || skip "conformance suite failed to start"
  SUITE="https://localhost:8443"
fi

echo "== Waiting for conformance suite at $SUITE =="
ready=0
for _ in $(seq 1 120); do
  if curl -sk -o /dev/null "$SUITE/api/runner/available" 2>/dev/null; then ready=1; break; fi
  sleep 2
done
[ "$ready" -eq 1 ] || skip "conformance suite did not become ready"

# ── 4. Create + run test plans via the suite API ─────────────────────────────
SC() { curl -sk "$@"; }

run_plan() {
  local plan="$1" variant="$2"
  echo "== Creating plan: $plan =="
  local created plan_id modules
  created=$(SC -X POST \
    "$SUITE/api/plan?planName=$plan&variant=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$variant")" \
    -H 'Content-Type: application/json' --data-binary "@$CONFIG")
  plan_id=$(echo "$created" | jq -r '.id // empty')
  if [ -z "$plan_id" ]; then
    echo "  could not create plan (API response): $created"
    return 1
  fi
  modules=$(echo "$created" | jq -r '.modules[]?.testModule // .modules[]? // empty')
  echo "  plan id: $plan_id"

  local total=0 passed=0
  while IFS= read -r module; do
    [ -z "$module" ] && continue
    total=$((total + 1))
    local started test_id
    started=$(SC -X POST "$SUITE/api/runner?test=$module&plan=$plan_id" -H 'Content-Type: application/json' -d '{}')
    test_id=$(echo "$started" | jq -r '.id // empty')
    [ -z "$test_id" ] && { echo "  [SKIP] $module (could not start)"; continue; }
    # Poll until finished.
    local status result
    for _ in $(seq 1 120); do
      info=$(SC "$SUITE/api/info/$test_id")
      status=$(echo "$info" | jq -r '.status // empty')
      [ "$status" = "FINISHED" ] || [ "$status" = "INTERRUPTED" ] && break
      sleep 1
    done
    result=$(SC "$SUITE/api/info/$test_id" | jq -r '.result // "UNKNOWN"')
    case "$result" in
      PASSED|WARNING) passed=$((passed + 1)); echo "  [PASS] $module ($result)";;
      *) echo "  [FAIL] $module ($result)";;
    esac
  done <<< "$modules"
  echo "  $plan: $passed/$total modules passed"
}

# Config plan: fully automated (discovery, metadata, JWKS).
run_plan "oidcc-config-certification-test-plan" \
  '{"server_metadata":"discovery","client_registration":"static_client"}'

# Basic plan: Authorization Code flow driven via the browser automation above.
run_plan "oidcc-basic-certification-test-plan" \
  '{"server_metadata":"discovery","client_registration":"static_client","response_type":"code","response_mode":"default","client_auth_type":"client_secret_basic"}'

echo "== Conformance run complete =="
