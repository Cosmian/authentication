#!/usr/bin/env bash
# =============================================================================
# OIDC end-to-end conformance harness (curl + jq/openssl/python3).
#
# Exercises the OpenID Provider exhaustively against a *running* auth-verifier:
#   - discovery metadata + JWKS shape
#   - Authorization Code + PKCE (S256) happy path (confidential + public clients)
#   - token / id_token / refresh (rotation + reuse detection) / userinfo /
#     introspection / revocation
#   - a full negative-case matrix (bad client, bad redirect_uri, missing/invalid
#     PKCE, reused/expired code, wrong secret, invalid token, ...)
#
# By default the script builds and boots a throwaway server on a temp SQLite DB
# with a DEDICATED OIDC signing key (separate from the session/TLS key). Set
# BASE_URL to run against an already-running server instead.
#
# Usage:
#   .github/scripts/test/oidc_curl_suite.sh
#   BASE_URL=https://127.0.0.1:8443 CACERT=/path/ca.pem \
#     ADMIN_USER=admin ADMIN_PASS=change_me .github/scripts/test/oidc_curl_suite.sh
# =============================================================================
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
cd "$REPO_ROOT" || exit

# ── Configuration ────────────────────────────────────────────────────────────
CERTS="$REPO_ROOT/server/src/tests/certificates/ec"
CACERT="${CACERT:-$CERTS/auth.ca.pem}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-change_me}"
REALM="oidc-suite"
USER_NAME="alice"
USER_PASS="s3cret-password"
REDIRECT="https://client.example.org/cb"
WORK="$(mktemp -d)"
SERVER_PID=""

# ── Dependency checks ────────────────────────────────────────────────────────
for tool in curl jq openssl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FATAL: '$tool' is required"; exit 2; }
done

# ── Assertion framework ──────────────────────────────────────────────────────
PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { # expected actual message
  if [ "$1" == "$2" ]; then pass "$3"; else fail "$3 (expected='$1' actual='$2')"; fi
}
assert_ne() { if [ "$1" != "$2" ]; then pass "$3"; else fail "$3 (both='$1')"; fi
}
assert_nonempty() { if [ -n "$1" ] && [ "$1" != "null" ]; then pass "$2"; else fail "$2 (empty)"; fi
}

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# ── Helpers ──────────────────────────────────────────────────────────────────
CURL() { curl -sS --cacert "$CACERT" "$@"; }
urlenc() { python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }
qparam() { # url key
  python3 -c "import urllib.parse,sys;print(urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query).get(sys.argv[2],[''])[0])" "$1" "$2"
}
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
jwt_field() { # token json_field  (decodes payload)
  python3 -c "import sys,base64,json;s=sys.argv[1].split('.')[1];s+='='*(-len(s)%4);print(json.loads(base64.urlsafe_b64decode(s)).get(sys.argv[2],''))" "$1" "$2"
}
jwt_header() { # token json_field  (decodes header)
  python3 -c "import sys,base64,json;s=sys.argv[1].split('.')[0];s+='='*(-len(s)%4);print(json.loads(base64.urlsafe_b64decode(s)).get(sys.argv[2],''))" "$1" "$2"
}
extract_flow() { grep -o 'name="flow_token" value="[^"]*"' "$1" | head -1 | sed 's/.*value="//;s/"$//'; }

gen_pkce() {
  VERIFIER=$(openssl rand 32 | b64url)
  CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | b64url)
}

# Run authorize→login→consent, echo the authorization code. Args: client_id scope state nonce challenge
get_code() {
  local cid="$1" scope="$2" state="$3" nonce="$4" challenge="$5"
  local url
  url="$BASE/oidc/authorize?response_type=code&client_id=$cid&redirect_uri=$REDIRECT_ENC&scope=$(urlenc "$scope")&state=$state&nonce=$nonce&code_challenge=$challenge&code_challenge_method=S256"
  CURL "$url" -o "$WORK/login.html"
  local ft; ft=$(extract_flow "$WORK/login.html")
  CURL -X POST "$BASE/oidc/authorize/login" \
    --data-urlencode "flow_token=$ft" \
    --data-urlencode "username=$USER_NAME" \
    --data-urlencode "password=$USER_PASS" -o "$WORK/consent.html"
  local ct; ct=$(extract_flow "$WORK/consent.html")
  CURL -D "$WORK/h.txt" -o /dev/null -X POST "$BASE/oidc/authorize/consent" \
    --data-urlencode "flow_token=$ct" --data-urlencode "decision=approve"
  local loc; loc=$(grep -i '^location:' "$WORK/h.txt" | tr -d '\r' | sed 's/^[Ll]ocation: //')
  qparam "$loc" code
}

# ── Start a throwaway server (unless BASE_URL is provided) ────────────────────
start_server() {
  echo "== Building auth_verifier =="
  cargo build -p auth_verifier >/dev/null 2>&1 || { echo "build failed"; exit 2; }

  local port=18443
  BASE="https://127.0.0.1:$port"

  # Dedicated OIDC signing key (separate from the session/TLS key).
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
supported_scopes = ["openid", "profile", "email", "offline_access", "roles"]
TOML

  echo "== Starting server on $BASE =="
  ./target/debug/auth_verifier "$WORK/config.toml" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!

  for _ in $(seq 1 60); do
    if CURL -o /dev/null "$BASE/.well-known/openid-configuration" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  echo "server did not become ready; log:"; cat "$WORK/server.log"; exit 2
}

if [ -n "${BASE_URL:-}" ]; then
  BASE="$BASE_URL"
  echo "== Using external server at $BASE =="
else
  start_server
fi
REDIRECT_ENC=$(urlenc "$REDIRECT")

# ── Provisioning (admin API) ─────────────────────────────────────────────────
echo "== Provisioning realm, user, clients =="
CJ="$WORK/cookies.txt"
CURL -u "$ADMIN_USER:$ADMIN_PASS" -c "$CJ" -X POST "$BASE/login?realm=_" \
  -H 'Content-Type: application/json' -d '{}' -o /dev/null
COOKIE=$(grep '_ea_' "$CJ" | awk '{print $NF}')
assert_nonempty "$COOKIE" "admin login sets a session cookie"

CURL -b "$CJ" -X POST "$BASE/admins/realms" -H 'Content-Type: application/json' \
  -d "{\"id\":\"$REALM\",\"auth_params\":{\"username_password_params\":{\"allow_expired_passwords\":true}},\"session_max_age_seconds\":3600,\"session_max_stale_age_seconds\":3600}" \
  -o /dev/null

PW_BYTES=$(python3 -c "import json,sys;print(json.dumps(list(sys.argv[1].encode())))" "$USER_PASS")
CURL -b "$CJ" -X POST "$BASE/realms/$REALM/userpass" -H 'Content-Type: application/json' \
  -d "{\"realm\":\"$REALM\",\"username\":\"$USER_NAME\",\"password\":$PW_BYTES,\"change_password\":false,\"roles\":[\"Auditor\"]}" \
  -o /dev/null

# Confidential client
CONF=$(CURL -b "$CJ" -X POST "$BASE/realms/$REALM/clients" -H 'Content-Type: application/json' -d '{
  "client_name":"Conf Client",
  "redirect_uris":["'"$REDIRECT"'"],
  "grant_types":["authorization_code","refresh_token","client_credentials"],
  "response_types":["code"],
  "scopes":["openid","profile","email","offline_access","roles"],
  "token_endpoint_auth_method":"client_secret_basic"}')
CID=$(echo "$CONF" | jq -r .client_id)
CSECRET=$(echo "$CONF" | jq -r .client_secret)
assert_nonempty "$CID" "confidential client created"
assert_nonempty "$CSECRET" "confidential client returns a secret"

# Public (PKCE-only) client
PUB=$(CURL -b "$CJ" -X POST "$BASE/realms/$REALM/clients" -H 'Content-Type: application/json' -d '{
  "client_name":"Public Client",
  "redirect_uris":["'"$REDIRECT"'"],
  "grant_types":["authorization_code","refresh_token"],
  "response_types":["code"],
  "scopes":["openid","profile"],
  "token_endpoint_auth_method":"none"}')
PID=$(echo "$PUB" | jq -r .client_id)
assert_nonempty "$PID" "public client created"
assert_eq "null" "$(echo "$PUB" | jq -r .client_secret)" "public client has no secret"

# ── Discovery + JWKS ─────────────────────────────────────────────────────────
echo "== Discovery + JWKS =="
META=$(CURL "$BASE/.well-known/openid-configuration")
assert_eq "$BASE" "$(echo "$META" | jq -r .issuer)" "discovery issuer matches"
assert_eq "$BASE/oidc/authorize" "$(echo "$META" | jq -r .authorization_endpoint)" "authorization_endpoint"
assert_eq "$BASE/oidc/token" "$(echo "$META" | jq -r .token_endpoint)" "token_endpoint"
assert_eq "S256" "$(echo "$META" | jq -r '.code_challenge_methods_supported[0]')" "S256 advertised"
assert_eq "ES256" "$(echo "$META" | jq -r '.id_token_signing_alg_values_supported[0]')" "ES256 advertised"

JWKS=$(CURL "$BASE/oidc/jwks")
assert_ne "0" "$(echo "$JWKS" | jq '.keys | length')" "JWKS has keys"
assert_eq "EC" "$(echo "$JWKS" | jq -r '.keys[0].kty')" "JWKS key is EC"

# ── Happy path (confidential client) ─────────────────────────────────────────
echo "== Authorization Code + PKCE (confidential) =="
gen_pkce
CODE=$(get_code "$CID" "openid profile email offline_access roles" "st-1" "nonce-xyz" "$CHALLENGE")
assert_nonempty "$CODE" "authorization code obtained"

TOK=$(CURL -u "$CID:$CSECRET" -X POST "$BASE/oidc/token" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=$VERIFIER")
AT=$(echo "$TOK" | jq -r .access_token)
IDT=$(echo "$TOK" | jq -r .id_token)
RT=$(echo "$TOK" | jq -r .refresh_token)
assert_nonempty "$AT" "access_token issued"
assert_nonempty "$IDT" "id_token issued"
assert_nonempty "$RT" "refresh_token issued"
assert_eq "Bearer" "$(echo "$TOK" | jq -r .token_type)" "token_type is Bearer"

# ID token claims + header
assert_eq "$USER_NAME" "$(jwt_field "$IDT" sub)" "id_token sub"
assert_eq "$CID" "$(jwt_field "$IDT" aud)" "id_token aud == client_id"
assert_eq "nonce-xyz" "$(jwt_field "$IDT" nonce)" "id_token nonce echoed"
assert_eq "$BASE" "$(jwt_field "$IDT" iss)" "id_token iss == issuer"
assert_nonempty "$(jwt_field "$IDT" at_hash)" "id_token has at_hash"
assert_nonempty "$(jwt_header "$IDT" kid)" "id_token header has kid"
# Access token is an RFC 9068 at+jwt
assert_eq "at+jwt" "$(jwt_header "$AT" typ)" "access token typ is at+jwt"

# UserInfo
UI=$(CURL -H "Authorization: Bearer $AT" "$BASE/oidc/userinfo")
assert_eq "$USER_NAME" "$(echo "$UI" | jq -r .sub)" "userinfo sub"
assert_eq "Auditor" "$(echo "$UI" | jq -r '.roles[0]')" "userinfo roles"

# Introspection (active)
INTRO=$(CURL -u "$CID:$CSECRET" -X POST "$BASE/oidc/introspect" --data-urlencode "token=$AT")
assert_eq "true" "$(echo "$INTRO" | jq -r .active)" "introspect access token active"
assert_eq "$USER_NAME" "$(echo "$INTRO" | jq -r .sub)" "introspect sub"

# Refresh rotation
REF=$(CURL -u "$CID:$CSECRET" -X POST "$BASE/oidc/token" \
  --data-urlencode "grant_type=refresh_token" --data-urlencode "refresh_token=$RT")
RT2=$(echo "$REF" | jq -r .refresh_token)
assert_nonempty "$RT2" "refresh returns a new refresh token"
assert_ne "$RT" "$RT2" "refresh token rotates"

# Reuse of the old (revoked) refresh token fails and triggers family revocation
REUSE=$(CURL -u "$CID:$CSECRET" -X POST "$BASE/oidc/token" \
  --data-urlencode "grant_type=refresh_token" --data-urlencode "refresh_token=$RT")
assert_eq "invalid_grant" "$(echo "$REUSE" | jq -r .error)" "revoked refresh reuse rejected"

# Revoke the rotated refresh token
RC=$(CURL -o /dev/null -w '%{http_code}' -u "$CID:$CSECRET" -X POST "$BASE/oidc/revoke" --data-urlencode "token=$RT2")
assert_eq "200" "$RC" "revoke returns 200"
INTRO2=$(CURL -u "$CID:$CSECRET" -X POST "$BASE/oidc/introspect" --data-urlencode "token=$RT2")
assert_eq "false" "$(echo "$INTRO2" | jq -r .active)" "revoked refresh is inactive"

# ── Happy path (public client, client_secret_post via client_id in body) ─────
echo "== Authorization Code + PKCE (public client) =="
gen_pkce
CODE_P=$(get_code "$PID" "openid profile" "st-2" "n2" "$CHALLENGE")
TOK_P=$(CURL -X POST "$BASE/oidc/token" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=$PID" \
  --data-urlencode "code=$CODE_P" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=$VERIFIER")
assert_nonempty "$(echo "$TOK_P" | jq -r .access_token)" "public client token issued"
assert_nonempty "$(echo "$TOK_P" | jq -r .id_token)" "public client id_token issued"

# ── client_credentials ───────────────────────────────────────────────────────
echo "== client_credentials grant =="
CC=$(CURL -u "$CID:$CSECRET" -X POST "$BASE/oidc/token" \
  --data-urlencode "grant_type=client_credentials" --data-urlencode "scope=roles")
assert_nonempty "$(echo "$CC" | jq -r .access_token)" "client_credentials access token"
assert_eq "null" "$(echo "$CC" | jq -r .id_token)" "client_credentials has no id_token"
assert_eq "null" "$(echo "$CC" | jq -r .refresh_token)" "client_credentials has no refresh_token"

# ── Negative cases ───────────────────────────────────────────────────────────
echo "== Negative cases =="

# Unknown client_id at authorize → 400 error page (no redirect)
RC=$(CURL -o /dev/null -w '%{http_code}' "$BASE/oidc/authorize?response_type=code&client_id=nope&redirect_uri=$REDIRECT_ENC&scope=openid&code_challenge=x&code_challenge_method=S256")
assert_eq "400" "$RC" "unknown client_id → 400"

# Unregistered redirect_uri → 400 error page
RC=$(CURL -o /dev/null -w '%{http_code}' "$BASE/oidc/authorize?response_type=code&client_id=$CID&redirect_uri=$(urlenc https://evil.example/x)&scope=openid&code_challenge=x&code_challenge_method=S256")
assert_eq "400" "$RC" "bad redirect_uri → 400"

# Missing PKCE → 302 redirect with error=invalid_request
LOC=$(CURL -o /dev/null -D - "$BASE/oidc/authorize?response_type=code&client_id=$CID&redirect_uri=$REDIRECT_ENC&scope=openid&state=zz" | grep -i '^location:' | tr -d '\r' | sed 's/^[Ll]ocation: //')
assert_eq "invalid_request" "$(qparam "$LOC" error)" "missing PKCE → invalid_request redirect"
assert_eq "zz" "$(qparam "$LOC" state)" "error redirect preserves state"

# Unsupported response_type → 302 unsupported_response_type
LOC=$(CURL -o /dev/null -D - "$BASE/oidc/authorize?response_type=token&client_id=$CID&redirect_uri=$REDIRECT_ENC&scope=openid&code_challenge=x&code_challenge_method=S256" | grep -i '^location:' | tr -d '\r' | sed 's/^[Ll]ocation: //')
assert_eq "unsupported_response_type" "$(qparam "$LOC" error)" "response_type=token rejected"

# Wrong PKCE verifier at token → invalid_grant
gen_pkce
CODE_N=$(get_code "$CID" "openid" "s" "n" "$CHALLENGE")
BAD=$(CURL -u "$CID:$CSECRET" -X POST "$BASE/oidc/token" \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$CODE_N" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=this-is-the-wrong-verifier-at-least-forty-three-chars")
assert_eq "invalid_grant" "$(echo "$BAD" | jq -r .error)" "wrong PKCE verifier → invalid_grant"

# Reuse of a consumed code → invalid_grant
gen_pkce
CODE_R=$(get_code "$CID" "openid" "s" "n" "$CHALLENGE")
CURL -u "$CID:$CSECRET" -X POST "$BASE/oidc/token" \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$CODE_R" \
  --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "code_verifier=$VERIFIER" -o /dev/null
REPLAY=$(CURL -u "$CID:$CSECRET" -X POST "$BASE/oidc/token" \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$CODE_R" \
  --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "code_verifier=$VERIFIER")
assert_eq "invalid_grant" "$(echo "$REPLAY" | jq -r .error)" "code replay → invalid_grant"

# Wrong client secret → 401 invalid_client
RC=$(CURL -o /dev/null -w '%{http_code}' -u "$CID:wrong-secret" -X POST "$BASE/oidc/token" --data-urlencode "grant_type=client_credentials")
assert_eq "401" "$RC" "wrong client secret → 401"

# Unknown grant_type → unsupported_grant_type
UG=$(CURL -u "$CID:$CSECRET" -X POST "$BASE/oidc/token" --data-urlencode "grant_type=magic")
assert_eq "unsupported_grant_type" "$(echo "$UG" | jq -r .error)" "unknown grant_type rejected"

# Invalid bearer at userinfo → 401
RC=$(CURL -o /dev/null -w '%{http_code}' -H "Authorization: Bearer not-a-token" "$BASE/oidc/userinfo")
assert_eq "401" "$RC" "invalid bearer → 401 at userinfo"

# Public client cannot use client_credentials
PCC=$(CURL -X POST "$BASE/oidc/token" --data-urlencode "grant_type=client_credentials" --data-urlencode "client_id=$PID")
assert_eq "invalid_grant" "$(echo "$PCC" | jq -r .error)" "public client_credentials rejected"

# ── Summary ──────────────────────────────────────────────────────────────────
echo
echo "=============================================="
echo "OIDC harness: $PASS passed, $FAIL failed"
echo "=============================================="
[ "$FAIL" -eq 0 ]
