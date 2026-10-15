#!/usr/bin/env bash
# SAML end-to-end tests: the SAML auth_verifier Docker image as SP against a real Keycloak IdP.
# Brings the stack up (saml_e2e/stack.sh), runs HTTP-level checks and the Playwright browser
# tests in e2e/, then tears it down.
#
# Env: see saml_e2e/stack.sh; SAML_E2E_KEEP=1 leaves the stack running afterwards;
#      SAML_E2E_SKIP_BROWSER=1 skips the Playwright tests (needs pnpm and a Playwright Chromium).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
STACK="$SCRIPT_DIR/saml_e2e/stack.sh"

SP_PORT="${SP_PORT:-8443}"
IDP_PORT="${IDP_PORT:-9443}"
SP_REALM="${SP_REALM:-sso-demo}"
SP="https://127.0.0.1:${SP_PORT}"
IDP_SSO_URL="https://127.0.0.1:${IDP_PORT}/realms/demo/protocol/saml"

PASS=0
FAIL=0

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] || [ "$FAIL" -gt 0 ]; then
    bash "$STACK" logs
  fi
  if [ "${SAML_E2E_KEEP:-}" = 1 ]; then
    echo "SAML_E2E_KEEP=1: stack left running; stop it with: bash $STACK down"
  else
    bash "$STACK" down
  fi
}
trap cleanup EXIT

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
  if grep -qF -- "$needle" <<<"$haystack"; then
    echo "  PASS  $label"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $label (expected to contain '$needle', got: ${haystack:0:300})"
    FAIL=$((FAIL + 1))
  fi
}

# Status code and Location header of a request, without following redirects: "<code> <location>".
status_and_location() {
  curl -ks -o /dev/null -w '%{http_code} %{redirect_url}\n' "$@"
}

bash "$STACK" up

echo ""
echo "── SP metadata ───────────────────────────────────────────────────────"
METADATA=$(curl -ks "$SP/saml/$SP_REALM/metadata")
assert_contains "AuthnRequestsSigned=\"true\"" 'AuthnRequestsSigned="true"' "$METADATA"
assert_contains "entityID is the SP entity ID" "entityID=\"$SP/saml/$SP_REALM\"" "$METADATA"
assert_contains "ACS URL advertised" "Location=\"$SP/saml/$SP_REALM/acs\"" "$METADATA"

echo ""
echo "── Login redirect ────────────────────────────────────────────────────"
read -r CODE LOCATION < <(status_and_location "$SP/saml/$SP_REALM/login")
assert_eq "GET /saml/$SP_REALM/login → 302" "302" "$CODE"
assert_contains "redirects to the Keycloak SSO URL" "$IDP_SSO_URL?" "$LOCATION"
assert_contains "AuthnRequest is signed (Signature)" "Signature=" "$LOCATION"
assert_contains "AuthnRequest is signed (SigAlg)" "SigAlg=" "$LOCATION"

# Keycloak verifies the AuthnRequest signature against the SP certificate before showing
# its login form; an unsigned or badly signed request gets an error page instead.
IDP_PAGE=$(curl -ks "$LOCATION")
assert_contains "Keycloak accepts the signed AuthnRequest (login form shown)" 'id="kc-form-login"' "$IDP_PAGE"

echo ""
echo "── Return URL allowlist ──────────────────────────────────────────────"
read -r CODE _ < <(status_and_location -G --data-urlencode "return_to=$SP/whoami?realm=$SP_REALM" "$SP/saml/$SP_REALM/login")
assert_eq "allowed return_to → 302" "302" "$CODE"
read -r CODE _ < <(status_and_location -G --data-urlencode "return_to=https://evil.example.com/" "$SP/saml/$SP_REALM/login")
assert_eq "foreign return_to → 400" "400" "$CODE"

echo ""
echo "── ACS refusals ──────────────────────────────────────────────────────"
CODE=$(curl -ks -o /dev/null -w '%{http_code}' -X POST -d 'SAMLResponse=eA==&RelayState=x' "$SP/saml/$SP_REALM/acs")
assert_eq "ACS without the login cookie → 401" "401" "$CODE"

echo ""
echo "── Realm without SAML ────────────────────────────────────────────────"
CODE=$(curl -ks -o /dev/null -w '%{http_code}' "$SP/saml/_/login")
assert_eq "GET /saml/_/login → 400" "400" "$CODE"

echo ""
echo "=========================================="
echo "HTTP checks: $PASS passed, $FAIL failed"
echo "=========================================="

BROWSER_STATUS=0
if [ "${SAML_E2E_SKIP_BROWSER:-}" != 1 ]; then
  echo ""
  echo "── Browser tests (Playwright) ────────────────────────────────────────"
  pnpm --dir "$REPO_ROOT/e2e" install --frozen-lockfile
  SP_PORT="$SP_PORT" IDP_PORT="$IDP_PORT" SP_REALM="$SP_REALM" \
    pnpm --dir "$REPO_ROOT/e2e" exec playwright test || BROWSER_STATUS=$?
fi

[ "$FAIL" -eq 0 ] && [ "$BROWSER_STATUS" -eq 0 ]
