#!/usr/bin/env bash
# Start/stop the SAML end-to-end stack: the SAML auth_verifier image (SP) next to a
# Keycloak IdP, both published on 127.0.0.1 so a browser on the host can reach them.
#
# Usage: stack.sh up|down|logs
#
# Env:
#   DOCKER_IMAGE_NAME  SAML auth_verifier image (default: newest local cosmian-auth-verifier:*-saml)
#   KEYCLOAK_IMAGE     Keycloak image (default: pinned digest below)
#   SAML_E2E_DIR       work dir for keys, configs and metadata (default: /tmp/saml-e2e)
#   SP_PORT, IDP_PORT  host ports (default: 8443, 9443)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Multi-arch (amd64 + arm64) index digest of quay.io/keycloak/keycloak:26.4 (26.4.7).
KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.4@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007}"
WORK_DIR="${SAML_E2E_DIR:-/tmp/saml-e2e}"
SP_PORT="${SP_PORT:-8443}"
IDP_PORT="${IDP_PORT:-9443}"
SP_CONTAINER=saml-e2e-sp
IDP_CONTAINER=saml-e2e-idp

export SP_ORIGIN="https://127.0.0.1:${SP_PORT}"
export SP_REALM="${SP_REALM:-sso-demo}"
# Realm created through the admin UI by the e2e tests; Keycloak only needs its client.
SP_UI_REALM="${SP_UI_REALM:-sso-ui}"
IDP_ORIGIN="https://127.0.0.1:${IDP_PORT}"
IDP_METADATA_URL="${IDP_ORIGIN}/realms/demo/protocol/saml/descriptor"

resolve_sp_image() {
  if [ -n "${DOCKER_IMAGE_NAME:-}" ]; then
    echo "$DOCKER_IMAGE_NAME"
    return
  fi
  local image
  image=$(docker images --format '{{.Repository}}:{{.Tag}}' cosmian-auth-verifier | grep -- '-saml$' | head -n1 || true)
  if [ -z "$image" ]; then
    echo "ERROR: no cosmian-auth-verifier:*-saml image found; run 'mise run docker:load -- --variant saml' or set DOCKER_IMAGE_NAME" >&2
    exit 1
  fi
  echo "$image"
}

generate_keys() {
  if [ -d "$WORK_DIR" ] && [ -n "$(ls -A "$WORK_DIR")" ] && [ ! -f "$WORK_DIR/.saml-e2e" ]; then
    echo "ERROR: $WORK_DIR is not empty and was not created by this script" >&2
    exit 1
  fi
  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR"
  touch "$WORK_DIR/.saml-e2e"
  # Both containers run as uid 1000 and must read these throw-away files.
  chmod 755 "$WORK_DIR"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$WORK_DIR/tls.key.pem"
  openssl req -new -x509 -key "$WORK_DIR/tls.key.pem" -out "$WORK_DIR/tls.cert.pem" -days 2 \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  openssl req -x509 -newkey rsa:3072 -sha256 -days 2 -nodes -subj "/CN=saml-e2e-sp" \
    -keyout "$WORK_DIR/saml-sp.key.pem" -out "$WORK_DIR/saml-sp.cert.pem" 2>/dev/null
}

write_sp_config() {
  cat >"$WORK_DIR/auth_verifier.toml" <<TOML
host_name = "0.0.0.0"
host_port = ${SP_PORT}
admin_ui_path = "/srv/admin-ui"
roles = ["SuperAdmin", "DomainAdmin", "CryptoOfficer", "Auditor", "User"]

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
}

write_idp_realm() {
  SP_CERT=$(grep -v -- '-----' "$WORK_DIR/saml-sp.cert.pem" | tr -d '\n')
  export SP_CERT
  local realm rendered=()
  for realm in "$SP_REALM" "$SP_UI_REALM"; do
    # shellcheck disable=SC2016 # literal variable list for envsubst
    SP_REALM="$realm" envsubst '${SP_ORIGIN} ${SP_REALM} ${SP_CERT}' \
      <"$SCRIPT_DIR/keycloak-realm.json.tmpl" >"$WORK_DIR/kc-$realm.json"
    rendered+=("$WORK_DIR/kc-$realm.json")
  done
  jq -s '.[0] + {clients: [.[].clients[]]}' "${rendered[@]}" >"$WORK_DIR/demo-realm.json"
  rm -f "${rendered[@]}"
}

wait_for() {
  local name="$1" url="$2" container="$3" tries="${4:-90}"
  echo "Waiting for $name ($url)…"
  for i in $(seq 1 "$tries"); do
    if curl -ksf -o /dev/null "$url"; then
      echo "$name is ready (attempt $i)"
      return 0
    fi
    if ! docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
      echo "ERROR: $container exited prematurely" >&2
      docker logs "$container" 2>&1 | tail -n 100 >&2 || true
      return 1
    fi
    sleep 2
  done
  echo "ERROR: $name not ready after $((tries * 2)) s" >&2
  docker logs "$container" 2>&1 | tail -n 100 >&2 || true
  return 1
}

seed_sp_realm() {
  local jar="$WORK_DIR/admin.cookies" code
  code=$(curl -ks -o /dev/null -w '%{http_code}' -c "$jar" -X POST \
    -H "Authorization: Basic $(printf 'admin:change_me' | base64)" \
    -H "Content-Type: application/json" -d '{}' "$SP_ORIGIN/login?realm=_")
  [ "$code" = 200 ] || { echo "ERROR: admin login returned $code" >&2; return 1; }

  jq -n --rawfile metadata "$WORK_DIR/idp-metadata.xml" \
    --arg realm "$SP_REALM" --arg origin "$SP_ORIGIN" '{
      id: $realm,
      auth_params: {
        saml_params: {
          metadata_xml: $metadata,
          sp_entity_id: "\($origin)/saml/\($realm)",
          sp_acs_url: "\($origin)/saml/\($realm)/acs",
          subject_attribute: "username",
          role_attribute: "groups",
          attribute_claim_map: { email: "mail" },
          allowed_return_origins: [$origin],
          default_return_url: "\($origin)/whoami?realm=\($realm)"
        }
      },
      session_max_age_seconds: 3600,
      session_max_stale_age_seconds: 3600
    }' >"$WORK_DIR/sp-realm.json"

  code=$(curl -ks -o "$WORK_DIR/sp-realm.response" -w '%{http_code}' -b "$jar" -X POST \
    -H "Content-Type: application/json" --data-binary "@$WORK_DIR/sp-realm.json" \
    "$SP_ORIGIN/admins/realms")
  case "$code" in
    2*) echo "Created SP realm $SP_REALM" ;;
    *)
      echo "ERROR: creating realm $SP_REALM returned $code: $(cat "$WORK_DIR/sp-realm.response")" >&2
      return 1
      ;;
  esac
}

up() {
  local sp_image
  sp_image=$(resolve_sp_image)
  down
  generate_keys
  write_sp_config
  write_idp_realm
  chmod 644 "$WORK_DIR"/*

  echo "Starting IdP: $KEYCLOAK_IMAGE"
  docker run -d --name "$IDP_CONTAINER" -p "127.0.0.1:${IDP_PORT}:${IDP_PORT}" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    -e KC_HTTPS_PORT="$IDP_PORT" -e KC_HOSTNAME="$IDP_ORIGIN" \
    -e KC_HTTPS_CERTIFICATE_FILE=/conf/tls.cert.pem \
    -e KC_HTTPS_CERTIFICATE_KEY_FILE=/conf/tls.key.pem \
    -v "$WORK_DIR:/conf:ro" \
    -v "$WORK_DIR/demo-realm.json:/opt/keycloak/data/import/demo-realm.json:ro" \
    "$KEYCLOAK_IMAGE" start-dev --import-realm >/dev/null

  echo "Starting SP: $sp_image"
  docker run -d --name "$SP_CONTAINER" -p "127.0.0.1:${SP_PORT}:${SP_PORT}" \
    -v "$WORK_DIR:/conf:ro" -e AUTH_SERVER_CONF=/conf/auth_verifier.toml \
    "$sp_image" >/dev/null

  wait_for "SP" "$SP_ORIGIN/public/version" "$SP_CONTAINER" 30
  wait_for "IdP" "$IDP_METADATA_URL" "$IDP_CONTAINER" 90
  curl -ksSf -o "$WORK_DIR/idp-metadata.xml" "$IDP_METADATA_URL"
  seed_sp_realm
  echo "SAML e2e stack is up: SP $SP_ORIGIN, IdP $IDP_ORIGIN (work dir $WORK_DIR)"
}

down() {
  docker rm -f "$SP_CONTAINER" "$IDP_CONTAINER" >/dev/null 2>&1 || true
}

logs() {
  for c in "$SP_CONTAINER" "$IDP_CONTAINER"; do
    echo "──── docker logs $c ────"
    docker logs "$c" 2>&1 | tail -n 200 || true
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  logs) logs ;;
  *)
    echo "Usage: $0 up|down|logs" >&2
    exit 2
    ;;
esac
