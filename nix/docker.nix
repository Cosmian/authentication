{
  pkgs ? import <nixpkgs> { },
  # Auth server derivation to include in the image
  authServer ? null,
  # Version (from Cargo.toml)
  version,
}:

let
  actualAuthServer =
    if authServer != null then
      authServer
    else
      builtins.throw "authServer parameter is required. Pass it from default.nix";

  imageName = "cosmian-auth-server";
  imageTag = "${version}";

  # ── Entrypoint script ─────────────────────────────────────────────────────
  # Resolves the configuration file at runtime:
  #   1. AUTH_SERVER_CONF env var (explicit path)
  #   2. /etc/auth_server/auth_server.toml  (volume-mounted config)
  #   3. Auto-generate a self-signed TLS certificate + minimal TOML in /tmp
  #
  # To use a custom configuration:
  #   docker run -e AUTH_SERVER_CONF=/my/config.toml \
  #              -v /host/config.toml:/my/config.toml:ro \
  #              -v /host/certs:/my/certs:ro \
  #              cosmian-auth-server
  #
  # Or mount at the default location:
  #   docker run -v /host/auth_server.toml:/etc/auth_server/auth_server.toml:ro \
  #              -v /host/certs:/etc/auth_server/certs:ro \
  #              cosmian-auth-server
  startupScript = pkgs.runCommand "auth-server-entrypoint" { } ''
    mkdir -p $out/bin
    cat > $out/bin/docker-entrypoint.sh << 'EOF'
#!${pkgs.bash}/bin/bash
set -e

# ── Resolve configuration file ─────────────────────────────────────────────
CONF_PATH="''${AUTH_SERVER_CONF:-}"
if [ -z "$CONF_PATH" ]; then
  CONF_PATH="/etc/auth_server/auth_server.toml"
fi

if [ ! -f "$CONF_PATH" ]; then
  echo "No configuration file found at '$CONF_PATH'."
  echo "Generating self-signed TLS certificate and a minimal configuration."

  GEN_DIR="/tmp/auth_server"
  mkdir -p "$GEN_DIR/certs"

  # Generate an EC P-256 private key
  openssl ecparam -name prime256v1 -genkey -noout \
    -out "$GEN_DIR/certs/server.key.pem"

  # Self-signed certificate valid for 10 years, with SAN for localhost
  openssl req -new -x509 \
    -key "$GEN_DIR/certs/server.key.pem" \
    -out "$GEN_DIR/certs/server.cert.pem" \
    -days 3650 \
    -subj "/CN=cosmian-auth-server" \
    -addext "subjectAltName=IP:0.0.0.0,IP:127.0.0.1,DNS:localhost"

  # CA chain = self-signed cert (single-tier PKI)
  cp "$GEN_DIR/certs/server.cert.pem" "$GEN_DIR/certs/ca.pem"

  TOML_FILE="$GEN_DIR/auth_server.toml"
  printf 'host_name = "0.0.0.0"\n'   > "$TOML_FILE"
  printf 'host_port = 9005\n'        >> "$TOML_FILE"
  printf 'roles = ["SuperAdmin", "DomainAdmin", "CryptoOfficer", "Auditor", "User"]\n' >> "$TOML_FILE"
  printf '\n[tls_params]\n'          >> "$TOML_FILE"
  printf 'server_private_key = "%s"\n' "$GEN_DIR/certs/server.key.pem" >> "$TOML_FILE"
  printf 'server_certificate = "%s"\n' "$GEN_DIR/certs/server.cert.pem" >> "$TOML_FILE"
  printf 'server_ca_chain    = "%s"\n' "$GEN_DIR/certs/ca.pem"          >> "$TOML_FILE"
  printf '\n[database_params]\n'     >> "$TOML_FILE"
  printf 'backend        = "sqlite"\n'           >> "$TOML_FILE"
  printf 'connection_url = "sqlite::memory:"\n'  >> "$TOML_FILE"

  CONF_PATH="$TOML_FILE"
  echo "Generated configuration : $CONF_PATH"
  echo "Self-signed certificate : $GEN_DIR/certs/server.cert.pem"
  echo ""
  echo "To use a custom configuration:"
  echo "  Mount your TOML at /etc/auth_server/auth_server.toml, or"
  echo "  set AUTH_SERVER_CONF to the path of your configuration file."
fi

echo "Starting auth_server with configuration: $CONF_PATH"
exec auth_server "$CONF_PATH"
EOF
    chmod +x $out/bin/docker-entrypoint.sh
  '';

  runtimeEnv = pkgs.buildEnv {
    name = "auth-server-runtime-env";
    paths = [
      actualAuthServer
      pkgs.tzdata
      pkgs.coreutils
      pkgs.bash
      pkgs.openssl # required for self-signed cert generation at startup
    ];
  };

  etcPasswd = pkgs.writeTextFile {
    name = "passwd";
    text = ''
      root:x:0:0:root:/root:/bin/sh
      auth:x:1000:1000:Auth User:/home/auth:/bin/sh
    '';
    destination = "/etc/passwd";
  };

  etcGroup = pkgs.writeTextFile {
    name = "group";
    text = ''
      root:x:0:
      auth:x:1000:
    '';
    destination = "/etc/group";
  };

  etcNsswitch = pkgs.writeTextFile {
    name = "nsswitch.conf";
    text = ''
      hosts: files dns
      networks: files
      passwd: files
      group: files
    '';
    destination = "/etc/nsswitch.conf";
  };

  # Runtime directories
  authDirectories = pkgs.runCommand "auth-server-directories" { } ''
    mkdir -p $out/home/auth
    mkdir -p $out/etc/auth_server
    mkdir -p $out/tmp
    chmod 1777 $out/tmp
  '';

in
pkgs.dockerTools.buildImage {
  name = imageName;
  tag = imageTag;

  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths = [
      runtimeEnv
      etcPasswd
      etcGroup
      etcNsswitch
      pkgs.dockerTools.caCertificates
      startupScript
      authDirectories
    ];
    pathsToLink = [
      "/bin"
      "/etc"
      "/home"
      "/tmp"
      "/usr"
      "/var"
    ];
  };

  config = {
    # The entrypoint resolves configuration at runtime.
    # Pass a custom config path as CMD to override the default lookup:
    #   docker run cosmian-auth-server /path/to/auth_server.toml
    Entrypoint = [ "/bin/docker-entrypoint.sh" ];
    Cmd = [ ];
    ExposedPorts = {
      "9005/tcp" = { };
    };
    User = "1000:1000";
    WorkingDir = "/home/auth";
    Labels = {
      "org.opencontainers.image.title" = "Cosmian Authentication Server";
      "org.opencontainers.image.version" = version;
      "org.opencontainers.image.vendor" = "Cosmian";
    };
  };

  created = "now";
}
