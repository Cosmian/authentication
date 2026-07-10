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
  #   3. Fall back to the pre-generated dev certificate baked into the image
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
  echo "Using built-in development configuration (self-signed TLS, in-memory SQLite)."
  echo "WARNING: The TLS private key is embedded in the image — NOT for production use."
  echo "         To use a custom configuration:"
  echo "           Mount your TOML at /etc/auth_server/auth_server.toml, or"
  echo "           set AUTH_SERVER_CONF to the path of your configuration file."
  CONF_PATH="/etc/auth_server/dev/auth_server.toml"
fi

echo "Starting auth_server with configuration: $CONF_PATH"
exec auth_server "$CONF_PATH"
EOF
    chmod +x $out/bin/docker-entrypoint.sh
  '';

  # Pre-generate a self-signed dev certificate at Nix build time.
  # openssl runs here (in the Nix sandbox), never inside the running container.
  # The private key is embedded in the image and is NOT secret — it is used only
  # as a zero-configuration fallback for development and testing.
  devCerts = pkgs.runCommand "auth-server-dev-certs"
    { nativeBuildInputs = [ pkgs.openssl ]; }
    ''
      mkdir -p $out/etc/auth_server/dev/certs
      openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out $out/etc/auth_server/dev/certs/server.key.pem
      openssl req -new -x509 \
        -key $out/etc/auth_server/dev/certs/server.key.pem \
        -out $out/etc/auth_server/dev/certs/server.cert.pem \
        -days 3650 \
        -subj "/CN=cosmian-auth-server" \
        -addext "subjectAltName=IP:0.0.0.0,IP:127.0.0.1,DNS:localhost"
      cp $out/etc/auth_server/dev/certs/server.cert.pem \
         $out/etc/auth_server/dev/certs/ca.pem
    '';

  devConfig = pkgs.writeTextFile {
    name = "auth-server-dev-config";
    text = ''
      # Development-only — TLS key embedded in image, NOT for production.
      host_name = "0.0.0.0"
      host_port = 9005
      roles = ["SuperAdmin", "DomainAdmin", "CryptoOfficer", "Auditor", "User"]

      [tls_params]
      server_private_key = "/etc/auth_server/dev/certs/server.key.pem"
      server_certificate = "/etc/auth_server/dev/certs/server.cert.pem"
      server_ca_chain    = "/etc/auth_server/dev/certs/ca.pem"

      [database_params]
      backend        = "sqlite"
      connection_url = "sqlite::memory:"
    '';
    destination = "/etc/auth_server/dev/auth_server.toml";
  };

  runtimeEnv = pkgs.buildEnv {
    name = "auth-server-runtime-env";
    paths = [
      actualAuthServer
      pkgs.tzdata
      pkgs.coreutils
      pkgs.bash
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
      devCerts
      devConfig
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

  # Fix /tmp permissions and wire up standard ELF interpreter / library paths.
  #
  # auth_server has its ELF interpreter patched to the system path
  # (/lib64/ld-linux-x86-64.so.2 on x86_64, /lib/ld-linux-aarch64.so.1 on
  # aarch64) and its RPATH removed so it runs on bare-metal Linux.  In a
  # Nix-built Docker image glibc lives in the Nix store (already in the
  # image closure as a transitive dep of bash/coreutils), not at standard
  # system paths.  Create /lib and /lib64 with symlinks into the Nix store
  # so the dynamic linker can find libc.so.6, libm.so.6, libgcc_s.so.1 etc.
  extraCommands =
    let
      isX86_64 = pkgs.stdenv.hostPlatform.isx86_64;
      glibcLib = "${pkgs.glibc.out}/lib";
      gccRtLib = "${pkgs.stdenv.cc.cc.lib}/lib";
      interpFile =
        if isX86_64 then "ld-linux-x86-64.so.2" else "ld-linux-aarch64.so.1";
      interpDir = if isX86_64 then "lib64" else "lib";
    in
    ''
      chmod 1777 tmp
      mkdir -p lib lib64

      # Interpreter symlink (the binary's PT_INTERP entry)
      ln -sf ${glibcLib}/${interpFile} ${interpDir}/${interpFile}

      # Shared libraries: glibc (libc.so.6, libm.so.6, libdl.so.2, …)
      for f in ${glibcLib}/*.so ${glibcLib}/*.so.*; do
        [ -e "$f" ] && ln -sf "$f" "lib/$(basename "$f")" || true
      done

      # Shared libraries: gcc runtime (libgcc_s.so.1)
      for f in ${gccRtLib}/libgcc_s.so*; do
        [ -e "$f" ] && ln -sf "$f" "lib/$(basename "$f")" || true
      done
    '';
}
