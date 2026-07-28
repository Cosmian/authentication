{
  pkgs ? import <nixpkgs> { },
  # Auth server derivation to include in the image
  authServer ? null,
  # Admin UI derivation to include in the image (optional)
  adminUi ? null,
  # Version (from Cargo.toml)
  version,
}:

let
  actualAuthServer =
    if authServer != null then
      authServer
    else
      builtins.throw "authServer parameter is required. Pass it from default.nix";

  # Admin UI static assets — included when adminUi derivation is provided.
  # Files are placed at /srv/admin-ui/ so the auth_verifier (or a reverse proxy)
  # can serve them. When adminUi is null the paths entry is simply omitted.
  adminUiContent =
    if adminUi != null then
      pkgs.runCommand "admin-ui-srv" { } ''
        mkdir -p $out/srv/admin-ui
        cp -r ${adminUi}/dist/. $out/srv/admin-ui/
      ''
    else
      null;

  imageName = "cosmian-auth-verifier";
  imageTag = "${version}";

  # ── Entrypoint script ─────────────────────────────────────────────────────
  # Resolves the configuration file at runtime:
  #   1. AUTH_SERVER_CONF env var (explicit path)
  #   2. /etc/cosmian/auth_verifier.toml  (volume-mounted config)
  #   3. Fall back to the pre-generated dev certificate baked into the image
  #
  # To use a custom configuration:
  #   docker run -e AUTH_SERVER_CONF=/my/config.toml \
  #              -v /host/config.toml:/my/config.toml:ro \
  #              -v /host/certs:/my/certs:ro \
  #              cosmian-auth-verifier
  #
  # Or mount at the default location:
  #   docker run -v /host/auth_verifier.toml:/etc/cosmian/auth_verifier.toml:ro \
  #              -v /host/certs:/etc/cosmian/certs:ro \
  #              cosmian-auth-verifier
  startupScript = pkgs.runCommand "auth-verifier-entrypoint" { } ''
    mkdir -p $out/bin
    cat > $out/bin/docker-entrypoint.sh << 'EOF'
#!${pkgs.bash}/bin/bash
set -e

# ── Resolve configuration file ─────────────────────────────────────────────
CONF_PATH="''${AUTH_SERVER_CONF:-}"
if [ -z "$CONF_PATH" ]; then
  CONF_PATH="/etc/cosmian/auth_verifier.toml"
fi

if [ ! -f "$CONF_PATH" ]; then
  echo "No configuration file found at '$CONF_PATH'."
  echo "Using built-in development configuration (self-signed TLS, in-memory SQLite)."
  echo "WARNING: The TLS private key is embedded in the image — NOT for production use."
  echo "         To use a custom configuration:"
  echo "           Mount your TOML at /etc/cosmian/auth_verifier.toml, or"
  echo "           set AUTH_SERVER_CONF to the path of your configuration file."
  CONF_PATH="/etc/cosmian/dev/auth_verifier.toml"
fi

echo "Starting auth_verifier with configuration: $CONF_PATH"
exec auth_verifier "$CONF_PATH"
EOF
    chmod +x $out/bin/docker-entrypoint.sh
  '';

  # Pre-generate a self-signed dev certificate at Nix build time.
  # openssl runs here (in the Nix sandbox), never inside the running container.
  # The private key is embedded in the image and is NOT secret — it is used only
  # as a zero-configuration fallback for development and testing.
  devCerts = pkgs.runCommand "auth-verifier-dev-certs"
    { nativeBuildInputs = [ pkgs.openssl ]; }
    ''
      mkdir -p $out/etc/cosmian/dev/certs
      openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out $out/etc/cosmian/dev/certs/server.key.pem
      openssl req -new -x509 \
        -key $out/etc/cosmian/dev/certs/server.key.pem \
        -out $out/etc/cosmian/dev/certs/server.cert.pem \
        -days 3650 \
        -subj "/CN=cosmian-auth-verifier" \
        -addext "subjectAltName=IP:0.0.0.0,IP:127.0.0.1,DNS:localhost"
      cp $out/etc/cosmian/dev/certs/server.cert.pem \
         $out/etc/cosmian/dev/certs/ca.pem
    '';

  devConfig = pkgs.writeTextFile {
    name = "auth-verifier-dev-config";
    text = ''
      # Development-only — TLS key embedded in image, NOT for production.
      host_name = "0.0.0.0"
      host_port = 8443
      roles = ["SuperAdmin", "DomainAdmin", "CryptoOfficer", "Auditor", "User"]

      [tls_params]
      server_private_key = "/etc/cosmian/dev/certs/server.key.pem"
      server_certificate = "/etc/cosmian/dev/certs/server.cert.pem"
      server_ca_chain    = "/etc/cosmian/dev/certs/ca.pem"

      [database_params]
      backend        = "sqlite"
      connection_url = "sqlite::memory:"
    '';
    destination = "/etc/cosmian/dev/auth_verifier.toml";
  };

  runtimeEnv = pkgs.buildEnv {
    name = "auth-verifier-runtime-env";
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
  authDirectories = pkgs.runCommand "auth-verifier-directories" { } ''
    mkdir -p $out/home/auth
    mkdir -p $out/etc/cosmian
    mkdir -p $out/tmp
    chmod 1777 $out/tmp
  '';

in
pkgs.dockerTools.buildImage {
  name = imageName;
  tag = imageTag;

  copyToRoot = pkgs.buildEnv {
    name = "image-root";
    paths =
      [
        runtimeEnv
        etcPasswd
        etcGroup
        etcNsswitch
        pkgs.dockerTools.caCertificates
        startupScript
        authDirectories
        devCerts
        devConfig
      ]
      ++ pkgs.lib.optional (adminUiContent != null) adminUiContent;
    pathsToLink = [
      "/bin"
      "/etc"
      "/home"
      "/srv"
      "/tmp"
      "/usr"
      "/var"
    ];
  };

  config = {
    # The entrypoint resolves configuration at runtime.
    # Pass a custom config path as CMD to override the default lookup:
    #   docker run cosmian-auth-verifier /path/to/auth_verifier.toml
    Entrypoint = [ "/bin/docker-entrypoint.sh" ];
    Cmd = [ ];
    ExposedPorts = {
      "8443/tcp" = { };
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
  # auth_verifier has its ELF interpreter patched to the system path
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

      ${pkgs.lib.optionalString (adminUiContent != null) ''
        # Verify admin-ui assets were bundled correctly
        if [ ! -f srv/admin-ui/index.html ]; then
          echo "ERROR: /srv/admin-ui/index.html not found in Docker image" >&2
          echo "Contents of srv/:" >&2
          find srv/ -type f 2>/dev/null || echo "(srv/ is empty or missing)" >&2
          exit 1
        fi
        UI_FILES=$(find srv/admin-ui -type f | wc -l)
        echo "admin-ui check PASSED: $UI_FILES files present at /srv/admin-ui/"
      ''}
    '';
}
