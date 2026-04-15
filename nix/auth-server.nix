{
  pkgs ? import <nixpkgs> { },
  pkgs234 ? pkgs, # nixpkgs 22.05 with glibc 2.34 (Rocky Linux 9 compatibility)
  lib ? pkgs.lib,
  # Provide a rustPlatform that uses the desired Rust but links against pkgs234 (glibc 2.34)
  rustPlatform ? pkgs.rustPlatform,
  # Version (from Cargo.toml)
  version,
  # Linkage mode: true for static OpenSSL, false for dynamic OpenSSL
  static ? true,
}:

let
  # On Linux, use pkgs234 stdenv (glibc 2.34) to broaden runtime compatibility.
  # On macOS, use the default stdenv.
  platform = if pkgs.stdenv.isLinux then pkgs234 else pkgs;

  # Name tag for output symlinks
  linkTag = if static then "static" else "dynamic";

  # Expected deterministic sha256 of the final installed binary (auth_server)
  # Naming convention (matches repository files):
  #   auth-server.<static|dynamic>.<arch>.<os>.sha256
  expectedHashDir = ./expected-hashes;

  # Helper: read & trim a hash file, returning null when absent or placeholder.
  readHashFile =
    name:
    let
      path = expectedHashDir + "/${name}";
    in
    if builtins.pathExists path then
      let
        raw = builtins.readFile path;
        trimmed = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] raw;
        isPlaceholder = builtins.match "^0+$" trimmed != null;
      in
      if trimmed != "" && !isPlaceholder then trimmed else null
    else
      null;

  # Pre-read expected hashes for every arch+os combination this derivation supports.
  expectedHash_x86_64_linux = readHashFile "auth-server.${linkTag}.x86_64.linux.sha256";
  expectedHash_aarch64_linux = readHashFile "auth-server.${linkTag}.aarch64.linux.sha256";
  expectedHash_x86_64_darwin = readHashFile "auth-server.${linkTag}.x86_64.darwin.sha256";
  expectedHash_arm64_darwin = readHashFile "auth-server.${linkTag}.arm64.darwin.sha256";

  srcRoot = ../.;

  filteredSrc = lib.cleanSourceWith {
    src = srcRoot;
    filter =
      path: type:
      let
        rel = lib.removePrefix (toString srcRoot + "/") (toString path);
        isEphemeral =
          lib.hasInfix "/target/" rel
          || lib.hasSuffix "/target" rel;
        basePaths =
          rel == "Cargo.toml"
          || rel == "Cargo.lock"
          || rel == "LICENSE"
          || rel == "README.md"
          || rel == "client"
          || lib.hasPrefix "client/" rel
          || rel == "server"
          || lib.hasPrefix "server/" rel;
      in
      lib.cleanSourceFilter path type && (!isEphemeral) && basePaths;
  };

  # Git-sourced crate output hashes.
  # When adding a new git dep, set a fake hash here, run nix-build, and copy the
  # "got: sha256-..." value from the error into this attribute set.
  gitDepOutputHashes = { };

  # Build inputs: darwin frameworks + iconv
  buildInputs =
    [ ]
    ++ lib.optionals pkgs.stdenv.isDarwin (
      let
        fw = pkgs.darwin.apple_sdk.frameworks;
      in
      [
        fw.SystemConfiguration
        fw.Security
        fw.CoreFoundation
        pkgs.libiconv
      ]
    );

  # Native build inputs needed by vendored OpenSSL and aws-lc-sys
  nativeBuildInputs =
    [
      pkgs.pkg-config
      pkgs.perl # required by openssl crate vendored build
      pkgs.cmake # required by aws-lc-sys
    ]
    ++ lib.optionals pkgs.stdenv.isLinux [
      platform.patchelf
    ];

in
rustPlatform.buildRustPackage {
  pname = "auth_server";
  inherit version;

  src = filteredSrc;

  # Use cargoLock instead of cargoHash to support git-sourced dependencies
  # (e.g. cosmian_logger from github.com/Cosmian/http_client_server).
  # Output hashes for git deps must be set in gitDepOutputHashes above.
  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = gitDepOutputHashes;
  };

  inherit buildInputs nativeBuildInputs;

  # Enable vendored OpenSSL + database support by default
  buildFeatures = [ ];

  # Build only the server binary
  cargoBuildFlags = [ "-p" "auth_server" "--bin" "auth_server" ];

  doCheck = false;
  # Disable cargo-auditable: the pinned nixpkgs version doesn't support edition 2024
  auditable = false;

  # Custom build phase: explicit cargo build so we control flags precisely.
  # We must set CC_<triple> / CXX_<triple> explicitly here because we use a
  # custom buildPhase that bypasses cargoBuildHook, which normally injects these
  # variables pointing to platform.stdenv.cc (pkgs234, glibc 2.34).  Without
  # them the cc/cmake crates fall back to whatever `cc` is found in PATH, which
  # may be from the modern nixpkgs (glibc 2.40) and would produce object files
  # referencing __isoc23_strtol / __isoc23_sscanf — symbols absent in glibc 2.34.
  buildPhase =
    let
      # On aarch64 Linux, pkgs234's default stdenv.cc is gcc-9.3.0 which is rejected
      # by aws-lc-sys v0.39.1+ due to a memcmp bug (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189).
      # Use gcc11 from pkgs234 instead — still glibc 2.34 compatible but without the bug.
      effectiveCc =
        if pkgs.stdenv.isLinux && platform.stdenv.hostPlatform.isAarch64
        then platform.gcc11
        else platform.stdenv.cc;
      ccBin = "${effectiveCc}/bin/${effectiveCc.targetPrefix}cc";
      cxxBin = "${effectiveCc}/bin/${effectiveCc.targetPrefix}c++";
      # Convert "x86_64-unknown-linux-gnu" → "x86_64_unknown_linux_gnu"
      rustTriple = lib.replaceStrings [ "-" ] [ "_" ] platform.stdenv.hostPlatform.config;
      ccExports = lib.optionalString pkgs.stdenv.isLinux ''
        export CC_${rustTriple}=${ccBin}
        export CXX_${rustTriple}=${cxxBin}
      '';
    in
    ''
      echo "== cargo build auth_server (release) =="
      ${ccExports}cargo build --release -p auth_server --bin auth_server
    '';

  # Custom install phase: copy the binary and immediately patch its ELF
  # interpreter to the SYSTEM dynamic linker (not the Nix store one),
  # so the resulting binary is portable to any Linux with glibc >= 2.34.
  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin"
    install -m755 target/release/auth_server "$out/bin/auth_server"

    if [ "$(uname)" = "Linux" ]; then
      ARCH="$(uname -m)"
      if [ "$ARCH" = "x86_64" ]; then
        DL="/lib64/ld-linux-x86-64.so.2"
      elif [ "$ARCH" = "aarch64" ]; then
        DL="/lib/ld-linux-aarch64.so.1"
      fi
      if [ -n "$DL" ]; then
        patchelf --set-interpreter "$DL" "$out/bin/auth_server" \
          || echo "Warning: patchelf failed (binary may be statically linked)"
        patchelf --remove-rpath "$out/bin/auth_server" 2>/dev/null || true
      fi
    fi
    runHook postInstall
  '';

  # postInstall: verify binary and run hash checks.
  postInstall = ''
    BIN="$out/bin/auth_server"
    [ -f "$BIN" ] || { echo "ERROR: Binary not found at $BIN"; exit 1; }
    echo "Binary exists at: $BIN"

    file "$BIN" || true
    if [ "$(uname)" = "Linux" ]; then
      readelf -l "$BIN" | grep -A 2 "interpreter" || true
    elif [ "$(uname)" = "Darwin" ]; then
      otool -L "$BIN" || true
    fi

    if [ "$(uname)" = "Linux" ]; then
      # Verify GLIBC requirement does not exceed 2.34 (Rocky Linux 9 compatibility)
      MAX_VER=$(readelf -sW "$BIN" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -V | tail -n1)
      if [ -n "$MAX_VER" ]; then
        if [ "$(printf '%s\n' "$MAX_VER" "2.34" | sort -V | tail -n1)" != "2.34" ]; then
          echo "ERROR: GLIBC $MAX_VER > 2.34 — binary not portable to Rocky Linux 9"; exit 1
        fi
      fi

      # Compute and save binary hash
      ACTUAL=$(sha256sum "$BIN" | awk '{print $1}')
      echo "$ACTUAL" > "$out/bin/auth_server.sha256"
      echo "Binary sha256: $ACTUAL"

      ARCH_LINUX="$(uname -m)"
      case "$ARCH_LINUX" in
        x86_64) ARCH_TAG="x86_64" ;;
        aarch64|arm64) ARCH_TAG="aarch64" ;;
        *) ARCH_TAG="$ARCH_LINUX" ;;
      esac
      HASH_FILENAME="auth-server.${linkTag}.$ARCH_TAG.linux.sha256"

      EXPECTED=""
      case "$ARCH_LINUX" in
        x86_64)  EXPECTED="${toString expectedHash_x86_64_linux}" ;;
        aarch64) EXPECTED="${toString expectedHash_aarch64_linux}" ;;
      esac

      if [ -n "$EXPECTED" ]; then
        if [ "$ACTUAL" = "$EXPECTED" ]; then
          echo "Deterministic hash check PASSED: $ACTUAL"
        else
          echo "ERROR: Deterministic hash MISMATCH!"
          echo "  Expected: $EXPECTED"
          echo "  Actual:   $ACTUAL"
          echo "  Update:   echo '$ACTUAL' > nix/expected-hashes/$HASH_FILENAME"
          exit 1
        fi
      else
        echo "NOTE: No expected hash for $HASH_FILENAME — bootstrapping (hash not yet recorded)"
        echo "$ACTUAL" > "$out/bin/$HASH_FILENAME"
        echo "  Copy to repo: nix/expected-hashes/$HASH_FILENAME"
      fi
    elif [ "$(uname)" = "Darwin" ]; then
      ACTUAL=$(shasum -a 256 "$BIN" | awk '{print $1}')
      echo "$ACTUAL" > "$out/bin/auth_server.sha256"
      echo "Binary sha256: $ACTUAL"

      ARCH_DARWIN="$(uname -m)"
      case "$ARCH_DARWIN" in
        x86_64) ARCH_TAG="x86_64" ;;
        arm64)  ARCH_TAG="arm64" ;;
        *) ARCH_TAG="$ARCH_DARWIN" ;;
      esac
      HASH_FILENAME="auth-server.${linkTag}.$ARCH_TAG.darwin.sha256"

      EXPECTED=""
      case "$ARCH_DARWIN" in
        x86_64) EXPECTED="${toString expectedHash_x86_64_darwin}" ;;
        arm64)  EXPECTED="${toString expectedHash_arm64_darwin}" ;;
      esac

      if [ -n "$EXPECTED" ]; then
        if [ "$ACTUAL" = "$EXPECTED" ]; then
          echo "Deterministic hash check PASSED: $ACTUAL"
        else
          echo "ERROR: Deterministic hash MISMATCH!"
          echo "  Expected: $EXPECTED"
          echo "  Actual:   $ACTUAL"
          echo "  Update:   echo '$ACTUAL' > nix/expected-hashes/$HASH_FILENAME"
          exit 1
        fi
      else
        echo "NOTE: No expected hash for $HASH_FILENAME — bootstrapping"
        echo "$ACTUAL" > "$out/bin/$HASH_FILENAME"
        echo "  Copy to repo: nix/expected-hashes/$HASH_FILENAME"
      fi
    fi

    echo "postInstall complete — binary is ready"
  '';

  meta = {
    description = "Cosmian Authentication Server";
    homepage = "https://github.com/Cosmian/authentication";
    license = {
      spdxId = "BUSL-1.1";
      fullName = "Business Source License 1.1";
      free = false;
    };
    maintainers = [ ];
    platforms = lib.platforms.unix;
  };
}
