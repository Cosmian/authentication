{
  pkgs ? import <nixpkgs> { },
  stdenv ? pkgs.stdenv,
  lib ? pkgs.lib,
  # Version (from workspace Cargo.toml)
  version,
}:

let
  # Filter source to exclude generated / ephemeral directories
  sourceFilter =
    path: _type:
    let
      baseName = baseNameOf path;
    in
    baseName != "node_modules"
    && baseName != "dist"
    && baseName != ".git";

  # Fetch and cache the pnpm offline store for reproducible installs.
  # pnpm_9 supports lockfile format 9.0 used by admin-ui/pnpm-lock.yaml.
  pnpmDeps = pkgs.pnpm_9.fetchDeps {
    pname = "cosmian-auth-admin-ui-deps";
    inherit version;

    src = lib.cleanSourceWith {
      src = ../admin-ui;
      filter = sourceFilter;
    };

    hash =
      let
        placeholder = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        platformSuffix =
          if stdenv.hostPlatform.isDarwin then
            "darwin"
          else if stdenv.hostPlatform.isx86_64 then
            "linux-x86_64"
          else if stdenv.hostPlatform.isAarch64 then
            "linux-aarch64"
          else
            builtins.throw "Unsupported platform for admin-ui pnpm hash: ${stdenv.hostPlatform.system}";
        hashFile = ./expected-hashes + "/admin-ui.pnpm." + platformSuffix + ".sha256";
      in
      if builtins.pathExists hashFile then
        let
          raw = builtins.readFile hashFile;
          trimmed = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] raw;
        in
        assert trimmed != placeholder && trimmed != "";
        trimmed
      else
        builtins.throw ("Expected admin-ui pnpm deps hash file not found: " + hashFile);
  };

in
stdenv.mkDerivation {
  pname = "cosmian-auth-admin-ui";
  inherit version;

  src = lib.cleanSourceWith {
    src = ../admin-ui;
    filter = sourceFilter;
  };

  nativeBuildInputs = [
    pkgs.nodejs_22
    pkgs.pnpm_9
    pkgs.pnpm_9.configHook
  ];

  # configHook runs pnpm install --offline --frozen-lockfile
  inherit pnpmDeps;

  buildPhase = ''
    export HOME=$TMPDIR
    pnpm run build
  '';

  installPhase = ''
    if [ ! -d dist ]; then
      echo "ERROR: dist/ not found after pnpm run build" >&2
      exit 1
    fi
    if [ ! -f dist/index.html ]; then
      echo "ERROR: dist/index.html not found — Vite build may have failed" >&2
      exit 1
    fi
    mkdir -p $out/dist
    cp -r dist/. $out/dist/
    echo "admin-ui installed to $out/dist/ ($(find $out/dist -type f | wc -l) files)"
  '';

  meta = with lib; {
    description = "Cosmian Authentication Server — Admin UI";
    homepage = "https://github.com/Cosmian/authentication";
    platforms = platforms.unix;
  };
}
