{
  # Pin nixpkgs so nix-build works without '-I nixpkgs=…' or channels.
  # Linux builds target glibc 2.34 (Rocky Linux 9 compatibility).
  pkgs ?
    let
      rustOverlay = import (
        builtins.fetchTarball {
          url = "https://github.com/oxalica/rust-overlay/archive/a313afc75b85fc77ac154bf0e62c36f68361fd0b.tar.gz";
          sha256 = "0fb18ysw2dgm3033kcv3nlhsihckssnq6j5ayq4zjq148f12m7yv";
        }
      );
      nixpkgsSrc = builtins.fetchTarball {
        url = "https://package.cosmian.com/nixpkgs/8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296.tar.gz";
        sha256 = "sha256-CqCX4JG7UiHvkrBTpYC3wcEurvbtTADLbo3Ns2CEoL8=";
      };
    in
    import nixpkgsSrc {
      overlays = [ rustOverlay ];
      config.allowUnfree = true;
    },
}:

let
  # Pinned nixpkgs tarball (same commit as above)
  nixpkgsSrc = builtins.fetchTarball {
    url = "https://package.cosmian.com/nixpkgs/8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296.tar.gz";
    sha256 = "sha256-CqCX4JG7UiHvkrBTpYC3wcEurvbtTADLbo3Ns2CEoL8=";
  };

  # Modern Rust toolchain via rust-overlay (pinned to commit a313afc, includes Rust 1.94.1)
  rustOverlay = import (
    builtins.fetchTarball {
      url = "https://github.com/oxalica/rust-overlay/archive/a313afc75b85fc77ac154bf0e62c36f68361fd0b.tar.gz";
      sha256 = "0fb18ysw2dgm3033kcv3nlhsihckssnq6j5ayq4zjq148f12m7yv";
    }
  );

  pkgsWithRust = import nixpkgsSrc {
    overlays = [ rustOverlay ];
    config.allowUnfree = true;
  };

  # Latest stable Rust toolchain from the pinned overlay (currently 1.94.1).
  # Using 'latest' ensures we always use the most recent stable in the pinned overlay.
  rustToolchain = pkgsWithRust.rust-bin.stable.latest.minimal.override {
    extensions = [
      "rustfmt"
      "clippy"
    ];
  };

  # For Linux, pin nixpkgs 22.05 (glibc 2.34) for Rocky Linux 9 compatibility.
  pkgs234 =
    if pkgs.stdenv.isLinux then
      import (builtins.fetchTarball {
        url = "https://package.cosmian.com/nixpkgs/380be19fbd2d9079f677978361792cb25e8a3635.tar.gz";
        sha256 = "sha256-Zffu01pONhs/pqH07cjlF10NnMDLok8ix5Uk4rhOnZQ=";
      }) { config.allowUnfree = true; }
    else
      pkgs;

  # pkgs234.makeRustPlatform (nixpkgs 22.05) has two bugs for git deps with
  # workspace inheritance (version.workspace = true, added in Cargo 1.64):
  #
  # Bug 1: import-cargo-lock.nix is called with `{}` (no cargo override), so it
  #   uses buildPackages.cargo (= cargo-1.60.0) which can't parse workspace syntax.
  #   Fix: extend pkgs234 to set cargo = rustToolchain so buildPackages.cargo is modern.
  #
  # Bug 2: pkgs234's import-cargo-lock.nix is missing the replace-workspace-values.py
  #   step, so workspace inheritance keys remain in vendored Cargo.toml files.
  #   Fix: use the modern importCargoLock from pkgsWithRust which has this step,
  #   and inject it into the pkgs234-based rustPlatform.buildRustPackage.
  pkgs234Fixed =
    if pkgs.stdenv.isLinux then
      pkgs234.extend (_: _: { cargo = rustToolchain; })
    else
      pkgs234;

  # Custom importCargoLock that wraps fetchurl with a browser User-Agent.
  # The default fetchurl sends "curl/X Nixpkgs/Y" which crates.io CDN may
  # reject with HTTP 403 from CI runner IPs.  By injecting curlOpts we
  # override the User-Agent at the curl command level inside the builder.
  importCargoLockWithUA =
    let
      wrappedFetchurl = attrs: pkgsWithRust.fetchurl (attrs // {
        curlOpts = "--user-agent \"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\"";
      });
    in
    pkgsWithRust.callPackage (nixpkgsSrc + "/pkgs/build-support/rust/import-cargo-lock.nix") {
      fetchurl = wrappedFetchurl;
      inherit (pkgsWithRust) cargo;
    };

  # rustPlatform: on Linux use pkgs234Fixed (glibc 2.34) with modern importCargoLock
  rustPlatform =
    if pkgs.stdenv.isLinux then
      let
        base = pkgs234Fixed.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };
      in
      base // {
        buildRustPackage = base.buildRustPackage.override {
          importCargoLock = importCargoLockWithUA;
        };
      }
    else
      pkgsWithRust.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      } // {
        buildRustPackage = (pkgsWithRust.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        }).buildRustPackage.override {
          importCargoLock = importCargoLockWithUA;
        };
      };

  # Extract version from workspace Cargo.toml
  cargoTomlContent = builtins.readFile ./Cargo.toml;
  lines = pkgs.lib.splitString "\n" cargoTomlContent;
  extractVersion =
    lines:
    let
      findWorkspacePackage =
        idx:
        if idx >= builtins.length lines then
          null
        else if pkgs.lib.hasPrefix "[workspace.package]" (builtins.elemAt lines idx) then
          idx
        else
          findWorkspacePackage (idx + 1);

      workspaceIdx = findWorkspacePackage 0;

      findVersion =
        idx:
        if idx >= builtins.length lines || workspaceIdx == null then
          null
        else
          let
            line = builtins.elemAt lines idx;
            isNextSection = pkgs.lib.hasPrefix "[" line && idx > workspaceIdx;
          in
          if isNextSection then
            null
          else if pkgs.lib.hasPrefix "version" (pkgs.lib.replaceStrings [ " " "\t" ] [ "" "" ] line) then
            builtins.elemAt (pkgs.lib.splitString "\"" line) 1
          else
            findVersion (idx + 1);
    in
    if workspaceIdx == null then
      throw "Could not find [workspace.package] in Cargo.toml"
    else
      let
        ver = findVersion (workspaceIdx + 1);
      in
      if ver == null then throw "Could not find version in [workspace.package] section" else ver;

  authVersion = extractVersion lines;

  # Build cargo-generate-rpm from crates.io (not available in all pinned nixpkgs)
  cargoGenerateRpmTool = rustPlatform.buildRustPackage rec {
    pname = "cargo-generate-rpm";
    version = "0.16.0";
    src = pkgs.fetchCrate {
      inherit pname version;
      sha256 = "sha256-esp3MJ24RQpMFn9zPgccp7NESoFAUPU7y+YRsJBVVr4=";
    };
    cargoSha256 = "sha256-mUsoPBgv60Eir/uIK+Xe+GmXdSFKXoopB4PlvFvHZuA=";
    nativeBuildInputs = [
      rustToolchain
      pkgs.pkg-config
      pkgs.git
      pkgs.cacert
    ];
    doCheck = false;
  };

  # Build admin-ui (pure pnpm+Vite frontend, no WASM)
  admin-ui = pkgs.callPackage ./nix/admin-ui.nix {
    version = authVersion;
  };

  # Build auth-verifier for static linkage
  auth-verifier-static = pkgs.callPackage ./nix/auth-verifier.nix {
    inherit pkgs pkgs234 rustPlatform;
    version = authVersion;
    static = true;
  };

  # Build auth-verifier for dynamic linkage
  auth-verifier-dynamic = pkgs.callPackage ./nix/auth-verifier.nix {
    inherit pkgs pkgs234 rustPlatform;
    version = authVersion;
    static = false;
  };

  # Docker image derivation (Linux only)
  docker-image = pkgs.callPackage ./nix/docker.nix {
    inherit pkgs;
    authServer = auth-verifier-static;
    adminUi = admin-ui;
    version = authVersion;
  };

in
{
  # Build attributes accessible via -A
  inherit
    admin-ui
    auth-verifier-static
    auth-verifier-dynamic
    docker-image
    cargoGenerateRpmTool
    rustToolchain
    ;

  # Convenience aliases used by packaging scripts
  "auth-verifier-static-openssl" = auth-verifier-static;
  "auth-verifier-dynamic-openssl" = auth-verifier-dynamic;
}
