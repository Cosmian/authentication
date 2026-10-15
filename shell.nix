{
  variant ? "default",
  pkgs ?
    let
      rustOverlay = import (
        builtins.fetchTarball {
          url = "https://github.com/oxalica/rust-overlay/archive/a313afc75b85fc77ac154bf0e62c36f68361fd0b.tar.gz";
          sha256 = "0fb18ysw2dgm3033kcv3nlhsihckssnq6j5ayq4zjq148f12m7yv";
        }
      );
      pinned =
        import
          (builtins.fetchTarball {
            url = "https://package.cosmian.com/nixpkgs/8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296.tar.gz";
          })
          {
            overlays = [ rustOverlay ];
            config.allowUnfree = true;
          };
    in
    pinned,
}:

let
  withCurl = (builtins.getEnv "WITH_CURL") == "1";

  rustToolchain = pkgs.rust-bin.stable.latest.default;

  # glibc-2.34 package set (same pin as default.nix), used to build the bundled xmlsec.
  pkgs234 =
    if pkgs.stdenv.isLinux then
      import (builtins.fetchTarball {
        url = "https://package.cosmian.com/nixpkgs/380be19fbd2d9079f677978361792cb25e8a3635.tar.gz";
        sha256 = "sha256-Zffu01pONhs/pqH07cjlF10NnMDLok8ix5Uk4rhOnZQ=";
      }) { }
    else
      pkgs;

  xmlsecStatic = import ./nix/xmlsec-static.nix { inherit pkgs pkgs234; };

in
pkgs.mkShell {
  name = "auth-verifier-dev";

  buildInputs =
    [
      rustToolchain
      pkgs.pkg-config
      pkgs.perl # for vendored OpenSSL
      pkgs.cmake # for aws-lc-sys (jsonwebtoken/aws_lc_rs)
      pkgs.openssl
      pkgs.cargo-deny
      pkgs.cargo-edit
      # SAML: samael's `xmlsec` feature links the bundled xmlsec + libxml2 (nix/xmlsec-static.nix).
      xmlsecStatic
      pkgs.llvmPackages.libclang # bindgen
    ]
    ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
      pkgs.libiconv
      pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
      pkgs.darwin.apple_sdk.frameworks.Security
      pkgs.darwin.apple_sdk.frameworks.CoreFoundation
    ]
    ++ pkgs.lib.optionals withCurl [ pkgs.curl ];

  shellHook = ''
    # bindgen (via samael's xmlsec feature) parses libxml2 headers with libclang, which needs
    # both the stdenv C headers (stdio.h) and clang's own builtin headers (stddef.h). Pull the
    # former from the cc-wrapper flags and the latter from libclang's resource include dir (its
    # version subdir is major-only on clang >= 16, so glob it).
    export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
    export BINDGEN_EXTRA_CLANG_ARGS="$(cat ${pkgs.stdenv.cc}/nix-support/libc-cflags 2>/dev/null) $(cat ${pkgs.stdenv.cc}/nix-support/cc-cflags 2>/dev/null) -idirafter $(echo ${pkgs.llvmPackages.libclang.lib}/lib/clang/*/include)"
    echo "Authentication Verifier dev shell (Rust $(rustc --version))"
  '';
}
