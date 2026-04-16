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

in
pkgs.mkShell {
  name = "auth-server-dev";

  buildInputs =
    [
      rustToolchain
      pkgs.pkg-config
      pkgs.perl # for vendored OpenSSL
      pkgs.cmake # for aws-lc-sys (jsonwebtoken/aws_lc_rs)
      pkgs.openssl
      pkgs.cargo-deny
      pkgs.cargo-edit
    ]
    ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
      pkgs.libiconv
      pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
      pkgs.darwin.apple_sdk.frameworks.Security
      pkgs.darwin.apple_sdk.frameworks.CoreFoundation
    ]
    ++ pkgs.lib.optionals withCurl [ pkgs.curl ];

  shellHook = ''
    echo "Auth Server dev shell (Rust $(rustc --version))"
  '';
}
