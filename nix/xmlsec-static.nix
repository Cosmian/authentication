# Static, OpenSSL-only xmlsec (+ libxml2) for samael's `xmlsec` feature.
# Built with the glibc-2.34 toolchain (pkgs234) from current upstream sources, so the
# bundled objects stay Rocky Linux 9 compatible without inheriting nixpkgs 22.05's
# outdated xmlsec 1.2 / libxml2 2.9.
{ pkgs, pkgs234 }:
let
  stdenv = pkgs234.stdenv;

  # Compile-time headers only: the final binary resolves OpenSSL symbols against the
  # server's vendored OpenSSL, so no second OpenSSL ends up in the process.
  openssl = pkgs234.openssl_3_0;

  libxml2 = stdenv.mkDerivation {
    pname = "libxml2-static";
    inherit (pkgs.libxml2) version src;
    nativeBuildInputs = [ pkgs234.pkg-config ];
    configureFlags = [
      "--enable-static"
      "--disable-shared"
      "--with-pic"
      "--without-python"
      "--without-icu"
      "--without-lzma"
      "--without-zlib"
      "--without-readline"
    ];
  };
in
stdenv.mkDerivation {
  pname = "xmlsec-static";
  inherit (pkgs.xmlsec) version src;

  nativeBuildInputs = [ pkgs234.pkg-config ];
  buildInputs = [
    libxml2
    openssl
  ];

  configureFlags = [
    "--enable-static"
    "--disable-shared"
    "--with-pic"
    # Link the OpenSSL backend directly instead of loading it at runtime (drops libltdl).
    "--disable-crypto-dl"
    "--disable-apps-crypto-dl"
    "--with-default-crypto=openssl"
    "--without-gnutls"
    "--without-gcrypt"
    "--without-nss"
    "--without-nspr"
    # SAML never uses XSLT transforms; they are an attack surface in signed XML.
    "--without-libxslt"
    "--disable-apps"
    "--disable-docs"
  ];

  # xmlsec1-config shells out to xml2-config at build time; wrap it so the static libxml2
  # is found without relying on the caller's PATH.
  propagatedBuildInputs = [ libxml2 ];

  # Drop the shared OpenSSL library dir from every link-time descriptor: `-lssl -lcrypto`
  # must resolve against the server's vendored OpenSSL, not a second shared copy.
  postInstall = ''
    for f in $out/bin/xmlsec1-config $out/lib/pkgconfig/*.pc $out/lib/xmlsec1Conf.sh $out/lib/*.la; do
      substituteInPlace "$f" --replace "-L${openssl.out}/lib" ""
    done
    substituteInPlace $out/bin/xmlsec1-config --replace "xml2-config" "${libxml2}/bin/xml2-config"
  '';

  passthru = { inherit libxml2; };
}
