## Bug Fixes

- Serve the `/.well-known/jwks.json` endpoint from a dedicated `/.well-known` scope wrapped with permissive CORS, so browser-based clients receive the same CORS headers as the other unauthenticated endpoints ([#7](https://github.com/Cosmian/authentication/pull/7)).
- Fix the `rustls`-only build (`--no-default-features --features database,rustls`): make `PeerCertificate` store backend-neutral DER bytes instead of an `openssl::x509::X509`, so the `rustls` TLS backend no longer references the unlinked `openssl` crate ([#7](https://github.com/Cosmian/authentication/pull/7)).

## Refactor

- Build the JWKS document by parsing the public key with the RustCrypto `x509-cert`/`spki` crates instead of hand-rolled PEM→DER conversion and manual DER byte-scanning; this unifies the previous `openssl`/`rustls` feature-split into a single backend-independent implementation and drops the unused `pem` dependency ([#7](https://github.com/Cosmian/authentication/pull/7)).

## CI

- Add a Clippy job for the `openssl` TLS backend (`--no-default-features --features database,openssl`) alongside the existing `rustls` backend check ([#7](https://github.com/Cosmian/authentication/pull/7)).
