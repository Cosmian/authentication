## Security

- Drop actix-web's `cookies` feature and build/parse session and SAML cookies as headers, removing cookie 0.16.2 (RUSTSEC-2026-0594) and its `deny.toml` exception.
