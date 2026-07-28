## Security

- Removed the self-signed TLS certificate and private key that were baked into
  the Docker image; embedding a private key in a public image is a security
  anti-pattern and gave a false sense of HTTPS security.

## Features

- The server now binds **plain HTTP** by default when no `[tls_params]` section
  is present in the configuration, making zero-config Docker deployments work
  without any embedded credentials.
- Added **ephemeral HS256 JWT signing** as a last-resort fallback when neither
  `[tls_params]` nor `[session_jwt_params]` is configured; a prominent warning
  is printed at startup to indicate that sessions will not survive a restart.
- `[tls_params]` is now an **optional** TOML section; when present the server
  continues to serve HTTPS and reuses the TLS key pair for JWT signing.
- The Docker image default dev configuration now listens on HTTP port 8080
  instead of HTTPS port 8443.
- Updated `ExposedPorts` in the Docker image metadata from `8443/tcp` to
  `8080/tcp` to reflect the new default.

## Docs

- Updated `server/auth_verifier.toml` sample to document `[tls_params]` as
  optional and to explain the three-tier JWT key resolution order.
