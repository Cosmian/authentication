# authentication

`authentication` is a Rust workspace that provides:

- `auth_verifier`: a multi-realm authentication server supporting username/password, JWT/OIDC, mTLS, and TOTP
- `auth_client`: a client library and shared types used to integrate with the server

## Documentation

Project documentation is in `server/documentation`:

- [Index](server/documentation/docs/index.md)
- [Getting Started](server/documentation/docs/getting_started.md)
- [API Reference](server/documentation/docs/api_reference.md)
- [Authentication Flows](server/documentation/docs/authentication_flows.md)
- [Session Management](server/documentation/docs/session_management.md)
- [Authorization and Administration](server/documentation/docs/authorization_and_administration.md)
- [Two-Factor Authentication](server/documentation/docs/two_factor_authentication.md)
- [Server Configuration](server/documentation/docs/server_configuration.md)
- [Client Library](server/documentation/docs/client_library.md)

## Build

From the workspace root:

```bash
# Build all workspace members
cargo build --workspace

# Build one crate
cargo build -p auth_verifier
cargo build -p auth_client
```

## Test

From the workspace root:

```bash
# Run all tests in the workspace
cargo test --workspace

# Run tests for a single crate
cargo test -p auth_verifier
cargo test -p auth_client
```
