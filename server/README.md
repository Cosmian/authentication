# auth_verifier

The Auth authentication server. Handles client authentication across multiple schemes (username/password, JWT/OIDC, mTLS client certificates, TOTP), maintains server-side sessions, and exposes APIs for session validation and realm/user administration.

For architecture and usage documentation, see [documentation/](documentation/index.md).

---

## Building

```bash
# Build the library (used by other crates in the workspace)
cargo build -p auth_verifier

# Build the server binary
cargo build --release --bin auth_verifier

# Build with rustls instead of openssl (default)
cargo build --release --bin auth_verifier --no-default-features --features rustls
```

### Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `openssl` | Yes | Use OpenSSL for TLS (via actix-web's openssl feature) |
| `rustls` | No | Use rustls for TLS instead of OpenSSL |
| `database` | Yes | Enable SQLite/PostgreSQL/MySQL backends via sqlx |
| `no_jwt_validation` | No | Disable JWT expiry/issuer validation — **test only, never enable in production** |

---

## Running

```bash
# Reads ./auth_verifier.toml from the current working directory
./target/release/auth_verifier

# Explicit config path
./target/release/auth_verifier /path/to/auth_verifier.toml
```

A sample fully-commented configuration file is provided at `auth_verifier.toml`. See [documentation/server_configuration.md](documentation/server_configuration.md) for the full reference.

---

## Testing

```bash
# Run all unit and integration tests
cargo test -p auth_verifier

# Run a specific test module
cargo test -p auth_verifier -- tests::jwt_tests

# Run with output (useful for debugging)
cargo test -p auth_verifier -- --nocapture

# Run a single test
cargo test -p auth_verifier -- tests::user_api::test_get_userpass_returns_empty_password --exact
```

The test suite uses an in-memory SQLite database and embedded test TLS certificates (located in `src/tests/certificates/`). No external services are required.
