# auth_client

HTTP client and shared types for the [Auth Authentication Server](../authentication_server).

For full documentation including API server integration guides and type references, see [authentication_server/documentation/client_library.md](../authentication_server/documentation/client_library.md).

---

## Building

```bash
cargo build -p auth_client
```

### Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `_server` | No | Enables `actix-web::ResponseError` for `AuthError` and sqlx error variants. Used only by the `auth_verifier` crate — do not enable in API server code. |

---

## Testing

The client library has no standalone integration tests (its behaviour is tested through `auth_verifier`'s test suite). To run unit tests:

```bash
cargo test -p auth_client
```

To run the full test suite including integration tests against a live server instance:

```bash
cargo test -p auth_verifier
```

The integration tests are located in `crate/authentication_server/src/tests/` and use an embedded in-memory server — no external services are required.
