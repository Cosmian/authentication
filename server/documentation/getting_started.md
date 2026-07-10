# Getting Started

This guide walks through deploying the Auth authentication server from scratch: compiling the binary, writing a configuration file, bootstrapping the first administrator, and verifying the setup using `curl` and the `auth_client` crate.

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Rust toolchain | ≥ 1.91.0 (see `rust-toolchain.toml`) |
| OpenSSL / LibreSSL | Any modern version (for key generation) |
| PostgreSQL / MySQL / Redis | Optional — defaults to SQLite |

---

## 1. Build the Binary

From the workspace root:

```bash
cargo build --release --bin auth_verifier
```

The binary is placed at `target/release/auth_verifier`.

---

## 2. Generate TLS Certificates

The server requires a TLS certificate at startup. For a development setup, generate self-signed EC P-256 certificates:

```bash
# Generate CA key and self-signed CA certificate
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ca.key.pem
openssl req -new -x509 -days 3650 -key ca.key.pem -out ca.cert.pem \
    -subj "/CN=My Auth CA" \
    -addext "basicConstraints=CA:TRUE" \
    -addext "keyUsage=digitalSignature,cRLSign,keyCertSign"

# Generate server key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out server.key.pem

# Generate server certificate signed by the CA
openssl req -new -key server.key.pem -out server.csr \
    -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
openssl x509 -req -sha256 -in server.csr -CA ca.cert.pem -CAkey ca.key.pem \
    -CAcreateserial -out server.cert.pem -days 365 \
    -extfile <(echo "subjectAltName=IP:127.0.0.1,DNS:localhost")
```

For production, use certificates issued by a trusted CA or an internal PKI.

---

## 3. Write the Configuration File

Create `auth_verifier.toml`:

```toml
host_name = "0.0.0.0"
host_port = 8443

[tls_params]
server_private_key = "server.key.pem"
server_certificate = "server.cert.pem"
server_ca_chain    = "ca.cert.pem"

[database_params]
backend        = "sqlite"
connection_url = "sqlite://auth_verifier.db"
```

See [server_configuration.md](server_configuration.md) for the full configuration reference.

---

## 4. Bootstrap the First Super Admin

On the **first startup**, set these environment variables to create the initial super admin:

```bash
export APP_REALM_ADMIN_USERNAME="admin"
export APP_REALM_ADMIN_INITIAL_PASSWORD="change_me"

./target/release/auth_verifier auth_verifier.toml
```

The server hashes the password with **Argon2id** and stores it. Remove or unset these variables before any subsequent restarts — they are silently ignored if the admin already exists.

> **Security:** Never commit `APP_REALM_ADMIN_INITIAL_PASSWORD` to source control. Rotate the password immediately after bootstrapping.

---

## 5. Verify the Server Is Running

```bash
# Verify the server answers (requires the CA cert for TLS verification)
curl --cacert ca.cert.pem https://localhost:8443/public/version
# → "0.1.2"
```

---

## 6. Log In as Super Admin

```bash
curl --cacert ca.cert.pem \
     -X POST "https://localhost:8443/login?realm=_" \
     -u "admin:change_me" \
     -c cookies.txt \
     -v
```

A successful response returns HTTP `200` with:

```json
{
  "next_step": "Authenticated",
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

and sets the `_ea_` session cookie (stored in `cookies.txt`).

---

## 7. Create Your First Realm

With the admin session cookie:

```bash
curl --cacert ca.cert.pem \
     -X POST "https://localhost:8443/admins/realms" \
     -b cookies.txt \
     -H "Content-Type: application/json" \
     -d '{
       "id": "my-service",
       "auth_params": {
         "username_password_params": {
           "allow_expired_passwords": false
         }
       },
       "session_max_age_seconds": 3600,
       "session_max_stale_age_seconds": 1800
     }'
```

---

## 8. Create a Client Credential

```bash
# Create a username/password credential for "alice" in "my-service"
curl --cacert ca.cert.pem \
     -X POST "https://localhost:8443/realms/my-service/userpass" \
     -b cookies.txt \
     -H "Content-Type: application/json" \
     -d '{
       "realm": "my-service",
       "username": "alice",
       "password": [115,101,99,114,101,116],
       "change_password": false
     }'
```

> The `password` field is a JSON byte array of the UTF-8 encoded plaintext password. The server hashes it with Argon2id.

---

## 9. Authenticate as a Client

```bash
curl --cacert ca.cert.pem \
     -X POST "https://localhost:8443/login?realm=my-service" \
     -u "alice:secret" \
     -c client_cookies.txt
# → {"next_step":"Authenticated","session_id":"…"}
```

---

## 10. Validate the Session from Your API Server

In your API server code, use the `auth_client` crate:

```rust
use auth_client::{AuthClient, AuthClientScheme};

let client = AuthClient::new(
    "https://localhost:8443",
    &std::fs::read_to_string("ca.cert.pem")?,
    AuthClientScheme::None,
)?;

// session_id is extracted from the incoming _ea_ cookie
let session = client.get_session(session_id).await?;
match session {
    None    => { /* session not found or expired — return 401 */ }
    Some(s) => println!("Request from {} in realm {}", s.username, s.realm_id),
}
```

See [client_library.md](client_library.md) for the full API server integration guide.

---

## Next Steps

| Goal | Document |
|------|----------|
| Configure PostgreSQL / Redis backends | [Server Configuration](server_configuration.md) |
| Set up JWT / OAuth2 authentication | [Authentication Flows](authentication_flows.md) |
| Set up mTLS client certificates | [Authentication Flows](authentication_flows.md) |
| Enable TOTP two-factor authentication | [Two-Factor Authentication](two_factor_authentication.md) |
| Understand session handling | [Session Management](session_management.md) |
| Set up realm admins | [Authorization and Administration](authorization_and_administration.md) |
| Use the full client library | [Client Library](client_library.md) |
