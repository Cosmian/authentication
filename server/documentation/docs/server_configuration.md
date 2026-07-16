# Server Configuration Reference

The auth-verifier is configured entirely through a TOML file. Start the server with:

```bash
# Default: reads ./auth_verifier.toml from the current working directory
auth_verifier

# Explicit path
auth_verifier /path/to/auth_verifier.toml
```

All file paths in the configuration are resolved relative to the **current working directory** at startup, unless they are absolute paths.

A fully commented sample configuration is provided in `auth_verifier.toml` at the root of the `authentication_server` crate directory.

---

## Table of Contents

- [Server Configuration Reference](#server-configuration-reference)
  - [Table of Contents](#table-of-contents)
  - [Network Binding](#network-binding)
    - [Development shortcut](#development-shortcut)
  - [TLS Configuration](#tls-configuration)
    - [Generating certificates](#generating-certificates)
  - [Session JWT Keys](#session-jwt-keys)
  - [Primary Database](#primary-database)
    - [Redis](#redis)
  - [Session Store](#session-store)
  - [Stale Session Collector](#stale-session-collector)
  - [Forward Proxy](#forward-proxy)
  - [API Documentation (Swagger UI)](#api-documentation-swagger-ui)
  - [Bootstrap Environment Variables](#bootstrap-environment-variables)
  - [Complete Example — Production (PostgreSQL + Redis)](#complete-example--production-postgresql--redis)
  - [Complete Example — Development (SQLite in-memory)](#complete-example--development-sqlite-in-memory)
  - [Realm Authentication Parameters](#realm-authentication-parameters)

---

## Network Binding

```toml
# The hostname or IP address the server binds to.
# Use "0.0.0.0" to listen on all interfaces,
# or an explicit IP to bind to a single interface.
host_name = "0.0.0.0"   # REQUIRED

# The TCP port the server listens on. The server only serves TLS.
host_port = 8443          # REQUIRED
```

| Key | Type | Required | Default |
|-----|------|----------|---------|
| `host_name` | `String` | Yes | — |
| `host_port` | `u16` | Yes | — |

### Development shortcut

```toml
# When set, every unauthenticated request is treated as if it came from
# this username. Enables testing without credentials.
# NEVER use in production.
default_username = "dev_user"
```

| Key | Type | Required | Default |
|-----|------|----------|---------|
| `default_username` | `String` | No | `null` |

---

## TLS Configuration

The `[tls_params]` section is **required**. The server listens on TLS only.

```toml
[tls_params]
# Path to the server private key in PKCS#8 PEM format.
# Must be an EC (P-256 recommended) or RSA key.
server_private_key = "certificates/server.key.pem"  # REQUIRED

# Path to the server TLS certificate (or certificate chain) in PEM format.
# When using an intermediate CA, concatenate the leaf and intermediate
# certificates in this file (leaf first).
server_certificate = "certificates/server.cert.pem"  # REQUIRED

# Path to the CA certificate chain used by clients to verify this server.
# This is the trust anchor distributed to API servers and client tools.
server_ca_chain = "certificates/ca.cert.pem"  # REQUIRED

# Optional: path to a separate CA chain for verifying *client* certificates
# in mTLS authentication flows. When omitted, server_ca_chain is used.
# client_ca_cert_chain = "certificates/client-ca.chain.pem"

# Optional: colon-separated list of cipher suites.
# When omitted, the TLS backend's default list is used.
# Recommended TLS 1.3 suite (ANSSI-compliant):
# tls_cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
```

| Key | Type | Required | Default |
|-----|------|----------|---------|
| `server_private_key` | `String` (path) | Yes | — |
| `server_certificate` | `String` (path) | Yes | — |
| `server_ca_chain` | `String` (path) | Yes | — |
| `client_ca_cert_chain` | `String` (path) | No | Same as `server_ca_chain` |
| `tls_cipher_suites` | `String` | No | TLS backend defaults |

### Generating certificates

See [getting_started.md](getting_started.md#2-generate-tls-certificates) for commands to generate self-signed development certificates.

For production, use certificates issued by a trusted CA (Let's Encrypt, an internal PKI, etc.).

---

## Session JWT Keys

By default, the server reuses the TLS private key to sign session JWTs. You can specify a dedicated EC key pair to keep TLS and session-signing keys separate (recommended for production):

```toml
[session_jwt_params]
# Path to the EC private key PEM file used to sign session JWTs (ES256).
jwt_ec_private_key = "certificates/jwt.key.pem"

# Path to the corresponding EC public key PEM file used to verify session JWTs.
jwt_ec_public_key = "certificates/jwt.pub.pem"
```

| Key | Type | Required | Default |
|-----|------|----------|---------|
| `jwt_ec_private_key` | `String` (path) | Yes (if section present) | — |
| `jwt_ec_public_key` | `String` (path) | Yes (if section present) | — |

Generate a dedicated JWT key pair:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out jwt.key.pem
openssl ec -in jwt.key.pem -pubout -out jwt.pub.pem
```

---

## Primary Database

The `[database_params]` section configures the store for users, realms, and credentials.

When omitted, the server creates an **SQLite file** named `auth_verifier.db` in the working directory.

```toml
[database_params]
# Database backend: "sqlite" | "postgresql" | "mysql"
backend = "postgresql"

# Connection URL.
#   SQLite:     sqlite://relative/path.db
#               sqlite:///absolute/path.db
#               sqlite::memory:   (in-memory; all data lost on restart)
#   PostgreSQL: postgresql://user:password@host:5432/dbname
#               postgresql://user:password@/run/postgresql/dbname  (Unix socket)
#   MySQL:      mysql://user:password@host:3306/dbname
connection_url = "postgresql://auth:secret@db.example.com:5432/auth_auth"

# Maximum number of pooled connections (default: 10).
max_connections = 20

# Minimum number of idle connections kept in the pool (default: 0).
min_connections = 2

# Seconds before a connection attempt is aborted (default: 30).
connect_timeout_secs = 10

# Seconds before an idle connection is closed (default: 600).
idle_timeout_secs = 300

# When true (default), the database schema is created / migrated at startup.
# Set to false when migrations are managed externally (e.g., Flyway, Liquibase).
auto_init_schema = true
```

| Key | Type | Required | Default |
|-----|------|----------|---------|
| `backend` | `"sqlite"` \| `"postgresql"` \| `"mysql"` | No | `"sqlite"` |
| `connection_url` | `String` | No | `"sqlite://auth_verifier.db"` |
| `max_connections` | `u32` | No | `10` |
| `min_connections` | `u32` | No | `0` |
| `connect_timeout_secs` | `u64` | No | `30` |
| `idle_timeout_secs` | `u64` | No | `600` |
| `auto_init_schema` | `bool` | No | `true` |

### Redis

Redis is supported as a session store backend (see [Session Store](#session-store)) but **not** as the primary database for users, realms, and credentials. The primary database must be SQLite, PostgreSQL, or MySQL.

---

## Session Store

The session store holds active session tokens. By default it shares the primary database. For high-throughput deployments, use a dedicated Redis instance:

```toml
[sessions_store_params]
# Backend: "sqlite" | "postgresql" | "mysql" | "redis"
backend = "redis"

# Redis connection URL
connection_url = "redis://localhost:6379"

# Maximum connections in the pool (default: 10).
max_connections = 50
```

| Key | Type | Required | Default |
|-----|------|----------|---------|
| `backend` | `"sqlite"` \| `"postgresql"` \| `"mysql"` \| `"redis"` | No | Same as `database_params` |
| `connection_url` | `String` | No | Same as `database_params` |
| `max_connections` | `u32` | No | `10` |
| `min_connections` | `u32` | No | `0` |
| `connect_timeout_secs` | `u64` | No | `30` |
| `idle_timeout_secs` | `u64` | No | `600` |
| `auto_init_schema` | `bool` | No | `true` |

> **Redis note:** Redis cleans up expired sessions automatically via TTL. The stale-session collector is not needed when using Redis.

---

## Stale Session Collector

A background task that periodically purges expired sessions from the session store. Only relevant for SQL-backed session stores; Redis handles expiry automatically via TTL.

```toml
[stale_session_collector_config]
# How often (in seconds) the cleanup task runs.
# Default: 60 seconds.
cleanup_interval_seconds = 300
```

| Key | Type | Required | Default |
|-----|------|----------|---------|
| `cleanup_interval_seconds` | `u64` | No | `60` |

---

## Forward Proxy

When the auth-verifier needs to fetch JWKs from an external Identity Provider through an HTTP proxy:

```toml
[proxy_params]
# Proxy URL — scheme, host, and port are required.
url = "http://proxy.corp.example.com:3128"

# Optional Basic-Auth credentials for the proxy.
basic_auth_username = "proxy_user"
# WARNING: plain-text passwords in config files are a security risk.
# Consider using environment variable substitution or a secrets manager.
basic_auth_password = "proxy_password"

# Optional: replace the entire Proxy-Authorization header with a custom value.
# custom_auth_header = "Bearer <token>"

# Hosts that bypass the proxy.
exclusion_list = ["localhost", "127.0.0.1", "10.0.0.0/8", "192.168.0.0/16"]
```

| Key | Type | Required | Default |
|-----|------|----------|---------|
| `url` | URL string | Yes (if section present) | — |
| `basic_auth_username` | `String` | No | `null` |
| `basic_auth_password` | `String` | No | `null` |
| `custom_auth_header` | `String` | No | `null` |
| `exclusion_list` | `Vec<String>` | No | `[]` |

---

## API Documentation (Swagger UI)

Two unauthenticated public routes expose the API schema. Both are served under `/public` and require no credentials.

| Route | Description |
|-------|-------------|
| `GET /public/swagger-ui` | Interactive Swagger UI (assets loaded from unpkg CDN) |
| `GET /public/openapi.yaml` | Raw OpenAPI 3.1 schema (YAML, embedded in the binary) |

```bash
# Open in browser
https://<host_name>:<host_port>/public/swagger-ui

# Download the schema
curl -k https://<host_name>:<host_port>/public/openapi.yaml
```

The YAML schema is embedded at compile time from `server/documentation/openapi.yaml`. Any change to that file takes effect after the next build.

> **Note:** The Swagger UI page loads JavaScript and CSS from `unpkg.com`. In air-gapped environments the page will load but the UI assets will be missing. Serve the raw YAML instead and use a local Swagger UI deployment or [editor.swagger.io](https://editor.swagger.io).

---

## Bootstrap Environment Variables

These environment variables are read **once on first startup** to create the initial super admin. They are ignored if the admin already exists.

| Variable | Description |
|----------|-------------|
| `APP_REALM_ADMIN_USERNAME` | Username for the initial super admin |
| `APP_REALM_ADMIN_INITIAL_PASSWORD` | Plaintext password (hashed with Argon2id at boot) |

```bash
export APP_REALM_ADMIN_USERNAME="admin"
export APP_REALM_ADMIN_INITIAL_PASSWORD="$(openssl rand -base64 32)"
./auth_verifier auth_verifier.toml
```

> **Security:** Unset these variables after the first run. Never store them in the TOML file itself.

---

## Complete Example — Production (PostgreSQL + Redis)

```toml
# auth_verifier.toml — production example

host_name = "0.0.0.0"
host_port = 8443

[tls_params]
server_private_key    = "/etc/auth/tls/server.key.pem"
server_certificate    = "/etc/auth/tls/server.cert.pem"
server_ca_chain       = "/etc/auth/tls/ca.chain.pem"
client_ca_cert_chain  = "/etc/auth/tls/client-ca.chain.pem"
tls_cipher_suites     = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"

[session_jwt_params]
jwt_ec_private_key = "/etc/auth/jwt/jwt.key.pem"
jwt_ec_public_key  = "/etc/auth/jwt/jwt.pub.pem"

[database_params]
backend             = "postgresql"
connection_url      = "postgresql://auth_auth:s3cr3t@postgres:5432/auth_auth"
max_connections     = 20
min_connections     = 2
connect_timeout_secs = 10
idle_timeout_secs   = 300
auto_init_schema    = true

[sessions_store_params]
backend        = "redis"
connection_url = "redis://redis:6379/0"
max_connections = 100

[stale_session_collector_config]
cleanup_interval_seconds = 600

[proxy_params]
url            = "http://proxy.corp.example.com:3128"
exclusion_list = ["localhost", "127.0.0.1", "10.0.0.0/8"]
```

---

## Complete Example — Development (SQLite in-memory)

```toml
# auth_verifier.toml — development example

host_name = "127.0.0.1"
host_port = 8443
default_username = "dev_admin"

[tls_params]
server_private_key = "src/tests/certificates/ec/auth.server.key.pem"
server_certificate = "src/tests/certificates/ec/auth.server.cert.pem"
server_ca_chain    = "src/tests/certificates/ec/auth.ca.pem"

# In-memory SQLite — fast startup, all data lost on restart
[database_params]
backend        = "sqlite"
connection_url = "sqlite::memory:"
```

---

## Realm Authentication Parameters

Realm configuration is managed at runtime via the API, not through the TOML file. These parameters are stored in the database and modified through `POST /admins/realms` and `PUT /admins/realms/{realm_id}`.

For each realm you can configure:

```json
{
  "id": "my-service",
  "auth_params": {
    "username_password_params": {
      "allow_expired_passwords": false
    },
    "jwt_params": {
      "idp_params": [
        {
          "jwt_issuer_uri": "https://accounts.google.com",
          "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
          "jwt_audience": "my-client-id.apps.googleusercontent.com"
        }
      ],
      "smallest_refresh_interval_seconds": 300
    },
    "totp_params": {
      "algorithm": "SHA1",
      "step": 30
    }
  },
  "session_max_age_seconds": 3600,
  "session_max_stale_age_seconds": 1800
}
```

| Field | Type | Description |
|-------|------|-------------|
| `session_max_age_seconds` | `i64` | Maximum absolute session lifetime (seconds) |
| `session_max_stale_age_seconds` | `i64` | Maximum idle time before a session expires (seconds) |
| `auth_params.username_password_params` | Object | Enable username/password auth |
| `auth_params.username_password_params.allow_expired_passwords` | `bool` | Allow login with an expired password (forces `ChangePassword` next step) |
| `auth_params.jwt_params` | Object | Enable JWT/OIDC authentication |
| `auth_params.jwt_params.idp_params` | Array | One entry per trusted Identity Provider |
| `auth_params.jwt_params.idp_params[].jwt_issuer_uri` | `String` | Expected `iss` claim value |
| `auth_params.jwt_params.idp_params[].jwks_uri` | `String` | URL to fetch the JWKS from |
| `auth_params.jwt_params.idp_params[].jwt_audience` | `String` | Expected `aud` claim value (optional) |
| `auth_params.jwt_params.smallest_refresh_interval_seconds` | `i64` | Minimum JWKS refresh interval (optional) |
| `auth_params.totp_params` | Object | TOTP algorithm settings for per-realm config |
| `auth_params.totp_params.algorithm` | `"SHA1"` \| `"SHA256"` \| `"SHA512"` | HMAC algorithm for TOTP codes |
| `auth_params.totp_params.step` | `u64` | Time step in seconds (default: `30`) |
