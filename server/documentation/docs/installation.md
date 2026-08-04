# Installation

This guide covers **deploying the Authentication Verifier as a running service**: obtaining
the binary, provisioning TLS certificates, writing a configuration file,
bootstrapping the initial administrator, and running and verifying the server.

Once the server is up, follow [Getting Started](getting_started.md) for the
first-run walkthrough (creating your first realm and client credential), and see
[Server Configuration](server_configuration.md) for the full `auth_verifier.toml`
reference.

---

## 1. Prerequisites

| Requirement | Notes |
|-------------|-------|
| Rust toolchain | The version pinned in `rust-toolchain.toml` (currently `1.94.1`). Only needed to build from source. |
| OpenSSL / LibreSSL | Any modern version — used to generate TLS certificates. |
| Database (optional) | Defaults to SQLite (a local file). PostgreSQL, MySQL, or Redis (session store only) are supported for production. |

---

## 2. Obtain the Binary

The Authentication Verifier is distributed as source. Build the release binary from the
workspace root:

```bash
cargo build --release --bin auth_verifier
```

The binary is produced at `target/release/auth_verifier`. Copy it to a stable
location, for example:

```bash
sudo install -m 0755 target/release/auth_verifier /usr/local/bin/auth_verifier
```

---

## 3. Provide TLS Certificates

The server **requires TLS** — all three PEM files (`server_private_key`,
`server_certificate`, `server_ca_chain`) must be present at startup.

> **Key requirement:** the certificate key must be **EC P-256** (`prime256v1`).
> The same EC key is reused to sign session JWTs (the JWKS the API servers
> validate against); the JWKS builder requires P-256. If you use a P-384/P-521
> TLS key, provide a dedicated P-256 key pair under `[session_jwt_params]` (see
> [Server Configuration](server_configuration.md)).

For a development/test deployment, generate a self-signed EC P-256 chain:

```bash
# Root CA
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ca.key.pem
openssl req -new -x509 -days 3650 -key ca.key.pem -out ca.cert.pem \
    -subj "/CN=Auth CA" \
    -addext "basicConstraints=CA:TRUE" \
    -addext "keyUsage=digitalSignature,cRLSign,keyCertSign"

# Server certificate — SANs MUST cover every hostname/IP clients use to reach it
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out server.key.pem
openssl req -new -key server.key.pem -out server.csr \
    -subj "/CN=auth.example.com" \
    -addext "subjectAltName=DNS:auth.example.com,DNS:localhost,IP:127.0.0.1"
openssl x509 -req -sha256 -in server.csr -CA ca.cert.pem -CAkey ca.key.pem \
    -CAcreateserial -out server.cert.pem -days 365 \
    -extfile <(echo "subjectAltName=DNS:auth.example.com,DNS:localhost,IP:127.0.0.1")
```

For production, use certificates issued by a trusted CA or your internal PKI.
Make sure the certificate SANs include the exact host any client — including a
Cosmian KMS configured with `vault_auth_verifier_url` — uses to connect.

---

## 4. Write the Configuration File

Create `auth_verifier.toml`. A minimal production-oriented configuration:

```toml
host_name = "0.0.0.0"
host_port = 8443

[tls_params]
server_private_key = "/etc/cosmian/auth-verifier/certs/server.key.pem"
server_certificate = "/etc/cosmian/auth-verifier/certs/server.cert.pem"
server_ca_chain    = "/etc/cosmian/auth-verifier/certs/ca.cert.pem"

# Use a PERSISTENT database. AppRole role_ids/secret_ids and sessions are stored
# here and MUST survive restarts — never use "sqlite::memory:" outside tests.
[database_params]
backend          = "sqlite"
connection_url   = "sqlite:///var/lib/cosmian/auth_verifier.db"
auto_init_schema = true
```

See [Server Configuration](server_configuration.md) for every option (PostgreSQL/
MySQL backends, a dedicated Redis session store, forward proxy, stale-session
cleanup, and dedicated JWT signing keys).

---

## 5. Bootstrap the First Administrator

On its **first startup** — when the admin realm (`_`) has no administrator yet —
the server automatically creates a super-admin account:

| Field | Value |
|-------|-------|
| Realm | `_` (the admin realm) |
| Username | `admin` |
| Initial password | `change_me` |
| `change_password` | `true` — the password **must** be changed on first login |

> **Security:** the initial credentials are well-known. Log in immediately after
> the first start and change the password (the `change_password` flag forces a
> reset on first login). Restrict network access to the admin API (`/login`,
> `/admins/*`, `/auth/approle/*`, …) to trusted operators.

---

## 6. Run the Server

The binary takes the configuration file path as its first argument (defaulting to
`./auth_verifier.toml`):

```bash
auth_verifier /etc/cosmian/auth-verifier/auth_verifier.toml
```

Log verbosity is controlled by the `RUST_LOG` environment variable (it is **not**
a configuration-file field):

```bash
RUST_LOG="info,auth_verifier=debug" \
  auth_verifier /etc/cosmian/auth-verifier/auth_verifier.toml
```

### Run as a systemd service

Create `/etc/systemd/system/auth-verifier.service`:

```ini
[Unit]
Description=Cosmian auth-verifier
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/auth_verifier /etc/cosmian/auth-verifier/auth_verifier.toml
Environment=RUST_LOG=info,auth_verifier=info
Restart=on-failure
User=cosmian
Group=cosmian
# Harden: the process only needs its config, certs, and data directory.
StateDirectory=cosmian
WorkingDirectory=/var/lib/cosmian

[Install]
WantedBy=multi-user.target
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now auth-verifier
sudo systemctl status auth-verifier
```

> The Authentication Verifier can also run as a container; mount the config, certificates,
> and a persistent volume for the database, and publish port `8443`.

---

## 7. Verify

```bash
# Health/version endpoint (requires the CA cert for TLS verification)
curl --cacert ca.cert.pem https://auth.example.com:8443/public/version

# Admin login — returns HTTP 200, {"next_step": "...", "session_id": "..."}
# and sets the "_ea_" session cookie in cookies.txt
curl --cacert ca.cert.pem -c cookies.txt \
     -X POST "https://auth.example.com:8443/login?realm=_" \
     -u "admin:change_me"
```

---

## Next steps

- [Getting Started](getting_started.md) — first-run walkthrough: create your first
  realm and client credential, verify with `curl` and the `auth_client` crate.
- [Server Configuration](server_configuration.md) — full `auth_verifier.toml`
  reference.
- [AppRole, Kubernetes & Token Authentication](app_auth_api.md) — machine-to-machine
  auth used by the Cosmian KMS SPIRE integration.
- **SPIRE / SPIFFE integration** — to run the Authentication Verifier as the authentication
  backend behind a Cosmian KMS for SPIRE, see the KMS documentation's
  *Integrations → SPIRE / SPIFFE* page.
