# AppRole, Kubernetes & Token Authentication

The auth-verifier exposes an HTTP authentication API compatible with SPIRE's `UpstreamAuthority` and `KeyManager` plugins, under the `/auth/` prefix. This lets SPIRE — and any other tool that speaks the same protocol — authenticate against the auth-verifier without requiring a separate secrets cluster.

!!! note "Scope of this document"
    This page covers the **auth-verifier side only**: AppRole login, Kubernetes service-account login, and token self-service. For the KMS-side crypto engines (`/v1/transit/*`, `/v1/{pki_mount}/*`) and the full end-to-end SPIRE flow, see the [KMS SPIRE/SPIFFE integration guide](../../documentation/docs/integrations/spire_spiffe.md).

## Contents

- [Standards and Protocol References](#standards-and-protocol-references)
- [Endpoint overview](#endpoint-overview)
- [Token format and storage](#token-format-and-storage)
- [AppRole auth method](#approle-auth-method) — server-to-server and SPIRE workloads
- [Kubernetes auth method](#kubernetes-auth-method) — Kubernetes pod workloads
- [Token self-service](#token-self-service) — lookup, renew, revoke (all auth methods)
- [Database schema](#database-schema)
- [Integration with the Cosmian KMS](#integration-with-the-cosmian-kms)
- [Security notes](#security-notes)

---

## Standards and Protocol References

### AppRole auth method

AppRole is not an IETF/W3C standard; it is an HTTP authentication protocol that has become a de-facto standard for machine-to-machine and SPIRE workloads.

| Reference | Description |
|-----------|-------------|
| [AppRole Auth API specification](https://developer.hashicorp.com/vault/api-docs/auth/approle) | Authoritative wire protocol definition for `/auth/approle/*` request and response shapes. |
| [SPIRE `UpstreamAuthority` plugin source](https://github.com/spiffe/spire/tree/main/pkg/server/plugin/upstreamauthority/vault) | SPIRE-side Go plugin implementation that consumes this protocol. |
| [RFC 4648 §5 — Base64url encoding](https://datatracker.ietf.org/doc/html/rfc4648#section-5) | Token body format: `hvs.<base64url(32 random bytes)>`. |
| [RFC 4086 — Randomness Requirements for Security](https://datatracker.ietf.org/doc/html/rfc4086) | Entropy requirements for token and secret-ID generation. |
| [FIPS 180-4 — Secure Hash Standard (SHA-256)](https://csrc.nist.gov/publications/detail/fips/180/4/final) | Token values and secret IDs are stored only as their SHA-256 hashes. |

### Kubernetes auth method

The Kubernetes auth method validates service-account JWTs per the following standards:

| Reference | Description |
|-----------|-------------|
| [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) | JWT format; `exp` (§4.1.4) and `nbf` (§4.1.5) are validated; `iss` (§4.1.1) and `aud` (§4.1.3) are validated when configured. |
| [RFC 7517 — JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517) | JWKS format for the Kubernetes API server's signing keys; `kid` (§4.5) used for key selection. |
| [RFC 7518 — JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518) | Only asymmetric algorithms (RS256/RS384/RS512/ES256/ES384) are accepted. |
| [Kubernetes Bound Service Account Tokens](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens) | Service-account JWT format, `sub` claim shape (`system:serviceaccount:<ns>:<name>`), and projected volume usage. |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Kubernetes ≥1.21 exposes an OIDC-compliant JWKS at `/.well-known/openid-configuration`. |

### Token self-service

Token self-service follows a simple HTTP self-service protocol for token introspection and lifecycle management:

| Reference | Description |
|-----------|-------------|
| [Token self-service endpoint specification](https://developer.hashicorp.com/vault/api-docs/auth/token) | `lookup-self`, `renew-self`, `revoke-self` endpoint shapes. |

---

## Endpoint overview

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST`/`PUT` | `/auth/approle/login` | none | Exchange `role_id` + `secret_id` for an app token |
| `POST` | `/auth/approle/role/{name}` | admin session | Create or update an AppRole role |
| `GET` | `/auth/approle/role/{name}/role-id` | admin session | Read the stable `role_id` |
| `POST` | `/auth/approle/role/{name}/secret-id` | admin session | Generate a new `secret_id` |
| `POST` | `/auth/approle/role/{name}/secret-id/destroy` | admin session | Invalidate a `secret_id` by accessor |
| `DELETE` | `/auth/approle/role/{name}` | admin session | Delete a role |
| `GET` | `/auth/approle/role?list=true` | admin session | List all roles |
| `POST` | `/auth/kubernetes/login` | none | Exchange a Kubernetes service-account JWT for an app token |
| `POST` | `/auth/kubernetes/role/{name}` | admin session | Create or update a Kubernetes role |
| `DELETE` | `/auth/kubernetes/role/{name}` | admin session | Delete a Kubernetes role |
| `GET` | `/auth/token/lookup-self` | `X-Vault-Token` | Validate a token and return its metadata |
| `POST` | `/auth/token/renew-self` | `X-Vault-Token` | Extend a renewable token's TTL |
| `POST` | `/auth/token/revoke-self` | `X-Vault-Token` | Immediately invalidate a token |

**Admin session** means an active `_ea_` cookie issued by `POST /login?realm=_` (the `_` admin realm). See [Authorization and Administration](authorization_and_administration.md) for details.

---

## Token format and storage

Issued tokens use the `hvs.<base64url(32 random bytes)>` format, mirroring the SPIRE-compatible token prefix expected on the wire. The raw token is **never stored** — only its SHA-256 hash is persisted. Clients receive the token once at login time; there is no way to retrieve it again.

---

## AppRole auth method

AppRole is the recommended method for **server-to-server** and **SPIRE** workloads. An operator provisions a role out-of-band and hands the resulting `role_id` + `secret_id` to the service.

### Step 1 — Create a role (admin)

```http
POST /auth/approle/role/{name}
Content-Type: application/json
Cookie: _ea_=<admin session cookie>

{
  "token_ttl": 3600,
  "secret_id_ttl": 86400,
  "token_policies": ["default"],
  "bind_secret_id": true
}
```

| Field            | Type             | Default | Description                                                       |
| ---------------- | ---------------- | ------- | ----------------------------------------------------------------- |
| `token_ttl`      | integer          | `3600`  | Lifetime of issued tokens in seconds.                             |
| `secret_id_ttl`  | integer          | `0`     | Lifetime of generated secret IDs in seconds. `0` means no expiry. |
| `token_policies` | array of strings | `[]`    | Policies attached to every token issued by this role.             |
| `bind_secret_id` | boolean          | `true`  | When `true`, a valid `secret_id` is required for login.           |

**Response:** `204 No Content`

### Step 2 — Read the `role_id` (admin)

The `role_id` is a stable UUID generated when the role is created. Hand this to the service that will log in.

```http
GET /auth/approle/role/{name}/role-id
Cookie: _ea_=<admin session cookie>
```

**Response:**

```json
{
  "data": {
    "role_id": "a5d7e2f1-0c3b-4a8d-9e6f-1234567890ab"
  }
}
```

### Step 3 — Generate a `secret_id` (admin)

Secret IDs are single-use or limited-use credentials bound to a role.

```http
POST /auth/approle/role/{name}/secret-id
Content-Type: application/json
Cookie: _ea_=<admin session cookie>

{
  "ttl": 0,
  "num_uses": 1
}
```

| Field      | Type    | Default | Description                                                       |
| ---------- | ------- | ------- | ----------------------------------------------------------------- |
| `ttl`      | integer | `0`     | Per-secret-ID TTL override in seconds. `0` uses the role default. |
| `num_uses` | integer | `0`     | Maximum number of login uses. `0` means unlimited.                |

**Response:**

```json
{
  "data": {
    "secret_id": "b7c4e9d2-1a2b-4c3d-8e5f-fedcba987654",
    "secret_id_accessor": "9f8e7d6c-5b4a-3c2d-1e0f-abcdef012345"
  }
}
```

Save the `secret_id` securely — it cannot be retrieved again. The `secret_id_accessor` can be used later to invalidate the secret ID without knowing the secret itself.

### Step 4 — Login (client)

The service exchanges its `role_id` + `secret_id` for an app token. Both `POST` and `PUT` are accepted (SPIRE's Go SDK may issue either).

```http
POST /auth/approle/login
Content-Type: application/json

{
  "role_id": "a5d7e2f1-0c3b-4a8d-9e6f-1234567890ab",
  "secret_id": "b7c4e9d2-1a2b-4c3d-8e5f-fedcba987654"
}
```

**Response:**

```json
{
  "auth": {
    "client_token": "hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob",
    "renewable": true,
    "lease_duration": 3600,
    "policies": ["default"],
    "metadata": {
      "role_name": "spire-server"
    }
  }
}
```

The `client_token` must be passed as `X-Vault-Token` on all subsequent requests to the KMS's `/v1/transit/*` and `/v1/<pki_mount>/*` scopes.

!!! warning "Secret ID consumption"
    Each login call **consumes** one use of the `secret_id`. When `num_uses` is `1` (the SPIRE demo default), the secret ID is invalidated after the first successful login. Generate a new one before SPIRE restarts.

### Managing roles

**Destroy a `secret_id`** (admin, by accessor):

```http
POST /auth/approle/role/{name}/secret-id/destroy
Content-Type: application/json
Cookie: _ea_=<admin session cookie>

{
  "secret_id_accessor": "9f8e7d6c-5b4a-3c2d-1e0f-abcdef012345"
}
```

**Response:** `204 No Content`

**List all roles** (admin):

```http
GET /auth/approle/role?list=true
Cookie: _ea_=<admin session cookie>
```

**Response:**

```json
{
  "data": {
    "keys": ["spire-server", "mistral-agents"]
  }
}
```

**Delete a role** (admin):

```http
DELETE /auth/approle/role/{name}
Cookie: _ea_=<admin session cookie>
```

**Response:** `204 No Content`. All secret IDs for that role are deleted automatically (cascade).

---

## Kubernetes auth method

The Kubernetes auth method lets workloads running as Kubernetes service accounts authenticate by presenting their pod-mounted service-account JWT. No operator-provisioned secret is required — the JWT itself is the credential.

### Step 1 — Create a Kubernetes role (admin)

```http
POST /auth/kubernetes/role/{name}
Content-Type: application/json
Cookie: _ea_=<admin session cookie>

{
  "jwks_url": "https://kubernetes.default.svc/.well-known/jwks.json",
  "bound_service_account_names": ["my-app"],
  "bound_service_account_namespaces": ["production"],
  "token_ttl": 3600
}
```

| Field                              | Type    | Description                                                                              |
| ---------------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| `jwks_url`                         | string  | URL of the Kubernetes JWKS endpoint. Used to verify the service-account JWT's signature. |
| `bound_service_account_names`      | array   | Allowed service-account names. Use `["*"]` to allow any name.                            |
| `bound_service_account_namespaces` | array   | Allowed namespaces. Use `["*"]` to allow any namespace.                                  |
| `token_ttl`                        | integer | Lifetime of issued tokens in seconds.                                                    |

**Response:** `204 No Content`

### Step 2 — Login (client)

```http
POST /auth/kubernetes/login
Content-Type: application/json

{
  "role": "my-k8s-role",
  "jwt": "<service account JWT from /var/run/secrets/kubernetes.io/serviceaccount/token>"
}
```

**Response:**

```json
{
  "auth": {
    "client_token": "hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob",
    "renewable": true,
    "lease_duration": 3600,
    "policies": [],
    "metadata": {}
  }
}
```

The server:

1. Fetches the JWKS from the role's `jwks_url`.
2. Selects the correct key by `kid` from the JWT header.
3. Validates the JWT signature and expiry.
4. Checks `sub` (`system:serviceaccount:<namespace>:<name>`) against the role's allow-lists.
5. Issues a app token on success.

!!! warning "JWKS availability"
    A JWKS endpoint outage blocks new Kubernetes logins for the duration of the outage. Existing tokens remain valid until their TTL expires.

### Delete a Kubernetes role (admin)

```http
DELETE /auth/kubernetes/role/{name}
Cookie: _ea_=<admin session cookie>
```

**Response:** `204 No Content`

---

## Token self-service

All app tokens — regardless of which auth method produced them — support the same self-service endpoints. These require a valid `X-Vault-Token` header.

### `GET /auth/token/lookup-self`

Validate a token and return its current metadata. This endpoint is called by the KMS middleware on every request to the `/v1/transit/*` and `/v1/<pki_mount>/*` scopes (with a 30-second cache).

```http
GET /auth/token/lookup-self
X-Vault-Token: hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob
```

**Response:**

```json
{
  "data": {
    "id": "hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob",
    "entity_id": "spire-server",
    "policies": ["default"],
    "renewable": true,
    "ttl": 3541,
    "creation_time": 1753670400
  }
}
```

`id` is the token itself (echoed from the `X-Vault-Token` request header). SPIRE reads this field to warm its internal token state.

**Returns `403 Forbidden`** if the token is missing, invalid, expired, or has been revoked.

### `POST /auth/token/renew-self`

Extend a renewable token's TTL back to its configured `lease_duration`.

```http
POST /auth/token/renew-self
X-Vault-Token: hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob
```

**Response:**

```json
{
  "auth": {
    "client_token": "hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob",
    "renewable": true,
    "lease_duration": 3600,
    "policies": ["default"],
    "metadata": {}
  }
}
```

`client_token` is the token echoed from the `X-Vault-Token` request header. SPIRE uses this to refresh its in-memory token state.

### `POST /auth/token/revoke-self`

Immediately invalidate the current token.

```http
POST /auth/token/revoke-self
X-Vault-Token: hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob
```

**Response:** `204 No Content`

!!! note "Revocation propagation"
    Once a token is revoked, subsequent `lookup-self` calls return `403` immediately. If the KMS's token-validation cache has a live entry for that token, requests to the KMS may still succeed for up to `app_token_cache_ttl_secs` seconds (default: 30). Reduce or disable caching on the KMS side if your threat model requires faster revocation propagation.

---

## Database schema

The SPIRE auth API stores its state in four tables, added alongside the existing auth-verifier schema on all three database backends (SQLite, PostgreSQL, MySQL):

```sql
-- Issued tokens (all auth methods)
CREATE TABLE app_tokens (
    token_hash          BLOB PRIMARY KEY,    -- SHA-256(raw "hvs.<base64>" token)
    entity              TEXT NOT NULL,       -- AppRole role name or K8s service-account name
    policies            TEXT NOT NULL,       -- comma-separated
    expiry              INTEGER NOT NULL,    -- Unix timestamp; 0 = never
    renewable           BOOLEAN NOT NULL,
    lease_duration_secs INTEGER NOT NULL,
    created_at          INTEGER NOT NULL
);

-- AppRole roles
CREATE TABLE approle_roles (
    name                TEXT PRIMARY KEY,
    role_id             TEXT UNIQUE NOT NULL,
    secret_id_ttl_secs  INTEGER NOT NULL,
    token_ttl_secs      INTEGER NOT NULL,
    bind_secret_id      BOOLEAN NOT NULL,
    token_policies      TEXT NOT NULL        -- comma-separated
);

-- AppRole secret IDs (hashed, limited-use)
CREATE TABLE app_secret_ids (
    accessor            TEXT PRIMARY KEY,    -- UUID returned to the admin
    secret_id_hash      BLOB NOT NULL,       -- SHA-256(raw secret_id)
    role_name           TEXT NOT NULL REFERENCES approle_roles(name) ON DELETE CASCADE,
    expiry              INTEGER NOT NULL,    -- 0 = no expiry
    num_uses_remaining  INTEGER NOT NULL     -- -1 = unlimited
);

-- Kubernetes roles
CREATE TABLE k8s_roles (
    name                TEXT PRIMARY KEY,
    jwks_url            TEXT NOT NULL,
    bound_sa_names      TEXT NOT NULL,       -- JSON array
    bound_sa_namespaces TEXT NOT NULL,       -- JSON array
    token_ttl_secs      INTEGER NOT NULL
);
```

Raw token values and raw secret IDs are never written to the database — only their SHA-256 hashes.

---

## Integration with the Cosmian KMS

The auth-verifier's `/auth/token/lookup-self` endpoint is the only point of contact between the auth-verifier and the KMS. The KMS calls it to validate every `X-Vault-Token` presented to its `/v1/transit/*` and `/v1/<pki_mount>/*` scopes.

Configure the KMS to point at the auth-verifier with these parameters (see [KMS SPIRE/SPIFFE integration guide](../../documentation/docs/integrations/spire_spiffe.md#configuration-reference)):

```toml
[vault]
vault_api_enabled             = true
vault_auth_verifier_url       = "https://auth.example.com"
vault_auth_verifier_ca_cert   = "/path/to/ca.pem"  # omit if using a public CA
vault_token_cache_ttl_secs    = 30
```

!!! tip "Single entry point"
    The KMS exposes a **single HTTPS entry point** for SPIRE. The `/auth/*` endpoints
    (login, token renew, etc.) are **proxied transparently** by the KMS to the
    auth-verifier. SPIRE only needs to know the KMS address — it never contacts the
    auth-verifier directly. No external reverse proxy (e.g. nginx) is required.

---

## Security notes

- **Login endpoints are unauthenticated** — `POST /auth/approle/login` and `POST /auth/kubernetes/login` are intentionally open; the credential is the request body. Apply rate limiting at the reverse-proxy level in production.
- **No admin token-revocation endpoint** — a leaked, not-yet-expired token can only be revoked via `revoke-self` (self-service) or direct database deletion. There is no admin endpoint to revoke all tokens for a given role yet.
- **Secret ID consumption** — `consume_secret_id` atomically decrements `num_uses_remaining` in a single database transaction, preventing replay. A secret ID with `num_uses = 1` is permanently invalidated after the first login.
- **Raw values never stored** — token values and secret IDs follow the same hashing convention as passwords: only SHA-256 hashes are persisted. A database compromise does not expose any usable credential.

---

## See also

- [KMS SPIRE/SPIFFE integration guide](../../documentation/docs/integrations/spire_spiffe.md) — full end-to-end flow, KMS configuration, CLI reference, and troubleshooting.
- [Architecture Decision Record — ADR-0002](adr/2026-07-26-app-auth-api-for-spire.md) — design rationale, alternatives considered, and database schema motivation.
- [Authorization and Administration](authorization_and_administration.md) — the `AdminAuth` middleware reused for AppRole/Kubernetes role administration.
- `ckms` AppRole provisioning commands — CLI wrapper for AppRole provisioning against this API.
