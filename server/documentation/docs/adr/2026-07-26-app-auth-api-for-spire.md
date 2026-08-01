# ADR-0002 — AppRole-Compatible Auth API for SPIRE

| Field      | Value                                     |
|------------|--------------------------------------------|
| **Status** | Accepted                                    |
| **Date**   | 2026-07-26                                  |
| **Branch** | `spire`                                     |
| **PR**     | #19                                         |
| **Scope**  | Authentication Server + Cosmian KMS         |

---

## Context

An enterprise Zero Trust M2M integration initiative requires
[SPIRE](https://spiffe.io/) to use the Cosmian stack as a drop-in replacement for
an AppRole-compatible auth server. SPIRE's `UpstreamAuthority` and `KeyManager`
plugins each authenticate once via the standard auth HTTP API before calling the
PKI/Transit crypto engines. This implementation mirrors the wire protocol described by
SPIRE's own integration (auth methods, request/response shapes for
`/auth/<mount>/login` and token self-service).

SPIRE supports four auth methods in that integration (Token, Cert, AppRole, Kubernetes); this beta
targets the two mechanisms suited to server-to-server and cluster workloads:

- **AppRole** — `POST /v1/auth/approle/login` with `{role_id, secret_id}`, used by the
  SPIRE server itself (provisioned out-of-band by an operator or CI job) and by the
  Mistral client agents.
- **Kubernetes** — `POST /v1/auth/kubernetes/login` with `{role, jwt}`, used by
  workloads running as Kubernetes service accounts.

Both flows return an opaque app token that the caller then presents as
`X-Vault-Token: <token>` on every subsequent request to the KMS's crypto engines
(`/v1/transit/`, `/v1/<pki_mount>/` — see the companion KMS ADR
`documentation/docs/adr/2026-07-26-spire-spiffe-via-vault-api.md`). The KMS validates
that token by calling back into Authentication Verifier's `GET /v1/auth/token/lookup-self`.

### Problem

Before this feature, Authentication Verifier had no concept of an app-style bearer token, AppRole,
or Kubernetes service-account login — its only authentication schemes were
username/password, JWT/OIDC, and mTLS, all designed around human/administrator sessions
(`_ea_` cookie) rather than short-lived machine credentials consumed by a third-party
client library (SPIRE's Go auth SDK).

## Decisions

### Decision 1 — New `/auth/` scope, unauthenticated login + admin-gated CRUD

> **Implementation note**: the initial design used a `/v1/auth/` prefix (matching
> the AppRole protocol URL scheme). During implementation the prefix was shortened to
> `/auth/` to avoid an Actix-web FIFO routing conflict with existing authenticated
> scopes. All current routes, the OpenAPI schema, and client URLs use `/auth/...`
> (no `/v1/` prefix). References to `/v1/auth/...` elsewhere in this ADR describe
> the original design intent; the live paths are listed in the table below.

Three new endpoint modules under `server/src/server/endpoints/`:

| Module | Routes | Auth |
|--------|--------|------|
| `approle.rs` | `POST/PUT /auth/approle/login` | none (credential is the body) |
| `approle.rs` | `POST /auth/approle/role/{name}`, `GET .../role-id`, `POST .../secret-id`, `POST .../secret-id/destroy`, `DELETE /role/{name}`, `GET /role?list=true` | `CookieAuthSameServer` + `AdminAuth` |
| `kubernetes.rs` | `POST /auth/kubernetes/login` | none (credential is the K8s SA JWT) |
| `kubernetes.rs` | `POST /auth/kubernetes/role/{name}`, `DELETE /role/{name}` | `CookieAuthSameServer` + `AdminAuth` |
| `auth_token.rs` | `GET /auth/token/lookup-self`, `POST /auth/token/renew-self`, `POST /auth/token/revoke-self` | `app_token_extract` middleware |

Role/secret-ID administration reuses the existing `AdminAuth` middleware rather than
introducing a new authorization model — an admin who can manage realm credentials can
also provision AppRole and Kubernetes roles.

**Distinct scope prefix**: the `/auth/` scope was deliberately kept separate from
`/login`, `/realms`, etc. to avoid an Actix-web FIFO routing conflict between the new
unauthenticated login routes and existing authenticated scopes matching a similar path
shape (see commit `310bfe9`).

**Content-type tolerance**: `approle_login` accepts both `POST` and `PUT` and
parses the body as raw `Bytes` rather than via Actix's typed `Json` extractor, because
SPIRE's Go SDK issues `PUT` requests and does not reliably set
`Content-Type: application/json` (commits `f21d4a4`, `045b2d9`).

### Decision 2 — New database-backed models: tokens, AppRole roles/secret-IDs, K8s roles

Four new tables, added to all three backends (SQLite, PostgreSQL, MySQL):

```sql
CREATE TABLE app_tokens (
    token_hash          BLOB PRIMARY KEY,   -- SHA-256(raw "hvs.<base64>" token)
    entity              TEXT NOT NULL,      -- AppRole role name / K8s SA name
    policies            TEXT NOT NULL,      -- comma-separated
    expiry              INTEGER NOT NULL,   -- unix timestamp, 0 = never
    renewable           BOOLEAN NOT NULL,
    lease_duration_secs INTEGER NOT NULL,
    created_at          INTEGER NOT NULL
);

CREATE TABLE approle_roles (
    name                TEXT PRIMARY KEY,
    role_id             TEXT UNIQUE NOT NULL,  -- stable UUID SPIRE stores as approle_id
    secret_id_ttl_secs  INTEGER NOT NULL,       -- 0 = no expiry
    token_ttl_secs      INTEGER NOT NULL,
    bind_secret_id      BOOLEAN NOT NULL,
    token_policies      TEXT NOT NULL           -- JSON array
);

CREATE TABLE app_secret_ids (
    accessor            TEXT PRIMARY KEY,      -- UUID, returned to the admin
    secret_id_hash      BLOB NOT NULL,          -- SHA-256(raw secret_id)
    role_name           TEXT NOT NULL REFERENCES approle_roles(name) ON DELETE CASCADE,
    expiry              INTEGER NOT NULL,       -- 0 = no expiry
    num_uses_remaining  INTEGER NOT NULL        -- -1 = unlimited
);

CREATE TABLE k8s_roles (
    name                TEXT PRIMARY KEY,
    jwks_url            TEXT NOT NULL,
    bound_sa_names      TEXT NOT NULL,          -- JSON array
    bound_sa_namespaces TEXT NOT NULL,          -- JSON array
    token_ttl_secs      INTEGER NOT NULL
);
```

**Token format**: `hvs.<base64url(32 random bytes)>` (matches the SPIRE-compatible token
prefix). Only the SHA-256 hash is stored — the raw token is never persisted, matching
the existing password-hashing convention in this codebase.

**Secret-ID consumption**: `consume_secret_id` validates the presented secret ID
against its stored hash and atomically decrements `num_uses_remaining` in the same
query, preventing a secret ID from being replayed beyond its configured use count.

**Rationale for dedicated tables over reusing `admins`/`userpass`**: AppRole and
Kubernetes credentials are machine identities with a fundamentally different lifecycle
(role/secret-ID pairs, single/limited-use secrets, token leases) from human admin or
realm-user records. Reusing those tables would force nullable, auth-method-specific
columns onto unrelated models.

### Decision 3 — Kubernetes login validates the service-account JWT against the cluster's JWKS

`k8s_login` decodes the presented JWT's header to select the signing key, then
validates its signature against the `jwks_url` configured for that K8s role, and checks
`sub` matches `system:serviceaccount:<namespace>:<name>` against the role's
`bound_sa_names`/`bound_sa_namespaces` allow-lists before issuing a token. This mirrors
SPIRE's expected Kubernetes auth flow: the service-account JWT is the only credential,
verified purely by signature + claim matching (no separate secret).

### Decision 4 — Token issuance and validation shared helper

`issue_app_token()` (in `approle.rs`, reused by `kubernetes.rs`) is the single
code path that mints a `app_tokens` row and returns a `AppAuthResponse`, so both
auth methods produce tokens with identical shape, TTL handling, and hashing. Token
self-service (`lookup-self`, `renew-self`, `revoke-self`) is implemented once in
`auth_token.rs` and works identically regardless of which auth method produced the
token, since validation only depends on the token hash row, not on how it was created.

## End-to-end flow (SPIRE server startup)

```text
SPIRE server (UpstreamAuthority plugin)
  └─ POST /auth/approle/login  { role_id, secret_id }
        ↓
Authentication Verifier (approle_login)
  └─ look up role by role_id, consume secret_id, issue token
        ↓
  { auth: { client_token: "hvs....", renewable: true, lease_duration: 3600 } }
        ↓
SPIRE server
  └─ POST /<pki_mount>/root/sign-intermediate   (X-Vault-Token: hvs....)
        ↓
KMS (app token middleware)
  └─ GET /auth/token/lookup-self  (X-Vault-Token: hvs....)   [30s cache]
        ↓
Authentication Verifier (auth_token_lookup_self)
  └─ { data: { policies, renewable, ttl, creation_time } }
        ↓
KMS
  └─ token valid → sign the CSR, return the intermediate CA chain
```

## Consequences

### Positive

- SPIRE (and any other auth-API-speaking tool using the same protocol) can authenticate against Authentication Verifier
  with zero changes to its own auth-method implementation — only `auth_api_addr` changes.
- AppRole and Kubernetes credentials are fully isolated from human admin/session data;
  compromising one does not expose the other.
- Reusing `AdminAuth` for role/secret-ID provisioning avoids a second authorization
  model; realm admins already capable of managing credentials can provision machine
  identities too.
- Token self-service (`lookup-self`/`renew-self`/`revoke-self`) is auth-method-agnostic,
  so adding a future auth method (e.g. TLS Cert) requires no changes to token validation.

### Negative / risks

- **New attack surface**: `/auth/approle/login` and `/auth/kubernetes/login` are
  intentionally unauthenticated (the credential is the request body/JWT itself); secret
  ID and JWT validation must remain constant-time-safe and rate-limited in production
  hardening beyond this beta.
- **Secret ID and token hashes only, no revocation list**: a leaked, not-yet-expired
  token can only be invalidated via `revoke-self` (self-service) or direct DB deletion —
  there is no admin-facing "revoke all tokens for role X" endpoint yet.
- **Kubernetes JWKS fetched per configured role**: no local caching/pinning beyond
  whatever the JWT validation library does internally; a JWKS endpoint outage blocks new
  Kubernetes logins (existing tokens remain valid until their TTL expires).
- **Cross-repo coupling**: this feature is only fully functional together with the KMS's
  `/v1/transit/` and `/v1/<pki_mount>/` implementation and its 30-second token-validation
  cache (see the companion KMS ADR). A protocol change on either side requires
  coordinated review.

## Alternatives considered

### A — Reuse the existing JWT/session model for machine credentials

**Rejected**: SPIRE's client library speaks this HTTP auth API verbatim
(role_id/secret_id or service-account JWT to a `/login` endpoint, opaque bearer token
in `X-Vault-Token`); it has no support for the `_ea_` session cookie or this server's
existing JWT claim shape. Implementing an API shaped like that protocol was required regardless of
what happened underneath; reusing the existing session model would not have changed
that requirement while adding awkward translation logic.

### B — Store AppRole/K8s credentials as `admins` with a `machine` flag

**Rejected**: would force lifecycle fields (secret-ID TTL, use-count, JWKS URL,
bound namespaces) as nullable columns onto the `admins` table for records that are not
administrators in any authorization sense. Dedicated tables keep both models simple.

### C — Implement app token validation as a stateless signed token (JWT) instead of a DB-backed opaque token

**Rejected**: The protocol's token format and semantics (renewable leases, revocation,
`lookup-self` returning live TTL) are inherently stateful — a self-contained JWT cannot
support renewal or immediate revocation without also maintaining server-side state,
which would negate the simplicity benefit of choosing JWTs in the first place.

## Related documents

- KMS `documentation/docs/adr/2026-07-26-spire-spiffe-via-vault-api.md` — companion ADR
  describing the KMS's `/v1/transit/` and `/v1/<pki_mount>/` crypto-engine implementation
  and its token-validation cache.
- `server/documentation/authorization_and_administration.md` — `AdminAuth` and realm
  authorization model reused for AppRole/K8s role administration.
- `server/documentation/openapi.yaml` — documents the `/auth/token/*`,
  `/auth/approle/*`, and `/auth/kubernetes/*` paths introduced by this feature.
