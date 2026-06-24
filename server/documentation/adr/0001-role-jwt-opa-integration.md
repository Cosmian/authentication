# ADR-0001 — RBAC Roles in JWT for KMS OPA Authorization

| Field      | Value                                   |
|------------|-----------------------------------------|
| **Status** | Accepted                                |
| **Date**   | 2026-06-24                              |
| **Branch** | `add_role_to_user`                      |
| **PR**     | #6                                      |
| **Scope**  | Authentication Server + Cosmian KMS     |

---

## Context

Cosmian KMS uses an [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
sidecar to enforce Role-Based Access Control (RBAC) on every KMIP operation
(see KMS ADR-0001 — *RBAC Authorization with OPA*). The OPA policy receives a
structured input document containing the caller's identity, the requested
operation, the target object, and the caller's **roles**:

```json
{
  "user":           "alice@example.com",
  "user_domain":    "acme",
  "roles":          ["CryptoOfficer"],
  "operation":      "get",
  "object_uid":     "abc123",
  "object_domain":  "acme",
  "is_owner":       false
}
```

The `roles` array is the pivot of the KMS RBAC model. If `roles` is empty, the
OPA reference policy denies access for every non-owner operation (fail-closed).

### Problem

Before this ADR, the Authentication Server issued JWTs that contained no role
information. The `ClientClaims` struct held `RegisteredClaims` and
`AuthPrivateClaims` but no authorization claims. As a result:

- KMS received a JWT with an empty `roles` array.
- OPA denied every non-owner request regardless of who the user was.
- The RBAC model was structurally impossible to use.

### Role vocabulary

The KMS reference Rego policy defines five roles drawn from FIPS 140-3 §7.4,
NIST SP 800-57 Part 2 §4.3, and ANSI/INCITS 359-2004:

| Role            | Description                                              |
|-----------------|----------------------------------------------------------|
| `SuperAdmin`    | Cross-domain administrator; all operations everywhere    |
| `DomainAdmin`   | Domain-scoped administrator; manage objects in a domain  |
| `CryptoOfficer` | Key lifecycle (create, import, destroy) in own domain    |
| `Auditor`       | Read-only access (get, locate, get_attributes)           |
| `User`          | Crypto-use only (encrypt, decrypt, sign, verify)         |

The Authentication Server does not interpret these strings — it stores and
forwards them verbatim. Role semantics live entirely in the OPA policy.

### Domain scoping

KMS RBAC is domain-scoped: a `CryptoOfficer` in domain `"acme"` may not manage
keys belonging to domain `"globex"`. In the Authentication Server the concept of
*domain* maps directly to a *realm* — the isolated authentication namespace that
users authenticate to. There is no separate domain concept; realm and domain are
the same thing.

Previously the JWT carried a redundant `as_domain` private claim alongside
`as_rid` (realm ID). This duplication was error-prone and added complexity in
KMS middleware that extracted both.

---

## Decisions

### Decision 1 — Store roles in `UserPass`

Add a `roles: Vec<String>` field to the `UserPass` model:

```rust
pub struct UserPass {
    pub realm: String,
    pub username: String,
    pub password: Vec<u8>,
    pub change_password: bool,
    /// RBAC roles assigned to this user.
    /// Emitted in the JWT `roles` claim for OPA policy evaluation.
    #[serde(default)]
    pub roles: Vec<String>,
}
```

**Storage**: serialised as a JSON array (`TEXT NOT NULL DEFAULT '[]'`) in the
`userpass` table across all three backends (SQLite, PostgreSQL, MySQL). JSON is
used rather than a separate junction table to avoid a schema join on every login
while keeping the data self-describing and easy to inspect.

**Online migration**: each backend detects whether the `roles` column exists at
startup and adds it with `ALTER TABLE … ADD COLUMN` if missing. Existing rows
receive the empty array default with no data loss.

**Rationale for `Vec<String>` over a foreign-key role table**: roles are small,
rarely change, and must be available on every login. A lookup-table design would
require a JOIN or a second query on every authentication request with no
compensating benefit for the current scale.

### Decision 2 — Propagate roles in the JWT `roles` claim (RFC 9068)

Introduce `AuthorizationClaims` and embed it in `ClientClaims`:

```rust
/// RFC 9068 §7.2.1.1 / RFC 7643 §4.1.2 authorization claims.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorizationClaims {
    /// RBAC roles. Absence / empty array → fail-closed in OPA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

pub struct ClientClaims {
    #[serde(flatten)] pub registered:    RegisteredClaims,
    #[serde(flatten)] pub authorization: AuthorizationClaims, // ← new
    #[serde(flatten)] pub private:       AuthPrivateClaims,
}
```

At login, `issue_token()` receives `roles: Vec<String>` fetched from the
`UserPass` record and encodes them as `"roles": ["CryptoOfficer"]` in the JWT
payload.

**Claim name**: `roles` is registered in the IANA JWT Claims Registry by
RFC 9068 §7.2.1.1 (OAuth 2.0 access tokens) and defined as a SCIM User
attribute in RFC 7643 §4.1.2. RFC 9068 states *"no specific vocabulary is
provided for `roles`"*, giving the Authentication Server freedom to use the
KMS-defined role names without deviation from the standard.

**Skip-if-empty policy**: when the user has no roles, the `roles` claim is
omitted from the JWT entirely (not emitted as `"roles": null` or `"roles": []`).
This keeps tokens compact and removes ambiguity about the meaning of an explicit
empty array vs. absence.

**Scope restriction**: roles are only embedded for `UsernamePassword`
authentication. For JWT-relay and mTLS auth schemes the `roles` array defaults
to `[]` (fail-closed). Those flows are used for machine-to-machine scenarios
where the client credential carries its own OPA-resolvable identity.

### Decision 3 — Remove `as_domain`; use `as_rid` as the domain

The `as_domain` private claim is removed. KMS middleware reads the realm ID from
the existing `as_rid` claim and treats it as the user domain. This:

- Eliminates two fields that always had identical values in practice.
- Simplifies the JWT payload by one claim.
- Clarifies the model: in Cosmian, a realm *is* the security domain.

The KMS `OpaInput.user_domain` is populated from `as_rid`.

### Decision 4 — Expose available roles via `GET /public/roles`

A new unauthenticated endpoint returns the list of role names configured on the
server:

```text
GET /public/roles → 200 ["SuperAdmin","DomainAdmin","CryptoOfficer","Auditor","User"]
```

The roles list is declared in the server configuration (`auth_server.toml`):

```toml
roles = ["SuperAdmin", "DomainAdmin", "CryptoOfficer", "Auditor", "User"]
```

**Purpose**: the Admin UI role-assignment dropdowns are populated from this list
rather than being hardcoded, so operators deploying a custom OPA policy with
different role names can still use the UI without rebuilding the frontend.

**No server-side role validation**: the server stores whatever string values the
admin writes and forwards them to JWT consumers. The OPA policy is the only
authority on what roles are meaningful. This preserves the vocabulary-agnostic
design of the KMS OPA integration.

---

## End-to-end role propagation flow

```text
Admin UI
  └─ PUT /realms/{realm}/credentials/{username}   { roles: ["CryptoOfficer"] }
        ↓
Authentication Server
  └─ stores roles in userpass.roles (JSON column)
        ↓
KMS Client (or any service)
  └─ POST /login  →  JWT { roles: ["CryptoOfficer"], as_rid: "acme", sub: "alice" }
        ↓
Cosmian KMS middleware (JwtAuth)
  └─ AuthenticatedUser { username: "alice", roles: ["CryptoOfficer"], domain: Some("acme") }
        ↓
  task_local! OPA_USER_CONTEXT { roles: ["CryptoOfficer"], domain: Some("acme") }
        ↓
  OpaInput { user: "alice", user_domain: "acme", roles: ["CryptoOfficer"],
             operation: "create", object_uid: "*", … }
        ↓
OPA sidecar  POST /v1/data/kms/allow
  └─ kms.rego: CryptoOfficer + create → allow (same domain)
        ↓
  → 200 { "result": true }  →  KMS proceeds
```

---

## Consequences

### Positive

- OPA RBAC in KMS is fully operational; non-owner requests are evaluated by role
  rather than being universally denied.
- Zero-downtime migration: the `roles` column is added online at startup with an
  `ALTER TABLE` guard; existing deployments keep working without manual SQL.
- The Admin UI can assign roles without hardcoding role names in the frontend.
- The JWT is smaller (one fewer claim after removing `as_domain`).
- Role vocabulary is decoupled: replacing or extending the OPA policy with new
  role names requires no Auth Server change.

### Negative / risks

- **No server-side validation of role strings**: an admin can store any string.
  Typos will silently produce tokens that OPA rejects. Mitigation: the
  `GET /public/roles` list acts as the canonical vocabulary; the Admin UI
  populates dropdowns from it, making free-text entry unnecessary in normal
  operation.
- **Roles stored in `userpass`, not in a general user object**: if future
  authentication schemes (e.g. mTLS with user identity from the certificate CN)
  need role-based access, a separate role store will be required.
- **JWT revocation**: if an admin changes a user's roles, existing sessions carry
  the old roles until the JWT expires. Operators should set short JWT TTLs for
  sensitive role changes or invalidate sessions explicitly via the
  `DELETE /sessions` endpoint.

### Neutral

- The `UserPass.password` field continues to be zeroed in read responses
  (`password: vec![]`). The `roles` field is returned in full on reads.

---

## Alternatives considered

### A — Store roles in a dedicated `user_roles` junction table

**Rejected**: adds a JOIN or a second query on every login; roles are small
per-user sets that change rarely; JSON column is simpler and adequate.

### B — Resolve roles from OPA data bundle, not the Auth Server

**Rejected**: would require OPA data to be authoritative for both role
*assignment* (write path) and role *evaluation* (read path). The Auth Server is
the existing system of record for user identity; it is simpler and more coherent
to store roles alongside the credential they apply to.

### C — Add a dedicated `roles` claim using a custom private claim name

**Rejected**: `roles` is an IANA-registered claim (RFC 9068 / RFC 7643); using a
private name (`as_roles`, `cosmian_roles`) when a standard name exists serves no
purpose and breaks interoperability with any consumer that understands RFC 9068.

### D — Keep `as_domain` alongside `as_rid`

**Rejected**: domain and realm had identical values in every observed case. Two
claims with identical semantics increase JWT size and create confusion when they
diverge through misconfiguration. Removing the redundant one is the simplest fix.

---

## Related documents

- KMS `documentation/docs/adr/0001-rbac-opa-authorization.md` — upstream ADR
  describing the KMS OPA integration, OPA modes, and the reference Rego policy.
- `server/documentation/authorization_and_administration.md` — admin/realm
  authorization model.
- `server/documentation/openapi.yaml` — API contract including the `roles` field
  on `UserPass` and the `GET /public/roles` endpoint.
- RFC 9068 §2.2.3.1 and §7.2.1.1 — `roles` claim specification for OAuth 2.0
  access tokens.
- RFC 7643 §4.1.2 — SCIM `roles` attribute definition.
