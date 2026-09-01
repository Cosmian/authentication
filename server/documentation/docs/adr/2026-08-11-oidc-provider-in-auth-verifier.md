---
title: "ADR-2026-08-11: Embed a Full OpenID Connect Provider in auth-verifier"
status: "Accepted"
date: "2026-08-11"
authors: "KMS Core Team — operators, security engineers, contributors"
tags: ["architecture", "decision", "oidc", "authentication", "authorization"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-08-11: Embed a Full OpenID Connect Provider in auth-verifier

| Field      | Value                                                             |
|------------|-------------------------------------------------------------------|
| **Status** | Accepted                                                          |
| **Date**   | 2026-08-11                                                        |
| **Branch** | `feat_oidc` (auth-verifier) / `auth_verifier_oidc` (kms)         |
| **Scope**  | Authentication Server + Cosmian KMS                               |

---

## Context

### Problem

Cosmian KMS operators require their KMS instances to support an
**OIDC Authorization Code + PKCE login flow** for end-users without depending on
a public cloud identity provider (Google, Azure AD, Auth0) or a heavyweight
on-premise identity stack (Keycloak, PingFederate).

Before this decision:

- The KMS UI and `ckms` CLI supported OIDC login only via external cloud IdPs
  configured under `[ui_oidc_auth]` in the KMS config.  Air-gapped deployments and
  organisations with strict data-sovereignty requirements could not use this flow.
- The `auth-verifier` server was already the on-premise identity backend for username/password
  authentication (`POST /login`) and issued session JWTs (`_ea_` cookie) used by the
  KMS middleware.  It maintained per-realm user accounts, Argon2-hashed credentials,
  TOTP, and RBAC roles — but it exposed **no OAuth 2.0 / OIDC endpoints**.
- Operators who wanted OIDC had to run a separate identity layer
  (e.g. Keycloak or Dex) and wire it to the auth-verifier through a custom integration,
  adding operational complexity, an extra failure domain, and synchronisation of user
  accounts across two systems.

### Requirements

1. Standard **OpenID Connect 1.0** compliance with mandatory **PKCE** (RFC 7636).
2. Issuance of **RFC 9068 `at+jwt` access tokens** so existing bearer-token relying
   parties (KMS, CLI) can validate them without protocol changes.
3. **Zero new infrastructure** — the OIDC OP must be part of the existing auth-verifier
   binary; no sidecar or external dependency.
4. **Security separation** between token types: ID tokens, access tokens, and session
   cookies must be cryptographically distinct and non-substitutable.
5. Backward compatibility — existing username/password sessions and bearer-token
   validation in the KMS must continue to work unchanged.
6. A **single config section** in the KMS server is sufficient to activate everything:
   bearer-token validation, UI OIDC flow, and CLI OIDC flow.

---

## Decision

### Decision 1 — Implement a full OIDC Authorization Server inside auth-verifier

A complete **OpenID Connect Provider (OP)** was added to auth-verifier under the
`/oidc/` path prefix.  The OP reuses the existing user store (SQLite / PostgreSQL),
realm model, and Argon2 credential store — no new data layer is required.

**Implemented grant types**: `authorization_code` (mandatory PKCE), `refresh_token`,
`client_credentials`.  Implicit and hybrid flows are **not** supported.

**Standards implemented**:

| RFC / Spec                   | Role                                          |
|------------------------------|-----------------------------------------------|
| RFC 6749                     | OAuth 2.0 Authorization Framework             |
| RFC 6750                     | Bearer token usage                             |
| RFC 7636                     | PKCE (S256 only — mandatory)                  |
| RFC 8414                     | Authorization Server Metadata (discovery)     |
| RFC 7662                     | Token introspection                            |
| RFC 7009                     | Token revocation                               |
| RFC 9068                     | JWT Profile for OAuth 2.0 Access Tokens       |
| RFC 7515 / 7517 / 7518 / 7519 | JOSE / JWK / JWA / JWT                      |
| OpenID Connect Core 1.0       | ID tokens, UserInfo, nonce, `at_hash`         |
| OpenID Connect Discovery 1.0  | `/.well-known/openid-configuration`           |

**New endpoints** (all under the `/oidc/` scope):

| Method    | Path                             | Purpose                          |
|-----------|----------------------------------|----------------------------------|
| GET       | `/.well-known/openid-configuration` | Discovery metadata            |
| GET       | `/oidc/jwks`                     | Combined JWKS (OIDC + session)  |
| GET       | `/oidc/authorize`                | Authorization endpoint           |
| POST      | `/oidc/authorize/login`          | Credential submission            |
| POST      | `/oidc/authorize/consent`        | Consent → redirect with code    |
| POST      | `/oidc/token`                    | Token endpoint                   |
| GET/POST  | `/oidc/userinfo`                 | UserInfo (`sub`, `email`, roles) |
| POST      | `/oidc/introspect`               | RFC 7662 introspection           |
| POST      | `/oidc/revoke`                   | RFC 7009 revocation              |

**Client management** is exposed to realm-admins at
`POST /realms/{realm_id}/clients` (same scope as user management).

### Decision 2 — Dedicated OIDC signing key with `kid`-based dispatch in KMS

The OIDC OP signs ID tokens and `at+jwt` access tokens with a **dedicated EC P-256
key** whose JWK `kid` is included in every token header.  This key is kept separate
from the session-JWT signing key.

The auth-verifier serves a **combined JWKS** at `/oidc/jwks` containing both keys.
The KMS `AuthVerifier` middleware was updated to dispatch on the `kid` header:

- **`kid` present** (OIDC `at+jwt` access token) → direct lookup via
  `JwksManager::find(kid)` with refresh-on-miss for key rotation.
- **No `kid`** (legacy session JWT) → existing try-all-keys fallback.

The KMS default JWKS URI was changed from `/.well-known/jwks.json`
(session key only) to `/oidc/jwks` (combined JWKS).

### Decision 3 — Single `[auth_verifier]` section auto-configures the KMS

To keep operator configuration minimal, the KMS server auto-populates the
`[ui_oidc_auth]` settings when `auth_verifier_oidc_client_id` is present in
`[auth_verifier]` and no explicit `[ui_oidc_auth]` section is set.

Minimal on-premise OIDC config:

```toml
[auth_verifier]
auth_verifier_url                = "https://auth.example.com"
auth_verifier_realm              = "kms"
auth_verifier_oidc_client_id     = "kms-client"
auth_verifier_oidc_client_secret = "s3cr3t"
```

The `accept_invalid_certs` flag is propagated to the OIDC discovery HTTP client
so that dev/test environments with self-signed certificates work without extra config.

---

## Consequences

### Positive

- **POS-001**: Operators in air-gapped or data-sovereign environments can now use a
  full OIDC login flow without any cloud dependency or additional infrastructure.
- **POS-002**: The KMS `auth_method` endpoint returns `"JWT"` when OIDC is active via
  auth-verifier, causing the UI to show the standard OIDC button — no UI code change
  required.
- **POS-003**: `ckms login cosmian --use-oidc` gives CLI users the same browser-based
  PKCE flow used by external IdPs, reusing all existing CLI login infrastructure.
- **POS-004**: `kid`-based key dispatch in the KMS middleware is faster than the
  previous try-all-keys loop and gracefully handles signing-key rotation.
- **POS-005**: The combined JWKS endpoint (`/oidc/jwks`) is a strict superset of the
  old `/.well-known/jwks.json`, so upgrading is backward-compatible.
- **POS-006**: OAuth 2.0 client management is exposed to realm-admins via the existing
  admin API — no new admin role or surface.

### Negative

- **NEG-001**: OIDC authorization codes and refresh tokens require new DB tables
  (`oauth_clients`, `oauth_codes`, `oauth_tokens`).  Schema migrations are applied
  automatically; existing deployments must allow the migration to run on first start.
- **NEG-002**: The OIDC authorize endpoint serves an HTML login/consent UI
  (browser-facing), which introduces a new surface for web-security concerns (CSRF,
  CSP, clickjacking).  A strict per-page Content-Security-Policy header is applied.
- **NEG-003**: PKCE is mandatory — public clients that cannot store a `code_verifier`
  are unsupported (intentional: mitigates auth-code interception).
- **NEG-004**: The combined JWKS URI change (`/oidc/jwks`) requires operators to
  update existing `auth_verifier_jwks_uri` overrides if they were pinned to
  `/.well-known/jwks.json`.  The old endpoint continues to work but contains only the
  session key.

---

## Alternatives Considered

### Keycloak / PingFederate (External Identity Provider)

- **ALT-001 Description**: Run Keycloak (or another enterprise IdP) alongside
  auth-verifier.  Federate auth-verifier users to Keycloak via LDAP or SAML.
  Configure the KMS `[ui_oidc_auth]` to point at Keycloak.
- **ALT-002 Rejection Reason**: Adds a heavyweight Java service (≥512 MB RAM, separate
  DB, admin console) with its own patching lifecycle.  Requires user-account
  synchronisation between two systems.  Unacceptable operational overhead for the
  target embedded/air-gapped deployment profile.

### Dex / Hydra (Lightweight OIDC Proxy)

- **ALT-003 Description**: Deploy [Dex](https://dexidp.io/) or
  [Ory Hydra](https://www.ory.sh/hydra/) as a thin OIDC proxy that delegates
  authentication back to auth-verifier over LDAP or an HTTP connector.
- **ALT-004 Rejection Reason**: Still introduces a second binary, a second config file,
  and a second failure domain.  The connector protocol between auth-verifier and the
  proxy would be custom and fragile.  Auth-verifier already holds all user data; adding
  a proxy layer is pure overhead.

### Auth0 / AWS Cognito / Azure AD (Cloud IdP)

- **ALT-005 Description**: Continue requiring operators to configure a cloud IdP.
  Provide better documentation and tooling for cloud IdP setup.
- **ALT-006 Rejection Reason**: Directly violates the data-sovereignty and air-gap
  requirements stated in the context.  User credentials and session metadata would be
  processed outside the operator's infrastructure.

### Static JWKS + Pre-issued Tokens (No Dynamic OIDC)

- **ALT-007 Description**: Skip the full OIDC OP; issue long-lived `at+jwt` tokens
  offline and distribute them to KMS clients.  Auth-verifier exposes only the JWKS
  for validation.
- **ALT-008 Rejection Reason**: No revocation, no token refresh, no dynamic client
  registration.  Incompatible with browser-based login flows and unacceptable for
  production use where credential rotation is required.

---

## Implementation Notes

- **IMP-001**: The OIDC state (`OidcState`) is built once at startup from
  `oidc_params` in the server config.  When `oidc_params` is omitted, the server falls
  back to the session/TLS signing key with a logged warning.  Configure a dedicated key
  in production via `oidc_params.oidc_signing_private_key`.
- **IMP-002**: Authorization codes are single-use and expire after `code_ttl_secs`
  (default 60 s).  Refresh tokens expire after `refresh_token_ttl_secs` (default 14 days).
  Both are stored in the database and cleaned up by the existing stale-session collector.
- **IMP-003**: The OIDC `issuer` value must match the URL clients use to call the
  discovery endpoint.  Set it explicitly via `oidc_params.issuer`; the default is
  derived from `host_name`:`host_port` + TLS presence, which may not be routable from
  browser clients in NAT/proxy setups.
- **IMP-004**: The KMS OIDC discovery fetch inherits `accept_invalid_certs` from
  `auth_verifier_accept_invalid_certs` when OIDC is auto-configured from
  `[auth_verifier]`.  Never set this flag in production.
- **IMP-005**: KMS bearer-token validation uses the combined JWKS at `/oidc/jwks` by
  default (new default since this ADR).  Operators who pinned `auth_verifier_jwks_uri`
  to `/.well-known/jwks.json` must update their config to include the OIDC signing key.
- **IMP-006**: Success metrics — OIDC login latency, token issuance/revocation counts,
  and authorization-code expiry rates are logged at `INFO` level.  Instrument these
  with the existing OTLP exporter for production monitoring.

---

## References

- **REF-001**: [ADR-0001 — Role / JWT / OPA integration](2026-06-24-role-jwt-opa-integration.md)
- **REF-002**: [ADR-0002 — AppRole-Compatible Auth API for SPIRE](2026-07-26-app-auth-api-for-spire.md)
- **REF-003**: [OpenID Connect Provider documentation](../oidc.md)
- **REF-004**: RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
  <https://datatracker.ietf.org/doc/html/rfc9068>
- **REF-005**: RFC 7636 — PKCE for OAuth 2.0
  <https://datatracker.ietf.org/doc/html/rfc7636>
- **REF-006**: RFC 8414 — OAuth 2.0 Authorization Server Metadata
  <https://datatracker.ietf.org/doc/html/rfc8414>
- **REF-007**: OIDC endpoints — `server/src/server/endpoints/oidc/`
- **REF-008**: OIDC state builder — `server/src/oidc/mod.rs`
- **REF-009**: KMS `AuthVerifier` middleware — `crate/server/src/middlewares/auth_verifier/token.rs`
- **REF-010**: KMS `[auth_verifier]` config — `crate/server/src/config/command_line/auth_verifier_config.rs`
- **REF-011**: KMS auto-populate logic — `crate/server/src/config/params/server_params.rs`
- **REF-012**: Test config — `test_data/configs/server/oidc.toml`
