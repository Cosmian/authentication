# Authentication Flows

This document describes the complete authentication flows supported by the Auth authentication server: cookie-based session authentication, JWT bearer authentication, and client-certificate authentication.

---

## Overview

The authentication server sits in front of your application. Every **client** must prove its identity to the auth server before it can access any protected resource. Once authenticated, the server issues a **session cookie** (`_ea_`) that the client presents on subsequent API requests.

```text
Client ──► Auth Server ──► Session Cookie ──► Your API ──► Services
```

> **Terminology note:** Throughout this documentation, **client** means any entity that authenticates against the `/login` endpoint — a human via browser, the Auth CLI, or a machine/service account. An **Admin** (capitalised) is a database record representing an administrator account (super admin or realm admin). See [index.md](index.md#terminology) for the full glossary.

All communication uses **HTTPS** (TLS). Session cookies carry a plain-text `cookie_string` that is the session identifier stored in the server-side session store.

---

## Realms

Every authentication operation is scoped to a **realm**. A realm is an isolated authentication domain with its own:

- Session lifetime settings
- Authentication parameters (which methods are allowed, TOTP requirements, etc.)

The special `_` realm (called `ADMIN_REALM`) is the administrative realm. All administrator clients authenticate through this realm.

---

## Flow 1 — Username / Password (Cookie Session)

This is the most common flow for clients (human or automated) such as web browsers or the Auth CLI.

### Happy-path sequence

```mermaid
sequenceDiagram
    autonumber
    participant U as Client / Browser
    participant EA as Auth Server
    participant SS as Session Store
    participant API as Your API

    U->>EA: POST /login?realm={realm}<br/>{"username":"alice","password":"secret"}
    note over EA: EnsureAuth middleware validates credentials<br/>against the userpass table (Argon2id)
    EA->>SS: upsert_session(session_id, realm, claims, cookie_string)
    SS-->>EA: OK
    EA-->>U: 200 OK<br/>Set-Cookie: _ea_=<cookie_string><br/>{"session_id":"…", "next_step":"Authenticated"}

    U->>API: GET /api/resource<br/>Cookie: _ea_=<cookie_string>
    note over API: CookieAuthSameServer middleware<br/>1. Extracts cookie_string from _ea_ cookie<br/>2. Looks up session in store by cookie_string<br/>3. Returns SessionData claims to handler
    API->>EA: (internal) find_users_by_auth_scheme
    EA-->>API: Admin{id, realms, …}
    API-->>U: 200 OK  {"data": …}
```

### What the session cookie contains

The `_ea_` cookie value is a plain-text `cookie_string`. All session state is kept server-side in the session store. The `cookie_string` is used as a lookup key to retrieve the full `SessionData` record:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | `String` | Unique session identifier (UUID) |
| `realm_id` | `String` | Realm the session belongs to |
| `username` | `String` | Authenticated client username |
| `auth_scheme` | `String` | Authentication method used (`userpass`, `jwt`, `cert`) |
| `cookie_string` | `String` | The opaque value stored in the `_ea_` cookie |
| `max_age_seconds` | `i64` | Maximum absolute session lifetime |
| `max_stale_age_seconds` | `i64` | Maximum idle time before the session is considered stale |
| `created_at` | `i64` | Unix timestamp when the session was created |

### Credential validation

Passwords are hashed with **Argon2id** using a per-user salt:

```text
salt  = SHA-256(lowercase(username))  → base64url
hash  = Argon2id(password, salt, memory=19456, iterations=2, parallelism=1)
```

The hash is stored in the `userpass` table. On login, the server recomputes the hash and compares it in constant time.

---

## Flow 2 — Username / Password with 2FA (TOTP)

When a client's account has TOTP enabled, the login sequence requires a second step.

### Sequence with TOTP

```mermaid
sequenceDiagram
    autonumber
    participant U as Client / Browser
    participant App as Authenticator App
    participant EA as Auth Server
    participant SS as Session Store

    U->>EA: POST /login?realm={realm}<br/>{"username":"alice","password":"secret"}
    note over EA: Primary credentials valid
    EA->>EA: is_totp_enabled(realm, alice) → true
    EA-->>U: 200 OK<br/>{"next_step":"TotpRequired", "session_id":null}

    U->>App: Read current TOTP code
    App-->>U: "482913"

    U->>EA: POST /login?realm={realm}<br/>{"username":"alice","password":"secret","totp_code":"482913"}
    note over EA: TOTP token validated against stored secret
    EA->>SS: upsert_session(…)
    SS-->>EA: OK
    EA-->>U: 200 OK<br/>Set-Cookie: _ea_=<cookie_string><br/>{"next_step":"Authenticated"}
```

> **Note:** The `next_step` field in the response tells the client what to do next:
>
> - `"Authenticated"` — login complete, cookie issued
> - `"TotpRequired"` — provide a TOTP code to proceed

See [two_factor_authentication.md](two_factor_authentication.md) for the full TOTP enrollment and management flows.

---

## Flow 3 — JWT Bearer Token

Machine-to-machine scenarios (service accounts, CI pipelines, SDKs) use RS256 or ES256 JWT tokens instead of cookies.

### Sequence

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (Service)
    participant IDP as External Identity Provider
    participant EA as Auth Server
    participant API as Your API
    participant SS as Session Store

    C->>IDP: Request JWT (RS256/ES256)
    note over IDP: Signs JWT with private key<br/>sub=client_id, aud=api_audience
    IDP-->>C: Bearer eyJhbG…

    C->>API: GET /api/resource<br/>Authorization: Bearer eyJhbG…
    note over API: JwtAuth middleware
    API->>EA: GET /public/jwks  (key discovery)
    EA-->>API: JWKS (public keys)
    note over API: Validates JWT signature + exp + aud
    API->>SS: upsert_session(jwt_claims)
    SS-->>API: session_id
    API-->>C: 200 OK  {"data": …}
```

### Key discovery

The server exposes a JWKS endpoint at `GET /public/jwks` which returns the RSA/EC public keys used to verify tokens. The JWT middleware caches this document and refreshes it on a configurable interval.

### JWT requirements

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | Subject (user or service identifier) |
| `aud` | Yes | Must match the configured audience |
| `exp` | Yes | Expiration time (Unix seconds) |
| `iss` | Yes | Issuer URL matching JWKS discovery URL |

---

## Flow 4 — Client Certificate (mTLS)

For high-assurance scenarios, clients authenticate using an EC P-256 client certificate over mutual TLS.

### Sequence

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant EA as Auth Server (TLS)
    participant SS as Session Store
    participant API as Your API

    note over C,EA: TLS handshake — client presents certificate
    C->>EA: POST /login?realm={realm}  (+ client cert in TLS layer)
    note over EA: extract_peer_certificate middleware<br/>extracts DN from certificate
    EA->>EA: Validate certificate chain against CA
    EA->>SS: upsert_session(cert_subject_claims)
    SS-->>EA: OK
    EA-->>C: 200 OK<br/>Set-Cookie: _ea_=<cookie_string>

    C->>API: GET /api/resource<br/>Cookie: _ea_=<cookie_string>
    API-->>C: 200 OK  {"data": …}
```

---

## Session Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Active : POST /login (credentials valid)
    Active --> Active : Any authenticated request<br/>(resets stale timer)
    Active --> Expired : session_max_age_seconds elapsed
    Active --> Revoked : DELETE /sessions/session (explicit logout)
    Expired --> [*] : Stale-session collector removes it
    Revoked --> [*] : Immediately rejected by CookieAuthSameServer
```

### Session parameters (per realm)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `session_max_age_seconds` | 3600 | Maximum absolute lifetime of a session |
| `session_max_stale_age_seconds` | 3600 | Maximum idle time before a session is considered stale |

Sessions are stored in the configured session backend (SQLite / PostgreSQL / MySQL / Redis).

### Explicit logout

To invalidate a session:

```http
DELETE /sessions/session
Content-Type: application/json

{"session_ids": ["<session_id>"]}
```

Administratively, a super admin can revoke all sessions for a realm:

```http
DELETE /sessions/session/realms/{realm_id}
```

---

## API Endpoint Reference

### Authentication endpoints

| Method | Path | Description | Auth required |
|--------|------|-------------|---------------|
| `POST` | `/login?realm={realm}` | Authenticate and issue a session cookie | No (credentials in body) |
| `GET` | `/whoami?realm={realm}` | Return the current session's claims | Session cookie |
| `GET` | `/public/version` | Server version string | No |
| `GET` | `/public/jwks` | JSON Web Key Set for JWT verification | No |

### Session management endpoints

| Method | Path | Description | Auth required |
|--------|------|-------------|---------------|
| `GET` | `/sessions/session/{id}` | Retrieve `SessionData` by session ID (`null` when not found) | — |
| `POST` | `/sessions/session/{id}` | Retrieve `SessionData` and optionally apply a `SessionsAction` | — |
| `POST` | `/sessions/session/realms/{realm}/admins` | Get `SessionData` list for a set of users | — |
| `DELETE` | `/sessions/session` | Delete sessions by ID list (logout) | — |
| `DELETE` | `/sessions/session/expired` | Purge all expired sessions | — |
| `DELETE` | `/sessions/session/realms/{realm}` | Revoke all sessions for a realm | — |

---

## Session Actions on `POST /sessions/session/{id}`

When fetching a session you can pass an optional `sessions_action` in the request body to perform a bulk logout as part of the same call. This is the recommended way to implement "log out everywhere else" and "log out everywhere" features.

### Request body

```json
{
  "authenticated_clients": [
    { "username": "alice", "auth_scheme": "UsernamePassword" }
  ],
  "sessions_action": "LogoutOtherSessions"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `authenticated_clients` | `Vec<AuthenticatedClientScheme>` | Users whose sessions should be affected by the action |
| `sessions_action` | `SessionsAction` (optional) | Action to perform; omit for a plain session lookup |

### `SessionsAction` variants

| Variant | Behaviour |
|---------|-----------|
| `LogoutOtherSessions` | Deletes all active sessions for the given clients **except** the session being queried. Use this to implement "keep this session, log out everywhere else". |
| `LogoutAllSessions` | Deletes **all** active sessions for the given clients, including the queried session. The session data is returned before deletion. Use this to implement "log out everywhere". |

### Sequence — `LogoutOtherSessions`

```mermaid
sequenceDiagram
    autonumber
    participant U as Client
    participant EA as Auth Server
    participant SS as Session Store

    U->>EA: POST /sessions/session/{session_a}<br/>{sessions_action: "LogoutOtherSessions", authenticated_clients: [...]}
    EA->>SS: get_session(session_a)
    SS-->>EA: SessionData for session_a
    EA->>SS: get_sessions_for_clients(authenticated_clients)
    SS-->>EA: [session_a, session_b, session_c]
    EA->>SS: delete_sessions([session_b, session_c])
    SS-->>EA: OK
    EA-->>U: 200 OK  SessionData for session_a
    note over U: session_a still valid<br/>session_b, session_c invalidated
```

### Sequence — `LogoutAllSessions`

```mermaid
sequenceDiagram
    autonumber
    participant U as Client
    participant EA as Auth Server
    participant SS as Session Store

    U->>EA: POST /sessions/session/{session_a}<br/>{sessions_action: "LogoutAllSessions", authenticated_clients: [...]}
    EA->>SS: get_session(session_a)
    SS-->>EA: SessionData for session_a
    EA->>SS: get_sessions_for_clients(authenticated_clients)
    SS-->>EA: [session_a, session_b, session_c]
    EA->>SS: delete_sessions([session_a, session_b, session_c])
    SS-->>EA: OK
    EA-->>U: 200 OK  SessionData for session_a (returned before deletion)
    note over U: all sessions invalidated
```

---

## Request Authentication Decision Diagram

The following shows how the middleware stack decides whether to admit or reject an incoming request:

```mermaid
flowchart TD
    A[Incoming request] --> B{Has session cookie?}
    B -- No --> C{Has Bearer token?}
    B -- Yes --> D[CookieAuthSameServer]
    D --> G{Session found\nin store by cookie_string?}
    G -- No --> F[401 Unauthorized]
    G -- Yes --> H[SessionData → ClientClaims injected]
    H --> I{UserAuth required?}
    I -- Yes --> J[DB lookup: find_users_by_auth_scheme]
    J --> K{Admin record exists?}
    K -- No --> F
    K -- Yes --> L[Admin injected → handler runs]
    I -- No --> M[Handler runs with claims only]

    C -- No --> N{Has Basic Auth header?}
    C -- Yes --> O[JwtAuth middleware]
    O --> P{JWT sig + exp + aud valid?}
    P -- No --> F
    P -- Yes --> H
    N -- No --> F
    N -- Yes --> Q[UsernamePasswordAuth]
    Q --> R{Argon2id hash matches?}
    R -- No --> F
    R -- Yes --> H
```

---
