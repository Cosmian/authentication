# Data Flow Diagram — Cosmian Authentication Verifier

## Level 0 — System Context

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000
    classDef semitrusted fill:#fff3cd,stroke:#cc8800
    classDef trusted fill:#d4edda,stroke:#008800
    classDef datastore fill:#cce5ff,stroke:#0066cc

    subgraph Internet["Internet / LAN (Untrusted)"]
        Browser["Browser\n(Admin UI / login form)"]:::untrusted
        KMS["KMS Server\n(BFF proxy)"]:::untrusted
        SPIRE["SPIRE / K8s workload\n(AppRole / K8s JWT)"]:::untrusted
    end

    subgraph AuthVerifier["Auth Verifier Server (Trusted)"]
        HTTP["TLS / HTTP Layer\nActix-web"]:::trusted
        MW["Middleware Stack\n(ExtractRealm → UsernamePassword/JWT →\nCookieAuth → AdminAuth → EnsureAuth)"]:::semitrusted
        Endpoints["Endpoints\n(/login, /whoami, /sessions,\n/admins, /auth/approle, /auth/kubernetes,\n/.well-known/jwks.json)"]:::trusted
        JWT["JWT Session\nIssuance & Validation\n(EC P-256 / ES256)"]:::trusted
    end

    DB[("Database\n(SQLite / PostgreSQL / MySQL)\nCredentials, Sessions,\nAppRoles, K8s Roles")]:::datastore
    ExtIdP["External IdP\n(OIDC / JWKS endpoint)"]:::untrusted

    Browser -.->|"HTTPS: POST /login\n(Basic Auth credentials)"| HTTP
    KMS -.->|"HTTP (internal): /sessions\n(session CRUD — NO AUTH)"| HTTP
    KMS -.->|"HTTP: GET /.well-known/jwks.json"| HTTP
    SPIRE -.->|"HTTP: POST /auth/approle/login\nor /auth/kubernetes/login"| HTTP
    HTTP --> MW
    MW --> Endpoints
    Endpoints --> JWT
    Endpoints <-->|"SQL"| DB
    JWT <-->|"SQL: session store"| DB
    HTTP ==>|"HTTPS: fetch JWKS"| ExtIdP
```

## Level 1 — User Login Flow (POST /login)

```mermaid
flowchart TD
    classDef untrusted fill:#ffd6d6,stroke:#cc0000
    classDef semitrusted fill:#fff3cd,stroke:#cc8800
    classDef trusted fill:#d4edda,stroke:#008800
    classDef datastore fill:#cce5ff,stroke:#0066cc

    Client["Browser / KMS BFF\n(Basic Auth header)"]:::untrusted
    TLS["TLS Termination\nauth_verifier.rs"]:::trusted
    CORS["Cors::permissive()\n⚠ all origins allowed"]:::semitrusted
    ExtRealm["ExtractRealm\nextract_realm.rs\nLooks up realm in DB"]:::semitrusted
    UserPassMW["UsernamePasswordAuth\nusername_password.rs\nValidates Argon2 hash"]:::semitrusted
    JwtMW["JwtAuth\njwt_middleware.rs\n(if realm has jwt_params)"]:::semitrusted
    EnsureMW["EnsureAuth\nensure_auth.rs\nRejects if not authenticated"]:::semitrusted
    Login["login() handler\nclient_endpoints.rs"]:::trusted
    TOTP["TOTP validation\n(if enabled for user)"]:::trusted
    IssueToken["issue_token()\nsession/jwt.rs\nES256 JWT, exp=session_max_age"]:::trusted
    BuildCookie["build_cookie()\nSecure; HttpOnly; SameSite=Strict"]:::trusted
    StoreSession["session_store.upsert_session()\ncookie stored in DB"]:::trusted
    DB[("Session Store\n(DB)")]:::datastore

    Client -.->|"POST /login\nAuthorization: Basic <b64>"| TLS
    TLS --> CORS
    CORS --> ExtRealm
    ExtRealm -->|"Realm injected"| UserPassMW
    UserPassMW -->|"AuthenticatedClientScheme injected"| JwtMW
    JwtMW --> EnsureMW
    EnsureMW -->|"authenticated"| Login
    Login --> TOTP
    TOTP -->|"valid"| IssueToken
    IssueToken --> BuildCookie
    BuildCookie --> StoreSession
    StoreSession -->|"INSERT session"| DB
    StoreSession -->|"200 OK + Set-Cookie: _ea_=<JWT>"| Client
```

## Level 2 — AppRole Login Flow (POST /auth/approle/login)

```mermaid
flowchart TD
    classDef untrusted fill:#ffd6d6,stroke:#cc0000
    classDef trusted fill:#d4edda,stroke:#008800
    classDef datastore fill:#cce5ff,stroke:#0066cc

    SPIRE["SPIRE / CI agent\n{role_id, secret_id}"]:::untrusted
    TLS["TLS / HTTP Layer"]:::trusted
    Handler["approle_login()\napprole.rs"]:::trusted
    LookupRole["DB: get_approle_by_role_id()"]:::trusted
    ConsumeSecret["DB: consume_secret_id()\nSHA-256 hash compare + decrement num_uses"]:::trusted
    IssueToken["issue_app_token()\nraw token returned once"]:::trusted
    DB[("Database\n(AppRoles, SecretIDs, Tokens)")]:::datastore

    SPIRE -.->|"POST /auth/approle/login\n{role_id, secret_id}"| TLS
    TLS --> Handler
    Handler -->|"SHA-256(role_id) lookup"| LookupRole
    LookupRole --> DB
    Handler -->|"SHA-256(secret_id) lookup + consume"| ConsumeSecret
    ConsumeSecret --> DB
    ConsumeSecret -->|"success"| IssueToken
    IssueToken --> DB
    IssueToken -->|"200 OK: {auth: {client_token: <token>}}"| SPIRE
```

## Level 3 — Sessions API (unauthenticated — ⚠ CRITICAL trust boundary gap)

```mermaid
flowchart TD
    classDef untrusted fill:#ffd6d6,stroke:#cc0000
    classDef trusted fill:#d4edda,stroke:#008800
    classDef danger fill:#ff4444,stroke:#990000,color:#fff
    classDef datastore fill:#cce5ff,stroke:#0066cc

    KMS["KMS Server\n(legitimate caller)"]:::trusted
    Attacker["Attacker\n(any network client)"]:::untrusted
    SessionsScope["/sessions scope\n⚠ NO AUTH MIDDLEWARE\nonly Cors::permissive() + ExtractRealm"]:::danger
    SessionStore[("Session Store\nstores: realm, user identity,\ncookie_string (contains JWT)")]:::datastore

    KMS -.->|"POST /sessions (upsert)\nGET /sessions/{id}\nDELETE /sessions"| SessionsScope
    Attacker -.->|"Same endpoints\nno credentials required"| SessionsScope
    SessionsScope <-->|"SQL"| SessionStore
```

## Notes

- The `/sessions` scope (Level 3) has **no authentication middleware** — this is the most critical architectural gap in the current system. It is assumed to be an internal-only API, but there is no network-level or application-level enforcement.
- `Cors::permissive()` is applied on every scope including admin endpoints. The TODO comment at `auth_verifier.rs:324` acknowledges this is not yet tightened.
- In dev mode (no TLS), `Secure` cookies are set but browsers will not send them back over plain HTTP, making the `reqwest`-based test work (it ignores the `Secure` flag) while real browsers would not.
- The JWKS endpoint (`/.well-known/jwks.json`) is unauthenticated and public by design (OIDC standard). It has a 1-hour `Cache-Control` header.
