# API Reference

Complete reference for all HTTP endpoints exposed by the Authentication Verifier.

All endpoints are served over **HTTPS only**. The base URL is `https://{host}:{port}`.

---

## Table of Contents

- [Public Endpoints](#public-endpoints)
- [Authentication — Login and Session Claims](#authentication--login-and-session-claims)
- [Session Management](#session-management)
- [Machine Authentication (AppRole / Kubernetes / Token)](#machine-authentication-approle--kubernetes--token)
- [Realm Administration](#realm-administration)
- [Admin Administration](#admin-administration)
- [Credential Management](#credential-management)
- [TOTP Management](#totp-management)
- [Common Response Codes](#common-response-codes)
- [Authentication for Admin Endpoints](#authentication-for-admin-endpoints)
- [Data Types](#data-types)

---

## Public Endpoints

No authentication required.

### `GET /public/version`

Returns the server version string.

#### Response

```text
HTTP/1.1 200 OK
Content-Type: text/plain

"0.1.2"
```

---

### `GET /.well-known/jwks.json`

Returns the JSON Web Key Set containing the server's public key(s) for JWT signature verification.

> **Note:** Only available in test builds. Production deployments expose JWKS through the Identity Provider's own JWKS endpoint.

#### Response

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "use": "sig"
    }
  ]
}
```

---

## Authentication — Login and Session Claims

### `POST /login?realm={realm_id}`

Authenticate a client and issue a session cookie. The authentication method is determined by the `Authorization` header or the request body.

**Authentication methods:**

| Method             | How to supply credentials                          |
| ------------------ | -------------------------------------------------- |
| Username/Password  | `Authorization: Basic <base64(username:password)>` |
| JWT Bearer         | `Authorization: Bearer <jwt_token>`                |
| Client Certificate | Client certificate in TLS handshake                |

#### Request body (optional — for the TOTP code)

```json
{
  "totp_code": "482913"
}
```

| Field       | Type               | Description                          |
| ----------- | ------------------ | ------------------------------------ |
| `totp_code` | `String` \| `null` | TOTP verification code for 2FA step  |

**Response — `200 OK`**

```json
{
  "next_step": "Authenticated",
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Set-Cookie header: `_ea_=<cookie_string>; HttpOnly; Secure; SameSite=Strict`

| Field        | Type                                                        | Description                                                 |
| ------------ | ----------------------------------------------------------- | ----------------------------------------------------------- |
| `next_step`  | `"Authenticated"` \| `"TotpRequired"` \| `"ChangePassword"` | What the client should do next                              |
| `session_id` | `String` \| `null`                                          | UUID of the new session (only present when `Authenticated`) |

**Response — `401 Unauthorized`** — credentials invalid or missing.

**Response — `200 OK` with `"next_step": "TotpRequired"`** — primary credentials valid but TOTP code is required. Re-submit the request with `totp_code`.

---

### `GET /whoami?realm={realm_id}`

Returns the JWT claims for the currently authenticated session.

**Authentication:** Session cookie (`_ea_` cookie).

**Response — `200 OK`**

```json
{
  "iss": "auth-auth",
  "sub": "alice",
  "aud": ["my-service"],
  "exp": 1745000000,
  "iat": 1744996400,
  "as_as": "up",
  "as_rid": "my-service"
}
```

See [Data Types — ClientClaims](#clientclaims) for the full field reference.

**Response — `401 Unauthorized`** — no valid session cookie.

---

## Session Management

### `GET /sessions/{session_id}`

Retrieve session data by session ID. Returns `null` (not an error) when the session does not exist or has expired.

**Response — `200 OK`** (session found)

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "realm_id": "my-service",
  "username": "alice",
  "auth_scheme": "up",
  "cookie_string": "eyJ…",
  "max_age_seconds": 3600,
  "max_stale_age_seconds": 1800,
  "created_at": 1744996400
}
```

**Response — `200 OK`** (session not found)

```json
null
```

---

### `POST /sessions/{session_id}`

Retrieve session data and optionally apply a bulk logout action in the same request.

#### Request body

```json
{
  "authenticated_clients": [
    { "username": "alice", "auth_scheme": "UsernamePassword" }
  ],
  "sessions_action": "LogoutOtherSessions"
}
```

| Field                   | Type                                                       | Description                            |
| ----------------------- | ---------------------------------------------------------- | -------------------------------------- |
| `authenticated_clients` | `AuthenticatedClientScheme[]`                              | Clients whose sessions may be affected |
| `sessions_action`       | `"LogoutOtherSessions"` \| `"LogoutAllSessions"` \| `null` | Action to perform alongside the lookup |

**`sessions_action` values:**

| Value                   | Effect                                                                                                              |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `"LogoutOtherSessions"` | Delete all sessions for the given clients **except** the queried one                                                |
| `"LogoutAllSessions"`   | Delete **all** sessions for the given clients (including the queried one); session data is returned before deletion |

**Response — `200 OK`** — same shape as `GET /sessions/{id}`.

---

### `POST /sessions/realms/{realm_id}/clients`

Return all session IDs for a set of authenticated clients in a realm.

#### Request body

```json
[
  { "username": "alice", "auth_scheme": "UsernamePassword" },
  { "username": "alice", "auth_scheme": "Jwt" }
]
```

**Response — `200 OK`**

```json
{
  "session_ids": [
    "550e8400-e29b-41d4-a716-446655440000",
    "660f9511-f3ac-52e5-c827-557766551111"
  ]
}
```

---

### `DELETE /sessions`

Delete sessions by ID.

#### Request body

```json
{
  "session_ids": [
    "550e8400-e29b-41d4-a716-446655440000"
  ]
}
```

**Response — `204 No Content`** — empty body.

---

### `DELETE /sessions/expired`

Delete all expired sessions from the session store.

**Response — `204 No Content`** — empty body.

---

### `DELETE /sessions/realms/{realm_id}`

Delete all sessions for a given realm (administrative bulk logout).

**Response — `204 No Content`** — empty body.

---

## Machine Authentication (AppRole / Kubernetes / Token)

Endpoints for machine-to-machine authentication. These sit under the `/auth/` prefix. Login endpoints are **unauthenticated** (the credential is the request body). Role management endpoints require an active admin session cookie. Token self-service endpoints require a valid `X-Vault-Token` header.

For complete request/response examples and field descriptions see [app_auth_api.md](app_auth_api.md).

### `POST /auth/approle/login`

Exchange a `role_id` + `secret_id` pair for an opaque app token. Also accepts `PUT` (SPIRE compatibility).

#### Request body

```json
{
  "role_id": "a5d7e2f1-0c3b-4a8d-9e6f-1234567890ab",
  "secret_id": "b7c4e9d2-1a2b-4c3d-8e5f-fedcba987654"
}
```

`secret_id` is optional when the role has `bind_secret_id: false`.

#### Response — `200 OK`

```json
{
  "auth": {
    "client_token": "hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob",
    "renewable": true,
    "lease_duration": 3600,
    "policies": ["default"],
    "metadata": { "role_name": "spire-server" }
  }
}
```

**Error responses:** `400 Bad Request` (invalid role_id or secret_id), `403 Forbidden` (secret_id exhausted).

---

### `POST /auth/approle/role/{name}`

Create or update an AppRole role. Requires admin session cookie.

#### Path parameter

`name` — role name (unique identifier for this role)

#### Request body

```json
{
  "token_ttl": 3600,
  "secret_id_ttl": 86400,
  "token_policies": ["default"],
  "bind_secret_id": true
}
```

| Field            | Type    | Default | Description |
|------------------|---------|---------|-------------|
| `token_ttl`      | integer | 3600    | Token lifetime in seconds |
| `secret_id_ttl`  | integer | 0       | Secret ID lifetime in seconds; `0` = no expiry |
| `token_policies` | array   | `[]`    | Policies attached to every issued token |
| `bind_secret_id` | boolean | true    | If `false`, login succeeds with `role_id` alone |

**Response — `204 No Content`**

---

### `GET /auth/approle/role/{name}/role-id`

Read the stable `role_id` for a role. Requires admin session cookie.

#### Response — `200 OK`

```json
{ "data": { "role_id": "a5d7e2f1-0c3b-4a8d-9e6f-1234567890ab" } }
```

---

### `POST /auth/approle/role/{name}/secret-id`

Generate a new `secret_id` for a role. Requires admin session cookie.

#### Request body

```json
{ "ttl": 0, "num_uses": 1 }
```

| Field      | Type    | Default | Description |
|------------|---------|---------|-------------|
| `ttl`      | integer | 0       | Per-secret-ID TTL override in seconds; `0` = use role default |
| `num_uses` | integer | 0       | Max login uses; `0` = unlimited |

#### Response — `200 OK`

```json
{
  "data": {
    "secret_id": "b7c4e9d2-1a2b-4c3d-8e5f-fedcba987654",
    "secret_id_accessor": "9f8e7d6c-5b4a-3c2d-1e0f-abcdef012345"
  }
}
```

Save the `secret_id` — it cannot be retrieved again. Use the `secret_id_accessor` to destroy it without knowing the value.

---

### `POST /auth/approle/role/{name}/secret-id/destroy`

Invalidate a `secret_id` by its accessor. Requires admin session cookie.

#### Request body

```json
{ "secret_id_accessor": "9f8e7d6c-5b4a-3c2d-1e0f-abcdef012345" }
```

**Response — `204 No Content`**

---

### `DELETE /auth/approle/role/{name}`

Delete a role and all its secret IDs (cascade). Requires admin session cookie.

**Response — `204 No Content`**

---

### `GET /auth/approle/role?list=true`

List all AppRole role names. Requires admin session cookie.

#### Response — `200 OK`

```json
{ "data": { "keys": ["spire-server", "mistral-agents"] } }
```

---

### `POST /auth/kubernetes/login`

Exchange a Kubernetes service-account JWT for an app token.

#### Request body

```json
{
  "role": "my-k8s-role",
  "jwt": "<service-account JWT from /var/run/secrets/kubernetes.io/serviceaccount/token>"
}
```

#### Response — `200 OK`

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

**Error responses:** `400 Bad Request` (invalid JWT or role), `403 Forbidden` (SA name / namespace not in allow-list).

---

### `POST /auth/kubernetes/role/{name}`

Create or update a Kubernetes auth role. Requires admin session cookie.

#### Request body

```json
{
  "jwks_url": "https://kubernetes.default.svc/.well-known/jwks.json",
  "bound_service_account_names": ["my-app"],
  "bound_service_account_namespaces": ["production"],
  "token_ttl": 3600
}
```

| Field | Type | Description |
|-------|------|-------------|
| `jwks_url` | string | URL of the Kubernetes JWKS endpoint |
| `bound_service_account_names` | array | Allowed SA names; `["*"]` = any |
| `bound_service_account_namespaces` | array | Allowed namespaces; `["*"]` = any |
| `token_ttl` | integer | Token lifetime in seconds |
| `expected_issuer` | string (optional) | If set, validates JWT `iss` claim |
| `bound_audiences` | array (optional) | If set, validates JWT `aud` claim |

**Response — `204 No Content`**

---

### `DELETE /auth/kubernetes/role/{name}`

Delete a Kubernetes role. Requires admin session cookie.

**Response — `204 No Content`**

---

### `GET /auth/token/lookup-self`

Validate an app token and return its metadata.

#### Request header

```http
X-Vault-Token: hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob
```

#### Response — `200 OK`

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

**Error response:** `403 Forbidden` — token missing, invalid, expired, or revoked.

---

### `POST /auth/token/renew-self`

Extend a renewable token's TTL back to its configured `lease_duration`.

#### Request header

```http
X-Vault-Token: hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob
```

#### Response — `200 OK`

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

**Error response:** `403 Forbidden` — token not found, expired, or not renewable.

---

### `POST /auth/token/revoke-self`

Immediately invalidate the current token.

#### Request header

```http
X-Vault-Token: hvs.AAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRob
```

**Response — `204 No Content`**

---

## Realm Administration

Realm CRUD endpoints live under `/admins/realms`. Creating, updating, and deleting realms requires **super admin** privileges. Listing and getting a single realm is accessible to any authenticated admin (filtered to their administered realms).

### `POST /admins/realms`

Create a new realm. Super admin only.

#### Request body

```json
{
  "id": "my-service",
  "auth_params": {
    "username_password_params": {
      "allow_expired_passwords": false
    }
  },
  "session_max_age_seconds": 3600,
  "session_max_stale_age_seconds": 1800
}
```

**Response — `201 Created`** — created `Realm` object.

**Response — `409 Conflict`** — realm ID already exists.

---

### `GET /admins/realms/{realm_id}`

Retrieve a realm by ID. Realm admins may only retrieve realms they administer.

**Response — `200 OK`**

```json
{
  "id": "my-service",
  "auth_params": { "username_password_params": { "allow_expired_passwords": false } },
  "session_max_age_seconds": 3600,
  "session_max_stale_age_seconds": 1800
}
```

**Response — `404 Not Found`** — realm does not exist.

---

### `PUT /admins/realms/{realm_id}`

Replace a realm's configuration. Super admin only. Returns the updated realm.

#### Request body — same shape as `POST /admins/realms`

**Response — `200 OK`** — updated `Realm` object.

---

### `DELETE /admins/realms/{realm_id}`

Delete a realm and all associated data. Super admin only.

**Response — `204 No Content`** — empty body.

---

### `GET /admins/realms`

List all realms. Super admins see all realms; realm admins see only their administered realms.

**Response — `200 OK`**

```json
[
  {
    "id": "_",
    "auth_params": {},
    "session_max_age_seconds": 3600,
    "session_max_stale_age_seconds": 3600
  },
  {
    "id": "my-service",
    ...
  }
]
```

---

### `GET /admins/userpass`

List all username/password credentials across every realm. Super admin only.

**Response — `200 OK`** — array of `UserPass` objects. The `password` field is always returned as an empty byte array.

---

## Admin Administration

### `POST /admins`

Create a new `Admin` record. Super admins may create any admin. Realm admins may create an admin only if every realm in the new admin's `realms` list is one they administer.

#### Request body

```json
{
  "id": "bob",
  "realms": ["my-service"],
  "userpass": "bob",
  "jwt": null,
  "fido2": null,
  "digital_credentials": null,
  "client_certificate": null,
  "totp_enabled": false,
  "totp_secret": null,
  "totp_auth_url": null
}
```

| Field                 | Type               | Description                                                |
| --------------------- | ------------------ | ---------------------------------------------------------- |
| `id`                  | `String`           | Unique user identifier                                     |
| `realms`              | `String[]`         | Realms this user administers. Use `["_"]` for super admin. |
| `userpass`            | `String` \| `null` | Username key referencing the `userpass` credential table   |
| `jwt`                 | `String` \| `null` | JWT subject identifier                                     |
| `fido2`               | `String` \| `null` | FIDO2 identifier (future)                                  |
| `digital_credentials` | `Object` \| `null` | Key-value map of digital credential identifiers (future)   |
| `client_certificate`  | `String` \| `null` | Client certificate identifier                              |
| `totp_enabled`        | `bool` \| `null`   | Whether TOTP is active for this user                       |
| `totp_secret`         | `String` \| `null` | Base32-encoded TOTP secret (read-only via API)             |
| `totp_auth_url`       | `String` \| `null` | `otpauth://` URL for QR code enrollment (read-only)        |

**Response — `201 Created`** — created `Admin` object.

---

### `GET /admins/{admin_id}`

Retrieve an admin by ID.

**Response — `200 OK`** — `Admin` object.

**Response — `404 Not Found`** — admin does not exist.

---

### `PUT /admins/{admin_id}`

Replace an admin record. Returns the updated admin.

#### Request body — same shape as `POST /admins`

**Response — `200 OK`** — updated `Admin` object.

---

### `DELETE /admins/{admin_id}`

Delete an admin record.

**Response — `204 No Content`** — empty body.

---

### `GET /admins`

List all admins. Super admin only.

**Response — `200 OK`** — array of `Admin` objects.

---

### `PUT /admins/{admin_id}/realms/{realm_id}`

Add a realm to an admin's `realms` list.

**Response — `200 OK`** — updated `Admin` object.

---

### `DELETE /admins/{admin_id}/realms/{realm_id}`

Remove a realm from an admin's `realms` list.

**Response — `200 OK`** — updated `Admin` object.

---

## Credential Management

All `/realms/{realm}` endpoints require a valid session from a user who administers the given realm (see [authorization_and_administration.md](authorization_and_administration.md)).

### `POST /realms/{realm_id}/userpass`

Create a username/password credential in a realm.

#### Request body

```json
{
  "realm": "my-service",
  "username": "alice",
  "password": [115, 101, 99, 114, 101, 116],
  "change_password": false
}
```

| Field             | Type     | Description                                                             |
| ----------------- | -------- | ----------------------------------------------------------------------- |
| `realm`           | `String` | Realm ID (must match path parameter)                                    |
| `username`        | `String` | Credential username                                                     |
| `password`        | `u8[]`   | UTF-8 bytes of the plaintext password. The server hashes with Argon2id. |
| `change_password` | `bool`   | When `true`, the next login returns `"ChangePassword"` next step        |

**Response — `201 Created`** — created `UserPass` object.

---

### `GET /realms/{realm_id}/userpass`

List all credentials in a realm.

**Response — `200 OK`** — array of `UserPass` objects. The `password` field is always empty.

---

### `GET /realms/{realm_id}/userpass/{username}`

Retrieve a single credential.

**Response — `200 OK`** — `UserPass` object. The `password` field is always empty.

**Response — `404 Not Found`** — credential does not exist.

---

### `PUT /realms/{realm_id}/userpass/{username}`

Update a credential (typically to change the password or set `change_password`).

#### Request body — same shape as `POST /realms/{realm}/userpass`

**Response — `200 OK`** — updated `UserPass` object.

---

### `DELETE /realms/{realm_id}/userpass/{username}`

Delete a credential.

**Response — `204 No Content`** — empty body.

---

## TOTP Management

See [two_factor_authentication.md](two_factor_authentication.md) for the full enrollment flow.

### `POST /realms/{realm_id}/totp/generate`

Generate a TOTP secret for a user. The secret is **not stored** at this point — it is only persisted after a successful verification call.

**Query parameters:** `realm={realm_id}`

#### Request body

```json
{
  "username": "alice",
  "issuer": "My Application"
}
```

**Response — `200 OK`**

```json
{
  "secret_base32": "JBSWY3DPEHPK3PXP",
  "otpauth_url": "otpauth://totp/My%20Application:alice?secret=JBSWY3DPEHPK3PXP&issuer=My%20Application&algorithm=SHA1&digits=6&period=30"
}
```

---

### `POST /realms/{realm_id}/totp/verify`

Verify a TOTP code and enable TOTP for the user. Call this after `generate` to confirm the user has enrolled their authenticator app.

**Query parameters:** `realm={realm_id}`

#### Request body

```json
{
  "username": "alice",
  "token": "482913",
  "secret": "JBSWY3DPEHPK3PXP",
  "issuer": "My Application"
}
```

**Response — `200 OK`** — empty body. TOTP is now active for the user.

**Response — `400 Bad Request`** — TOTP token is invalid.

---

### `DELETE /realms/{realm_id}/totp/{username}`

Disable TOTP for a user.

**Query parameters:** `realm={realm_id}`

**Response — `200 OK`** — empty body.

---

## Common Response Codes

| Code                        | Meaning                                                                             |
| --------------------------- | ----------------------------------------------------------------------------------- |
| `200 OK`                    | Success                                                                             |
| `400 Bad Request`           | Malformed request body or invalid parameter                                         |
| `401 Unauthorized`          | Missing or invalid credentials                                                      |
| `403 Forbidden`             | Authenticated but not authorised (e.g., realm admin trying to modify another realm) |
| `404 Not Found`             | Resource does not exist                                                             |
| `409 Conflict`              | Resource already exists (duplicate ID)                                              |
| `500 Internal Server Error` | Unexpected server error                                                             |

---

## Authentication for Admin Endpoints

Admin endpoints (`/admins`, `/admins/realms`, `/realms`) require a valid session cookie obtained by logging into the `_` realm (super admin) or the target realm (realm admin).

```bash
# Log in as super admin
curl --cacert ca.cert.pem \
     -X POST "https://localhost:8443/login?realm=_" \
     -u "admin:password" \
     -c cookies.txt

# Use the session cookie for admin calls
curl --cacert ca.cert.pem \
     -b cookies.txt \
     https://localhost:8443/admins/realms
```

See [authorization_and_administration.md](authorization_and_administration.md) for the full authorization matrix.

---

## Data Types

### `Realm`

```json
{
  "id": "my-service",
  "auth_params": {
    "username_password_params": { "allow_expired_passwords": false },
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
    "totp_params": { "algorithm": "SHA1", "step": 30 }
  },
  "session_max_age_seconds": 3600,
  "session_max_stale_age_seconds": 1800
}
```

### `Admin`

```json
{
  "id": "alice",
  "realms": ["my-service"],
  "userpass": "alice",
  "jwt": null,
  "fido2": null,
  "digital_credentials": null,
  "client_certificate": null,
  "totp_enabled": false,
  "totp_secret": null,
  "totp_auth_url": null
}
```

### `UserPass`

```json
{
  "realm": "my-service",
  "username": "alice",
  "password": [],
  "change_password": false
}
```

> The `password` field is always returned as an empty byte array from GET endpoints. Send the plaintext UTF-8 bytes only on create/update.

### `SessionData`

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "realm_id": "my-service",
  "username": "alice",
  "auth_scheme": "up",
  "cookie_string": "eyJ…",
  "max_age_seconds": 3600,
  "max_stale_age_seconds": 1800,
  "created_at": 1744996400
}
```

| Field         | Description                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------- |
| `auth_scheme` | `"up"` username/password · `"jwt"` JWT · `"cc"` client cert · `"f2"` FIDO2 · `"dc"` digital credentials |

### `AuthenticatedClientScheme`

```json
{ "username": "alice", "auth_scheme": "UsernamePassword" }
```

`auth_scheme` values: `"UsernamePassword"`, `"Jwt"`, `"ClientCertificate"`, `"Fido2"`, `"DigitalCredentials"`

### `ClientClaims`

The JWT payload returned by `GET /whoami`:

| Claim    | Type       | Description                                  |
| -------- | ---------- | -------------------------------------------- |
| `iss`    | `String`   | Issuer                                       |
| `sub`    | `String`   | Subject (authenticated username)             |
| `aud`    | `String[]` | Audience list                                |
| `exp`    | `i64`      | Expiration (Unix seconds)                    |
| `nbf`    | `i64`      | Not-before (Unix seconds)                    |
| `iat`    | `i64`      | Issued-at (Unix seconds)                     |
| `jti`    | `String`   | JWT ID                                       |
| `as_as`  | `String`   | Auth scheme used (`up`/`jwt`/`cc`/`f2`/`dc`) |
| `as_rid` | `String`   | Realm ID                                     |
