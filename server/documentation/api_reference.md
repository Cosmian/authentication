# API Reference

Complete reference for all HTTP endpoints exposed by the Auth authentication server.

All endpoints are served over **HTTPS only**. The base URL is `https://{host}:{port}`.

---

## Table of Contents

- [Public Endpoints](#public-endpoints)
- [Authentication — Login and Session Claims](#authentication--login-and-session-claims)
- [Session Management](#session-management)
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

**Response**

```text
HTTP/1.1 200 OK
Content-Type: text/plain

"0.1.2"
```

---

### `GET /public/jwks`

Returns the JSON Web Key Set containing the server's public key(s) for JWT signature verification.

> **Note:** Only available in test builds. Production deployments expose JWKS through the Identity Provider's own JWKS endpoint.

**Response**

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

| Method | How to supply credentials |
|--------|---------------------------|
| Username/Password | `Authorization: Basic <base64(username:password)>` |
| JWT Bearer | `Authorization: Bearer <jwt_token>` |
| Client Certificate | Client certificate in TLS handshake |

**Request body** (optional — for public-key FIDO2 challenge or TOTP code)

```json
{
  "public_key_pem": null,
  "totp_code": "482913"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `public_key_pem` | `String` \| `null` | Client public key (FIDO2 / digital credentials flows) |
| `totp_code` | `String` \| `null` | TOTP verification code for 2FA step |

**Response — `200 OK`**

```json
{
  "next_step": "Authenticated",
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Set-Cookie header: `_ea_=<cookie_string>; HttpOnly; Secure; SameSite=Strict`

| Field | Type | Description |
|-------|------|-------------|
| `next_step` | `"Authenticated"` \| `"TotpRequired"` \| `"ChangePassword"` | What the client should do next |
| `session_id` | `String` \| `null` | UUID of the new session (only present when `Authenticated`) |

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

### `GET /sessions/session/{session_id}`

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

### `POST /sessions/session/{session_id}`

Retrieve session data and optionally apply a bulk logout action in the same request.

**Request body**

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
| `authenticated_clients` | `AuthenticatedClientScheme[]` | Clients whose sessions may be affected |
| `sessions_action` | `"LogoutOtherSessions"` \| `"LogoutAllSessions"` \| `null` | Action to perform alongside the lookup |

**`sessions_action` values:**

| Value | Effect |
|-------|--------|
| `"LogoutOtherSessions"` | Delete all sessions for the given clients **except** the queried one |
| `"LogoutAllSessions"` | Delete **all** sessions for the given clients (including the queried one); session data is returned before deletion |

**Response — `200 OK`** — same shape as `GET /sessions/session/{id}`.

---

### `POST /sessions/session/realms/{realm_id}/clients`

Return all session IDs for a set of authenticated clients in a realm.

**Request body**

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

### `DELETE /sessions/session`

Delete sessions by ID.

**Request body**

```json
{
  "session_ids": [
    "550e8400-e29b-41d4-a716-446655440000"
  ]
}
```

**Response — `200 OK`** — empty body.

---

### `DELETE /sessions/session/expired`

Delete all expired sessions from the session store.

**Response — `200 OK`** — empty body.

---

### `DELETE /sessions/session/realms/{realm_id}`

Delete all sessions for a given realm (administrative bulk logout).

**Response — `200 OK`** — empty body.

---

## Realm Administration

All endpoints under `/admin` require the caller to be authenticated as a **super admin** (a `Admin` whose `realms` list contains `"_"`).

### `POST /admin/realm`

Create a new realm.

**Request body**

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

**Response — `200 OK`** — empty body on success.

**Response — `409 Conflict`** — realm ID already exists.

---

### `GET /admin/realm/{realm_id}`

Retrieve a realm by ID.

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

### `PUT /admin/realm/{realm_id}`

Replace a realm's configuration. Returns the updated realm.

**Request body** — same shape as `POST /admin/realm`.

**Response — `200 OK`** — updated `Realm` object.

---

### `DELETE /admin/realm/{realm_id}`

Delete a realm and all associated data.

**Response — `200 OK`** — empty body.

---

### `GET /admin/realms`

List all realms.

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

### `GET /admin/userpass`

List all username/password credentials across every realm (super admin only).

**Response — `200 OK`** — array of `UserPass` objects. The `password` field is always returned as an empty byte array.

---

## Admin Administration

### `POST /admins/admin`

Create a new `Admin` record. Super admin only.

**Request body**

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

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` | Unique user identifier |
| `realms` | `String[]` | Realms this user administers. Use `["_"]` for super admin. |
| `userpass` | `String` \| `null` | Username key referencing the `userpass` credential table |
| `jwt` | `String` \| `null` | JWT subject identifier |
| `fido2` | `String` \| `null` | FIDO2 identifier (future) |
| `digital_credentials` | `Object` \| `null` | Key-value map of digital credential identifiers (future) |
| `client_certificate` | `String` \| `null` | Client certificate identifier |
| `totp_enabled` | `bool` \| `null` | Whether TOTP is active for this user |
| `totp_secret` | `String` \| `null` | Base32-encoded TOTP secret (read-only via API) |
| `totp_auth_url` | `String` \| `null` | `otpauth://` URL for QR code enrollment (read-only) |

**Response — `200 OK`** — created `Admin` object.

---

### `GET /admins/admin/{user_id}`

Retrieve a user by ID.

**Response — `200 OK`** — `Admin` object.

**Response — `404 Not Found`** — user does not exist.

---

### `PUT /admins/admin/{user_id}`

Replace a user record. Returns the updated user.

**Request body** — same shape as `POST /admins/admin`.

**Response — `200 OK`** — updated `Admin` object.

---

### `DELETE /admins/admin/{user_id}`

Delete a user record.

**Response — `200 OK`** — empty body.

---

### `GET /admins`

List all users. Super admin only.

**Response — `200 OK`** — array of `Admin` objects.

---

### `PUT /admins/admin/{user_id}/realm/{realm_id}`

Add a realm to a user's `realms` list.

**Response — `200 OK`** — updated `Admin` object.

---

### `DELETE /admins/admin/{user_id}/realm/{realm_id}`

Remove a realm from a user's `realms` list.

**Response — `200 OK`** — updated `Admin` object.

---

## Credential Management

All `/realms/{realm}` endpoints require a valid session from a user who administers the given realm (see [authorization_and_administration.md](authorization_and_administration.md)).

### `POST /realms/{realm_id}/userpass`

Create a username/password credential in a realm.

**Request body**

```json
{
  "realm": "my-service",
  "username": "alice",
  "password": [115, 101, 99, 114, 101, 116],
  "change_password": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `realm` | `String` | Realm ID (must match path parameter) |
| `username` | `String` | Credential username |
| `password` | `u8[]` | UTF-8 bytes of the plaintext password. The server hashes with Argon2id. |
| `change_password` | `bool` | When `true`, the next login returns `"ChangePassword"` next step |

**Response — `200 OK`** — empty body.

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

**Request body** — same shape as `POST /realms/{realm}/userpass`.

**Response — `200 OK`** — updated `UserPass` object.

---

### `DELETE /realms/{realm_id}/userpass/{username}`

Delete a credential.

**Response — `200 OK`** — empty body.

---

## TOTP Management

See [two_factor_authentication.md](two_factor_authentication.md) for the full enrollment flow.

### `POST /realms/{realm_id}/totp/generate`

Generate a TOTP secret for a user. The secret is **not stored** at this point — it is only persisted after a successful verification call.

**Query parameters:** `realm={realm_id}`

**Request body**

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

**Request body**

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

| Code | Meaning |
|------|---------|
| `200 OK` | Success |
| `400 Bad Request` | Malformed request body or invalid parameter |
| `401 Unauthorized` | Missing or invalid credentials |
| `403 Forbidden` | Authenticated but not authorised (e.g., realm admin trying to modify another realm) |
| `404 Not Found` | Resource does not exist |
| `409 Conflict` | Resource already exists (duplicate ID) |
| `500 Internal Server Error` | Unexpected server error |

---

## Authentication for Admin Endpoints

Admin endpoints (`/admin`, `/admins`, `/realms`) require a valid session cookie obtained by logging into the `_` realm (super admin) or the target realm (realm admin).

```bash
# Log in as super admin
curl --cacert ca.cert.pem \
     -X POST "https://localhost:8443/login?realm=_" \
     -u "admin:password" \
     -c cookies.txt

# Use the session cookie for admin calls
curl --cacert ca.cert.pem \
     -b cookies.txt \
     https://localhost:8443/admin/realms
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

| Field | Description |
|-------|-------------|
| `auth_scheme` | `"up"` username/password · `"jwt"` JWT · `"cc"` client cert · `"f2"` FIDO2 · `"dc"` digital credentials |

### `AuthenticatedClientScheme`

```json
{ "username": "alice", "auth_scheme": "UsernamePassword" }
```

`auth_scheme` values: `"UsernamePassword"`, `"Jwt"`, `"ClientCertificate"`, `"Fido2"`, `"DigitalCredentials"`

### `ClientClaims`

The JWT payload returned by `GET /whoami`:

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | `String` | Issuer |
| `sub` | `String` | Subject (authenticated username) |
| `aud` | `String[]` | Audience list |
| `exp` | `i64` | Expiration (Unix seconds) |
| `nbf` | `i64` | Not-before (Unix seconds) |
| `iat` | `i64` | Issued-at (Unix seconds) |
| `jti` | `String` | JWT ID |
| `as_as` | `String` | Auth scheme used (`up`/`jwt`/`cc`/`f2`/`dc`) |
| `as_pk` | `String` | Client public key PEM (when applicable) |
| `as_rid` | `String` | Realm ID |
