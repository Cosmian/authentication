# OpenID Connect provider

The authentication server is a full **OpenID Connect (OIDC) Provider (OP)** in
addition to being a session/credential authentication server. It implements the
Authorization Code flow with mandatory PKCE, refresh tokens, and the
client-credentials grant, and exposes discovery, JWKS, UserInfo, token
introspection and token revocation endpoints.

Implicit and hybrid flows are **not** supported.

## Standards

| RFC / spec | Role |
|------------|------|
| RFC 6749 | OAuth 2.0 Authorization Framework |
| RFC 6750 | Bearer token usage |
| RFC 7636 | PKCE (S256 — mandatory) |
| RFC 8414 | Authorization Server Metadata (discovery) |
| RFC 7662 | Token introspection |
| RFC 7009 | Token revocation |
| RFC 9068 | JWT access tokens (`at+jwt`) |
| RFC 7515/7517/7518/7519 | JOSE / JWK / JWA / JWT |
| OpenID Connect Core / Discovery 1.0 | ID tokens, UserInfo, discovery |

## Security separation

The OP maintains strict internal separation between token types so they can
never be substituted for one another:

- **ID token** — signed JWT, `aud = client_id`, carries `nonce`, `auth_time`
  and `at_hash`.
- **Access token** — signed JWT with an explicit `typ: at+jwt` header
  (RFC 9068) and a distinct audience.
- **Session cookie** (`_ea_`) — opaque session key, unchanged, with its own
  signing key.

ID and access tokens are signed with a **dedicated OIDC signing key** whose
`kid` differs from the session-JWT key. Configure it under `oidc_params`; when
omitted the server falls back to the session/TLS key and logs a warning.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/.well-known/openid-configuration` | Discovery metadata |
| GET | `/oidc/jwks` | Combined JWKS (OIDC + session keys) |
| GET | `/oidc/authorize` | Authorization endpoint → login form |
| POST | `/oidc/authorize/login` | Submit credentials → consent screen |
| POST | `/oidc/authorize/consent` | Approve/deny → redirect with code |
| POST | `/oidc/token` | Token endpoint (code / refresh / client_credentials) |
| GET·POST | `/oidc/userinfo` | UserInfo (Bearer access token) |
| POST | `/oidc/introspect` | Token introspection (RFC 7662) |
| POST | `/oidc/revoke` | Token revocation (RFC 7009) |

## Configuration

```toml
[oidc_params]
issuer = "https://auth.example.com"
oidc_signing_private_key = "/etc/auth/oidc_signing.key.pem"
oidc_signing_public_key  = "/etc/auth/oidc_signing.pub.pem"
id_token_ttl_secs = 3600
access_token_ttl_secs = 3600
refresh_token_ttl_secs = 1209600
code_ttl_secs = 60
supported_scopes = ["openid", "profile", "email", "offline_access", "roles"]
# default_audience = "https://api.example.com"
```

All fields are optional. When `[oidc_params]` is absent the OP still runs with
defaults, deriving the issuer from the server host/port and signing with the
session/TLS key.

## Provisioning a client

OAuth clients are registered per realm by a realm admin:

```bash
curl -sk -b cookies.txt -X POST \
  https://localhost:8443/realms/my-realm/clients \
  -H 'Content-Type: application/json' \
  -d '{
        "client_name": "My Web App",
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scopes": ["openid", "profile", "email", "offline_access"],
        "token_endpoint_auth_method": "client_secret_basic"
      }'
```

The response returns the generated `client_id` and, for confidential clients,
the `client_secret` — shown **only once**. Use
`"token_endpoint_auth_method": "none"` for a public (PKCE-only) client.

## Authorization Code + PKCE flow

1. Redirect the user to
   `GET /oidc/authorize?response_type=code&client_id=…&redirect_uri=…&scope=openid…&state=…&nonce=…&code_challenge=…&code_challenge_method=S256`.
2. The server renders a login form; the user authenticates with their realm
   username/password (and TOTP if enabled), then approves the consent screen.
3. The server redirects back to `redirect_uri?code=…&state=…`.
4. Exchange the code at the token endpoint:

```bash
curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" -X POST \
  https://localhost:8443/oidc/token \
  -d grant_type=authorization_code \
  -d code=$CODE \
  -d redirect_uri=https://app.example.com/callback \
  -d code_verifier=$CODE_VERIFIER
```

The response contains `access_token`, `id_token`, `refresh_token`,
`token_type`, `expires_in` and `scope`. Refresh tokens rotate on every use, and
replaying a rotated (revoked) refresh token invalidates the whole token family.

See the [API reference](api_reference.md) and the OpenAPI schema for the full
endpoint and error catalogue.
