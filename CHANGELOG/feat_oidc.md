# Changelog — `develop`

## Features

- Added a full OpenID Connect **Provider (OP)** to auth-verifier: discovery
  (`/.well-known/openid-configuration`, RFC 8414), combined JWKS (`/oidc/jwks`),
  the authorization endpoint with an embedded login + consent flow
  (`/oidc/authorize`, `/oidc/authorize/login`, `/oidc/authorize/consent`), the
  token endpoint (`/oidc/token`), UserInfo (`/oidc/userinfo`), token
  introspection (`/oidc/introspect`, RFC 7662) and token revocation
  (`/oidc/revoke`, RFC 7009), so the server can now act as a standards-compliant
  Identity Provider in addition to a session/credential verifier.
- Implemented the Authorization Code grant with **mandatory PKCE (S256,
  RFC 7636)**, the `refresh_token` grant with rotation and reuse detection, and
  the `client_credentials` grant; implicit and hybrid flows are intentionally
  not supported.
- Enforced strict token-type separation for security: ID tokens (`aud =
  client_id`), RFC 9068 `at+jwt` access tokens (distinct audience and explicit
  `typ` header), and the opaque `_ea_` session cookie are signed/scoped
  independently, with a **dedicated OIDC signing key** (separate `kid`) that the
  combined JWKS publishes alongside the session key.
- Added realm-scoped OAuth client provisioning endpoints
  (`/realms/{realm_id}/clients`) so realm admins can register confidential or
  public (PKCE-only) relying parties; client secrets are returned once and
  stored only as SHA-256 hashes.
- Added `OidcParams` server configuration (issuer, dedicated signing key paths,
  token/refresh/code TTLs, supported scopes, default audience) with safe
  fall-backs to the session/TLS key when a dedicated OIDC key is not configured.
- Extended the client library (`auth_client`) with OAuth client CRUD methods and
  the `OAuthClientRequest`/`OAuthClientResponse` DTOs.

## Tests

- Added Rust integration tests covering the full authorization-code + PKCE flow,
  ID-token signature verification against the JWKS, refresh-token rotation and
  reuse detection, UserInfo, introspection, revocation, discovery,
  client_credentials, and a matrix of negative cases.
- Added an exhaustive `oidc_curl_suite.sh` bash/curl harness (49 assertions)
  that boots a throwaway server with a dedicated OIDC signing key and drives
  every endpoint, route and error scenario end-to-end.
- Added an OpenID Foundation Conformance Suite runner (`oidc_conformance.sh`,
  wired as `nix.sh oidc`) that provisions a test client, generates the suite
  configuration with headless login/consent automation, and runs the
  `oidcc-config` and `oidcc-basic` certification plans (skips gracefully without
  Docker).

## Docs

- Added `server/documentation/docs/oidc.md` describing the OP, its security
  separation model, configuration and flows, and synchronised the OpenAPI schema
  (`openapi.yaml`) with all new OIDC and client-management paths, schemas and
  parameters.
