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
- Added `server/documentation/docs/kms_oidc_setup.md` — step-by-step guide for
  configuring the auth-verifier as an OIDC Provider for the Cosmian KMS, covering
  both the explicit `[ui_config.ui_oidc_auth]` (Option A) and auto-populate
  `[auth_verifier]` (Option B) KMS config patterns.
- Added ADR `adr/2026-08-11-oidc-provider-in-auth-verifier.md` documenting the
  architectural decision to embed the OIDC OP directly in auth-verifier.
- Added three mermaid sequence diagrams to `oidc.md` (Authorization Code + PKCE
  end-to-end including the KMS Web UI's BFF session-cookie pattern and the
  authenticated KMIP call, refresh-token rotation with reuse detection, and
  client_credentials) so the currently-implemented flows are visually
  documented rather than only described in prose.
- Added a "Known limitations" section to `oidc.md` capturing the outcome of a
  scoped gaps review (rate limiting and structured audit logging on `/oidc/*`
  endpoints as near-term security hardening; RP-Initiated Logout, access-token
  revocation and safe signing-key rotation as follow-ups; consent-skip and
  operator branding as low-priority UX items; upstream federation, SCIM,
  dynamic client registration, PAR/FAPI and email-based password reset flagged
  as candidates for a dedicated future ADR rather than scheduled work).

## Features

- Added **`DevSeedUser`** list (`[[dev_seed.users]]`) to `DevSeedParams` so
  plain test users can be pre-seeded in the realm on first startup alongside the
  realm-admin and OIDC client, eliminating the manual user-creation step.
- `test_data/configs/auth_verifier/oidc_dev.toml` now seeds user `alice` /
  `alice123` so the full OIDC login flow works immediately after `cargo run`.

## Bug Fixes

- **CSP `form-action 'self'` blocked the Allow button in Firefox**: the consent
  page was sending `form-action 'self'` in the `Content-Security-Policy` header;
  Firefox applies this directive to the *post-consent redirect target* (not just
  the initial form action), blocking the redirect to the KMS callback URL.
  Fixed by splitting `page_login()` (keeps `form-action 'self'`) and
  `page_consent()` (omits `form-action`); the consent page is safe without it
  because both the form action and redirect target are server-controlled and
  validated against the registered `redirect_uri`.
  `[dev_seed.oidc_client]` is present in the server config, a fixed OIDC client
  with a known `client_id` and `client_secret` (stored SHA-256-hashed) is created
  idempotently on first startup, eliminating the manual client-registration step
  in development setups.
- `test_data/configs/auth_verifier/oidc_dev.toml` now pre-seeds the
  `kms-ui-dev` OIDC client so that both `cargo run -p auth_verifier` and
  `cargo run -p cosmian_kms_server` produce a working OIDC login button in the
  KMS Web UI without any additional steps.

## Features (admin-ui)

- Added **OIDC Clients** page (`/oidc-clients`) to the Admin UI with full CRUD:
  list, register (with one-time secret modal showing the KMS `[ui_config.ui_oidc_auth]`
  config snippet), edit, and delete — realm-scoped for realm admins and accordion
  view across all realms for super-admins.
- The one-time secret modal dynamically uses the server URL as the OIDC issuer in
  the generated KMS config snippet instead of a hardcoded value.

## Features

- **Themed OIDC sign-in and consent pages**: the server-rendered OIDC
  `authorize.rs` pages now match the admin-UI visual design —
  CSS custom-property tokens for primary (`#e34319` light / `#9e6eff` dark),
  background (`#f0f2f5` / `#2a2d30`), and card (`#fff` / `#393E46`);
  automatic `@media (prefers-color-scheme: dark)` dark mode; inline SVG icons
  in input fields (user, lock, TOTP hash); scope tags on the consent page;
  400 px card width matching the admin-UI `LoginPage`; "Cosmian Authentication
  Server" footer; no external resources (compatible with CSP `default-src 'none'`).
