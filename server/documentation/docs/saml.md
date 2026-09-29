# SAML 2.0 Single Sign-On

The Authentication Verifier can act as a SAML 2.0 **Service Provider (SP)**: users of a realm
sign in at the organisation's identity provider (IdP) — Microsoft Entra ID, Okta, ADFS,
Keycloak, Shibboleth, … — and come back with the usual `_ea_` session cookie. Nothing changes
for the API servers that validate sessions: a SAML session is a session like any other, with
`as_as` (auth scheme) set to `"sa"`.

The design and its trade-offs are recorded in
[ADR-0003](adr/2026-09-25-saml-service-provider.md).

---

## Table of Contents

- [What is supported](#what-is-supported)
- [Prerequisites](#prerequisites)
- [Step 1 — Create the SP signing key](#step-1--create-the-sp-signing-key)
- [Step 2 — Configure the realm](#step-2--configure-the-realm)
- [Step 3 — Register the realm at the IdP](#step-3--register-the-realm-at-the-idp)
- [Step 4 — Sign users in from your application](#step-4--sign-users-in-from-your-application)
- [Login flow](#login-flow)
- [Identity mapping](#identity-mapping)
- [Security checks](#security-checks)
- [Certificate and key rotation](#certificate-and-key-rotation)
- [Troubleshooting](#troubleshooting)

---

## What is supported

| Supported | Not supported |
|-----------|---------------|
| SP-initiated Web Browser SSO (SAML Profiles §4.1) | IdP-initiated (unsolicited) responses |
| `AuthnRequest` over **HTTP-Redirect**, signed with RSA-SHA256 | HTTP-POST or Artifact binding for requests |
| `Response` over **HTTP-POST** | Artifact binding for responses |
| Signed assertion, signed response, or both | Encrypted assertions |
| RSA or ECDSA signatures with SHA-256/384/512 | SHA-1 signatures or digests |
| IdP metadata pasted by an administrator | Fetching metadata from a URL |
| One IdP per realm | Federations / multi-IdP discovery |
| Local logout (`DELETE /sessions`) | SAML Single Logout |

SAML is a login method for the users of a realm. It is **never** an administrator credential:
admins keep signing in with the methods of the `_` realm.

---

## Prerequisites

1. **A server built with the `saml` feature.** SAML statically links the xmlsec and libxml2
   C libraries (see the ADR), so it is off by default. Build it inside the Nix shell:

    ```bash
    nix-shell --run "cargo build --release --features auth_verifier/saml"
    ```

    A server built without the feature refuses realms carrying SAML settings (HTTP 400) and
    refuses to start if `[saml_sp_params]` is configured.

2. **HTTPS.** The ACS URL must be `https://`, and the login cookie that protects against login
   CSRF is `Secure`.

3. **An SP signing key** in the server configuration — [Step 1](#step-1--create-the-sp-signing-key).
   Without it the `/saml` routes don't exist and realms can't enable SAML.

---

## Step 1 — Create the SP signing key

One RSA key signs the `AuthnRequest`s of every SAML realm, and its certificate is published in
the SP metadata that IdPs import. It is server configuration: it never goes through the
database or the admin API.

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -days 1095 -nodes \
    -subj "/CN=auth.example.com SAML SP" \
    -keyout saml-sp.key.pem -out saml-sp.cert.pem
chmod 600 saml-sp.key.pem
```

```toml
[saml_sp_params]
saml_rsa_private_key = "/etc/cosmian/saml-sp.key.pem"
saml_certificate     = "/etc/cosmian/saml-sp.cert.pem"
```

The server checks the pair at startup and stops if a file is unreadable, the key isn't RSA or
is shorter than 2048 bits, or the certificate doesn't match the key. A self-signed certificate
is fine: IdPs pin the certificate from the metadata rather than validating a chain. See
[Server configuration](server_configuration.md#saml-service-provider-key).

---

## Step 2 — Configure the realm

In the admin UI, open the realm (**Realms → Edit**) and tick **SAML 2.0 (single sign-on)**.
The same settings can be sent through the API as `auth_params.saml_params` on
`POST /admins/realms` or `PUT /admins/realms/{realm_id}`:

```json
{
  "saml_params": {
    "metadata_xml": "<md:EntityDescriptor entityID=\"https://idp.example.com/…\">…</md:EntityDescriptor>",
    "sp_entity_id": "https://auth.example.com/saml/my-service",
    "sp_acs_url": "https://auth.example.com/saml/my-service/acs",
    "subject_attribute": "email",
    "normalize_subject_case": true,
    "role_attribute": "groups",
    "attribute_claim_map": { "department": "dept" },
    "allowed_return_origins": ["https://app.example.com"],
    "default_return_url": "https://app.example.com/"
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `metadata_xml` | Yes | The IdP's SAML 2.0 metadata (one `EntityDescriptor`, at most 256 KiB). |
| `sp_entity_id` | Yes | This server's entity ID for the realm, given to the IdP. Conventionally `https://<server>/saml/<realm_id>`. |
| `sp_acs_url` | Yes | `https://<server>/saml/<realm_id>/acs` — the public URL browsers post the IdP's response to. |
| `subject_attribute` | No | Attribute whose single value becomes the user name. Unset: the NameID is used. Required when the IdP issues transient NameIDs. |
| `normalize_subject_case` | No | Lowercase the user name (default `false`). |
| `role_attribute` | No | Attribute whose values become the session `roles`. |
| `attribute_claim_map` | No | Attribute name → extra-claim name. Only listed attributes reach the session. |
| `allowed_return_origins` | Yes | `https://host[:port]` origins a login may return to. |
| `default_return_url` | Yes | Where a login returns when no `return_to` is given; must be under an allowed origin. |

The IdP fields (`idp_entity_id`, `idp_sso_url`, `idp_signing_certificates`,
`idp_nameid_format`) are **derived by the server from `metadata_xml`** on every save, and any
values sent for them are ignored. The metadata is refused if it isn't a single SAML 2.0
`EntityDescriptor`, has expired (`validUntil`), has no HTTPS HTTP-Redirect
`SingleSignOnService`, or has no signing certificate. Every refusal is an HTTP 400 naming the
field (`saml_params.<field>: <reason>`); the admin UI shows it next to that field.

The admin UI previews the parsed metadata — IdP entity ID, sign-in URL, signing certificates
with their expiry — before you save.

---

## Step 3 — Register the realm at the IdP

The IdP administrator needs this server's SP details. Either give them the SP metadata:

```text
https://auth.example.com/saml/my-service/metadata
```

(also available from the realm drawer's **Download SP metadata** button, or
`AuthClient::get_saml_metadata`), or enter by hand:

| IdP setting | Value |
|-------------|-------|
| Entity ID / Identifier / Audience | `sp_entity_id` |
| ACS URL / Reply URL (HTTP-POST) | `sp_acs_url` |
| Request signing certificate | The `[saml_sp_params]` certificate |
| Sign | Assertion, response, or both |
| Attributes to release | Those named in `subject_attribute`, `role_attribute` and `attribute_claim_map` |

Then paste the IdP's metadata into the realm ([Step 2](#step-2--configure-the-realm)).

---

## Step 4 — Sign users in from your application

Send the browser to the realm's login endpoint, with the page to come back to:

```text
https://auth.example.com/saml/my-service/login?return_to=https://app.example.com/dashboard
```

After signing in at the IdP, the browser returns to `return_to` (or `default_return_url`)
holding the `_ea_` session cookie. `return_to` must be an `https` URL under one of
`allowed_return_origins`; anything else is refused with HTTP 400 rather than silently
replaced, so a misconfigured link is noticed.

Your API validates the session exactly as for any other method — see
[Session management](session_management.md).

---

## Login flow

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant EA as Authentication Verifier
    participant S as SAML request store
    participant IdP as Identity Provider

    B->>EA: GET /saml/{realm}/login?return_to=…
    note over EA: return_to checked against allowed_return_origins
    EA->>S: store pending request (ID, realm, return URL; 10 min)
    EA-->>B: 302 to IdP SSO URL (signed AuthnRequest, RelayState = request ID)<br/>Set-Cookie: _ea_saml=<request ID>; Secure; HttpOnly; SameSite=None
    B->>IdP: GET SSO URL
    IdP-->>B: sign-in page (MFA, …)
    B->>IdP: credentials
    IdP-->>B: auto-submitting form
    B->>EA: POST /saml/{realm}/acs (SAMLResponse, RelayState)<br/>Cookie: _ea_saml=<request ID>
    note over EA: _ea_saml must equal RelayState
    EA->>S: take pending request (single use, same realm)
    note over EA: verify signature and conditions,<br/>record assertion ID (replay cache),<br/>map identity
    EA-->>B: 200 page continuing to the return URL<br/>Set-Cookie: _ea_=…; SameSite=Strict (session)
    B->>B: navigate to return URL
```

The pending requests and the replay cache live in the session store's database (SQLite,
PostgreSQL, MySQL or Redis) and are purged on the stale-session collector's interval. The
`/saml` routes share the per-IP rate limit of `/login`.

The ACS answers with a small page instead of a redirect: the `SameSite=Strict` session cookie
may be withheld on a navigation that directly follows the IdP's cross-site POST, and
continuing from a page of this server makes it a same-site navigation.

SAML sessions don't go through this server's TOTP step: multi-factor authentication is the
IdP's responsibility.

---

## Identity mapping

| Session field | Source |
|---------------|--------|
| `sub` (user name) | `subject_attribute`'s value — exactly one non-empty value is required — or else the `<NameID>`. A transient NameID is refused unless `subject_attribute` is set, as it changes on every login. Lowercased when `normalize_subject_case` is set. |
| `roles` | The deduplicated values of `role_attribute`. None when it is unset or not sent, which policies treat as no access. |
| extra claims | For each `attribute_claim_map` entry the IdP sent: a string, or an array for several values. At most 4 KiB in total; claim names this server sets itself (`sub`, `roles`, `as_rid`, …) are refused when saving. |
| `as_as` | `"sa"` |
| `as_rid` | The realm ID |

Roles come straight from the IdP: this server does not filter them against its role list.

---

## Security checks

A response is accepted only if **all** of these hold; otherwise the ACS answers
`401 SAML error: <reason>` and logs an `auth.login.failure` event.

| Check | Rule |
|-------|------|
| Browser binding | The `_ea_saml` cookie set by `/login` equals `RelayState` (prevents login CSRF: a response obtained elsewhere can't be posted into someone else's browser). |
| Solicited | `InResponseTo` names a pending request of this realm, which is consumed (single use, 10-minute lifetime). |
| Signature | The assertion, or the response containing it, is signed by one of the IdP certificates from the metadata. Unsigned content is ignored (XML signature-wrapping defence). |
| Algorithms | RSA or ECDSA with SHA-256/384/512 only, for both signature and digest. |
| Issuer | Equals the IdP entity ID. |
| Audience | An `AudienceRestriction` is present and every one of them names `sp_entity_id`. |
| Recipient / Destination | Equal `sp_acs_url`. |
| Time | `NotBefore` / `NotOnOrAfter` hold with 3 minutes of clock skew, and the assertion was issued at most 5 minutes ago. |
| Authentication | The assertion has an `AuthnStatement` and a bearer `SubjectConfirmation`. |
| Status | The response status is `Success`. |
| Replay | The assertion ID hasn't been used before (remembered for as long as it could be accepted). |

---

## Certificate and key rotation

**IdP signing certificate.** When the IdP rolls its certificate, paste its new metadata into
the realm. During a planned rollover, metadata listing both certificates keeps logins working
across the switch. The admin UI shows each certificate's expiry in the preview and flags a
realm card when a certificate expires within 30 days.

**SP signing key.** Replace the files named in `[saml_sp_params]` and restart the server, then
have every IdP import the new metadata. IdPs that verify request signatures reject requests
signed with the new key until they do.

---

## Troubleshooting

Rejections are logged with the reason:

```text
WARN event="auth.login.failure" realm=my-service auth_scheme="saml" SAML login rejected: …
```

| Symptom | Likely cause |
|---------|--------------|
| `404` on `/saml/…` | The server was built without `saml`, or `[saml_sp_params]` isn't set. |
| `400 realm '…' does not exist or does not use SAML` | Wrong realm in the URL, or SAML isn't enabled for it. |
| `400 return_to is not under an allowed return origin` | Add the origin to `allowed_return_origins`. |
| `401 this sign-in was not started from this browser` | The browser didn't send back the `_ea_saml` cookie: the login was started in another browser or profile, or the server isn't reached over HTTPS. Start again from `/saml/{realm}/login`. |
| `401 unknown or expired sign-in request` | More than 10 minutes at the IdP, the response was already used, or it answers another realm. |
| `401 … must be signed` / signature errors | The IdP signs with a certificate missing from the pasted metadata, or signs neither the assertion nor the response. Refresh the metadata. |
| `401 … AudienceRequirement` / `not addressed to this service provider` | The IdP's entity ID / audience setting differs from `sp_entity_id`. |
| `401 … Recipient` / `destination` | The IdP's ACS / reply URL differs from `sp_acs_url` (watch for `http` vs `https` and trailing slashes). |
| `401 … expired` / `not valid until` | Clock drift above 3 minutes between the IdP and this server — check NTP. |
| `401 the NameID is transient …` | Set `subject_attribute`, or configure a persistent NameID at the IdP. |
| `401 subject attribute '…' is missing` | The IdP doesn't release that attribute to this SP. |
