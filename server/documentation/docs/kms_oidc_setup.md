# Configuring OIDC for the KMS

This guide walks through setting up the Authentication Verifier as an **on-premise
OpenID Connect (OIDC) Provider** for the Cosmian KMS, using the Admin UI for all
auth-verifier-side configuration.

By the end you will have:

- Auth-verifier running as a full OIDC OP
- An OIDC client registered in the `kms` realm
- A test user (`alice`) able to log in via the KMS Web UI
- KMS configured to accept `at+jwt` bearer tokens and serve the OIDC login flow

---

## Prerequisites

- Auth-verifier binary built (`cargo build -p auth_verifier`)
- KMS binary built (`cargo build -p cosmian_kms_server --features non-fips`)
- `curl` available for smoke tests

---

## Step 1 — Start the auth-verifier

Use the dev configuration supplied in the KMS repository:

```bash
cd authentication
./target/debug/auth_verifier \
  ../test_data/configs/auth_verifier/oidc_dev.toml
```

The server starts on `https://127.0.0.1:8443` and seeds:

| Item | Value |
|------|-------|
| Realm | `kms` |
| Realm-admin username | `kms-admin` |
| Realm-admin password | `change_me` |
| Admin realm | `_` (login with `realm=_`) |

Verify the OIDC Provider is live:

```bash
curl -sk "https://127.0.0.1:8443/.well-known/openid-configuration" | python3 -m json.tool
```

Expected: a JSON document containing `issuer`, `authorization_endpoint`,
`token_endpoint`, `jwks_uri`, etc.

---

## Step 2 — Open the Admin UI

Browse to **https://127.0.0.1:8443/admin-ui** and log in:

| Field | Value |
|-------|-------|
| Username | `kms-admin` |
| Password | `change_me` |
| Realm | `_` (the admin realm) |

> **Tip**: the Admin UI login page always authenticates against the `_` (admin) realm,
> regardless of which realm you later select in the header.

---

## Step 3 — Register the KMS OIDC client

In the Admin UI:

1. Select realm **kms** in the header drop-down.
2. Navigate to **OIDC Clients** in the sidebar.
3. Click **New Client**.
4. Fill in the form:

   | Field | Value |
   |-------|-------|
   | Client Name | `cosmian-kms-ui` |
   | Redirect URIs | `http://localhost:9998/ui/callback` (one per line) |
   | Grant Types | `authorization_code`, `refresh_token` |
   | Scopes | `openid`, `profile`, `email` |
   | Auth Method | `client_secret_basic` |

5. Click **Register**.

A **one-time secret dialog** appears containing:
- `client_id` — a server-generated opaque ID
- `client_secret` — shown **only once**; copy it immediately

The dialog also shows the exact TOML snippet to paste into the KMS config.

> **Alternative (curl)**:
> ```bash
> # Login as kms-admin (in admin realm _)
> curl -sk -X POST "https://127.0.0.1:8443/login?realm=_" \
>   -H "Authorization: Basic $(printf 'kms-admin:change_me' | base64 -w0)" \
>   -H "Content-Type: application/json" -d '{}' \
>   -c /tmp/kms.jar -b /tmp/kms.jar
>
> # Register the client
> curl -sk -X POST "https://127.0.0.1:8443/realms/kms/clients" \
>   -b /tmp/kms.jar -c /tmp/kms.jar \
>   -H "Content-Type: application/json" \
>   -d '{
>     "client_name": "cosmian-kms-ui",
>     "redirect_uris": ["http://localhost:9998/ui/callback"],
>     "grant_types": ["authorization_code","refresh_token","client_credentials"],
>     "response_types": ["code"],
>     "scopes": ["openid","profile","email"],
>     "token_endpoint_auth_method": "client_secret_basic"
>   }'
> ```

---

## Step 4 — Create a test user

In the Admin UI, navigate to **Credentials** (realm: `kms`) → **New Credential**:

| Field | Value |
|-------|-------|
| Username | `alice` |
| Password | `alice123` |

> **Alternative (curl)** — the password field is `Vec<u8>` on the wire:
> ```bash
> PASS=$(python3 -c "import json; print(json.dumps(list('alice123'.encode())))")
> curl -sk -X POST "https://127.0.0.1:8443/realms/kms/userpass" \
>   -b /tmp/kms.jar -c /tmp/kms.jar \
>   -H "Content-Type: application/json" \
>   -d "{\"realm\":\"kms\",\"username\":\"alice\",\"password\":${PASS},
>        \"change_password\":false,\"roles\":[]}"
> ```

---

## Step 5 — Configure the KMS

Two configuration patterns are available:

### Option A — Explicit `[ui_config.ui_oidc_auth]` (recommended)

Use this when you have an explicit OIDC client or when the OIDC issuer differs from
the bearer-token auth-verifier.

```toml
# test_data/configs/server/auth_verifier_oidc.toml

[auth_verifier]
auth_verifier_url   = "https://127.0.0.1:8443"
auth_verifier_realm = "kms"
auth_verifier_accept_invalid_certs = true   # dev/test only

[ui_config.ui_oidc_auth]
ui_oidc_issuer_url    = "https://127.0.0.1:8443"
ui_oidc_client_id     = "<client_id from Step 3>"
ui_oidc_client_secret = "<client_secret from Step 3>"
```

The `[auth_verifier]` section handles **bearer-token validation** (both OIDC `at+jwt`
and legacy session JWTs).  The `[ui_config.ui_oidc_auth]` section handles the
**Web UI OIDC flow**.  The credentials only appear in one place.

### Option B — Auto-populate shorthand

Omit `[ui_config.ui_oidc_auth]` and add the client credentials to `[auth_verifier]`:

```toml
[auth_verifier]
auth_verifier_url                = "https://127.0.0.1:8443"
auth_verifier_realm              = "kms"
auth_verifier_oidc_client_id     = "<client_id from Step 3>"
auth_verifier_oidc_client_secret = "<client_secret from Step 3>"
auth_verifier_accept_invalid_certs = true
```

The KMS detects that `[ui_config.ui_oidc_auth]` is absent and auto-derives it from
`[auth_verifier]`.  This is the minimal config — ideal for simple single-instance
setups where the same auth-verifier serves both purposes.

> **When to use which option**:
>
> | Scenario | Option |
> |----------|--------|
> | Same auth-verifier for bearer tokens and UI login | **B** (shorter) |
> | Different OIDC issuer for UI vs. bearer tokens | **A** (explicit) |
> | Customised `ui_oidc_logout_url` | **A** (explicit, add the field) |
> | Existing `[ui_config.ui_oidc_auth]` already set | **A** (remove the fields from `[auth_verifier]`) |

---

## Step 6 — Start the KMS

```bash
cargo run -p cosmian_kms_server --features non-fips -- \
  -c test_data/configs/server/auth_verifier_oidc.toml
```

On successful startup the log shows:

```
OIDC: discovered endpoints from https://127.0.0.1:8443/.well-known/openid-configuration
```

Verify:

```bash
curl -s http://localhost:9998/ui/auth_method
# → {"auth_method":"JWT","auth_methods":["JWT","AUTH_VERIFIER"]}
```

`"JWT"` confirms that OIDC discovery succeeded and the Web UI will show the
OIDC login button.

---

## Step 7 — Test the login flow

1. Browse to **http://localhost:9998/ui/**
2. Click **Login** — you are redirected to the auth-verifier OIDC authorize page.
3. Enter `alice` / `alice123`.
4. Approve the consent screen.
5. You are redirected back to the KMS UI and authenticated.

Verify the session:

```bash
curl -s http://localhost:9998/ui/whoami \
  --cookie-jar /tmp/kms-session.jar --cookie /tmp/kms-session.jar
# → {"user_id":"alice"}
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `auth_method` returns `AUTH_VERIFIER` instead of `JWT` | OIDC discovery failed | Check `auth_verifier_accept_invalid_certs = true` and that auth-verifier is running |
| Callback returns `Failed to exchange auth code` | reqwest TLS error to auth-verifier | Set `auth_verifier_accept_invalid_certs = true` in KMS config |
| `Missing sub and email claims in id_token` | Unexpected token format | Check the auth-verifier OIDC signing key config |
| `access_denied` on consent | Wrong form field name | The consent form uses `decision=approve`, not `action=approve` |
| KMS starts but no OIDC button | `[ui_config.ui_oidc_auth]` is empty | Add issuer URL + client credentials, or use Option B auto-populate |
| `UNIQUE constraint failed: userpass` | User already exists | Safe to ignore — login will work |

---

## See Also

- [OpenID Connect Provider reference](oidc.md)
- [ADR — Embed OIDC Provider in auth-verifier](adr/2026-08-11-oidc-provider-in-auth-verifier.md)
- KMS config reference: `test_data/configs/server/auth_verifier_oidc.toml`
- KMS config (auto-populate): `test_data/configs/server/oidc.toml`
