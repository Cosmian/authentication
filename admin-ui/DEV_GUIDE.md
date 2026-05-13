# Local Development Guide

How to run the auth server and admin UI together for end-to-end development
and testing against a real backend.

---

## Prerequisites

| Tool | How to get it |
|------|---------------|
| Rust toolchain | Managed by `rust-toolchain.toml` at the workspace root — `rustup` installs the pinned version automatically |
| pnpm | `npm install -g pnpm` or see [pnpm.io](https://pnpm.io/installation) |

---

## 1. Build the auth server

From the **workspace root**:

```bash
cargo build -p auth_server
```

The binary is written to `target/debug/auth_server`.

---

## 2. Start the auth server

```bash
cargo run -p auth_server -- server/auth_server.dev.toml
```

`server/auth_server.dev.toml` is a minimal development configuration that:
- Binds to `https://localhost:8443`
- Uses the self-signed test TLS certificates bundled with the source tree
- Uses an **in-memory SQLite database** (data is lost when the server stops)
- Auto-creates the schema and seeds the initial admin on first start

On first start you will see a log line similar to:

```
INFO  auth_server > server listening on https://localhost:8443
```

> **Persistent data**: replace `sqlite::memory:` with
> `sqlite://auth_server_dev.db` in `server/auth_server.dev.toml` to keep
> data between restarts.

---

## 3. Start the admin UI

In a second terminal, from the `admin-ui/` directory:

```bash
pnpm install   # first time only
pnpm dev       # or: pnpm dev:real
```

Vite starts at `http://localhost:5173/admin-ui`.

---

## 4. Log in

Open `http://localhost:5173/admin-ui` in your browser.

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `change_me` |

The initial `admin` account is a super-admin seeded automatically by the
server on first start.

> The account is created with `change_password: true`, but the admin realm
> has `allow_expired_passwords: true`, so the login succeeds immediately
> without a forced password-change step.

---

## Architecture: how requests flow

```
Browser
  ↓  http://localhost:5173/admin-ui
Vite dev server (port 5173)
  ↓  proxy: /login /whoami /sessions /realms /admins /public
Auth server (port 8443, TLS)
```

The Vite dev server proxies all API paths to the auth server (`secure: false`
so the self-signed certificate is accepted). The browser only ever talks to
`localhost:5173`, so there are no cross-origin cookie issues.

The proxy is configured in [vite.config.ts](vite.config.ts) and is active in
the default (`development`) mode. It is disabled in `mock` mode, where MSW
intercepts requests in the browser instead.

---

## Switching modes

| Command | What it does |
|---------|-------------|
| `pnpm dev` or `pnpm dev:real` | Proxy to real auth server at `https://localhost:8443` |
| `pnpm dev:mock` | MSW intercepts all requests in-browser; no server needed |

The target URL is set in `.env.development` (`VITE_AUTH_URL`). Override it
for a non-default server address:

```bash
VITE_AUTH_URL=https://my-server:9000 pnpm dev
```

---

## Troubleshooting

**Browser shows "Failed to fetch" or network error on login**

- Confirm the auth server is running: `curl -k https://localhost:8443/public/version`
- Check the server log for startup errors (bad cert path, port already in use)

**`ERR_CERT_AUTHORITY_INVALID` in browser**

The Vite proxy strips TLS verification (`secure: false`), so browser cert
errors should not appear for proxied API calls. If you see them on the UI
page itself, the UI assets are served over plain HTTP from Vite — this is
expected.

**Session cookie not set / always redirected to login**

The Vite proxy forwards the `Set-Cookie` header from the server to the
browser. Ensure you are opening `http://localhost:5173/admin-ui` (not the
HTTPS server directly) so the cookie domain matches.

**`cargo run` fails with "address already in use"**

Another process is using port 8443. Find and stop it:

```bash
lsof -ti :8443 | xargs kill
```

**Data is gone after restarting the server**

The dev config uses `sqlite::memory:`. Switch to a file-based DB in
`server/auth_server.dev.toml`:

```toml
connection_url = "sqlite://auth_server_dev.db"
```
