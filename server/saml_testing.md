# Testing the SAML branch

A hands-on guide to check SAML single sign-on (`feat/saml-integration`) on your machine:
build the server and the admin UI, start a local identity provider, and sign in through it.
Every command below was run as written.

You will test two things: **the server** (SAML login, metadata, security checks) and **the
admin UI** (configuring a realm for SAML). The product documentation is in
[`documentation/docs/saml.md`](documentation/docs/saml.md); this guide only covers testing.

---

## What you need

| Tool | Why |
|------|-----|
| [Nix](https://nixos.org/download) | The SAML build links the C libraries xmlsec/libxml2, which the repo's `nix-shell` provides. Only needed to **build**; the built server runs anywhere. If `nix-shell` is "command not found" after installing, see [If something goes wrong](#if-something-goes-wrong). |
| Docker | Runs a local identity provider (Keycloak). |
| Node 22.12+ and pnpm | Builds the admin UI. |
| `curl`, `openssl` | Used in the checks. |

Use **two terminals**: one for the server (it stays running), one for everything else. Run
every command from the repository root.

---

## 1. Get the code and run the automated tests

```bash
git checkout feat/saml-integration
nix-shell --run "cargo test -p auth_verifier --features saml --lib -- saml --test-threads=4"
(cd admin-ui && pnpm install && pnpm test:unit)
```

The first `nix-shell` builds xmlsec and takes a while; later runs are quick. All tests should
pass. (The complete server suite is `cargo test --workspace --features auth_verifier/saml
--lib -- --test-threads=4` and takes about ten minutes; it is not required for this guide.)

## 2. Build the server and the admin UI

```bash
nix-shell --run "cargo build -p auth_verifier --features saml"   # -> target/debug/auth_verifier
(cd admin-ui && pnpm build)                                      # -> admin-ui/dist
```

Release-style build, if you want it: `nix-build -A auth-verifier-static-saml`.

## 3. Start the server (terminal 1)

The development config already has a commented SAML signing-key block. Enable it in a copy,
with a fresh database. Do this only while no server is running:

```bash
rm -f /tmp/saml-guide.db
sed -e 's/^# \[saml_sp_params\]/[saml_sp_params]/' \
    -e 's/^# saml_rsa_private_key/saml_rsa_private_key/' \
    -e 's/^# saml_certificate/saml_certificate/' \
    -e 's#sqlite:///tmp/path.db#sqlite:///tmp/saml-guide.db#' \
    server/auth_verifier.dev.toml > /tmp/saml-guide.toml
```

Start the server:

```bash
./target/debug/auth_verifier /tmp/saml-guide.toml
```

**This command does not return.** The server runs in this terminal, printing log lines, until
you press Ctrl-C. That is expected: leave it running and use a second terminal for everything
else. To stop or restart it, press Ctrl-C here first (never delete `/tmp/saml-guide.db` while
it runs).

From the second terminal, check that it answers (a debug build needs a little while to start):

```bash
curl -sk https://127.0.0.1:8443/public/version
```

Notes:

- The server uses **HTTPS on port 8443** with a self-signed test certificate. Ignore the
  comments at the top of the dev config that mention plain HTTP on 8080.
- Always use **`127.0.0.1`**, not `localhost`: the test certificate is issued for that address.
- In your browser, open <https://127.0.0.1:8443/admin-ui/> once and accept the certificate
  warning.
- Admin UI login: `admin` / `change_me`.

## 4. Start the identity provider (terminal 2)

Keycloak plays the company IdP. This creates a `demo` realm with a user `alice`, her groups,
and a SAML client for your server, which trusts your server's signing certificate, so
Keycloak really verifies the signature on your server's requests:

```bash
SP_CERT=$(grep -v -- '-----' server/src/tests/certificates/rsa/auth.server.cert.pem | tr -d '\n')
mkdir -p /tmp/kc && cat > /tmp/kc/demo-realm.json <<EOF
{
  "realm": "demo", "enabled": true, "sslRequired": "none",
  "groups": [{ "name": "admins" }, { "name": "users" }],
  "users": [{
    "username": "alice", "email": "alice@example.com", "emailVerified": true,
    "firstName": "Alice", "lastName": "Tester", "enabled": true,
    "groups": ["/admins", "/users"],
    "credentials": [{ "type": "password", "value": "alice-pw", "temporary": false }]
  }],
  "clients": [{
    "clientId": "https://127.0.0.1:8443/saml/sso-demo", "protocol": "saml", "enabled": true,
    "redirectUris": ["https://127.0.0.1:8443/saml/sso-demo/acs"],
    "attributes": {
      "saml_assertion_consumer_url_post": "https://127.0.0.1:8443/saml/sso-demo/acs",
      "saml.assertion.signature": "true", "saml.server.signature": "false",
      "saml.client.signature": "true", "saml.signature.algorithm": "RSA_SHA256",
      "saml.signing.certificate": "$SP_CERT",
      "saml.authnstatement": "true", "saml_name_id_format": "username"
    },
    "protocolMappers": [
      { "name": "username", "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
        "config": { "user.attribute": "username", "attribute.name": "username", "attribute.nameformat": "Basic" } },
      { "name": "email", "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
        "config": { "user.attribute": "email", "attribute.name": "email", "attribute.nameformat": "Basic" } },
      { "name": "groups", "protocol": "saml", "protocolMapper": "saml-group-membership-mapper",
        "config": { "attribute.name": "groups", "attribute.nameformat": "Basic", "full.path": "false", "single": "false" } }
    ]
  }]
}
EOF

docker run -d --rm --name kc-saml-demo -p 9443:9443 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HTTPS_PORT=9443 -e KC_HOSTNAME=https://127.0.0.1:9443 \
  -e KC_HTTPS_CERTIFICATE_FILE=/certs/auth.server.cert.pem \
  -e KC_HTTPS_CERTIFICATE_KEY_FILE=/certs/auth.server.key.pem \
  -v "$PWD/server/src/tests/certificates/ec:/certs:ro" \
  -v /tmp/kc/demo-realm.json:/opt/keycloak/data/import/demo-realm.json:ro \
  quay.io/keycloak/keycloak:26.4 start-dev --import-realm
```

The first run downloads the image and Keycloak needs a few seconds to start, so the command
below fails (`curl: (35)` or `(7)`) until it is ready; just rerun it. It saves the IdP's
metadata, which you will paste into the admin UI:

```bash
curl -sk https://127.0.0.1:9443/realms/demo/protocol/saml/descriptor -o /tmp/idp-metadata.xml && wc -c /tmp/idp-metadata.xml
```

When you paste it in step 5, copy it **from this file** (`cat /tmp/idp-metadata.xml`, or open it
in an editor), not from the descriptor URL in a browser. A browser shows the XML as a tree, and
copying from that view loses the `xmlns:` declarations on the first line, which makes the
admin UI reject it as "not well-formed XML".

Use the **`demo`** realm created by the import, exactly as written above. Do not create a
Keycloak realm by hand: it would have no SAML client for your server and no user, and sign-in
would fail with "Invalid requester".

Open <https://127.0.0.1:9443/> in your browser once and accept its certificate warning too
(the IdP has its own address, so it needs its own exception). The Keycloak admin console is at
`https://127.0.0.1:9443/admin` (`admin` / `admin`), the demo user is `alice` / `alice-pw`.

## 5. Create a SAML realm in the admin UI

1. Sign in at <https://127.0.0.1:8443/admin-ui/> as `admin` / `change_me`.
2. **Realms → Create Realm**, Realm ID **`sso-demo`** (it must be exactly this: the IdP was set
   up for it). Two different realms are involved: `sso-demo` is the realm on **your server**,
   `demo` is the realm inside **Keycloak** (the IdP).
3. Tick **SAML 2.0 (single sign-on)**. The SAML settings appear in the drawer, in the order of
   the table below. **Scroll down inside the drawer**: the last section, "After sign-in",
   holds two **required** fields that are easy to miss.
4. Fill in the fields, then click **Create** at the bottom of the drawer.

| Drawer section | Field | Value | Required |
|----------------|-------|-------|----------|
| (top) | Realm ID | `sso-demo` | Yes |
| IdP metadata | IdP metadata XML | The content of `/tmp/idp-metadata.xml` | Yes |
| This server | SP entity ID | Prefilled: `https://127.0.0.1:8443/saml/sso-demo` | Yes |
| This server | Assertion Consumer Service URL | Prefilled: `https://127.0.0.1:8443/saml/sso-demo/acs` | Yes |
| Identity mapping | Subject attribute | `username` | No, but needed here (see below) |
| Identity mapping | Role attribute | `groups` | No |
| Identity mapping | Extra claims | Click **Add claim mapping**: attribute `email`, claim `mail` | No |
| After sign-in | **Allowed return origins** | `https://127.0.0.1:8443`, then press **Enter** so it becomes a tag | **Yes** |
| After sign-in | **Default return URL** | `https://127.0.0.1:8443/whoami?realm=sso-demo` | **Yes** |

Notes:

- As soon as the metadata is pasted, a **summary panel** appears: IdP entity ID `https://127.0.0.1:9443/realms/demo`, the sign-in URL and the signing certificate with a green validity tag.
- **The Create button stays greyed out, with no message, until every required field is filled.** If it won't enable, check the two "After sign-in" fields at the bottom first. The default return URL must be under one of the allowed origins.
- Without a subject attribute, the user name would be Keycloak's opaque persistent NameID (something like `G-d56e48b8-…`) instead of `alice`.

The realm card now shows a **SAML** tag. Reopen it with **Edit**: the **Download SP metadata**
button gives the file an IdP administrator would import.

## 6. Sign in through the IdP

In the browser, open:

```text
https://127.0.0.1:8443/saml/sso-demo/login
```

You are sent to Keycloak; sign in as `alice` / `alice-pw`. You land on
`/whoami?realm=sso-demo`, which shows the session your server issued:

```json
{"sub":"alice", "roles":["admins","users"], "as_as":"sa", "as_rid":"sso-demo", "mail":"alice@example.com", …}
```

`as_as: "sa"` means the session came from SAML; `roles` and `mail` came from the IdP's
attributes through your mapping. The browser now holds the `_ea_` session cookie, exactly as
after any other login.

---

## 7. Things worth trying

### In the admin UI (edit the `sso-demo` realm)

| Do | Expect |
|----|--------|
| Replace the metadata with `<not-xml` | An error **under** the field; your text stays as typed; the summary disappears. |
| Add an extra claim named `sub` (or `roles`, `iss`…) | "'sub' is a reserved claim name" under that field, and Save is disabled. |
| Add the return origin `http://127.0.0.1:8443/x` | "must be an https origin…". |
| Change the ACS URL to end with `/saml/other/acs` | "must end with /saml/sso-demo/acs". |
| Edit the seeded realm `dev-realm` (no TOTP) | **TOTP stays unticked** and **Save is disabled** until you change something. (This branch fixes a bug that switched TOTP on.) |

To see the **certificate expiry warning**, paste metadata carrying a certificate that expires
in 10 days:

```bash
EXP=$(openssl req -x509 -newkey rsa:2048 -nodes -days 10 -subj "/CN=expiring-idp" \
      -keyout /dev/null 2>/dev/null | grep -v -- '-----' | tr -d '\n')
sed -E "s|(<ds:X509Certificate>)[^<]*|\1$EXP|" /tmp/idp-metadata.xml > /tmp/idp-metadata-expiring.xml
```

The summary shows an orange **"Expires in 10 days"** tag and, once saved, so does the realm
card. Logins fail while this certificate is saved (it isn't Keycloak's), so paste
`/tmp/idp-metadata.xml` back afterwards. Dark mode is stored in the browser: run
`localStorage.setItem("admin-ui-darkMode","true")` in the browser console and reload.

### On the server

| Do | Expect |
|----|--------|
| `curl -sk https://127.0.0.1:8443/saml/sso-demo/metadata` | XML with `AuthnRequestsSigned="true"` and your signing certificate. |
| `curl -sk -o /dev/null -w "%{http_code}\n" -G --data-urlencode "return_to=https://evil.example.com/" https://127.0.0.1:8443/saml/sso-demo/login` | `400`: only the allowed origin is accepted (`https://127.0.0.1:8443/…` gives `302`). |
| `curl -sk -X POST -d 'SAMLResponse=eA==&RelayState=x' https://127.0.0.1:8443/saml/sso-demo/acs` | `401 … not started from this browser`: an ACS call without the login cookie is refused. |
| `curl -sk -o /dev/null -w "%{http_code}\n" https://127.0.0.1:8443/saml/dev-realm/login` | `400`: that realm doesn't use SAML. |

**The IdP must sign.** Ask Keycloak to stop signing, then sign in again:

```bash
K="docker exec kc-saml-demo /opt/keycloak/bin/kcadm.sh"
$K config credentials --server http://localhost:8080 --realm master --user admin --password admin
CID=$($K get clients -r demo -q clientId=https://127.0.0.1:8443/saml/sso-demo --fields id --format csv --noquotes | tr -d '\r')
$K update clients/$CID -r demo -s 'attributes."saml.assertion.signature"=false'
```

The login now ends with `401 … SAML Response and all assertions must be signed`. Restore it
with the same command and `=true`.

**Bad signing key.** Stop the server, point `saml_certificate` in `/tmp/saml-guide.toml` at
`server/src/tests/certificates/rsa/auth.user1.cert.pem`, and start it: it refuses to start
with `saml_certificate does not match saml_rsa_private_key`. Undo the change afterwards.

---

## If something goes wrong

| Symptom | Likely cause |
|---------|--------------|
| The admin UI says the metadata is "not well-formed XML" | The XML was copied from a browser page, which drops the `xmlns:` declarations on the first line (the real document starts with `<md:EntityDescriptor xmlns="urn:oasis:…" xmlns:md=… xmlns:ds=…`). Copy it from the saved file instead: `cat /tmp/idp-metadata.xml`. |
| Keycloak shows "Invalid requester" and you made your own Keycloak realm | Only the imported `demo` realm has the SAML client and the user `alice`. Use `https://127.0.0.1:9443/realms/demo/protocol/saml/descriptor` for the metadata. |
| Login or saving fails with `500 … attempt to write a readonly database` | The database file was deleted or replaced while the server was running. Press Ctrl-C in terminal 1 and redo step 3 from the top. |
| Server exits at start with `Address already in use` | Another server is still running on port 8443. Press Ctrl-C in its terminal (or `pkill -f target/debug/auth_verifier`), then start again. |
| `nix-shell: command not found` | Nix is installed but not on this terminal's PATH (common in an editor's integrated terminal, which can inherit a "Nix already loaded" marker without the PATH). Run `unset __ETC_PROFILE_NIX_SOURCED; . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh` in that terminal, or open a fresh login shell. |
| Browser shows a certificate warning page | Expected: accept it for both `https://127.0.0.1:8443` and `https://127.0.0.1:9443`. |
| Keycloak shows "Invalid requester" or a signature error | The realm ID or URLs differ from `sso-demo` / `https://127.0.0.1:8443`, or you used `localhost`. |
| `401 unknown or expired sign-in request` | The login took over 10 minutes, or was already used. Start again from `/saml/sso-demo/login`. |
| `404` on `/saml/...` | The server was started with the original dev config (no `[saml_sp_params]`) or is not the SAML build. |
| Server exits at start with `built without the saml feature` | Rebuild with `--features saml` inside `nix-shell` (step 2). |
| Keycloak still shows old settings | It only imports the realm file on a fresh container: `docker rm -f kc-saml-demo` and rerun step 4. |

## Clean up

```bash
docker rm -f kc-saml-demo          # stops Keycloak
rm -rf /tmp/kc /tmp/saml-guide.*   # test files and database
# stop the server with Ctrl-C in terminal 1
```
