# Security Policy

- [Security Policy](#security-policy)
  - [Reporting a Vulnerability](#reporting-a-vulnerability)
  - [Severity Rating](#severity-rating)
  - [Known Vulnerabilities](#known-vulnerabilities)
    - [2026](#2026)
      - [COSMIAN-AUTH-2026-001 — Plaintext password storage via create\_userpass endpoint](#cosmian-auth-2026-001--plaintext-password-storage-via-create_userpass-endpoint)
      - [COSMIAN-AUTH-2026-002 — Plaintext password storage via update\_userpass endpoint](#cosmian-auth-2026-002--plaintext-password-storage-via-update_userpass-endpoint)
      - [COSMIAN-AUTH-2026-003 — TLS private key baked into the Docker image](#cosmian-auth-2026-003--tls-private-key-baked-into-the-docker-image)
      - [COSMIAN-AUTH-2026-004 — Vulnerable admin UI transitive dependencies](#cosmian-auth-2026-004--vulnerable-admin-ui-transitive-dependencies)
  - [Summary Table](#summary-table)
  - [Security Best Practices](#security-best-practices)
  - [Cryptography](#cryptography)
  - [Security Audits](#security-audits)
  - [Contact](#contact)

---

## Reporting a Vulnerability

We take the security of the Cosmian Authentication Server seriously. If you
discover a security vulnerability, please report it responsibly:

1. **Do not** report security vulnerabilities through public GitHub issues.
2. **GitHub Security Advisories** (preferred): Use the [private vulnerability reporting feature](https://github.com/Cosmian/authentication/security/advisories/new).
3. **Email**: Send details to [tech@cosmian.com](mailto:tech@cosmian.com).

**What to include:** A clear description, steps to reproduce, potential impact,
and suggested fix if available.

**Response timeline:**

- **Acknowledgement**: within 48 hours
- **Investigation**: within 5 business days
- **Fix**: as quickly as possible, coordinated disclosure with the reporter

---

## Severity Rating

| Rating   | Description                                                                                                    |
| -------- | ------------------------------------------------------------------------------------------------------------- |
| Critical | Full authentication bypass, session forgery, or unauthenticated privilege escalation affecting any deployment |
| High     | Credential or key exposure, super-admin/realm-admin privilege escalation, or 2FA bypass under realistic attack |
| Moderate | Requires specific conditions or limited scope; no direct credential compromise                                |
| Low      | Minimal practical impact, build-time only, or very difficult to exploit                                       |

The auth-server threat model prioritises: authentication bypass, session cookie
forgery or hijacking, escalation between realm admins and super admins,
TOTP/2FA bypass, password or credential exposure at rest, machine-authentication
token leakage, and violations of the exclusive-ownership rule between admins.

---

## Known Vulnerabilities

### 2026

#### COSMIAN-AUTH-2026-001 — Plaintext password storage via create\_userpass endpoint

| Field      | Value                                        |
| ---------- | -------------------------------------------- |
| Severity   | High                                         |
| Published  | 16 July 2026                                 |
| Affected   | from 0.1.0 before 0.2.1                       |
| Fixed in   | 0.2.1                                        |
| Found by   | Cosmian engineering                          |
| References | [CHANGELOG](CHANGELOG.md), CWE-256, CWE-312  |

**Summary:** The `create_userpass` endpoint stored the password bytes supplied
by the client verbatim, without hashing. Because `validate_userpass` compares
the stored value against an Argon2id hash of the incoming password, every
username/password login for API-created credentials failed, while the plaintext
password remained persisted in the database.

**Impact:** Password confidentiality at rest was lost for credentials created
through the API: an attacker with read access to the database could recover the
users' cleartext passwords. Logins for those credentials were also broken until
the credential was recreated.

**Mitigation:** Upgrade to 0.2.1. The endpoint now calls
`hash_password_with_argon2` before persisting the record, so only the Argon2id
hash is stored.

---

#### COSMIAN-AUTH-2026-002 — Plaintext password storage via update\_userpass endpoint

| Field      | Value                                        |
| ---------- | -------------------------------------------- |
| Severity   | Moderate                                     |
| Published  | 6 August 2026                                |
| Affected   | from 0.1.0 before 0.3.0                       |
| Fixed in   | 0.3.0                                        |
| Found by   | Cosmian engineering                          |
| References | [CHANGELOG](CHANGELOG.md), CWE-256, CWE-312  |

**Summary:** The `update_userpass` endpoint shared the root cause of
COSMIAN-AUTH-2026-001: on a password reset (non-empty password bytes), the new
password was stored verbatim instead of being hashed.

**Impact:** Password confidentiality at rest was lost whenever a credential's
password was reset through the API. The exposure window was narrower than
COSMIAN-AUTH-2026-001 because it required an explicit password-reset call.

**Mitigation:** Upgrade to 0.3.0. Non-empty password bytes are now hashed with
Argon2id before storage; an empty `password: []` (roles/flags-only update)
preserves the existing hash.

---

#### COSMIAN-AUTH-2026-003 — TLS private key baked into the Docker image

| Field      | Value                                        |
| ---------- | -------------------------------------------- |
| Severity   | High                                         |
| Published  | 6 August 2026                                |
| Affected   | from 0.1.0 before 0.3.0                       |
| Fixed in   | 0.3.0                                        |
| Found by   | Cosmian engineering                          |
| References | [CHANGELOG](CHANGELOG.md), CWE-321           |

**Summary:** The published Docker image bundled a TLS server certificate and its
private key at build time. Every deployment based on the image therefore shared
the same, publicly retrievable private key.

**Impact:** Anyone with access to the image could extract the TLS private key and
impersonate the server or mount a man-in-the-middle attack against clients that
trusted the baked-in certificate.

**Mitigation:** Upgrade to 0.3.0. The container entrypoint now generates a
self-signed TLS certificate at runtime; no private key is stored in the image.

---

#### COSMIAN-AUTH-2026-004 — Vulnerable admin UI transitive dependencies

| Field      | Value                                                                          |
| ---------- | ------------------------------------------------------------------------------ |
| Severity   | Low                                                                            |
| Published  | 6 August 2026                                                                  |
| Affected   | from 0.1.0 before 0.3.0                                                          |
| Fixed in   | 0.3.0                                                                          |
| Found by   | Dependabot advisory scanner                                                    |
| References | [GHSA-qwww-vcr4-c8h2](https://github.com/advisories/GHSA-qwww-vcr4-c8h2), [CHANGELOG](CHANGELOG.md) |

**Summary:** The bundled admin UI shipped with transitive dependencies carrying
published advisories: `react-router` (GHSA-qwww-vcr4-c8h2) plus `js-yaml`,
`postcss`, and `brace-expansion`.

**Impact:** Build-time and client-side dependency advisories affecting the admin
UI bundle. Practical impact on the server binary is minimal; severity is Low.

**Mitigation:** Upgrade to 0.3.0. `react-router` was migrated to v8.3.0 and the
remaining advisories were resolved via pnpm overrides (`js-yaml@5.2.2`,
`postcss@8.5.25`, `brace-expansion@5.0.9`).

---

## Summary Table

| ID                   | Severity | Affected               | Fixed in | Title                                                    |
| -------------------- | -------- | ---------------------- | -------- | -------------------------------------------------------- |
| COSMIAN-AUTH-2026-001 | High     | 0.1.0 – 0.2.0          | 0.2.1    | Plaintext password storage via `create_userpass`         |
| COSMIAN-AUTH-2026-002 | Moderate | 0.1.0 – 0.2.1          | 0.3.0    | Plaintext password storage via `update_userpass`         |
| COSMIAN-AUTH-2026-003 | High     | 0.1.0 – 0.2.1          | 0.3.0    | TLS private key baked into the Docker image              |
| COSMIAN-AUTH-2026-004 | Low      | 0.1.0 – 0.2.1          | 0.3.0    | Vulnerable admin UI transitive dependencies              |

---

## Security Best Practices

When deploying the Cosmian Authentication Server, we recommend:

1. **Keep updated**: always run the latest supported release.
2. **TLS everywhere**: terminate TLS at the server and prefer mTLS for
   service-to-service authentication.
3. **Protect the database at rest**: it holds Argon2id password hashes, session
   state, and machine-authentication token hashes.
4. **Least-privilege administration**: prefer realm admins scoped to their
   realms over super admins that can administer everything.
5. **Realm isolation**: keep each authentication domain in its own realm.
6. **Session hygiene**: configure conservative session lifetimes and secure the
   session store; the `_ea_` cookie is an opaque lookup key, so all state lives
   server-side.
7. **Monitoring**: enable logging and monitor authentication events.

---

## Cryptography

The Cosmian Authentication Server relies on the following primitives:

- **Password hashing**: Argon2id, with `salt = SHA-256(lowercase(username))`.
- **mTLS**: EC P-256 client certificates verified during the TLS handshake.
- **Transport**: TLS via vendored OpenSSL (default) or rustls (feature
  `rustls`).
- **Machine tokens**: stored as `SHA-256(hvs.<random>)`, never persisted raw.

There is no FIPS build variant — the server ships a single build variant.

---

## Security Audits

Dependency and advisory hygiene is tracked through:

- **cargo-deny** — advisory and license scanning, configured in
  [`deny.toml`](deny.toml).
- **cargo-audit** — RustSec advisory scanning, configured in
  [`.cargo/audit.toml`](.cargo/audit.toml).
- **Dependabot** — automated dependency updates, configured in
  [`.github/dependabot.yml`](.github/dependabot.yml).
- **pre-commit** — includes `detect-private-key` and related hooks; see
  [`.pre-commit-config.yaml`](.pre-commit-config.yaml).

---

## Contact

For general security questions or concerns, contact
[tech@cosmian.com](mailto:tech@cosmian.com).

For vulnerability reports, use the private reporting methods described in
[Reporting a Vulnerability](#reporting-a-vulnerability).
