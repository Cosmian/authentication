# ADR-0003 — SAML 2.0 Service Provider: samael, statically bundled xmlsec, and the `saml` feature

| Field      | Value                                          |
|------------|------------------------------------------------|
| **Status** | Accepted                                       |
| **Date**   | 2026-09-25                                     |
| **Branch** | `feat/saml-integration`                        |
| **PR**     | *(to be filled when opened)*                   |
| **Scope**  | Authentication Server (build, packaging, SAML) |

---

## Context

Authentication Verifier already authenticates humans with username/password (optionally
with TOTP), accepts JWT/OIDC bearer tokens, and authenticates machines through mTLS,
AppRole and Kubernetes. The users none of these reach are **people whose identity lives
in a corporate identity provider (IdP) that only speaks SAML 2.0**, where the organization
requires federation (no local passwords, MFA and offboarding handled by the IdP). Serving
them requires Authentication Verifier to act as a SAML **Service Provider (SP)**: redirect
the browser to the IdP, receive the IdP's signed response, verify it, and issue the usual
session JWT (`_ea_` cookie).

The security of an SP rests on XML Signature verification (XML-DSig), XML
canonicalization and XML parsing — historically the source of SAML's worst vulnerabilities
(XML Signature Wrapping, canonicalization bugs, XXE). Normative references: OASIS SAML 2.0
Core, Bindings, Profiles, Metadata and Security Considerations (`saml-*-2.0-os`).

### Problem

The Rust ecosystem has no stable, audited SAML SP library. Whatever is chosen, the
signature-verification path must be trustworthy, and the result must still ship the way
this server ships today: one binary that runs on any Linux with glibc ≥ 2.34 (Rocky
Linux 9), with statically linked dependencies (only the base system — glibc and
`libgcc_s` — is dynamic) and packages that declare no runtime dependencies.

## Decisions

### Decision 1 — Use `samael` with its `xmlsec` feature

`samael` (0.0.22, MIT, the de-facto Rust SAML 2.0 crate) covers exactly the flow we need:
SP-initiated SSO with the HTTP-Redirect/HTTP-POST bindings, response and assertion
validation helpers, and SAML metadata. Its `xmlsec` feature performs XML-DSig through
**xmlsec1**, the long-established C library used by most SAML implementations, via bindgen.

The deciding criterion is the signature-verification path: reusing a battle-tested
XML-DSig implementation is safer than writing one or adopting a young one. `samael`
itself is pre-1.0; its version is pinned by `Cargo.lock` (and a `0.0.x` requirement
already matches a single version), and its verification path gets a dedicated security
review before SAML is released.

### Decision 2 — Bundle xmlsec and libxml2 statically, built for glibc 2.34

`nix/xmlsec-static.nix` builds **xmlsec 1.3.5** and **libxml2 2.13.4** from current
upstream sources (taken from the pinned nixpkgs) with the glibc-2.34 toolchain used for
release builds, as static archives:

- **OpenSSL backend only** (`--without-gnutls --without-gcrypt --without-nss`), linked
  directly (`--disable-crypto-dl`, so no `libltdl`). At link time its OpenSSL symbols
  resolve against the server's **vendored OpenSSL**; OpenSSL 3.0 headers are used only to
  compile. This keeps a single OpenSSL in the process.
- **No XSLT** (`--without-libxslt`): SAML never needs XSLT transforms, and they are an
  attack surface in signed XML. The resulting build also has HTTP/FTP fetching and MD5
  compiled out.
- The library descriptors (`.pc`, `xmlsec1-config`) are patched so that no shared OpenSSL
  library directory reaches the linker.

`shell.nix` provides this library plus libclang and the bindgen include setup needed to
compile `samael`.

Verified on Linux x86_64 (a test binary that calls into xmlsec): its only shared
dependencies are `libc`, `libm`, `libgcc_s` and the dynamic loader — the same list as the
current release binary; it embeds exactly one OpenSSL (3.6.2, the vendored copy); the
bundled archives reference no glibc symbols newer than 2.34; the size cost is under
3 MB on a 35 MB binary.

Wiring the Nix release derivation (`nix/auth-verifier.nix`) is deferred until SAML code
first calls `samael` from the server binary; before that, the linker drops the library
and a release-build linkage check would prove nothing.

### Decision 3 — Put the whole server-side SAML feature behind an optional `saml` feature

`saml = ["dep:samael"]`, **off by default**, modelled on `swagger-ui` and `admin-ui`:
the server-side SAML module (request store, factory, and later metadata, verification and
the `/saml/...` routes) compiles only with the feature. Default builds, plain `cargo` and
the existing CI jobs therefore need no C toolchain; a dedicated Nix-based CI job builds and
tests with the feature on.

The API contract types in the `auth_client` crate (`SamlParams`,
`RealmAuthParams.saml_params`, `AuthScheme::Saml`) are **not** gated. The client crate
never gates wire types (the scheme enum already lists methods the server does not
implement), and a client compiled without them would silently drop `saml_params` when
reading and re-saving a realm, because unknown fields are ignored. Instead, a server built
without `saml` refuses realm create/update requests carrying `saml_params` (HTTP 400), so
unusable configuration is never stored.

### Decision 4 — v1 protocol scope

- **SP-initiated Web Browser SSO only.** Every response must answer an `AuthnRequest` this
  server issued (`InResponseTo` correlation); unsolicited IdP-initiated responses are
  rejected, which removes a class of login-CSRF and injection attacks.
- **HTTP-Redirect** for the `AuthnRequest`, which is **signed**; **HTTP-POST** for the
  response. No Artifact or URI binding.
- **Signed assertions over TLS**; encrypted assertions are not supported.
- **No Single Logout**: logging out ends the local session only.
- **IdP metadata is pasted by an administrator** and validated when the realm is saved;
  no metadata URL fetching.

Anything outside this scope is added only for a concrete client need.

### Decision 5 — One server-wide RSA signing key, configured in the server file

The SP signing key (it signs our `AuthnRequest`s, and its certificate is published in
our SP metadata) is a single key shared by all SAML realms. It is set as two PEM file
paths in a new `[saml_sp_params]` section, the same way as the session and certificate
JWT keys, and never goes through the database or the admin API. `SamlParams` therefore
has no signing-key field.

- **RSA only, at least 2048 bits.** RSA is what IdPs universally accept. `samael` also
  signs with EC keys, but it emits DER-encoded ECDSA signatures where XML-DSig expects
  the raw `r‖s` form, which strict IdPs reject.
- **Checked at startup.** An unreadable file, a non-RSA or too-small key, or a
  certificate that doesn't match the key stops the server. A server built without `saml`
  refuses to start with the section set rather than ignoring it.
- **Required for SAML realms.** Realm create/update refuses `saml_params` (HTTP 400)
  while no key is configured.

Per-realm keys would only matter if one server fronted tenants that must not share an SP
identity; they can be added then without changing the realm API for existing realms.

## Consequences

### Positive

- No new runtime dependency for customers; packages stay dependency-free.
- One OpenSSL in the process, and a smaller attack surface (no XSLT, no network fetching,
  no runtime plugin loading).
- Builds without SAML are unaffected, and unused SAML configuration cannot be stored.

### Negative / risks

- **We own security updates for xmlsec and libxml2.** Because they are compiled in,
  operating-system updates no longer patch them. An advisory in either library requires
  bumping their sources (via the pinned nixpkgs) and shipping a new release.
- **Pre-1.0 dependency**: `samael` may change its API between releases and has no public
  audit; mitigated by version pinning and the pre-release security review.
- **Building with `saml` requires the Nix shell** (bundled xmlsec, libclang); plain `cargo`
  can only build without it.
- **Platform coverage**: the bundled build is verified on Linux x86_64 only so far;
  ARM64 and macOS must be verified before they ship SAML.

## Alternatives considered

### A — Pure-Rust XML-DSig (`bergshamra` crates, `uppsala`)

**Rejected for now**: no C dependency, but the crates are about seven months old
(0.9 / 0.10), unaudited, and not integrated with `samael`. Revisit once one reaches
maturity or an audit and is usable with a SAML library.

### B — Implement XML-DSig and canonicalization ourselves

**Rejected**: this is precisely the code where SAML vulnerabilities historically occur;
re-implementing it would trade a dependency risk for a larger, untested one.

### C — Link the distribution's shared xmlsec1

**Rejected**: it would be the first runtime package dependency; the distribution's
version varies per target (the glibc-2.34 package set only offers xmlsec 1.2.33 and
libxml2 2.9.14); and xmlsec would load the system's shared OpenSSL next to the server's
vendored one.

### D — Accept SAML assertions from a third party instead of being the SP (RFC 7522-style)

**Rejected**: assertions are bound to a specific audience and recipient and are single-use,
so someone must still act as the SP to obtain them, and the XML-DSig work remains. The
browser SP flow serves the target users directly.

## Related documents

- `nix/xmlsec-static.nix` — the bundled xmlsec/libxml2 build.
- `shell.nix` — development shell providing the bundled library and bindgen setup.
- `server/Cargo.toml` — the `saml` feature definition.
- OASIS SAML 2.0 standard: <https://www.oasis-open.org/standard/saml/>
- `samael`: <https://github.com/njaremko/samael>
