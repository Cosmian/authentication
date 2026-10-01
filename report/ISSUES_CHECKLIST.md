# SAML PR Review — Issue Checklist

**PR:** feat/saml-integration → remotes/origin/develop  
**Issue:** GitHub #889  
**Date:** 2026-09-23  

---

## BLOCKING ISSUES — Must Fix Before Merge

### ✋ Issue 1: SAML Store Factory Never Instantiated

- **Severity:** P1 (Runtime non-functional)
- **File:** `server/src/saml/factory.rs:20–22`
- **Problem:** `create_saml_request_store()` is never called. SAML realms have no login path.
- **Fix:** Wire factory into `start_auth_verifier()`, pass store to endpoint handlers
- **Complexity:** Medium (requires server startup refactor)
- **Blocks:** Issues 2, 3 (cleanup, expiry validation only matter once factory is used)
- **Dependency:** Follow-up PR (SAML endpoints) depends on this

- [ ] **Owner:** Fix store instantiation
- [ ] **Verification:** Confirm store is Arc<dyn SamlRequestStore> in server state
- [ ] **Testing:** Ensure factory is called during server init

---

### ✋ Issue 2: SQL Cleanup Never Scheduled

- **Severity:** P1 (Resource leak — unbounded table growth)
- **Files:**
  - `server/src/saml/impls/sqlite.rs:157–160` (delete_expired method)
  - `server/src/saml/factory.rs:17–20` (factory, no cleanup task)
- **Problem:** Expired rows never purged. Tables grow indefinitely.
- **Affected:** PostgreSQL, MySQL, SQLite
- **Unaffected:** Redis (TTL automatic)
- **Fix:** Implement background cleanup task (weekly or hourly)
- **Complexity:** Medium (similar to `start_stale_session_collector`)
- **Performance Impact:** Without fix, table scans degrade after weeks

- [ ] **Owner:** Implement cleanup collector
- [ ] **Reference Pattern:** `server/src/session/factory.rs` (start_stale_session_collector)
- [ ] **Testing:** Verify delete_expired is called; rows actually purged
- [ ] **Config:** Document cleanup interval (default: 1 hour)

---

### ✋ Issue 3: Redis Returns Expired Pending Requests

- **Severity:** P1 (Logic violation — accepts invalid requests)
- **File:** `server/src/saml/impls/redis.rs:52`
- **Problem:** `.max(1)` clamps negative TTL to 1 second. Expired requests stored + fetchable.
- **Impact:** Already-expired requests accepted within ≤1 second grace period
- **Fix:** Reject expired writes OR validate after GETDEL
- **Complexity:** Low

**Option A (Recommended):**

```rust
// In store_pending_request
if request.expires_at <= Utc::now().timestamp() {
    return Err(AuthError::Generic("Request already expired".into()));
}
```

**Option B (Alternative):**

```rust
// In take_pending_request, after GETDEL
let now = Utc::now().timestamp();
if request.expires_at <= now {
    return Ok(None);
}
```

- [ ] **Owner:** Implement fix (choose A or B)
- [ ] **Testing:** Unit test with expired request, verify rejection
- [ ] **Edge case:** Test clock skew (now() slightly advances during set_ex)

---

### ✋ Issue 4: Build Broken — samael+xmlsec Unconditional

- **Severity:** P1 (Build breaks — blocks all CI)
- **Files:**
  - `Cargo.toml` line 39 (samael = "0.0.22" with features = ["xmlsec"])
  - `server/Cargo.toml` line 49 (samael = { workspace = true })
  - `.github/workflows/main_base.yml` (no xmlsec1 installed)
  - `nix/auth-verifier.nix` (missing xmlsecStatic, libclang)
- **Problem:**
  - samael's build.rs calls xmlsec1-config, which fails without system xmlsec1 + libclang
  - Direct Cargo CI (main_base.yml) doesn't have them
  - Nix derivation doesn't provide them
  - Breaks `cargo build`, `cargo test`, `nix build`
- **Impact:** ❌ Blocks all downstream development
- **Fix:** Gate behind feature flag OR update build infra

**Option A (Recommended — Feature Flag):**

```toml
[dependencies]
samael = { version = "0.0.22", features = ["xmlsec"], optional = true }

[features]
saml = ["samael"]
```

- Default: no samael, no xmlsec needed
- Dev: `cargo build --features saml`
- Unblocks all CI until SAML endpoints ready

**Option B (Alternative — Update Build Infra):**

1. Add `xmlsec1-dev` to Ubuntu runners in main_base.yml
2. Add `libxml2-devel`, `xmlsec1-devel` to macOS via Homebrew
3. Update nix/auth-verifier.nix (see Issue 5)

- [ ] **Owner:** Implement Option A or B
- [ ] **Testing:** `cargo build`, `cargo test`, `nix build .#auth-verifier` all succeed
- [ ] **CI Validation:** Merge to develop; verify all workflows pass

---

### ✋ Issue 5: Nix Package Build Missing xmlsec Setup

- **Severity:** P1 (Build breaks — nix build fails)
- **File:** `nix/auth-verifier.nix` (not modified in PR; needs changes)
- **Problem:**
  - New file `nix/xmlsec-static.nix` + shell.nix updates are present
  - Package derivation `nix/auth-verifier.nix` NOT updated
  - Missing: `xmlsecStatic`, `libclang`, `LIBCLANG_PATH`, `BINDGEN_EXTRA_CLANG_ARGS`
  - `nix build .#auth-verifier` fails
- **Impact:** ❌ Package CI jobs fail; users can't `nix build` auth-verifier
- **Fix:** Update auth-verifier.nix OR use feature flag (Issue 4 Option A)

**If continuing with unconditional samael:**

```nix
{
  buildInputs = [
    # ... existing ...
    xmlsecStatic  # Import from xmlsec-static.nix
    pkgs.llvmPackages.libclang
  ];

  preBuild = ''
    export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
    export BINDGEN_EXTRA_CLANG_ARGS="..."
  '';
}
```

- [ ] **Owner:** Update nix/auth-verifier.nix
- [ ] **Testing:** `nix build .#auth-verifier` succeeds
- [ ] **CI:** Verify packaging workflow passes

---

### ✋ Issue 6: Pre-Release Dependency Without Audit — samael 0.0.22

- **Severity:** P1 (Dependency risk)
- **File:** `Cargo.toml` line 39 (workspace root)
- **Problem:**
  - samael 0.0.22 is pre-1.0, labeled "work-in-progress"
  - No security audit evidence
  - No documented justification for this crate
  - OpenSSL transitive deps not pinned (semver ranges allow drift)
- **Impact:** Potential upstream breaking changes; security gaps in pre-release code
- **Fix:** Document decision, add security review before shipping

- [ ] **Owner:** Create ADR (Architectural Decision Record)
  - Why samael? (criteria: SAML 2.0 compliance, active maintenance, Rust ecosystem fit)
  - Alternatives considered? (xmldsig, xml-crypto bindings, etc.)
  - Timeline for moving to stable version?
- [ ] **Owner:** Add pre-merge security review task
  - Run `/security-review` on samael crate
  - Document samael's pre-release status in SECURITY.md
  - Track timeline for upgrade to stable
- [ ] **Owner:** Pin samael and OpenSSL transitive deps

  ```toml
  samael = "=0.0.22"  # Exact version until stable
  openssl = "=0.10.81"  # Lock transitive
  ```

- [ ] **Reviewer:** Approve security audit before merge

---

## HIGH-PRIORITY ISSUES — Strongly Recommended Before Merge

### ⚠️ Issue 7: MySQL Breaks SAML ID Case-Sensitivity

- **Severity:** P2 (Data integrity — ID mismatches)
- **File:** `server/src/saml/impls/mysql.rs:24–26`
- **Problem:** Default collation `utf8mb4_general_ci` is case-insensitive. SAML IDs are case-sensitive.
- **Impact:**
  - `take_pending_request("_abc", ...)` can match `_ABC`
  - Assertion ID replay cache collisions on case difference
  - False replay positives → valid logins rejected
- **Fix:** Use binary collation

  ```sql
  request_id TEXT COLLATE utf8mb4_bin PRIMARY KEY,
  assertion_id TEXT COLLATE utf8mb4_bin PRIMARY KEY,
  ```

- **Complexity:** Low (schema change only)

- [ ] **Owner:** Update MySQL schema
- [ ] **Testing:** Unit test case-sensitivity (id='abc' vs 'ABC' treated as different)

---

### ⚠️ Issue 8: MySQL Assertion IDs Silently Truncated to 255 Chars

- **Severity:** P2 (Data integrity — false replay positives)
- **File:** `server/src/saml/impls/mysql.rs:42–45`
- **Problem:** `VARCHAR(255)` + `INSERT IGNORE` silently truncates long IDs. SAML has no length limit.
- **Impact:**
  - Distinct assertions with same 255-char prefix treated as replay
  - Valid logins denied
- **Fix:** Use TEXT or digest-based key

  ```sql
  -- Option 1: Full ID as TEXT
  assertion_id TEXT NOT NULL PRIMARY KEY,
  
  -- Option 2: Digest-based key (safer indexing)
  assertion_id_hash BLOB NOT NULL PRIMARY KEY,
  full_assertion_id TEXT NOT NULL,
  ```

- **Complexity:** Medium (schema + insert logic update)

- [ ] **Owner:** Update MySQL schema
- [ ] **Owner:** Update record_assertion_id logic
- [ ] **Testing:** Unit test with long IDs (>255 chars), verify no truncation

---

## DEFERRED WORK — Covered by Follow-up PRs

- [ ] HTTP endpoints (`/saml/{realm_id}/login`, `/saml/{realm_id}/acs`)
- [ ] SAML request handler (AuthnRequest creation, response validation, session creation)
- [ ] Server configuration for SAML parameters
- [ ] Realm admin UI for SAML setup
- [ ] E2E tests
- [ ] Documentation

---

## VALIDATION CHECKLIST

- [ ] Issue 1: Store factory wired into startup
- [ ] Issue 2: SQL cleanup scheduler implemented and running
- [ ] Issue 3: Redis expiry validation fixed
- [ ] Issue 4: samael gated OR build infra updated; `cargo build` passes on all platforms
- [ ] Issue 5: `nix build .#auth-verifier` passes
- [ ] Issue 6: ADR + security review task documented
- [ ] Issue 7: MySQL collation fixed
- [ ] Issue 8: MySQL ID truncation fixed
- [ ] Add PostgreSQL + MySQL + Redis integration tests
- [ ] All CI jobs pass (clippy, test, packaging, nix)
- [ ] Code review approved by maintainer

---

## SIGN-OFF

- [ ] **Author:** All issues acknowledged and scheduled
- [ ] **Reviewer:** All blockers verified fixed
- [ ] **CI:** Green on all platforms (Linux, macOS, Nix)
- [ ] **Ready to Merge:** Yes ✅

---

**Questions/Comments:**
(Space for reviewer notes)

---

## AUTHOR RESPONSE — Triage (2026-09-24)

Each finding was checked against the code at `58294a7` and the git history.

### Verdict per issue

| Issue | Verdict | Planned action | When |
|-------|---------|----------------|------|
| 1 — Store never instantiated | Correct, by design at this stage | Wire the store together with the endpoints (a store with no caller would only add startup state) | First endpoint (Chunk 6) |
| 2 — SQL cleanup never scheduled | **Correct, gap in the plan** | Add a periodic `delete_expired()` task, modeled on `start_stale_session_collector` | With the store wiring (Chunk 6) |
| 3 — Redis returns expired requests | **Correct** | Fix in **all four backends**: reject already-expired writes, and re-check expiry on `take` | Chunk 2c (next) |
| 4 — samael unconditional | Correct | Adopt Option A: optional `saml` Cargo feature, off by default | Step 0b (next) |
| 5 — `auth-verifier.nix` not wired | Correct | Add `xmlsecStatic` + libclang/bindgen setup, build with `--features saml`, run `nix-build -A auth-verifier-static` | Step 0b (next) |
| 6 — samael pre-1.0 | Correct as a risk; it was a deliberate choice | Write an ADR; security review of the signature-verification path before release | ADR now; review before release |
| 7 — MySQL case-insensitive IDs | **Correct** (effect: valid logins refused, not a bypass) | Binary collation for `request_id` | Chunk 2c |
| 8 — MySQL truncation | **Correct** (`INSERT IGNORE` truncates even in strict mode) | Key the replay cache by `SHA-256(assertion_id)` as `BINARY(32)` | Chunk 2c |
| Coverage — PG/MySQL/Redis untested | **Correct**; this also missed an existing convention | Run the SAML store tests against all backends through the same env-var switch as `server/src/tests/sessions_store.rs`, plus case and long-ID tests | Chunk 2c |
| SEC-01 — Redis replay-cache 1 s TTL | **Correct**, and it applies to every backend once rows are purged | `record_assertion_id` fails closed when `expires_at <= now`; the ACS must pass `NotOnOrAfter` + the same clock skew the validator accepts | Chunk 2c (store) / Chunk 5a (caller) |
| SEC-02 — `SamlParams` not validated | Correct; this is planned work | Validate metadata, origins, ACS URL and claim map at realm create/update | Chunk 3 |
| PANIC-01 — `claim_policy.rs` | Out of scope: not in this branch's diff (introduced in `d92a3f0`, release 0.4.0) | Separate ticket if wanted | — |
| ERR-01 — `AuthError::Generic` | Incorrect premise: existing session stores use `Generic` throughout, not `Db` | Consistent with the codebase; any change should be a repo-wide refactor | — |

### Proposed fixes not adopted

- **Issue 7/8, `TEXT ... PRIMARY KEY`:** MySQL rejects a `TEXT` primary key without a prefix length (error 1170).
- **Issue 8, `ON DUPLICATE KEY UPDATE expires_at = ?`:** do not use. A replay would report affected rows > 0 and be treated as a new assertion, which is a replay bypass. It would also extend the retention window.
- **Issue 6, pin `samael = "=0.0.22"`:** no effect. For `0.0.x` versions Cargo's default requirement already matches exactly `0.0.22`, and `Cargo.lock` pins the transitive OpenSSL crates.
- **Issue 6, SECURITY.md entry:** that file is reserved for vulnerabilities that shipped in a tagged release (AGENTS.md §11). The dependency rationale goes in the ADR instead.

### Proposed order

1. **Step 0b — build:** `saml` feature gate; wire and run the Nix release build; CHANGELOG entry.
2. **Chunk 2c — store hardening:** expiry contract in all backends, MySQL keys, tests on every backend.
3. **ADR** for the samael decision.
4. Continue the feature: Chunk 3 (metadata ingestion + `SamlParams` validation) → signature validation → endpoints and store wiring (with cleanup task) → admin UI → docs.

### Status update (2026-09-24)

- **Done in Step 0b — Issue 4:** optional `saml` feature (off by default); plain `cargo` builds and the existing CI jobs no longer compile samael. Servers built without it refuse `saml_params` with HTTP 400. Draft Nix-based `cargo-saml` CI job added for review.
- **Issue 5, deferred with reason:** the release build no longer compiles samael, because the feature is off by default. The Nix release derivation will be wired when SAML code first calls samael (Chunk 3/5a), since only then can the static-linkage check be meaningful.
- **Done in Chunk 2c — Issues 3, 7, 8, SEC-01 and backend coverage:** every backend refuses already-expired writes; Redis re-checks expiry on `take`; MySQL uses binary collation for IDs and `SHA-256(assertion_id)` as `BINARY(32)` replay keys. A new suite (`server/src/tests/saml_request_store.rs`) runs through `TEST_SESSIONS_STORE` and passes 10/10 against SQLite, PostgreSQL 16, MySQL 8.4 and Redis 7.
