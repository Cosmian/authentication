## Docs

- Added `SECURITY.md`, a hand-maintained security policy and vulnerability-disclosure ledger (reporting process, severity rating, per-advisory entries, summary table, best practices, cryptography notes), so the auth server has the same advisory-tracking surface as the KMS repository.
- Documented the advisory-ledger lifecycle in AGENTS.md §11 and mirrored a short pointer in `.github/copilot-instructions.md`, defining the `COSMIAN-AUTH-<YYYY>-NNN` ID scheme, the released-vs-unreleased rule, and the three-part internal-consistency requirement.

## Security

- Recorded previously shipped and fixed vulnerabilities in `SECURITY.md`: COSMIAN-AUTH-2026-001 and COSMIAN-AUTH-2026-002 (plaintext password storage via the `create_userpass`/`update_userpass` endpoints), COSMIAN-AUTH-2026-003 (TLS private key baked into the Docker image), and COSMIAN-AUTH-2026-004 (vulnerable admin UI transitive dependencies).
