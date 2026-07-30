## Bug Fixes

- Set binary permissions to `0755` (from `0500`) in DEB and RPM packaging metadata (`server/Cargo.toml`) so the `cosmian` user can execute `auth_verifier` under systemd (`status=203/EXEC` was the symptom).
- Remove `actions/checkout@v6` step from Docker-container packaging-test jobs; Docker containers have no git binary and the REST API fallback does not support submodules, causing the checkout step to fail.
