## Security

- Bump `actix-files` to 0.7 and update `actix-web`/`actix-http` to fix RUSTSEC-2026-0443, -0446, -0448 and -0455 flagged by `cargo deny`.
- Accept RUSTSEC-2026-0459 (bundled SQLite via `libsqlite3-sys`) in `deny.toml` because `sqlx-sqlite` caps `libsqlite3-sys` below the patched 0.39, and drop the now-unneeded RUSTSEC-2026-0258 ignore.
- Update admin-ui dependencies within their semver ranges to clear the `source-map-js` advisory and most `pnpm audit` findings, and regenerate the admin-ui pnpm Nix hashes.
