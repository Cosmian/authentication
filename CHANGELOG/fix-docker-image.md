## Bug Fixes

- `nix/docker.nix`: replace the broken static-config approach with a runtime
  entrypoint script (`docker-entrypoint.sh`) that mirrors the KMS pattern:
  resolves configuration via `AUTH_SERVER_CONF` env var →
  `/etc/auth_server/auth_server.toml` volume mount → auto-generated self-signed
  TLS certificate + minimal TOML in `/tmp/auth_server/` as a last resort; add
  `pkgs.openssl` to the runtime environment for on-startup cert generation;
  add `/tmp` (sticky-bit 1777), `/home/auth`, and `/etc/auth_server` directories;
  set `Entrypoint` to the entrypoint script.

## Testing

- `.github/scripts/test/test_docker_image.sh`: replace the broken HTTP smoke-test
  with a comprehensive HTTPS functional test suite (using `--insecure` for the
  auto-generated self-signed cert) that covers `GET /public/version`,
  `GET /public/roles`, `GET /.well-known/jwks.json`, `POST /login` (success +
  wrong password + unknown realm), `GET /whoami` (authenticated + unauthenticated).
