## Bug Fixes

- Add admin UI assets to DEB and RPM package metadata in `server/Cargo.toml` so the pre-built UI is bundled at `/usr/share/auth_verifier/admin-ui/`
- Add self-signed TLS certificate generation to the Docker dev config (`nix/docker.nix`) so the server can start without user-provided certs
- Add `[tls_params]` to all CI test configurations (Docker container test, systemd test) since the server requires TLS to start
- Update `verify_running_ui.sh` and `test_docker_image.sh` to auto-detect HTTPS and use `curl -k` for self-signed certificates
