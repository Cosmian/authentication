## Bug Fixes

- Bundle the pre-built admin UI in the DEB and RPM packages under `/usr/share/auth_verifier/admin-ui` so the installed server can serve it out of the box; previously the UI was only shipped in the Docker image.

## CI

- Build the `admin-ui` Nix derivation during DEB/RPM packaging and stage its `dist/` output where `cargo-deb` and `cargo-generate-rpm` resolve asset globs, and assert the UI is present in the DEB/RPM smoke tests.
