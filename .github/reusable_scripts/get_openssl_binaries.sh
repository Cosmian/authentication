#!/usr/bin/env bash
# No-op: auth_server uses openssl-sys with the `vendored` feature, which downloads
# and compiles OpenSSL from source during the Cargo build.
# No pre-built OpenSSL binaries are required.
echo "auth_server uses vendored OpenSSL — no pre-built binaries needed."
