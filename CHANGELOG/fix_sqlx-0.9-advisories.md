## Security

- Upgrade sqlx to 0.9.1: bundled SQLite moves to libsqlite3-sys >= 0.39 (RUSTSEC-2026-0459) and the MySQL driver no longer compiles `rsa` (RUSTSEC-2023-0071); both `deny.toml` exceptions are removed. MySQL connections that need RSA password exchange over plaintext (`caching_sha2_password`/`sha256_password` without TLS) now fail; use TLS (sqlx's default `ssl-mode=preferred` uses it when the server offers it) or `mysql_native_password`.
