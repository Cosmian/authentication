use std::{net::TcpListener, path::PathBuf};

use crate::{
    AuthError, AuthResult,
    server::parameters::{
        CertificateJwtParams, DatabaseBackend, DatabaseParams, ServerParams, TlsParams,
    },
};

/// Allocates a free TCP port on `127.0.0.1` by asking the OS for an ephemeral
/// port (`bind(":0")`), reading back the assigned port, and immediately releasing
/// the listener.  The server is then bound to this port by actix-web.
///
/// Using `127.0.0.1` (IPv4 only) instead of `localhost` avoids the dual-stack
/// ambiguity where `localhost` may resolve to `::1` on some systems, causing the
/// readiness probe and the TLS client URL to disagree on which interface to use.
///
/// The test TLS certificate carries `IP Address:127.0.0.1` as its SAN, so
/// connecting to `https://127.0.0.1:<port>` will pass certificate verification.
fn get_free_port() -> AuthResult<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| AuthError::Unexpected(format!("failed to allocate a free test port: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| AuthError::Unexpected(format!("failed to read ephemeral port: {e}")))?
        .port();
    // Dropping `listener` releases the port; the OS will not immediately reassign
    // it to another connection, so the TOCTOU window is negligible in test contexts.
    Ok(port)
}

fn certificates_dir() -> AuthResult<PathBuf> {
    let cargo_manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .map_err(|_e| AuthError::Unexpected("Failed to find cargo manifest dir".to_owned()))?,
    );
    Ok(cargo_manifest_dir.join("src/tests/certificates/ec"))
}

pub fn get_default_server_params() -> AuthResult<ServerParams> {
    let port = get_free_port()?;
    let certificates_dir = certificates_dir()?;

    let server_params = ServerParams {
        host_name: "127.0.0.1".to_string(),
        host_port: port,
        tls_params: Some(TlsParams {
            server_certificate: certificates_dir
                .join("auth.server.cert.pem")
                .to_string_lossy()
                .to_string(),
            server_private_key: certificates_dir
                .join("auth.server.key.pem")
                .to_string_lossy()
                .to_string(),
            server_ca_chain: certificates_dir
                .join("auth.ca.pem")
                .to_string_lossy()
                .to_string(),
            client_ca_cert_chain: Some(
                certificates_dir
                    .join("auth.ca.pem")
                    .to_string_lossy()
                    .to_string(),
            ),
            #[cfg(feature = "openssl")]
            tls_cipher_suites: None,
            #[cfg(feature = "rustls")]
            tls_cipher_suites: None,
        }),
        default_username: Some("default_user".to_string()),
        database_params: Some(DatabaseParams {
            backend: DatabaseBackend::SQLite,
            connection_url: "sqlite::memory:".to_string(),
            ..Default::default()
        }),
        proxy_params: None,
        // Use TLS keys for JWT by default in tests
        session_jwt_params: None,
        certificate_jwt_params: None,
        sessions_store_params: None,
        stale_session_collector_config: None,
        dev_seed: None,
        admin_ui_path: None,
        log: None,
        roles: Vec::new(),
        allowed_origins: Vec::new(),
        login_rate_limit_per_second: 5,
        login_rate_limit_burst: 10,
    };

    Ok(server_params)
}

/// Same as [`get_default_server_params`] but with `certificate_jwt_params` configured, using
/// the `auth.user1` EC keypair fixture — deliberately a *different* key from
/// `auth.server.{key,cert}.pem` (used for the session JWT via `tls_params`), so tests can
/// verify that certificates and session tokens are cryptographically isolated.
pub fn get_default_server_params_with_certify() -> AuthResult<ServerParams> {
    let certificates_dir = certificates_dir()?;
    let mut server_params = get_default_server_params()?;
    server_params.certificate_jwt_params = Some(CertificateJwtParams {
        cert_ec_private_key: certificates_dir
            .join("auth.user1.key.pem")
            .to_string_lossy()
            .to_string(),
        cert_ec_public_key: certificates_dir
            .join("auth.user1.cert.pem")
            .to_string_lossy()
            .to_string(),
    });
    Ok(server_params)
}

mod tests {
    use crate::{AuthResult, server::parameters::ServerParams, tests::get_default_server_params};
    use jsonwebtoken::AlgorithmFamily;

    #[test]
    fn test_jwt_keys_from_tls_params() -> AuthResult<()> {
        let server_params = get_default_server_params()?;

        let decoding_key = server_params.get_jwt_decoding_key()?;
        let encoding_key = server_params.get_jwt_encoding_key()?;

        assert_eq!(decoding_key.family(), AlgorithmFamily::Ec);
        assert_eq!(encoding_key.family(), AlgorithmFamily::Ec);

        Ok(())
    }

    /// Guards against `auth_verifier.dev.toml` drifting out of sync with `ServerParams`:
    /// it must parse, and its `certificate_jwt_params` keys must actually load — this is
    /// the config new contributors copy first when trying out `/certify` locally.
    ///
    /// Resolves the TOML's repo-root-relative key paths manually and loads them directly
    /// (rather than calling `ServerParams::get_certificate_*_key`, which resolves paths
    /// against the process's current working directory — mutating that process-wide for a
    /// single test would risk flakiness under parallel test execution).
    #[test]
    fn test_dev_toml_certificate_jwt_params_loads() -> AuthResult<()> {
        // Paths in the TOML are relative to the repo root (documented invocation:
        // `cargo run -p auth_verifier -- server/auth_verifier.dev.toml` from `authentication/`).
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let repo_root = std::path::Path::new(manifest_dir)
            .parent()
            .expect("server/ crate has a parent directory");
        let toml_path = repo_root.join("server/auth_verifier.dev.toml");
        let raw = std::fs::read_to_string(&toml_path)
            .unwrap_or_else(|e| panic!("failed to read {toml_path:?}: {e}"));
        let params: ServerParams =
            toml::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {toml_path:?}: {e}"));
        let cert_params = params
            .certificate_jwt_params
            .expect("auth_verifier.dev.toml should configure [certificate_jwt_params]");

        let private_pem = std::fs::read_to_string(repo_root.join(&cert_params.cert_ec_private_key))
            .unwrap_or_else(|e| panic!("failed to read cert_ec_private_key: {e}"));
        let public_pem = std::fs::read_to_string(repo_root.join(&cert_params.cert_ec_public_key))
            .unwrap_or_else(|e| panic!("failed to read cert_ec_public_key: {e}"));

        jsonwebtoken::EncodingKey::from_ec_pem(private_pem.as_bytes())
            .expect("cert_ec_private_key should be a valid EC private key PEM");
        jsonwebtoken::DecodingKey::from_ec_pem(public_pem.as_bytes())
            .expect("cert_ec_public_key should be a valid EC public key/certificate PEM");
        Ok(())
    }
}
