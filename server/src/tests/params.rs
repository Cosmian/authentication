use std::{
    path::PathBuf,
    sync::atomic::{AtomicU16, Ordering},
};

use crate::{
    AuthError, AuthResult,
    server::parameters::{DatabaseBackend, DatabaseParams, ServerParams, TlsParams},
};

/// Atomic counter for generating unique port numbers for parallel tests.
/// Starts at 59100 and increments for each test server instance.
/// Ports below 59000 are avoided to prevent conflicts with common applications.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(59100);

pub fn get_default_server_params() -> AuthResult<ServerParams> {
    // Get a unique port for this test server instance
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);

    let cargo_manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .map_err(|_e| AuthError::Unexpected("Failed to find cargo manifest dir".to_owned()))?,
    );
    let certificates_dir = cargo_manifest_dir.join("src/tests/certificates/ec");

    let server_params = ServerParams {
        host_name: "127.0.0.1".to_string(),
        host_port: port,
        tls_params: TlsParams {
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
        },
        default_username: Some("default_user".to_string()),
        database_params: Some(DatabaseParams {
            backend: DatabaseBackend::SQLite,
            connection_url: "sqlite::memory:".to_string(),
            ..Default::default()
        }),
        proxy_params: None,
        // Use TLS keys for JWT by default in tests
        session_jwt_params: None,
        sessions_store_params: None,
        stale_session_collector_config: None,
        dev_seed: None,
        admin_ui_path: None,
        roles: Vec::new(),
    };

    Ok(server_params)
}

mod tests {
    use crate::{AuthResult, tests::get_default_server_params};
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
}
