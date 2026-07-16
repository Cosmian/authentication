use std::{net::TcpListener, path::PathBuf};

use crate::{
    AuthError, AuthResult,
    server::parameters::{DatabaseBackend, DatabaseParams, ServerParams, TlsParams},
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

pub fn get_default_server_params() -> AuthResult<ServerParams> {
    let port = get_free_port()?;

    let cargo_manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .map_err(|_e| AuthError::Unexpected("Failed to find cargo manifest dir".to_owned()))?,
    );
    let certificates_dir = cargo_manifest_dir.join("src/tests/certificates/ec");

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
