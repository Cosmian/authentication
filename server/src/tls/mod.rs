#[cfg(feature = "openssl")]
pub mod openssl_config;
#[cfg(feature = "rustls")]
pub mod rustls_config;

/// Peer certificate extracted from a TLS handshake and inserted into request extensions.
/// Shared by both the OpenSSL and Rustls TLS backends.
#[cfg(feature = "openssl")]
#[derive(Debug, Clone)]
pub struct PeerCertificate {
    pub cert: openssl::x509::X509,
}
