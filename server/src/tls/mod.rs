#[cfg(feature = "openssl")]
pub mod openssl_config;
#[cfg(feature = "rustls")]
pub mod rustls_config;

/// Peer certificate extracted from a TLS handshake and inserted into request extensions.
/// Shared by both the OpenSSL and Rustls TLS backends.
///
/// The certificate is stored as raw DER bytes so the type stays independent of the
/// active TLS backend (the `rustls` build does not link OpenSSL). Consumers parse
/// the DER with whichever library they need.
#[cfg(any(feature = "openssl", feature = "rustls"))]
#[derive(Debug, Clone)]
pub struct PeerCertificate {
    pub cert_der: Vec<u8>,
}
