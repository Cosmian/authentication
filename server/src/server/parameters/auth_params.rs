#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SessionJwtParams {
    /// The path to the JWT EC private key PEM file used for signing session tokens
    pub jwt_ec_private_key: String,

    /// The path to the JWT EC public key PEM file used for verifying session tokens
    pub jwt_ec_public_key: String,
}

/// Signing key for `POST /certify` certificates. Deliberately separate from
/// [`SessionJwtParams`]: certificates are long-lived and always ES256, so they must never be
/// verifiable with the (possibly shorter-lived, algorithm-configurable) session JWT key.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CertificateJwtParams {
    /// The path to the certificate EC private key PEM file used for signing certificates
    pub cert_ec_private_key: String,

    /// The path to the certificate EC public key PEM file used for verifying certificates
    pub cert_ec_public_key: String,
}
