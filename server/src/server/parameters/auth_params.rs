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

/// This server's SAML Service Provider signing key, shared by all SAML realms. It signs our
/// `<AuthnRequest>`s, and its certificate is published in our SP metadata. RSA only (2048
/// bits or more): it is what IdPs universally accept.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SamlSpParams {
    /// The path to the RSA private key PEM file
    pub saml_rsa_private_key: String,

    /// The path to the X.509 certificate PEM file matching `saml_rsa_private_key`
    pub saml_certificate: String,
}
