use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};

use crate::{AuthError, AuthResult, server::parameters::SamlSpParams};

/// Smallest RSA key accepted (NIST SP 800-131A); IdPs commonly refuse anything shorter.
const MIN_RSA_BITS: u32 = 2048;

/// This server's SAML SP signing key and the certificate published for it, checked to
/// belong together.
#[expect(
    dead_code,
    reason = "the SAML endpoints that sign with it are not implemented yet"
)]
pub(crate) struct SamlSpSigningKey {
    pub(crate) private_key: PKey<Private>,
    pub(crate) certificate: X509,
}

/// Load and check the files named in `[saml_sp_params]`. Called at startup so that a bad
/// key stops the server instead of failing the first SAML login.
pub(crate) fn load_sp_signing_key(params: &SamlSpParams) -> AuthResult<SamlSpSigningKey> {
    let key_pem = read_pem_file(&params.saml_rsa_private_key)?;
    let certificate_pem = read_pem_file(&params.saml_certificate)?;
    parse_sp_signing_key(&key_pem, &certificate_pem)
}

fn read_pem_file(path: &str) -> AuthResult<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| AuthError::Init(format!("saml_sp_params: cannot read {path}: {e}")))
}

fn parse_sp_signing_key(key_pem: &[u8], certificate_pem: &[u8]) -> AuthResult<SamlSpSigningKey> {
    let private_key = PKey::private_key_from_pem(key_pem).map_err(|e| {
        init_error(&format!(
            "saml_rsa_private_key is not a PEM private key: {e}"
        ))
    })?;
    if private_key.rsa().is_err() {
        return Err(init_error("saml_rsa_private_key must be an RSA key"));
    }
    if private_key.bits() < MIN_RSA_BITS {
        return Err(init_error(&format!(
            "saml_rsa_private_key must be at least {MIN_RSA_BITS} bits, got {}",
            private_key.bits()
        )));
    }
    let certificate = X509::from_pem(certificate_pem).map_err(|e| {
        init_error(&format!(
            "saml_certificate is not a PEM X.509 certificate: {e}"
        ))
    })?;
    let certificate_key = certificate
        .public_key()
        .map_err(|e| init_error(&format!("saml_certificate has no usable public key: {e}")))?;
    if !certificate_key.public_eq(&private_key) {
        return Err(init_error(
            "saml_certificate does not match saml_rsa_private_key",
        ));
    }
    Ok(SamlSpSigningKey {
        private_key,
        certificate,
    })
}

fn init_error(message: &str) -> AuthError {
    AuthError::Init(format!("saml_sp_params: {message}"))
}

#[cfg(test)]
mod tests {
    use openssl::{pkey::PKey, rsa::Rsa};

    use super::{load_sp_signing_key, parse_sp_signing_key};
    use crate::{server::parameters::SamlSpParams, tests::helpers::test_saml_sp_params};

    fn fixture(relative_path: &str) -> String {
        format!(
            "{}/src/tests/certificates/{relative_path}",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    fn load_error(key: &str, certificate: &str) -> String {
        let params = SamlSpParams {
            saml_rsa_private_key: fixture(key),
            saml_certificate: fixture(certificate),
        };
        match load_sp_signing_key(&params) {
            Ok(_) => panic!("expected {key} + {certificate} to be refused"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn loads_a_matching_rsa_key_and_certificate() {
        assert!(load_sp_signing_key(&test_saml_sp_params()).is_ok());
    }

    #[test]
    fn refuses_a_certificate_of_another_key() {
        let error = load_error("rsa/auth.server.key.pem", "rsa/auth.user1.cert.pem");
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn refuses_a_non_rsa_key() {
        let error = load_error("ec/auth.server.key.pem", "ec/auth.server.cert.pem");
        assert!(error.contains("must be an RSA key"), "{error}");
    }

    #[test]
    fn refuses_an_rsa_key_under_2048_bits() {
        let small_key = PKey::from_rsa(Rsa::generate(1024).expect("generate RSA key"))
            .expect("wrap RSA key")
            .private_key_to_pem_pkcs8()
            .expect("encode RSA key");
        let certificate = std::fs::read(fixture("rsa/auth.server.cert.pem")).expect("read");
        let Err(error) = parse_sp_signing_key(&small_key, &certificate) else {
            panic!("expected a 1024-bit key to be refused");
        };
        assert!(error.to_string().contains("at least 2048 bits"), "{error}");
    }

    #[test]
    fn names_the_file_it_cannot_read() {
        let error = load_error("rsa/missing.key.pem", "rsa/auth.server.cert.pem");
        assert!(error.contains("rsa/missing.key.pem"), "{error}");
    }
}
