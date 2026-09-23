mod request_store;
pub use request_store::{PendingSamlRequest, SamlRequestStore};

mod impls;
pub use impls::SqliteSamlRequestStore;

mod factory;
pub use factory::create_saml_request_store;

#[cfg(test)]
mod tests {
    use samael::crypto::{CertificateDer, Crypto, CryptoProvider};

    // Runs libxml2 + xmlsec + its OpenSSL backend end to end, so a broken or mis-linked
    // xmlsec fails here rather than at the first real SAML login.
    #[test]
    fn xmlsec_backend_rejects_an_invalid_certificate() {
        let not_a_certificate = CertificateDer::from(vec![0u8; 16]);
        let result = Crypto::verify_signed_xml("<a/>", &not_a_certificate, None);
        assert!(result.is_err());
    }
}
