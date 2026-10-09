mod request_store;
pub use request_store::{PendingSamlRequest, SamlRequestStore};

mod impls;
pub use impls::SqliteSamlRequestStore;

mod factory;
pub use factory::create_saml_request_store;

mod params_validation;
pub(crate) use params_validation::validate_saml_params;

mod sp_signing_key;
pub(crate) use sp_signing_key::load_sp_signing_key;

mod response_validation;

mod identity_mapping;

mod authn_request;

mod sp_metadata;

mod endpoints;
pub(crate) use endpoints::{MAX_SAML_FORM_BYTES, SamlState, saml_acs, saml_login, saml_metadata};

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
