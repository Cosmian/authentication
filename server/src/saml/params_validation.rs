//! Validates a realm's SAML settings when the realm is created or updated.
//!
//! The IdP fields of [`SamlParams`] are always derived from the pasted IdP metadata, so a
//! caller cannot supply an SSO URL or signing certificate that the metadata does not state.

use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use samael::metadata::{
    EntityDescriptor, EntityDescriptorType, HTTP_REDIRECT_BINDING, IdpSsoDescriptor, de,
};
use url::Url;
use x509_cert::{
    Certificate,
    der::{Decode, EncodePem, pem::LineEnding},
};

use crate::{AuthError, AuthResult, SamlParams, reject_reserved_claim_names};

const SAML2_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const NAMEID_TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
/// Largest IdP metadata accepted. Real single-IdP metadata is well under this; federation
/// aggregates (thousands of IdPs) are not supported.
const MAX_METADATA_BYTES: usize = 256 * 1024;

fn invalid(field: &str, reason: impl std::fmt::Display) -> AuthError {
    AuthError::BadRequest(format!("saml_params.{field}: {reason}"))
}

/// Validate `params` for `realm_id` and fill in its IdP fields from `metadata_xml`.
pub(crate) fn validate_saml_params(params: &mut SamlParams, realm_id: &str) -> AuthResult<()> {
    let xml = params
        .metadata_xml
        .as_deref()
        .map(str::trim)
        .filter(|xml| !xml.is_empty())
        .ok_or_else(|| invalid("metadata_xml", "the IdP metadata XML is required"))?;
    let idp = parse_idp_metadata(xml)?;

    params.idp_entity_id = idp.entity_id;
    params.idp_sso_url = idp.sso_url;
    params.idp_signing_certificates = idp.signing_certificates;
    params.idp_nameid_format = idp.nameid_format;

    validate_sp_fields(params, realm_id)?;
    validate_identity_mapping(params)?;
    validate_return_urls(params)
}

struct IdpMetadata {
    entity_id: String,
    sso_url: String,
    signing_certificates: Vec<String>,
    nameid_format: Option<String>,
}

fn parse_idp_metadata(xml: &str) -> AuthResult<IdpMetadata> {
    if xml.len() > MAX_METADATA_BYTES {
        return Err(invalid(
            "metadata_xml",
            format!("larger than the {MAX_METADATA_BYTES}-byte limit"),
        ));
    }
    let document: EntityDescriptorType = de::from_str(xml).map_err(|e| {
        invalid(
            "metadata_xml",
            format!("not a SAML 2.0 <EntityDescriptor> document: {e}"),
        )
    })?;
    let entity: EntityDescriptor = match document {
        EntityDescriptorType::EntityDescriptor(entity) => entity,
        EntityDescriptorType::EntitiesDescriptor(_) => {
            return Err(invalid(
                "metadata_xml",
                "an <EntitiesDescriptor> bundle of several entities; paste the metadata of the single IdP",
            ));
        }
    };

    let entity_id = entity
        .entity_id
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| invalid("metadata_xml", "missing the IdP entityID"))?;
    if entity
        .valid_until
        .is_some_and(|valid_until| valid_until <= Utc::now())
    {
        return Err(invalid(
            "metadata_xml",
            "the metadata has expired (validUntil is in the past)",
        ));
    }

    let idp = entity
        .idp_sso_descriptors
        .unwrap_or_default()
        .into_iter()
        .find(|d| {
            d.protocol_support_enumeration
                .as_deref()
                .is_some_and(|p| p.split_whitespace().any(|p| p == SAML2_PROTOCOL))
        })
        .ok_or_else(|| {
            invalid(
                "metadata_xml",
                "no IDPSSODescriptor supporting the SAML 2.0 protocol",
            )
        })?;

    Ok(IdpMetadata {
        entity_id,
        sso_url: redirect_sso_url(&idp)?,
        signing_certificates: signing_certificates(&idp)?,
        nameid_format: idp.name_id_formats.first().map(|f| f.trim().to_string()),
    })
}

fn redirect_sso_url(idp: &IdpSsoDescriptor) -> AuthResult<String> {
    let service = idp
        .single_sign_on_services
        .iter()
        .find(|s| s.binding == HTTP_REDIRECT_BINDING)
        .ok_or_else(|| {
            invalid(
                "metadata_xml",
                "no SingleSignOnService with the HTTP-Redirect binding",
            )
        })?;
    let url = Url::parse(service.location.trim()).map_err(|e| {
        invalid(
            "metadata_xml",
            format!("invalid SingleSignOnService URL: {e}"),
        )
    })?;
    if url.scheme() != "https" {
        return Err(invalid(
            "metadata_xml",
            "the SingleSignOnService URL must use https",
        ));
    }
    Ok(url.to_string())
}

/// Signing certificates, as PEM. A `KeyDescriptor` without `use` applies to both signing
/// and encryption (SAML Metadata §2.4.1.1), so it counts as a signing key.
fn signing_certificates(idp: &IdpSsoDescriptor) -> AuthResult<Vec<String>> {
    let mut certificates = Vec::new();
    for key in &idp.key_descriptors {
        if key.key_use.as_deref().is_some_and(|u| u != "signing") {
            continue;
        }
        for base64_der in key
            .key_info
            .x509_data
            .iter()
            .flat_map(|data| &data.certificates)
        {
            certificates.push(der_certificate_to_pem(base64_der)?);
        }
    }
    if certificates.is_empty() {
        return Err(invalid(
            "metadata_xml",
            "no signing certificate in the IDPSSODescriptor",
        ));
    }
    Ok(certificates)
}

fn der_certificate_to_pem(base64_der: &str) -> AuthResult<String> {
    let compact: String = base64_der.chars().filter(|c| !c.is_whitespace()).collect();
    let der = STANDARD.decode(compact).map_err(|e| {
        invalid(
            "metadata_xml",
            format!("an X509Certificate is not valid base64: {e}"),
        )
    })?;
    let certificate = Certificate::from_der(&der).map_err(|e| {
        invalid(
            "metadata_xml",
            format!("an X509Certificate is not a valid certificate: {e}"),
        )
    })?;
    certificate
        .to_pem(LineEnding::LF)
        .map_err(|e| AuthError::Unexpected(format!("failed to PEM-encode a certificate: {e}")))
}

fn validate_sp_fields(params: &SamlParams, realm_id: &str) -> AuthResult<()> {
    if params.sp_entity_id.trim().is_empty() {
        return Err(invalid("sp_entity_id", "must not be empty"));
    }
    let acs = Url::parse(&params.sp_acs_url)
        .map_err(|e| invalid("sp_acs_url", format!("not a valid URL: {e}")))?;
    let expected_path = format!("/saml/{realm_id}/acs");
    if acs.scheme() != "https" || !acs.path().ends_with(&expected_path) {
        return Err(invalid(
            "sp_acs_url",
            format!("must be an https URL ending with {expected_path}"),
        ));
    }
    Ok(())
}

fn validate_identity_mapping(params: &SamlParams) -> AuthResult<()> {
    let subject_attribute_set = params
        .subject_attribute
        .as_deref()
        .is_some_and(|a| !a.trim().is_empty());
    if !subject_attribute_set && params.idp_nameid_format.as_deref() == Some(NAMEID_TRANSIENT) {
        return Err(invalid(
            "subject_attribute",
            "required because the IdP issues transient NameIDs, which change on every login",
        ));
    }

    if params
        .attribute_claim_map
        .keys()
        .any(|attribute| attribute.trim().is_empty())
    {
        return Err(invalid(
            "attribute_claim_map",
            "SAML attribute names must not be empty",
        ));
    }
    let mut claim_names = HashSet::new();
    for claim in params.attribute_claim_map.values() {
        if claim.trim().is_empty() {
            return Err(invalid(
                "attribute_claim_map",
                "claim names must not be empty",
            ));
        }
        if !claim_names.insert(claim) {
            return Err(invalid(
                "attribute_claim_map",
                format!("two SAML attributes map to the same claim '{claim}'"),
            ));
        }
    }
    reject_reserved_claim_names(params.attribute_claim_map.values()).map_err(|e| match e {
        AuthError::BadRequest(reason) => invalid("attribute_claim_map", reason),
        other => other,
    })
}

fn validate_return_urls(params: &SamlParams) -> AuthResult<()> {
    let mut allowed = HashSet::new();
    for origin in &params.allowed_return_origins {
        let url = Url::parse(origin).map_err(|e| {
            invalid(
                "allowed_return_origins",
                format!("'{origin}' is not a valid URL: {e}"),
            )
        })?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
        {
            return Err(invalid(
                "allowed_return_origins",
                format!("'{origin}' must be an https origin such as https://app.example.com"),
            ));
        }
        allowed.insert(url.origin().ascii_serialization());
    }

    let default = Url::parse(&params.default_return_url)
        .map_err(|e| invalid("default_return_url", format!("not a valid URL: {e}")))?;
    if default.scheme() != "https" {
        return Err(invalid("default_return_url", "must use https"));
    }
    if !allowed.contains(&default.origin().ascii_serialization()) {
        return Err(invalid(
            "default_return_url",
            "its origin must be listed in allowed_return_origins",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::helpers::{test_idp_certificate_base64, test_idp_metadata, test_saml_params};
    use std::collections::HashMap;
    use x509_cert::der::DecodePem;

    const REALM: &str = "acme";
    const TEST_CERT_PEM: &str = include_str!("../tests/certificates/ec/auth.server.cert.pem");

    fn valid_metadata() -> String {
        test_idp_metadata(HTTP_REDIRECT_BINDING, "https://idp.example.com/sso", "")
    }

    fn params(metadata_xml: String) -> SamlParams {
        SamlParams {
            metadata_xml: Some(metadata_xml),
            attribute_claim_map: HashMap::from([("department".to_string(), "dept".to_string())]),
            ..test_saml_params(REALM)
        }
    }

    fn rejection(mut params: SamlParams) -> String {
        match validate_saml_params(&mut params, REALM) {
            Err(AuthError::BadRequest(message)) => message,
            other => panic!("expected a BadRequest rejection, got {other:?}"),
        }
    }

    #[test]
    fn valid_settings_derive_the_idp_fields_from_the_metadata() {
        let mut params = params(valid_metadata());
        params.idp_entity_id = "https://attacker.example.com".to_string();
        params.idp_signing_certificates = vec!["-----BEGIN CERTIFICATE-----\nforged".to_string()];

        validate_saml_params(&mut params, REALM).expect("valid settings");

        assert_eq!(params.idp_entity_id, "https://idp.example.com/metadata");
        assert_eq!(params.idp_sso_url, "https://idp.example.com/sso");
        assert_eq!(params.idp_signing_certificates.len(), 1);
        let reparsed = Certificate::from_pem(params.idp_signing_certificates[0].as_bytes())
            .expect("stored certificate is valid PEM");
        let original = Certificate::from_pem(TEST_CERT_PEM.as_bytes()).expect("test certificate");
        assert_eq!(reparsed, original);
    }

    #[test]
    fn unprefixed_metadata_is_accepted() {
        let xml = valid_metadata().replace("<md:", "<").replace("</md:", "</");
        validate_saml_params(&mut params(xml), REALM).expect("unprefixed metadata");
    }

    #[test]
    fn metadata_is_required() {
        let mut params = params(String::new());
        params.metadata_xml = None;
        assert!(rejection(params).contains("saml_params.metadata_xml"));
    }

    #[test]
    fn garbage_metadata_is_rejected() {
        assert!(rejection(params("<not-saml/>".to_string())).contains("saml_params.metadata_xml"));
    }

    #[test]
    fn a_multi_entity_bundle_is_rejected_with_a_clear_message() {
        let bundle = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">{}</md:EntitiesDescriptor>"#,
            valid_metadata().replace(r#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata""#, "")
        );
        assert!(rejection(params(bundle)).contains("single IdP"));
    }

    #[test]
    fn oversized_metadata_is_rejected() {
        let padding = format!("<!--{}-->", "x".repeat(MAX_METADATA_BYTES));
        let xml = valid_metadata().replace(
            "<md:IDPSSODescriptor",
            &format!("{padding}<md:IDPSSODescriptor"),
        );
        assert!(rejection(params(xml)).contains("limit"));
    }

    #[test]
    fn expired_metadata_is_rejected() {
        let xml = valid_metadata().replace(
            "entityID=",
            r#"validUntil="2000-01-01T00:00:00Z" entityID="#,
        );
        assert!(rejection(params(xml)).contains("expired"));
    }

    #[test]
    fn metadata_without_a_redirect_sso_service_is_rejected() {
        let xml = test_idp_metadata(
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "https://idp.example.com/sso",
            "",
        );
        assert!(rejection(params(xml)).contains("HTTP-Redirect"));
    }

    #[test]
    fn a_plain_http_sso_url_is_rejected() {
        let xml = test_idp_metadata(HTTP_REDIRECT_BINDING, "http://idp.example.com/sso", "");
        assert!(rejection(params(xml)).contains("https"));
    }

    #[test]
    fn metadata_without_a_signing_certificate_is_rejected() {
        let xml = valid_metadata().replace(r#"use="signing""#, r#"use="encryption""#);
        assert!(rejection(params(xml)).contains("signing certificate"));
    }

    #[test]
    fn a_corrupt_certificate_is_rejected() {
        let xml =
            valid_metadata().replace(&test_idp_certificate_base64(), "bm90IGEgY2VydGlmaWNhdGU=");
        assert!(rejection(params(xml)).contains("not a valid certificate"));
    }

    #[test]
    fn an_acs_url_for_another_realm_is_rejected() {
        let mut params = params(valid_metadata());
        params.sp_acs_url = "https://auth.example.com/saml/other-realm/acs".to_string();
        assert!(rejection(params).contains("saml_params.sp_acs_url"));
    }

    #[test]
    fn transient_nameids_require_a_subject_attribute() {
        let transient = format!("<md:NameIDFormat>{NAMEID_TRANSIENT}</md:NameIDFormat>");
        let xml = test_idp_metadata(
            HTTP_REDIRECT_BINDING,
            "https://idp.example.com/sso",
            &transient,
        );
        assert!(rejection(params(xml.clone())).contains("saml_params.subject_attribute"));

        let mut with_subject = params(xml);
        with_subject.subject_attribute = Some("uid".to_string());
        validate_saml_params(&mut with_subject, REALM).expect("subject attribute set");
    }

    #[test]
    fn a_reserved_claim_name_is_rejected() {
        let mut params = params(valid_metadata());
        params.attribute_claim_map = HashMap::from([("groups".to_string(), "roles".to_string())]);
        assert!(rejection(params).contains("saml_params.attribute_claim_map"));
    }

    #[test]
    fn two_attributes_mapped_to_one_claim_are_rejected() {
        let mut params = params(valid_metadata());
        params.attribute_claim_map = HashMap::from([
            ("mail".to_string(), "email".to_string()),
            ("email".to_string(), "email".to_string()),
        ]);
        assert!(rejection(params).contains("same claim"));
    }

    #[test]
    fn return_origins_must_be_bare_https_origins() {
        for origin in [
            "http://app.example.com",
            "https://app.example.com/some/path",
            "https://user@app.example.com",
            "not a url",
        ] {
            let mut params = params(valid_metadata());
            params.allowed_return_origins = vec![origin.to_string()];
            assert!(
                rejection(params).contains("saml_params.allowed_return_origins"),
                "{origin} must be rejected"
            );
        }
    }

    #[test]
    fn the_default_return_url_must_be_under_an_allowed_origin() {
        let mut params = params(valid_metadata());
        params.default_return_url = "https://elsewhere.example.com/home".to_string();
        assert!(rejection(params).contains("saml_params.default_return_url"));
    }
}
