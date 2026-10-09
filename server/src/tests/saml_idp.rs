//! A fake SAML 2.0 IdP: builds signed `<samlp:Response>`s answering our `AuthnRequest`s, with
//! every field the ACS validation checks exposed so tests can break one at a time.

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use openssl::pkey::PKey;
use samael::crypto::{Crypto, CryptoProvider};

use crate::{SamlParams, tests::helpers::TEST_IDP_ENTITY_ID};

const PERSISTENT_NAMEID: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const SUCCESS_STATUS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// One response, before signing. Built by [`TestResponse::answering`] with valid values;
/// tests change fields to produce the invalid variants.
pub struct TestResponse {
    pub response_id: String,
    pub assertion_id: String,
    pub in_response_to: String,
    /// `<Issuer>` of both the response and the assertion.
    pub issuer: String,
    /// Response `Destination` and bearer `SubjectConfirmationData/@Recipient`.
    pub destination: String,
    /// One `<AudienceRestriction>` per entry, each naming that single audience.
    pub audience_restrictions: Vec<String>,
    pub status: String,
    pub name_id: String,
    pub name_id_format: String,
    pub attributes: Vec<(String, Vec<String>)>,
    pub issue_instant: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    /// `Conditions/@NotOnOrAfter` and the bearer confirmation's `NotOnOrAfter`.
    pub not_on_or_after: DateTime<Utc>,
    pub authn_statement: bool,
    pub sign_assertion: bool,
    pub sign_response: bool,
}

impl TestResponse {
    /// A valid response to `request_id` for a realm configured with `sp`: assertion signed,
    /// valid for five minutes, NameID `alice`, with an `email` and a two-valued `groups`
    /// attribute.
    pub fn answering(request_id: &str, sp: &SamlParams) -> Self {
        let now = Utc::now();
        Self {
            response_id: new_id(),
            assertion_id: new_id(),
            in_response_to: request_id.to_string(),
            issuer: TEST_IDP_ENTITY_ID.to_string(),
            destination: sp.sp_acs_url.clone(),
            audience_restrictions: vec![sp.sp_entity_id.clone()],
            status: SUCCESS_STATUS.to_string(),
            name_id: "alice".to_string(),
            name_id_format: PERSISTENT_NAMEID.to_string(),
            attributes: vec![
                ("email".to_string(), vec!["alice@example.com".to_string()]),
                (
                    "groups".to_string(),
                    vec!["admins".to_string(), "users".to_string()],
                ),
            ],
            issue_instant: now,
            not_before: now - Duration::minutes(1),
            not_on_or_after: now + Duration::minutes(5),
            authn_statement: true,
            sign_assertion: true,
            sign_response: false,
        }
    }
}

pub struct TestIdp {
    /// PKCS#1 DER, the form samael's xmlsec signer loads.
    private_key_der: Vec<u8>,
    certificate_base64: String,
}

impl TestIdp {
    /// The IdP that `test_idp_metadata` describes, so realms built from it trust its signatures.
    pub fn new() -> Self {
        Self::from_pem(
            include_str!("certificates/rsa/auth.user2.key.pem"),
            include_str!("certificates/rsa/auth.user2.cert.pem"),
        )
    }

    /// An IdP with another key, whose signatures the test realms must reject.
    pub fn untrusted() -> Self {
        Self::from_pem(
            include_str!("certificates/rsa/auth.user1.key.pem"),
            include_str!("certificates/rsa/auth.user1.cert.pem"),
        )
    }

    fn from_pem(key_pem: &str, certificate_pem: &str) -> Self {
        let private_key_der = PKey::private_key_from_pem(key_pem.as_bytes())
            .and_then(|key| key.rsa())
            .and_then(|rsa| rsa.private_key_to_der())
            .expect("test IdP RSA key");
        let certificate_base64 = certificate_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        Self {
            private_key_der,
            certificate_base64,
        }
    }

    /// Render `response` as XML, signing the assertion and/or the response as requested.
    pub fn sign(&self, response: &TestResponse) -> String {
        let assertion_signature = response
            .sign_assertion
            .then(|| self.signature_template(&response.assertion_id));
        let mut assertion = render_assertion(response, assertion_signature.as_deref());
        if response.sign_assertion {
            assertion = strip_xml_declaration(&self.sign_xml(&assertion)).to_string();
        }
        let response_signature = response
            .sign_response
            .then(|| self.signature_template(&response.response_id));
        let xml = render_response(response, response_signature.as_deref(), &assertion);
        if response.sign_response {
            self.sign_xml(&xml)
        } else {
            xml
        }
    }

    /// samael signs only the first `<ds:Signature>` template, hence one call per signed element.
    fn sign_xml(&self, xml: &str) -> String {
        Crypto::sign_xml(xml, &self.private_key_der).expect("xmlsec signs the test response")
    }

    /// RSA-SHA256 with a SHA-256 digest; samael's own template digests with SHA-1.
    fn signature_template(&self, referenced_id: &str) -> String {
        format!(
            r##"
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#{referenced_id}">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>"##,
            cert = self.certificate_base64
        )
    }
}

fn render_assertion(r: &TestResponse, signature: Option<&str>) -> String {
    let attributes: String = r
        .attributes
        .iter()
        .map(|(name, values)| {
            let values: String = values
                .iter()
                .map(|v| format!("<saml:AttributeValue>{}</saml:AttributeValue>", escape(v)))
                .collect();
            format!(
                "\n      <saml:Attribute Name=\"{}\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">{values}</saml:Attribute>",
                escape(name)
            )
        })
        .collect();
    let audience_restrictions: String = r
        .audience_restrictions
        .iter()
        .map(|audience| {
            format!(
                "\n    <saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction>",
                escape(audience)
            )
        })
        .collect();
    let authn_statement = if r.authn_statement {
        format!(
            r#"
  <saml:AuthnStatement AuthnInstant="{issued}" SessionIndex="{id}">
    <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
  </saml:AuthnStatement>"#,
            issued = timestamp(r.issue_instant),
            id = r.assertion_id,
        )
    } else {
        String::new()
    };
    format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issued}">
  <saml:Issuer>{issuer}</saml:Issuer>{signature}
  <saml:Subject>
    <saml:NameID Format="{format}">{name_id}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData InResponseTo="{in_response_to}" Recipient="{recipient}" NotOnOrAfter="{not_on_or_after}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">{audience_restrictions}
  </saml:Conditions>{authn_statement}
  <saml:AttributeStatement>{attributes}
  </saml:AttributeStatement>
</saml:Assertion>"#,
        id = r.assertion_id,
        issued = timestamp(r.issue_instant),
        issuer = escape(&r.issuer),
        signature = signature.unwrap_or_default(),
        format = escape(&r.name_id_format),
        name_id = escape(&r.name_id),
        in_response_to = escape(&r.in_response_to),
        recipient = escape(&r.destination),
        not_before = timestamp(r.not_before),
        not_on_or_after = timestamp(r.not_on_or_after),
    )
}

fn render_response(r: &TestResponse, signature: Option<&str>, assertion: &str) -> String {
    format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issued}" Destination="{destination}" InResponseTo="{in_response_to}">
  <saml:Issuer>{issuer}</saml:Issuer>{signature}
  <samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>
  {assertion}
</samlp:Response>"#,
        id = r.response_id,
        issued = timestamp(r.issue_instant),
        destination = escape(&r.destination),
        in_response_to = escape(&r.in_response_to),
        issuer = escape(&r.issuer),
        signature = signature.unwrap_or_default(),
        status = escape(&r.status),
    )
}

/// SAML IDs are `xs:ID`, so they must not start with a digit.
fn new_id() -> String {
    format!("_{}", uuid::Uuid::new_v4().simple())
}

fn timestamp(instant: DateTime<Utc>) -> String {
    instant.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn strip_xml_declaration(xml: &str) -> &str {
    match xml.trim_start().strip_prefix("<?xml") {
        Some(rest) => rest
            .split_once("?>")
            .map_or(xml, |(_, body)| body.trim_start()),
        None => xml,
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The certificate the test realms trust, in the form samael's verifier takes.
pub fn test_idp_certificate_der() -> samael::crypto::CertificateDer {
    STANDARD
        .decode(crate::tests::helpers::test_idp_certificate_base64())
        .expect("test IdP certificate is base64")
        .into()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use samael::{
        crypto::{Crypto, CryptoProvider, ReduceMode},
        schema::Response,
    };

    use super::{TestIdp, TestResponse, test_idp_certificate_der};
    use crate::tests::helpers::test_saml_params;

    fn verify(xml: &str) -> Result<String, samael::crypto::CryptoError> {
        Crypto::reduce_xml_to_signed(
            xml,
            &[test_idp_certificate_der()],
            ReduceMode::ValidateAndMarkNoAncestors,
        )
    }

    fn default_response() -> TestResponse {
        TestResponse::answering("_request-1", &test_saml_params("acme"))
    }

    #[test]
    fn signed_assertion_verifies_and_parses() {
        let xml = TestIdp::new().sign(&default_response());

        let verified = verify(&xml).expect("assertion signature verifies");
        assert!(verified.contains(">alice</saml:NameID>"), "{verified}");
        let parsed = Response::from_str(&xml).expect("samael parses the response");
        assert_eq!(parsed.in_response_to.as_deref(), Some("_request-1"));
        assert!(parsed.assertion.is_some());
    }

    #[test]
    fn response_and_assertion_can_both_be_signed() {
        let mut response = default_response();
        response.sign_response = true;
        let xml = TestIdp::new().sign(&response);

        assert_eq!(xml.matches("<ds:SignatureValue>").count(), 2, "{xml}");
        verify(&xml).expect("both signatures verify");
    }

    #[test]
    fn untrusted_signature_is_rejected() {
        let xml = TestIdp::untrusted().sign(&default_response());
        assert!(verify(&xml).is_err());
    }

    #[test]
    fn tampering_after_signing_breaks_the_signature() {
        let xml = TestIdp::new()
            .sign(&default_response())
            .replace(">alice<", ">mallory<");
        assert!(verify(&xml).is_err());
    }
}
