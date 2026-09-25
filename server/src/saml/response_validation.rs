use chrono::{Duration, Utc};
use samael::{
    crypto::AllowedSignatureAlgorithm,
    key_info::{KeyInfo, X509Data},
    metadata::{EntityDescriptor, IdpSsoDescriptor, KeyDescriptor},
    schema::Assertion,
    service_provider::ServiceProvider,
};

use crate::{AuthError, AuthResult, SamlParams, saml::SamlRequestStore};

/// Accepted difference between the IdP's clock and ours (samael's and Shibboleth's default).
const MAX_CLOCK_SKEW_SECONDS: i64 = 180;

/// How long after its `IssueInstant` an assertion is still accepted. This also bounds how
/// long a consumed assertion ID must be remembered to detect a replay.
const MAX_ISSUE_DELAY_SECONDS: i64 = 300;

/// Check a SAML `<Response>` answering our `AuthnRequest` `request_id`, against the realm
/// settings `params`, and return its verified assertion. Each assertion is accepted once.
///
/// samael checks the signature (of the response or the assertion), `InResponseTo`, issuer,
/// validity window, bearer `Recipient`, `Destination` and status; this adds what it leaves
/// out: a mandatory signature, the audience and `AuthnStatement` required by the Web Browser
/// SSO profile (SAMLProf §4.1.4.2), and replay detection.
pub(crate) async fn validate_saml_response(
    response_xml: &str,
    params: &SamlParams,
    request_id: &str,
    store: &dyn SamlRequestStore,
) -> AuthResult<Assertion> {
    let assertion = service_provider(params)?
        .parse_xml_response(response_xml, Some(&[request_id]))
        .map_err(|e| saml_error(&format!("rejected SAML response: {e}")))?;
    require_audience(&assertion, &params.sp_entity_id)?;
    if assertion
        .authn_statements
        .as_ref()
        .is_none_or(Vec::is_empty)
    {
        return Err(saml_error("assertion has no AuthnStatement"));
    }
    let accepted_until = assertion.issue_instant + Duration::seconds(MAX_ISSUE_DELAY_SECONDS);
    // samael enforces this too; checked here because the replay retention below relies on it.
    if accepted_until <= Utc::now() {
        return Err(saml_error("assertion was issued too long ago"));
    }
    // Rounded up: the store needs a whole second that is still in the future.
    if !store
        .record_assertion_id(&assertion.id, accepted_until.timestamp() + 1)
        .await?
    {
        return Err(saml_error("assertion has already been used"));
    }
    Ok(assertion)
}

fn service_provider(params: &SamlParams) -> AuthResult<ServiceProvider> {
    // Without a certificate samael accepts responses without verifying any signature.
    if params.idp_signing_certificates.is_empty() {
        return Err(saml_error("the realm has no IdP signing certificate"));
    }
    Ok(ServiceProvider {
        entity_id: Some(params.sp_entity_id.clone()),
        acs_url: Some(params.sp_acs_url.clone()),
        // samael falls back to the metadata URL as audience; ours is always the entity ID.
        metadata_url: None,
        slo_url: None,
        idp_metadata: trusted_idp(params),
        allow_idp_initiated: false,
        max_issue_delay: Duration::seconds(MAX_ISSUE_DELAY_SECONDS),
        max_clock_skew: Duration::seconds(MAX_CLOCK_SKEW_SECONDS),
        // Also restricts the digest algorithm, which keeps SHA-1 out entirely.
        allowed_signature_algorithms: Some(vec![
            AllowedSignatureAlgorithm::RsaSha256,
            AllowedSignatureAlgorithm::RsaSha384,
            AllowedSignatureAlgorithm::RsaSha512,
            AllowedSignatureAlgorithm::EcdsaSha256,
            AllowedSignatureAlgorithm::EcdsaSha384,
            AllowedSignatureAlgorithm::EcdsaSha512,
        ]),
        ..ServiceProvider::default()
    })
}

/// The IdP as samael expects it, built from the settings validated when the realm was saved.
fn trusted_idp(params: &SamlParams) -> EntityDescriptor {
    let certificates = params
        .idp_signing_certificates
        .iter()
        .map(|pem| {
            pem.lines()
                .filter(|line| !line.starts_with("-----"))
                .collect()
        })
        .collect();
    let signing_key = KeyDescriptor {
        key_use: Some("signing".to_string()),
        key_info: KeyInfo {
            id: None,
            x509_data: Some(X509Data { certificates }),
        },
        encryption_methods: None,
    };
    EntityDescriptor {
        entity_id: Some(params.idp_entity_id.clone()),
        idp_sso_descriptors: Some(vec![IdpSsoDescriptor {
            id: None,
            valid_until: None,
            cache_duration: None,
            protocol_support_enumeration: None,
            error_url: None,
            signature: None,
            key_descriptors: vec![signing_key],
            organization: None,
            contact_people: Vec::new(),
            artifact_resolution_service: Vec::new(),
            single_logout_services: Vec::new(),
            manage_name_id_services: Vec::new(),
            name_id_formats: Vec::new(),
            want_authn_requests_signed: None,
            single_sign_on_services: Vec::new(),
            name_id_mapping_services: Vec::new(),
            assertion_id_request_services: Vec::new(),
            attribute_profiles: Vec::new(),
            attributes: Vec::new(),
        }]),
        ..EntityDescriptor::default()
    }
}

/// SAMLCore §2.5.1.4: every `<AudienceRestriction>` must name us. samael accepts an
/// assertion with none, or when any single one does.
fn require_audience(assertion: &Assertion, sp_entity_id: &str) -> AuthResult<()> {
    let restrictions = assertion
        .conditions
        .as_ref()
        .and_then(|conditions| conditions.audience_restrictions.as_ref())
        .filter(|restrictions| !restrictions.is_empty())
        .ok_or_else(|| saml_error("assertion has no AudienceRestriction"))?;
    if restrictions
        .iter()
        .all(|restriction| restriction.audience.iter().any(|a| a == sp_entity_id))
    {
        Ok(())
    } else {
        Err(saml_error(
            "assertion is not addressed to this service provider",
        ))
    }
}

fn saml_error(message: &str) -> AuthError {
    AuthError::Saml(message.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use samael::schema::Assertion;

    use super::validate_saml_response;
    use crate::{
        AuthError, AuthResult, DatabaseBackend, DatabaseParams, SamlParams, SamlRequestStore,
        create_saml_request_store,
        saml::validate_saml_params,
        tests::{
            helpers::test_saml_params,
            saml_idp::{TestIdp, TestResponse},
        },
    };

    const REALM: &str = "acme";
    const REQUEST_ID: &str = "_request-1";

    fn realm_params() -> SamlParams {
        let mut params = test_saml_params(REALM);
        validate_saml_params(&mut params, REALM).expect("valid test settings");
        params
    }

    async fn memory_store() -> Arc<dyn SamlRequestStore> {
        create_saml_request_store(&DatabaseParams {
            backend: DatabaseBackend::SQLite,
            connection_url: "sqlite::memory:".to_string(),
            max_connections: 1,
            ..DatabaseParams::default()
        })
        .await
        .expect("in-memory SAML request store")
    }

    fn response() -> TestResponse {
        TestResponse::answering(REQUEST_ID, &realm_params())
    }

    async fn validate(xml: &str) -> AuthResult<Assertion> {
        validate_saml_response(
            xml,
            &realm_params(),
            REQUEST_ID,
            memory_store().await.as_ref(),
        )
        .await
    }

    async fn rejection(response: TestResponse) -> String {
        match validate(&TestIdp::new().sign(&response)).await {
            Err(AuthError::Saml(message)) => message,
            Err(other) => panic!("expected a SAML rejection, got {other:?}"),
            Ok(assertion) => panic!("expected a rejection, accepted {}", assertion.id),
        }
    }

    fn name_id(assertion: &Assertion) -> Option<&str> {
        assertion
            .subject
            .as_ref()
            .and_then(|subject| subject.name_id.as_ref())
            .map(|name_id| name_id.value.as_str())
    }

    fn assert_mentions(message: &str, expected: &str) {
        assert!(
            message.contains(expected),
            "expected {expected:?} in: {message}"
        );
    }

    #[actix_web::test]
    async fn a_valid_response_is_accepted() {
        let assertion = validate(&TestIdp::new().sign(&response()))
            .await
            .expect("valid response");
        assert_eq!(name_id(&assertion), Some("alice"));
    }

    #[actix_web::test]
    async fn a_response_signed_only_at_the_response_level_is_accepted() {
        let mut response = response();
        response.sign_assertion = false;
        response.sign_response = true;
        validate(&TestIdp::new().sign(&response))
            .await
            .expect("a signed response covers its assertion");
    }

    #[actix_web::test]
    async fn a_replayed_assertion_is_rejected() {
        let (params, store) = (realm_params(), memory_store().await);
        let xml = TestIdp::new().sign(&response());
        validate_saml_response(&xml, &params, REQUEST_ID, store.as_ref())
            .await
            .expect("first use");
        let Err(AuthError::Saml(message)) =
            validate_saml_response(&xml, &params, REQUEST_ID, store.as_ref()).await
        else {
            panic!("the second use must be rejected");
        };
        assert_mentions(&message, "already been used");
    }

    #[actix_web::test]
    async fn an_unsigned_response_is_rejected() {
        let mut response = response();
        response.sign_assertion = false;
        assert_mentions(&rejection(response).await, "must be signed");
    }

    #[actix_web::test]
    async fn a_signature_by_another_key_is_rejected() {
        let xml = TestIdp::untrusted().sign(&response());
        assert!(matches!(validate(&xml).await, Err(AuthError::Saml(_))));
    }

    #[actix_web::test]
    async fn a_response_modified_after_signing_is_rejected() {
        let xml = TestIdp::new()
            .sign(&response())
            .replace(">alice<", ">mallory<");
        assert!(matches!(validate(&xml).await, Err(AuthError::Saml(_))));
    }

    /// Signature wrapping: an unsigned assertion placed next to a validly signed one must never
    /// be the one returned.
    #[actix_web::test]
    async fn an_injected_unsigned_assertion_is_never_returned() {
        let legitimate = TestIdp::new().sign(&response());
        let mut forged = response();
        forged.name_id = "mallory".to_string();
        forged.sign_assertion = false;
        let forged = TestIdp::new().sign(&forged);
        let start = forged.find("<saml:Assertion").expect("assertion start");
        let end = forged.find("</saml:Assertion>").expect("assertion end");
        let forged_assertion = &forged[start..end + "</saml:Assertion>".len()];
        let insert_at = legitimate.find("<saml:Assertion").expect("assertion start");
        let wrapped = format!(
            "{}{forged_assertion}{}",
            &legitimate[..insert_at],
            &legitimate[insert_at..]
        );

        if let Ok(assertion) = validate(&wrapped).await {
            assert_eq!(name_id(&assertion), Some("alice"));
        }
    }

    #[actix_web::test]
    async fn a_response_to_another_request_is_rejected() {
        let mut response = response();
        response.in_response_to = "_another-request".to_string();
        assert_mentions(&rejection(response).await, "InResponseTo");
    }

    #[actix_web::test]
    async fn a_response_from_another_issuer_is_rejected() {
        let mut response = response();
        response.issuer = "https://evil.example.com/metadata".to_string();
        assert_mentions(&rejection(response).await, "Issuer");
    }

    #[actix_web::test]
    async fn a_response_for_another_acs_is_rejected() {
        let mut response = response();
        response.destination = "https://other.example.com/saml/acme/acs".to_string();
        assert_mentions(&rejection(response).await, "Recipient");
    }

    #[actix_web::test]
    async fn an_assertion_for_another_audience_is_rejected() {
        let mut response = response();
        response.audience_restrictions = vec!["https://other.example.com/sp".to_string()];
        assert_mentions(&rejection(response).await, "AudienceRequirement");
    }

    #[actix_web::test]
    async fn an_assertion_without_audience_restriction_is_rejected() {
        let mut response = response();
        response.audience_restrictions.clear();
        assert_mentions(&rejection(response).await, "no AudienceRestriction");
    }

    #[actix_web::test]
    async fn every_audience_restriction_must_name_us() {
        let mut response = response();
        let ours = realm_params().sp_entity_id;
        response.audience_restrictions = vec![ours, "https://other.example.com/sp".to_string()];
        assert_mentions(
            &rejection(response).await,
            "not addressed to this service provider",
        );
    }

    #[actix_web::test]
    async fn an_assertion_without_authn_statement_is_rejected() {
        let mut response = response();
        response.authn_statement = false;
        assert_mentions(&rejection(response).await, "no AuthnStatement");
    }

    #[actix_web::test]
    async fn an_expired_assertion_is_rejected() {
        let mut response = response();
        response.not_on_or_after = Utc::now() - Duration::minutes(4);
        assert_mentions(&rejection(response).await, "expired");
    }

    #[actix_web::test]
    async fn an_assertion_not_yet_valid_is_rejected() {
        let mut response = response();
        response.not_before = Utc::now() + Duration::minutes(4);
        assert_mentions(&rejection(response).await, "not valid until");
    }

    #[actix_web::test]
    async fn an_assertion_issued_too_long_ago_is_rejected_even_if_unexpired() {
        let mut response = response();
        response.issue_instant = Utc::now() - Duration::minutes(6);
        response.not_on_or_after = Utc::now() + Duration::hours(1);
        assert_mentions(&rejection(response).await, "expired");
    }

    #[actix_web::test]
    async fn an_unsuccessful_status_is_rejected() {
        let mut response = response();
        response.sign_response = true;
        response.status = "urn:oasis:names:tc:SAML:2.0:status:Responder".to_string();
        assert_mentions(&rejection(response).await, "StatusCode");
    }

    #[actix_web::test]
    async fn a_realm_without_idp_certificate_rejects_everything() {
        let mut params = realm_params();
        params.idp_signing_certificates.clear();
        let xml = TestIdp::new().sign(&response());
        let result =
            validate_saml_response(&xml, &params, REQUEST_ID, memory_store().await.as_ref()).await;
        assert!(
            matches!(result, Err(AuthError::Saml(ref m)) if m.contains("no IdP signing certificate"))
        );
    }
}
