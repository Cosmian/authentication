use chrono::Utc;
use samael::{
    metadata::HTTP_POST_BINDING,
    schema::{AuthnRequest, Issuer, NameIdPolicy},
};
use url::Url;

use crate::{AuthError, AuthResult, SamlParams, saml::sp_signing_key::SamlSpSigningKey};

const ENTITY_NAMEID_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

/// A fresh `AuthnRequest` ID: 128 random bits, prefixed because `xs:ID` can't start with a digit.
pub(super) fn new_request_id() -> String {
    format!("_{}", uuid::Uuid::new_v4().simple())
}

/// The IdP SSO URL carrying our signed `AuthnRequest` (HTTP-Redirect binding, SAMLBind §3.4),
/// with `request_id` as both the request ID and the `RelayState`.
pub(super) fn signed_authn_request_url(
    params: &SamlParams,
    request_id: &str,
    signing_key: &SamlSpSigningKey,
) -> AuthResult<Url> {
    // Built here rather than with samael's helper, whose request IDs are only 32 random bits.
    let request = AuthnRequest {
        id: request_id.to_string(),
        version: "2.0".to_string(),
        issue_instant: Utc::now(),
        destination: Some(params.idp_sso_url.clone()),
        issuer: Some(Issuer {
            format: Some(ENTITY_NAMEID_FORMAT.to_string()),
            value: Some(params.sp_entity_id.clone()),
            ..Issuer::default()
        }),
        assertion_consumer_service_url: Some(params.sp_acs_url.clone()),
        protocol_binding: Some(HTTP_POST_BINDING.to_string()),
        name_id_policy: params
            .idp_nameid_format
            .as_ref()
            .map(|format| NameIdPolicy {
                format: Some(format.clone()),
                allow_create: Some(true),
                ..NameIdPolicy::default()
            }),
        ..AuthnRequest::default()
    };
    request
        .signed_redirect(request_id, &signing_key.private_key)
        .map_err(|e| AuthError::Unexpected(format!("failed to sign the SAML AuthnRequest: {e}")))?
        .ok_or_else(|| AuthError::Unexpected("the SAML AuthnRequest has no destination".into()))
}
