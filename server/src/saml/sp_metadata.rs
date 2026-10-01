use base64::{Engine, engine::general_purpose::STANDARD};
use samael::metadata::HTTP_POST_BINDING;

use crate::{AuthError, AuthResult, SamlParams, saml::sp_signing_key::SamlSpSigningKey};

/// Our SAML 2.0 SP metadata for one realm (SAMLMeta §2.4.4), for the IdP administrator to import.
///
/// Rendered here because samael's generator advertises unsigned `AuthnRequest`s, an
/// encryption key and a Single Logout endpoint, none of which match this server.
pub(super) fn render_sp_metadata(
    params: &SamlParams,
    signing_key: &SamlSpSigningKey,
) -> AuthResult<String> {
    let certificate = signing_key.certificate.to_der().map_err(|e| {
        AuthError::Unexpected(format!("failed to encode the SAML certificate: {e}"))
    })?;
    let name_id_format = params
        .idp_nameid_format
        .as_ref()
        .map(|format| {
            format!(
                "\n    <md:NameIDFormat>{}</md:NameIDFormat>",
                escape_markup(format)
            )
        })
        .unwrap_or_default();
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{entity_id}">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>{name_id_format}
    <md:AssertionConsumerService Binding="{HTTP_POST_BINDING}" Location="{acs_url}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#,
        entity_id = escape_markup(&params.sp_entity_id),
        certificate = STANDARD.encode(certificate),
        acs_url = escape_markup(&params.sp_acs_url),
    ))
}

/// Escape text for an XML or HTML attribute value or element content.
pub(super) fn escape_markup(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
