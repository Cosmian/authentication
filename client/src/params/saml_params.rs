use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Per-realm SAML 2.0 Service Provider configuration for SP-initiated Web Browser SSO.
///
/// Stored inside [`crate::RealmAuthParams`] and serialized into the realm's `auth_params`
/// column. The IdP-side fields (`idp_entity_id`, `idp_sso_url`, `idp_signing_certificates`,
/// `idp_nameid_format`) are **server-derived**: the server parses `metadata_xml` when the
/// realm is created or updated and overwrites them, ignoring any values the caller sent.
/// Callers provide `metadata_xml`, the SP-side fields, the identity mapping, and the
/// return-URL policy.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SamlParams {
    // ── IdP side — derived from `metadata_xml` at ingestion ───────────────────────────
    /// IdP entityID; the `<Issuer>` value required on incoming responses. Parsed from
    /// `metadata_xml`.
    #[serde(default)]
    pub idp_entity_id: String,

    /// IdP HTTP-Redirect Single Sign-On Service URL that `<AuthnRequest>`s are sent to.
    /// Parsed from `metadata_xml`.
    #[serde(default)]
    pub idp_sso_url: String,

    /// PEM-encoded IdP signing certificate(s) used to verify assertion/response signatures.
    /// Parsed from `metadata_xml`.
    #[serde(default)]
    pub idp_signing_certificates: Vec<String>,

    /// Expected/requested `<NameID>` Format URI (e.g. persistent, emailAddress). Parsed
    /// from `metadata_xml` when the IdP advertises one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idp_nameid_format: Option<String>,

    /// Raw IdP metadata XML as supplied by the admin, retained for reference and re-parsing.
    /// Required on input; the structured IdP fields above are derived from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_xml: Option<String>,

    // ── SP side — this server's identity toward the IdP ───────────────────────────────
    /// This SP's entityID, advertised in our published SP metadata.
    pub sp_entity_id: String,

    /// This SP's Assertion Consumer Service URL (`/saml/{realm_id}/acs`), advertised in
    /// our published SP metadata.
    pub sp_acs_url: String,

    // ── Identity mapping — assertion → session claims ─────────────────────────────────
    /// SAML attribute whose single value becomes the session subject. When unset, the
    /// `<NameID>` is used instead; a `transient` NameID with no subject attribute is
    /// rejected (it is not a stable subject).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_attribute: Option<String>,

    /// Lowercase the resolved subject before use, for IdPs that are inconsistent about
    /// casing. Off by default.
    #[serde(default)]
    pub normalize_subject_case: bool,

    /// SAML attribute whose values populate the JWT `roles` claim, passed through as-is
    /// (no server-side RBAC filtering).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_attribute: Option<String>,

    /// Allowlist mapping SAML attribute name → session JWT extra-claim name. Only listed
    /// attributes are copied into the session; each is validated against the reserved claim
    /// names and the extra-claims size budget.
    #[serde(default)]
    pub attribute_claim_map: HashMap<String, String>,

    // ── Post-login redirect — open-redirect defense ───────────────────────────────────
    /// Allowed return-URL origins (`scheme://host[:port]`); any path under an approved
    /// origin is permitted. A `return_to` not matching one of these is rejected.
    #[serde(default)]
    pub allowed_return_origins: Vec<String>,

    /// Default post-login redirect URL, used when no `return_to` is supplied.
    pub default_return_url: String,
}
