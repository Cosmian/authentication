use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{collections::HashMap, fmt};

use crate::AuthScheme;

// ── aud deserializer ──────────────────────────────────────────────────────────

/// Deserializes the JWT `aud` (audience) claim.
///
/// Per RFC 7519 §4.1.3 the value MAY be a single case-sensitive string or an
/// array of strings.  Both representations are normalised to `Vec<String>`.
fn deserialize_aud<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AudVisitor;

    impl<'de> Visitor<'de> for AudVisitor {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or an array of strings for 'aud'")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(vec![v.to_owned()]))
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let values: Vec<String> =
                Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
            Ok(Some(values))
        }
    }

    deserializer.deserialize_any(AudVisitor)
}

// ── §4.1  Registered Claim Names ──────────────────────────────────────────────

/// The seven registered JWT claim names from RFC 7519 §4.1.
///
/// All claims are OPTIONAL per the specification.  The names are
/// standardised in the IANA "JSON Web Token Claims" registry and MUST
/// NOT be redefined with different semantics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisteredClaims {
    /// `iss` — Issuer: identifies the principal that issued the JWT
    /// (StringOrURI, case-sensitive).  RFC 7519 §4.1.1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// `sub` — Subject: identifies the principal that is the subject of the JWT.
    /// MUST be locally or globally unique.  RFC 7519 §4.1.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// `aud` — Audience: recipients the JWT is intended for.
    /// Accepts both a single string and an array (RFC 7519 §4.1.3).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_aud"
    )]
    pub aud: Option<Vec<String>>,

    /// `exp` — Expiration Time: the JWT MUST NOT be accepted on or after this
    /// NumericDate value.  RFC 7519 §4.1.4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// `nbf` — Not Before: the JWT MUST NOT be accepted before this
    /// NumericDate value.  RFC 7519 §4.1.5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// `iat` — Issued At: time at which the JWT was issued (NumericDate).
    /// RFC 7519 §4.1.6.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// `jti` — JWT ID: unique identifier for the JWT; used to prevent replay.
    /// RFC 7519 §4.1.7.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

// ── §4.2  Public Claim Names ───────────────────────────────────────────────────

/// Authorization claims.
///
/// The `roles` claim is registered in the IANA JWT Claims Registry by
/// RFC 9068 §7.2.1.1 and is defined in RFC 7643 §4.1.2 (SCIM User resource).
/// RFC 9068 §2.2.3.1 recommends using it to convey role memberships in access
/// tokens outside of delegation scenarios.  The value is simplified to a flat
/// `Vec<String>` rather than the full SCIM complex type; RFC 9068 states
/// "no specific vocabulary is provided for `roles`".
///
/// Serialised as flat fields in the JWT payload.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorizationClaims {
    /// RBAC roles assigned to the user (e.g. `["CryptoOfficer"]`).
    /// Absence or empty array means no roles (fail-closed in OPA).
    /// Claim name `roles` per RFC 9068 §7.2.1.1 / RFC 7643 §4.1.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

// ── §4.3  Private Claim Names ─────────────────────────────────────────────────

/// Private claims used exclusively within the Auth Authentication Server
/// (RFC 7519 §4.3).
///
/// These names are agreed between this server (producer) and its clients
/// (consumers).  They are subject to collision if used outside this
/// deployment and SHOULD NOT be forwarded to third-party systems.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthPrivateClaims {
    /// Authentication scheme that was used to establish this session.
    #[serde(rename = "as_as", skip_serializing_if = "Option::is_none")]
    pub auth_scheme: Option<AuthScheme>,

    /// Realm ID that the client authenticated to.
    /// Also used as the OPA domain scope: consumers should read `as_rid` for
    /// domain-scoped RBAC rather than a separate `as_domain` claim.
    #[serde(rename = "as_rid", skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

// ── Top-level JWT Claims Set ──────────────────────────────────────────────────

/// A JWT Claims Set (RFC 7519 §4) with explicit separation of the three
/// claim categories defined by the specification.
///
/// # Wire format
/// Serialises and deserialises as a **flat** JSON object, exactly matching
/// the JWT wire format expected by every consumer (including Google CSE
/// endpoints). The sub-struct boundaries exist only in Rust — they vanish
/// at the JSON level thanks to `#[serde(flatten)]`.
///
/// # Claim Name Uniqueness (RFC 7519 §4)
/// The specification requires Claim Names to be unique within a Claims Set.
/// Serde's flatten machinery enforces this structurally for the typed
/// fields.  The `extra` map captures any remaining unknown names so that
/// round-tripping tokens from third-party issuers is lossless.
///
/// # Extension
/// To add a new group of claims:
/// - Define a new `XxxClaims` struct (§4.2 if using collision-resistant
///   names, §4.3 if private to this deployment).
/// - Add `#[serde(flatten)] pub xxx: XxxClaims` to this struct.
/// - For truly ad-hoc private claims, insert directly into `extra`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientClaims {
    /// RFC 7519 §4.1 — the seven registered claim names.
    #[serde(flatten)]
    pub registered: RegisteredClaims,

    /// RFC 9068 §2.2.3.1 — authorization claims (roles).
    #[serde(flatten)]
    pub authorization: AuthorizationClaims,

    /// RFC 7519 §4.3 — Auth Authentication Server private claims.
    #[serde(flatten)]
    pub private: AuthPrivateClaims,

    /// Catch-all for any claims not covered by the typed fields above.
    ///
    /// Producers SHOULD use collision-resistant names (e.g. full URIs) for
    /// any claims placed here that are intended to be public (§4.2).
    /// Private claims (§4.3) may use short names but risk collision.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
