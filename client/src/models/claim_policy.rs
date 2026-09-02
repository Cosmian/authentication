use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::{AuthError, AuthResult, AuthScheme};

use super::certificate_claims::CertificateClaims;
use super::client_claims::{
    AuthPrivateClaims, AuthorizationClaims, ClientClaims, RegisteredClaims,
};

/// The set of claim names `ClientClaims` and `CertificateClaims` can emit through their typed
/// fields, computed once by serializing a fully-populated instance of each — every optional
/// field set to `Some`, so `skip_serializing_if` doesn't hide a name from this set — rather
/// than transcribed by hand into a separate list. A hand-maintained list drifts: it has to be
/// remembered on every new typed field, and nothing catches the omission.
///
/// Both `ClientClaims.extra` (merged into session JWTs) and `CertificateClaims.extra`
/// (populated from a session's extra claims via `/certify`) flatten their `extra` map after
/// every typed field with no deduplication against them, so a colliding key is emitted a
/// *second* time rather than overwritten — this deployment's own JWT decoder rejects the
/// resulting duplicate-key token, but a relying party using a "last duplicate wins" JSON
/// parser (the majority outside Rust/serde) would read the caller-supplied value instead of
/// this server's own.
fn reserved_claim_names() -> &'static HashSet<String> {
    static NAMES: OnceLock<HashSet<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        let client_claims_sample = ClientClaims {
            registered: RegisteredClaims {
                iss: Some(String::new()),
                sub: Some(String::new()),
                aud: Some(Vec::new()),
                exp: Some(0),
                nbf: Some(0),
                iat: Some(0),
                jti: Some(String::new()),
            },
            authorization: AuthorizationClaims {
                roles: Some(Vec::new()),
            },
            private: AuthPrivateClaims {
                auth_scheme: Some(AuthScheme::UsernamePassword),
                realm_id: Some(String::new()),
            },
            extra: HashMap::new(),
        };

        let certificate_claims_sample = CertificateClaims {
            realm_id: String::new(),
            sub: Some(String::new()),
            auth_scheme: AuthScheme::UsernamePassword,
            verification_key: String::new(),
            iat: 0,
            exp: 0,
            extra: HashMap::new(),
        };

        let mut names = object_keys(&client_claims_sample);
        names.extend(object_keys(&certificate_claims_sample));
        names
    })
}

/// Serialize `value` and collect its top-level JSON object keys.
fn object_keys<T: serde::Serialize>(value: &T) -> HashSet<String> {
    match serde_json::to_value(value).expect("claims types always serialize without error") {
        serde_json::Value::Object(map) => map.into_iter().map(|(k, _)| k).collect(),
        other => panic!("expected claims type to serialize to a JSON object, got: {other:?}"),
    }
}

/// Reject any claim name that would collide with a claim `ClientClaims` or `CertificateClaims`
/// set themselves via their typed fields — see [`reserved_claim_names`] for why this matters.
pub fn reject_reserved_claim_names<'a>(
    names: impl IntoIterator<Item = &'a String>,
) -> AuthResult<()> {
    let reserved = reserved_claim_names();
    for name in names {
        if reserved.contains(name) {
            return Err(AuthError::BadRequest(format!(
                "'{name}' is a reserved claim name and cannot be used as an extra claim"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_non_colliding_name() {
        let names = ["as_registrant".to_string()];
        assert!(reject_reserved_claim_names(names.iter()).is_ok());
    }

    #[test]
    fn rejects_every_registered_and_private_claim_name() {
        // Covers both names the reviewed suggestion got wrong: "as_as" (it wrote "as_scheme")
        // and "auth_scheme" (missing from its list entirely).
        for name in [
            "iss",
            "sub",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "roles",
            "as_as",
            "as_rid",
            "realm_id",
            "auth_scheme",
            "verification_key",
        ] {
            let names = [name.to_string()];
            let err = reject_reserved_claim_names(names.iter())
                .expect_err(&format!("'{name}' must be rejected as an extra claim name"));
            assert!(matches!(err, AuthError::BadRequest(ref m) if m.contains(name)));
        }
    }

    #[test]
    fn reserved_set_has_no_more_and_no_less_than_the_known_typed_field_names() {
        let mut names: Vec<&str> = reserved_claim_names().iter().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "as_as",
                "as_rid",
                "aud",
                "auth_scheme",
                "exp",
                "iat",
                "iss",
                "jti",
                "nbf",
                "realm_id",
                "roles",
                "sub",
                "verification_key",
            ]
        );
    }
}
