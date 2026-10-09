use std::collections::HashMap;

use samael::schema::Assertion;
use serde_json::Value;

use crate::{
    AuthError, AuthResult, SamlParams, models::validate_extra_claims_size,
    saml::params_validation::NAMEID_TRANSIENT,
};

/// The session identity taken from a verified assertion.
pub(crate) struct SamlIdentity {
    pub(crate) subject: String,
    pub(crate) roles: Vec<String>,
    pub(crate) extra_claims: HashMap<String, Value>,
}

/// Map a verified assertion to the session identity, following the realm's identity settings.
pub(crate) fn map_identity(assertion: &Assertion, params: &SamlParams) -> AuthResult<SamlIdentity> {
    let mut subject = match &params.subject_attribute {
        Some(name) => match attribute_values(assertion, name).as_slice() {
            [value] => (*value).to_string(),
            [] => {
                return Err(saml_error(&format!(
                    "subject attribute '{name}' is missing"
                )));
            }
            _ => {
                return Err(saml_error(&format!(
                    "subject attribute '{name}' has several values"
                )));
            }
        },
        None => name_id_subject(assertion)?,
    };
    if params.normalize_subject_case {
        subject = subject.to_lowercase();
    }

    let mut roles = Vec::new();
    if let Some(name) = &params.role_attribute {
        for role in attribute_values(assertion, name) {
            if !roles.iter().any(|r| r == role) {
                roles.push(role.to_string());
            }
        }
    }

    let mut extra_claims = HashMap::new();
    for (attribute, claim) in &params.attribute_claim_map {
        let value = match attribute_values(assertion, attribute).as_slice() {
            [] => continue,
            [single] => Value::String((*single).to_string()),
            several => Value::from(several.to_vec()),
        };
        extra_claims.insert(claim.clone(), value);
    }
    validate_extra_claims_size(&extra_claims)
        .map_err(|_| saml_error("the mapped attributes exceed the extra-claims size limit"))?;

    Ok(SamlIdentity {
        subject,
        roles,
        extra_claims,
    })
}

fn name_id_subject(assertion: &Assertion) -> AuthResult<String> {
    let name_id = assertion
        .subject
        .as_ref()
        .and_then(|subject| subject.name_id.as_ref())
        .filter(|name_id| !name_id.value.is_empty())
        .ok_or_else(|| saml_error("assertion has no NameID"))?;
    // The realm settings only see the format the IdP advertises, not the one it sends.
    if name_id.format.as_deref() == Some(NAMEID_TRANSIENT) {
        return Err(saml_error(
            "the NameID is transient and no subject attribute is configured",
        ));
    }
    Ok(name_id.value.clone())
}

/// Non-empty values of every attribute named `name` (matched on `Name`, not `FriendlyName`).
fn attribute_values<'a>(assertion: &'a Assertion, name: &str) -> Vec<&'a str> {
    assertion
        .attribute_statements
        .iter()
        .flatten()
        .flat_map(|statement| &statement.attributes)
        .filter(|attribute| attribute.name.as_deref() == Some(name))
        .flat_map(|attribute| &attribute.values)
        .filter_map(|value| value.value.as_deref())
        .filter(|value| !value.is_empty())
        .collect()
}

fn saml_error(message: &str) -> AuthError {
    AuthError::Saml(message.to_string())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use samael::schema::{Assertion, Response};
    use serde_json::{Value, json};

    use super::{SamlIdentity, map_identity};
    use crate::{
        AuthError, SamlParams,
        saml::params_validation::NAMEID_TRANSIENT,
        tests::{
            helpers::test_saml_params,
            saml_idp::{TestIdp, TestResponse},
        },
    };

    fn params() -> SamlParams {
        test_saml_params("acme")
    }

    /// The assertion of a default fake-IdP response after `change`, parsed without validation.
    fn assertion(change: impl FnOnce(&mut TestResponse)) -> Assertion {
        let mut response = TestResponse::answering("_request-1", &params());
        change(&mut response);
        Response::from_str(&TestIdp::new().sign(&response))
            .expect("parse test response")
            .assertion
            .expect("test response has an assertion")
    }

    fn mapped(assertion: &Assertion, params: &SamlParams) -> SamlIdentity {
        map_identity(assertion, params).expect("identity maps")
    }

    fn rejection(assertion: &Assertion, params: &SamlParams) -> String {
        match map_identity(assertion, params) {
            Err(AuthError::Saml(message)) => message,
            Err(other) => panic!("expected a SAML rejection, got {other:?}"),
            Ok(identity) => panic!("expected a rejection, mapped {}", identity.subject),
        }
    }

    #[test]
    fn the_nameid_is_the_default_subject() {
        assert_eq!(mapped(&assertion(|_| {}), &params()).subject, "alice");
    }

    #[test]
    fn a_missing_nameid_is_rejected() {
        let mut without = assertion(|_| {});
        if let Some(subject) = without.subject.as_mut() {
            subject.name_id = None;
        }
        assert!(rejection(&without, &params()).contains("no NameID"));
    }

    #[test]
    fn a_transient_nameid_is_rejected_unless_a_subject_attribute_is_set() {
        let transient = assertion(|r| r.name_id_format = NAMEID_TRANSIENT.to_string());
        assert!(rejection(&transient, &params()).contains("transient"));

        let params = SamlParams {
            subject_attribute: Some("email".to_string()),
            ..params()
        };
        assert_eq!(mapped(&transient, &params).subject, "alice@example.com");
    }

    #[test]
    fn the_subject_attribute_must_have_exactly_one_value() {
        let assertion = assertion(|_| {});
        let with = |name: &str| SamlParams {
            subject_attribute: Some(name.to_string()),
            ..params()
        };
        assert!(rejection(&assertion, &with("groups")).contains("several values"));
        assert!(rejection(&assertion, &with("department")).contains("missing"));
    }

    #[test]
    fn the_subject_can_be_lowercased() {
        let assertion = assertion(|r| r.name_id = "Alice@Example.COM".to_string());
        let params = SamlParams {
            normalize_subject_case: true,
            ..params()
        };
        assert_eq!(mapped(&assertion, &params).subject, "alice@example.com");
    }

    #[test]
    fn roles_come_from_the_role_attribute_only() {
        let assertion = assertion(|r| {
            r.attributes.push((
                "groups".to_string(),
                vec!["users".to_string(), String::new()],
            ));
        });
        assert!(mapped(&assertion, &params()).roles.is_empty());

        let params = SamlParams {
            role_attribute: Some("groups".to_string()),
            ..params()
        };
        assert_eq!(mapped(&assertion, &params).roles, ["admins", "users"]);
    }

    #[test]
    fn only_mapped_attributes_become_extra_claims() {
        let params = SamlParams {
            attribute_claim_map: HashMap::from([
                ("email".to_string(), "mail".to_string()),
                ("groups".to_string(), "teams".to_string()),
                ("department".to_string(), "dept".to_string()),
            ]),
            ..params()
        };
        let claims = mapped(&assertion(|_| {}), &params).extra_claims;
        assert_eq!(
            claims,
            HashMap::from([
                ("mail".to_string(), Value::from("alice@example.com")),
                ("teams".to_string(), json!(["admins", "users"])),
            ])
        );
    }

    #[test]
    fn oversized_extra_claims_are_rejected() {
        let assertion =
            assertion(|r| r.attributes = vec![("bio".to_string(), vec!["x".repeat(5000)])]);
        let params = SamlParams {
            attribute_claim_map: HashMap::from([("bio".to_string(), "bio".to_string())]),
            ..params()
        };
        assert!(rejection(&assertion, &params).contains("size limit"));
    }
}
