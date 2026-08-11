//! Combined JWKS document construction for the OIDC provider.

use crate::{AuthError, session::JwksData};

/// Build the combined JWKS served at the discovery `jwks_uri`.
///
/// Always includes the OIDC signing JWK. When a session public-key PEM is
/// provided and its JWK has a `kid` distinct from the OIDC key, it is included
/// too so relying parties can validate both OIDC-issued and session tokens from
/// a single endpoint. Duplicate `kid`s are de-duplicated.
pub fn build_combined_jwks(
    oidc_jwk: &serde_json::Value,
    session_pub_pem_path: Option<&str>,
) -> Result<JwksData, AuthError> {
    let mut keys = vec![oidc_jwk.clone()];
    let oidc_kid = oidc_jwk.get("kid").and_then(|v| v.as_str()).unwrap_or("");

    if let Some(path) = session_pub_pem_path
        && let Ok(pem) = std::fs::read_to_string(path)
        && let Ok((session_jwk, session_kid)) = crate::session::build_jwk_from_pem(&pem)
        && session_kid != oidc_kid
    {
        keys.push(session_jwk);
    }

    Ok(JwksData(serde_json::json!({ "keys": keys })))
}
