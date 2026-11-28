use actix_web::{
    dev::ResponseHead,
    http::header::{self, HeaderMap, HeaderValue, SET_COOKIE},
};

use crate::{AuthError, AuthResult};
use sha2::{Digest, Sha256};

pub const COOKIE_NAME: &str = "_ea_";

pub fn session_id_from_cookie_value(cookie_value: &[u8]) -> AuthResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(cookie_value);
    let session_id = hasher.finalize();
    Ok(hex::encode(session_id))
}

/// The `Set-Cookie` header value of the session cookie. The value is a JWT (base64url and dots),
/// which needs no escaping.
#[must_use]
pub fn build_cookie(value: &str, max_age_seconds: i64, is_https: bool) -> String {
    // Only set the Secure flag when the server is running over HTTPS.
    // Setting it on plain HTTP would prevent the browser from ever sending the cookie.
    let secure = if is_https { "; Secure" } else { "" };
    format!(
        "{COOKIE_NAME}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age_seconds}{secure}"
    )
}

pub fn delete_cookie(response: &mut ResponseHead) -> Result<(), AuthError> {
    let val = HeaderValue::from_str(&format!(
        "{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    ))
    .map_err(|err| {
        AuthError::Cookie(format!(
            "Failed to create a cookie for session deletion: {err}"
        ))
    })?;
    response.headers_mut().append(SET_COOKIE, val);

    Ok(())
}

/// Value of the cookie `name` among the `Cookie` request headers (RFC 6265 §5.4): the first
/// pair whose trimmed name matches exactly, with one pair of surrounding quotes removed.
pub fn request_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(candidate, _)| candidate.trim() == name)
        .map(|(_, value)| {
            let value = value.trim();
            value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value)
        })
}

/// Value of a stored `Set-Cookie` string (`name=value; attributes...`).
#[must_use]
pub fn set_cookie_value(set_cookie: &str) -> Option<&str> {
    set_cookie
        .split(';')
        .next()?
        .split_once('=')
        .map(|(_, v)| v.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_cookie_matches_exact_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; _ea_=\"x\"; _ea_saml=y"),
        );
        assert_eq!(request_cookie(&headers, "_ea_"), Some("x"));
        assert_eq!(request_cookie(&headers, "_ea_saml"), Some("y"));
        assert_eq!(request_cookie(&headers, "_e"), None);
    }

    #[test]
    fn built_cookie_round_trips_and_secure_follows_https() {
        assert_eq!(
            set_cookie_value(&build_cookie("tok", 60, true)),
            Some("tok")
        );
        assert!(build_cookie("tok", 60, true).contains("; Secure"));
        assert!(!build_cookie("tok", 60, false).contains("Secure"));
    }
}
