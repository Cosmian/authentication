use actix_web::{
    cookie::{Cookie, CookieJar, SameSite, time::Duration},
    dev::ResponseHead,
    http::header::{HeaderValue, SET_COOKIE},
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

pub fn build_cookie(
    value: &str,
    max_age_seconds: i64,
    is_https: bool,
) -> Result<Cookie<'static>, AuthError> {
    let mut cookie = Cookie::new(COOKIE_NAME.to_owned(), value.to_owned());

    // Only set the Secure flag when the server is running over HTTPS.
    // Setting it on plain HTTP would prevent the browser from ever sending the cookie.
    cookie.set_secure(is_https);
    cookie.set_http_only(true);
    cookie.set_same_site(Some(SameSite::Strict));
    cookie.set_path("/");
    cookie.set_max_age(Some(Duration::seconds(max_age_seconds)));

    let mut jar = CookieJar::new();
    jar.add(cookie);

    // set cookie
    let cookie = jar
        .delta()
        .next()
        .ok_or_else(|| {
            AuthError::Cookie(
                "Failed to create a session cookie for the outgoing response".to_string(),
            )
        })?
        .to_owned();
    Ok(cookie)
}

pub fn delete_cookie(response: &mut ResponseHead) -> Result<(), AuthError> {
    let mut removal_cookie = Cookie::build(COOKIE_NAME, "")
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .finish();

    removal_cookie.make_removal();

    let val = HeaderValue::from_str(&removal_cookie.to_string()).map_err(|err| {
        AuthError::Cookie(format!(
            "Failed to create a cookie for session deletion: {err}"
        ))
    })?;
    response.headers_mut().append(SET_COOKIE, val);

    Ok(())
}
