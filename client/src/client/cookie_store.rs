use cookie_store::{CookieStore, RawCookie, RawCookieParseError};
use cosmian_logger::error;
use reqwest::header::HeaderValue;
use std::sync::{Mutex, MutexGuard, PoisonError};

#[derive(Debug)]
pub struct AuthClientCookieStore(Mutex<CookieStore>);

impl Default for AuthClientCookieStore {
    /// Create a new, empty [`AuthClientCookieStore`]
    fn default() -> Self {
        AuthClientCookieStore::new()
    }
}

impl AuthClientCookieStore {
    /// Create a new [`AuthClientCookieStore`] from a default empty [`cookie_store::CookieStore`].
    pub fn new() -> AuthClientCookieStore {
        AuthClientCookieStore(Mutex::new(CookieStore::new()))
    }

    /// Lock and get a handle to the contained [`cookie_store::CookieStore`].
    pub fn lock(
        &self,
    ) -> Result<MutexGuard<'_, CookieStore>, PoisonError<MutexGuard<'_, CookieStore>>> {
        self.0.lock()
    }
}

impl reqwest::cookie::CookieStore for AuthClientCookieStore {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &url::Url) {
        let mut store = self.0.lock().unwrap();
        let cookies = cookie_headers.filter_map(|val| {
            std::str::from_utf8(val.as_bytes())
                .map_err(|e| {
                    error!("Failed to parse cookie header as UTF-8: {}", e);
                    RawCookieParseError::from(e)
                })
                .and_then(RawCookie::parse)
                .inspect_err(|e| error!("Invalid cookie: {e}"))
                .map(|c| c.into_owned())
                .ok()
        });
        store.store_response_cookies(cookies, url);
    }

    fn cookies(&self, url: &url::Url) -> Option<HeaderValue> {
        let store = self.0.lock().unwrap();
        let s = store
            .get_request_values(url)
            .map(|(name, value)| format!("{}={}", name, value))
            .collect::<Vec<_>>()
            .join("; ");

        if s.is_empty() {
            return None;
        }

        HeaderValue::from_bytes(s.as_bytes()).ok()
    }
}
