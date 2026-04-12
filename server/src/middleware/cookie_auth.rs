//! Cookie Authentication Middleware
//!
//! This middleware is responsible for authenticating incoming requests based on a session cookie
//! issued by the Authentication Server.
//! It extracts the cookie from the request, validates it against the session store,
//! and sets the Client Claims information in the request extensions for downstream handlers to use.

use crate::{
    AuthError,
    session::{COOKIE_NAME, JwtTokenConfig, SessionStore, session_id_from_cookie_value},
};
use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody},
    cookie::Cookie,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use cosmian_logger::{debug, trace};
use futures::{
    Future,
    future::{Ready, ok},
};
use std::{
    pin::Pin,
    rc::Rc,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};

/// `CookieAuthSameServer` is an Actix web middleware for Authentication using a cookie provided
/// by the Authentication Server.
#[derive(Clone)]
pub struct CookieAuthSameServer {
    /// The session store used to validate session cookies and retrieve associated user information from the database
    session_store: Arc<dyn SessionStore>,

    /// JWT Token Configuration for validating and decoding JWT tokens in the session cookie
    jwt_token_config: Arc<JwtTokenConfig>,
}

impl CookieAuthSameServer {
    /// Creates a new `CookieAuthSameServer` middleware with the given session store
    ///
    /// # Arguments
    /// * `session_store` - The session store instance implementing the `SessionStore` trait
    /// * `jwt_token_config` - The JWT token configuration for validating and decoding JWT tokens in the session cookie
    #[must_use]
    pub fn new(
        session_store: Arc<dyn SessionStore>,
        jwt_token_config: Arc<JwtTokenConfig>,
    ) -> Self {
        Self {
            session_store,
            jwt_token_config,
        }
    }
}

/// Implementation of the Transform trait for Actix middleware registration
///
/// This trait defines how to create a new middleware service (`CookieMiddleware`)
/// from the transformer.
impl<S, B> Transform<S, ServiceRequest> for CookieAuthSameServer
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = CookieMiddleware<S>;

    /// Creates a new instance of the `CookieMiddleware` service
    fn new_transform(&self, service: S) -> Self::Future {
        ok(CookieMiddleware {
            service: Rc::new(service),
            session_store: self.session_store.clone(),
            jwt_token_config: self.jwt_token_config.clone(),
        })
    }
}

/// `CookieMiddleware` is the middleware service that processes each request
///
/// This middleware extracts the session cookie from the request,
/// validates them, and sets the Client Claims information in the request extensions.
pub struct CookieMiddleware<S> {
    /// The next service in the middleware chain
    service: Rc<S>,

    /// The session store for validating session cookies and retrieving associated user information
    session_store: Arc<dyn SessionStore>,

    // JWT Token Configuration for validating and decoding JWT tokens in the session cookie
    jwt_token_config: Arc<JwtTokenConfig>,
}

/// Implementation of the Service trait for request processing
impl<S, B> Service<ServiceRequest> for CookieMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    /// Processes each request by extracting and validating the session cookie
    ///
    /// The middleware:
    /// 1. Extracts the session cookie from the request
    /// 2. Validates the session cookie against the session store
    /// 3. If valid, sets the Client Claims information in the request extensions
    /// 4. Calls the next service in the chain
    fn call(&self, req: ServiceRequest) -> Self::Future {
        trace!("Cookie Auth Same Server: processing incoming request for authentication");
        let service = self.service.clone();
        let session_store = self.session_store.clone();
        let jwt_token_config = self.jwt_token_config.clone();

        Box::pin(async move {
            // Extract the cookie from the request and validate it against the database
            // Try to extract the session cookie from the request
            let Some(cookie) = req.cookie(COOKIE_NAME) else {
                debug!("Cookie Auth Same Server: No session cookie found");
                return Err(AuthError::Session("No session cookie found".to_string()).into());
            };
            // Do not log the full cookie value to avoid exposing session credentials
            trace!(
                "Cookie Auth Same Server: Found session cookie with name: {}",
                cookie.name()
            );
            let session_id = session_id_from_cookie_value(cookie.value().as_bytes())?;

            let Some(session_data) = session_store.get_session(&session_id).await? else {
                debug!(
                    "Cookie Auth Same Server: No valid session found for cookie: {}",
                    session_id
                );
                return Err(AuthError::Session("Invalid session cookie".to_string()).into());
            };
            debug!(
                "Cookie Auth Same Server: Valid session found for cookie: {}",
                session_id
            );
            let cookie = Cookie::from_str(&session_data.cookie_string).map_err(|e| {
                AuthError::Unexpected(format!(
                    "Failed parsing the session cookie from the store: {e}"
                ))
            })?;

            let client_claims = crate::session::validate_token(
                cookie.value(),
                jwt_token_config.algorithm,
                &jwt_token_config.decoding_key,
            )?;

            debug!(
                "Cookie Auth: Successfully validated client '{}' ",
                client_claims
                    .registered
                    .sub
                    .as_deref()
                    .unwrap_or("<unknown>")
            );

            // Set the session cookie value in the request extensions for downstream handlers to use
            req.extensions_mut().insert(client_claims);

            // Call the next service in the chain
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
