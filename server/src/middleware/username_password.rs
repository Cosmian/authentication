//! Username/Password Authentication Middleware
//!
//! This middleware handles HTTP Basic Authentication by extracting and validating
//! credentials from the Authorization header.

use std::{
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::{BoxBody, EitherBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::header::AUTHORIZATION,
};
use base64::Engine;
use cosmian_logger::{debug, trace};
use futures::{
    Future,
    future::{Ready, ok},
};

use crate::{
    AuthenticatedClientScheme,
    database::Database,
    models::{AuthScheme, Realm},
};

/// `UsernamePasswordAuth` is an Actix web middleware for HTTP Basic Authentication
///
/// This middleware:
/// - Extracts credentials from the `Authorization` header (Basic scheme)
/// - Validates credentials against the configured `CredentialStore`
/// - Inserts an `AuthenticatedUser` into request extensions on successful authentication
#[derive(Clone)]
pub struct UsernamePasswordAuth {
    /// The database used to validate username/password pairs
    database: Arc<dyn Database>,
}

impl UsernamePasswordAuth {
    /// Creates a new `UsernamePasswordAuth` middleware with the given database
    ///
    /// # Arguments
    /// * `database` - The database instance implementing the `Database` trait
    #[must_use]
    pub fn new(database: Arc<dyn Database>) -> Self {
        Self { database }
    }
}

/// Implementation of the Transform trait for Actix middleware registration
///
/// This trait defines how to create a new middleware service (`UsernamePasswordMiddleware`)
/// from the transformer.
impl<S, B> Transform<S, ServiceRequest> for UsernamePasswordAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = UsernamePasswordMiddleware<S>;

    /// Creates a new instance of the `UsernamePasswordMiddleware` service
    fn new_transform(&self, service: S) -> Self::Future {
        ok(UsernamePasswordMiddleware {
            service: Rc::new(service),
            database: self.database.clone(),
        })
    }
}

/// `UsernamePasswordMiddleware` is the middleware service that processes each request
///
/// This middleware extracts credentials from the Authorization header,
/// validates them, and sets the authenticated user in the request extensions.
pub struct UsernamePasswordMiddleware<S> {
    /// The next service in the middleware chain
    service: Rc<S>,
    /// The database for validating credentials
    database: Arc<dyn Database>,
}

/// Implementation of the Service trait for request processing
impl<S, B> Service<ServiceRequest> for UsernamePasswordMiddleware<S>
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

    /// Processes each request by extracting and validating Basic Auth credentials
    ///
    /// The middleware:
    /// 1. Skips if the request is already authenticated
    /// 2. Extracts the Authorization header
    /// 3. Parses the Basic authentication scheme
    /// 4. Decodes and validates the credentials
    /// 5. Sets the AuthenticatedUser on success
    fn call(&self, req: ServiceRequest) -> Self::Future {
        trace!("UsernamePassword Middleware: Processing incoming request for authentication");
        let service = self.service.clone();
        let database = self.database.clone();
        Box::pin(async move {
            // Skip if already authenticated.
            if req.extensions().contains::<AuthenticatedClientScheme>() {
                debug!(
                    "UsernamePassword: An authenticated user was found; skipping authentication"
                );
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            // Try to extract and validate credentials
            match extract_basic_auth_credentials(&req) {
                Some((username, password)) => {
                    // Get realm from request extensions
                    let Some(realm) = req.extensions().get::<Realm>().cloned() else {
                        debug!(
                            "UsernamePassword: No realm found in request extensions; cannot authenticate"
                        );
                        let res = service.call(req).await?;
                        return Ok(res.map_into_left_body());
                    };

                    // Check if username/password authentication is allowed on the realm
                    let Some(params) = realm.auth_params.username_password_params.as_ref() else {
                        debug!(
                            "UsernamePassword: Realm '{}' does not provide username/password authentication",
                            &realm.id
                        );
                        let res = service.call(req).await?;
                        return Ok(res.map_into_left_body());
                    };

                    match database
                        .validate_userpass(&realm.id, &username, &password)
                        .await
                    {
                        Ok(true) => {
                            if params.allow_expired_passwords {
                                debug!(
                                    "UsernamePassword: successfully authenticated client: {username}"
                                );
                                req.extensions_mut().insert(AuthenticatedClientScheme {
                                    username,
                                    auth_scheme: AuthScheme::UsernamePassword,
                                });
                                let res = service.call(req).await?;
                                return Ok(res.map_into_left_body());
                            }
                            debug!("UsernamePassword: password expired for client: {username}");
                            Ok(req
                                .into_response(HttpResponse::Forbidden().body("Password expired"))
                                .map_into_right_body())
                        }
                        Ok(false) => {
                            debug!("UsernamePassword: successfully authenticated user: {username}");
                            req.extensions_mut().insert(AuthenticatedClientScheme {
                                username,
                                auth_scheme: AuthScheme::UsernamePassword,
                            });
                            let res = service.call(req).await?;
                            Ok(res.map_into_left_body())
                        }
                        Err(e) => {
                            debug!("UsernamePassword: credential validation error: {e}");
                            Ok(req
                                .into_response(
                                    HttpResponse::Unauthorized()
                                        .insert_header((
                                            "WWW-Authenticate",
                                            "Basic realm=\"Authentication Required\"",
                                        ))
                                        .body("Authentication service error"),
                                )
                                .map_into_right_body())
                        }
                    }
                }
                None => {
                    debug!(
                        "UsernamePassword: No Basic Authorization header found, passing through"
                    );
                    // No Basic Auth header present - pass through to next middleware
                    // This allows other authentication methods to be tried
                    let res = service.call(req).await?;
                    Ok(res.map_into_left_body())
                }
            }
        })
    }
}

/// Extracts username and password from the HTTP Basic Authorization header
///
/// # Arguments
/// * `req` - The service request to extract credentials from
///
/// # Returns
/// * `Some((username, password))` - If valid Basic auth credentials are found
/// * `None` - If no valid Basic auth header is present
fn extract_basic_auth_credentials(req: &ServiceRequest) -> Option<(String, String)> {
    let auth_header = req.headers().get(AUTHORIZATION)?;
    let auth_str = auth_header.to_str().ok()?;

    // Check for "Basic " prefix (case-insensitive)
    if !auth_str.to_lowercase().starts_with("basic ") {
        return None;
    }

    // Extract and decode the base64-encoded credentials
    let encoded_credentials = auth_str[6..].trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded_credentials)
        .ok()?;

    let credentials_str = String::from_utf8(decoded).ok()?;

    // Split on the first colon (password may contain colons)
    let colon_pos = credentials_str.find(':')?;
    let username = credentials_str[..colon_pos].to_string();
    let password = credentials_str[colon_pos + 1..].to_string();

    // Username must not be empty
    if username.is_empty() {
        return None;
    }

    Some((username, password))
}
