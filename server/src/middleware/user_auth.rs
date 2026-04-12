//! User Authentication Middleware
//!
//! This middleware is responsible for finding the User associated with Client Claims extracted by previous middlewares (e.g. CookieAuthSameServer).
//! It retrieves the User information from the database and sets it in the request extensions for downstream handlers

use crate::{AuthError, models::ClientClaims};
use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody},
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
    sync::Arc,
    task::{Context, Poll},
};

/// `UserAuth` is an Actix web middleware for fetching a User using the ClientClaims.
#[derive(Clone)]
pub struct UserAuth {
    /// The database used to retrieve the User information
    database: Arc<dyn crate::database::Database>,
}

impl UserAuth {
    /// Creates a new `UserAuth` middleware with the given database
    ///
    /// # Arguments
    /// * `database` - The database used to retrieve the User information
    #[must_use]
    pub fn new(database: Arc<dyn crate::database::Database>) -> Self {
        Self { database }
    }
}

/// Implementation of the Transform trait for Actix middleware registration
///
/// This trait defines how to create a new middleware service (`UserAuthMiddleware`)
/// from the transformer.
impl<S, B> Transform<S, ServiceRequest> for UserAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = UserAuthMiddleware<S>;

    /// Creates a new instance of the `UserAuthMiddleware` service
    fn new_transform(&self, service: S) -> Self::Future {
        ok(UserAuthMiddleware {
            service: Rc::new(service),
            database: self.database.clone(),
        })
    }
}

/// `UserAuthMiddleware` is the middleware service that processes each request
///
/// This middleware extracts the Client Claims from the request,
/// retrieves the associated User information from the database,
/// and sets the User information in the request extensions.
pub struct UserAuthMiddleware<S> {
    /// The next service in the middleware chain
    service: Rc<S>,

    /// The database used to retrieve the User information
    database: Arc<dyn crate::database::Database>,
}

/// Implementation of the Service trait for request processing
impl<S, B> Service<ServiceRequest> for UserAuthMiddleware<S>
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

    /// Processes each request by extracting and validating the Client Claims
    ///
    /// The middleware:
    /// 1. Extracts the Client Claims from the request
    /// 2. Retrieves the associated User information from the database
    /// 3. If valid, sets the User information in the request extensions
    /// 4. Calls the next service in the chain
    fn call(&self, req: ServiceRequest) -> Self::Future {
        trace!("User Auth: processing incoming request for authentication");
        let service = self.service.clone();

        let database = self.database.clone();
        let client_claims = req.extensions().get::<ClientClaims>().cloned();

        Box::pin(async move {
            let client_claims = client_claims.ok_or_else(|| {
                AuthError::Session(
                    "No client claims found in request extensions for UserAuth middleware"
                        .to_string(),
                )
            })?;
            let auth_scheme = client_claims.private.auth_scheme.as_ref().ok_or_else(|| {
                AuthError::Session("No auth scheme found in token claims".to_string())
            })?;
            let value = client_claims.registered.sub.as_ref().ok_or_else(|| {
                AuthError::Session("No subject (username) found in token claims".to_string())
            })?;

            let user = database
                .find_users_by_auth_scheme(*auth_scheme, value)
                .await
                .map_err(|e| {
                    AuthError::Unexpected(format!(
                        "Failed to query user by auth scheme and value: {e}"
                    ))
                })?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    AuthError::Session(
                        "No user found for the given auth scheme and value".to_string(),
                    )
                })?;

            debug!(
                "User Auth: Retrieved user '{}' from database for auth scheme '{:?}' and value '{}'",
                user.id, auth_scheme, value
            );

            // Set the User information in the request extensions for downstream handlers to use
            req.extensions_mut().insert(user);

            // Call the next service in the chain
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
