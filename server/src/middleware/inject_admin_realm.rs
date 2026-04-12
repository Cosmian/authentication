//! InjectAdminRealm injects the admin realm
//! into the request extensions for requests to the `/admin/` endpoints.

use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use cosmian_logger::debug;
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

use crate::{database::Database, models::ADMIN_REALM};

/// `InjectAdminRealm` is an Actix web middleware that injects the admin realm into the request extensions for requests to the `/admin/` endpoints.
#[derive(Clone)]
pub struct InjectAdminRealm {
    database: Arc<dyn Database>,
}

impl InjectAdminRealm {
    /// Creates a new `InjectAdminRealm` middleware with the given database
    ///
    /// # Arguments
    /// * `database` - The database instance implementing the `Database` trait
    #[must_use]
    pub fn new(database: Arc<dyn Database>) -> Self {
        Self { database }
    }
}

/// Implementation of the Transform trait, which is how Actix registers middleware
///
/// This trait defines how to create a new middleware service (`InjectAdminRealmMiddleware`) from the
/// transformer. The middleware will be part of the Actix service pipeline.
impl<S, B> Transform<S, ServiceRequest> for InjectAdminRealm
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = InjectAdminRealmMiddleware<S>;

    /// Creates a new instance of the `InjectAdminRealmMiddleware` service
    ///
    /// This is called once during application startup for each service
    /// that this middleware wraps. It passes the necessary configuration
    /// to the `InjectAdminRealmMiddleware`.
    fn new_transform(&self, service: S) -> Self::Future {
        ok(InjectAdminRealmMiddleware {
            service: Rc::new(service),
            database: self.database.clone(),
        })
    }
}

/// `InjectAdminRealmMiddleware` is the actual middleware service that processes each request
///
/// This middleware injects the admin realm into the request extensions for requests to the `/admin/` endpoints.
pub struct InjectAdminRealmMiddleware<S> {
    /// The next service in the middleware chain
    service: Rc<S>,
    /// The database used to retrieve realm information
    database: Arc<dyn Database>,
}

/// Implementation of the Service trait which defines how requests are processed
///
/// This is where the actual fallback authentication logic happens for each incoming request.
impl<S, B> Service<ServiceRequest> for InjectAdminRealmMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    /// Checks if the middleware is ready to process a request
    ///
    /// This forwards the readiness check to the wrapped service.
    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    /// Processes incoming requests to extract and validate the realm from the URL path.
    ///
    /// For requests matching `/authenticate/{realm}`:
    /// - Extracts the realm from the URL path
    /// - Validates the realm exists in the database
    /// - Inserts the realm object into request extensions for downstream use
    ///
    /// Non-matching requests are passed through unchanged.
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let database = self.database.clone();

        Box::pin(async move {
            process_realm_from_request(&req, database).await?;
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}

async fn process_realm_from_request(
    req: &ServiceRequest,
    database: Arc<dyn Database>,
) -> Result<(), actix_web::error::Error> {
    // Retrieve the admin realm from the database and inject it into the request extensions
    let realm = database
        .get_realm(ADMIN_REALM)
        .await
        .map_err(|e| {
            debug!("Authenticate: Error retrieving realm: {e}");
            actix_web::error::ErrorInternalServerError("Authentication service error")
        })?
        .ok_or_else(|| {
            debug!("Authenticate: the admin realm is not found; cannot authenticate",);
            actix_web::error::ErrorUnauthorized("Admin realm not found")
        })?;
    req.extensions_mut().insert(realm);
    Ok(())
}
