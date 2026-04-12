//! JWT Authentication Middleware
//!
//! This module contains the middleware implementation for JWT-based authentication.
//! It verifies and validates JWT tokens in incoming requests.

use crate::{
    AuthError, AuthResult, AuthenticatedClientScheme, JwtParams,
    middleware::jwt::JwksManager,
    models::{AuthScheme, Realm},
};
use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
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

/// `JwtAuth` is an Actix web middleware that handles authentication for the Authentication server.
///
/// In Actix web, middlewares consist of two parts:
/// 1. A transformer (this struct), which is used during service configuration
/// 2. A middleware service that processes each request
///
/// This transformer is responsible for creating the middleware service with the necessary
/// configuration for authentication.
///
/// This middleware handles:
/// - JWT-based authentication using provided JWT configurations
#[derive(Clone)]
pub struct JwtAuth {
    jwks_manager: Arc<JwksManager>,
}

impl JwtAuth {
    /// Creates a new `JwtAuth` with the optional JWT configurations
    ///
    /// # Parameters
    /// * `jwks_manager` - The JWKS manager for handling JSON Web Key Sets
    #[must_use]
    pub const fn new(jwks_manager: Arc<JwksManager>) -> Self {
        Self { jwks_manager }
    }
}

/// Implementation of the Transform trait, which is how Actix registers middleware
///
/// This trait defines how to create a new middleware service (`JwtAuthMiddleware`) from the
/// transformer. The middleware will be part of the Actix service pipeline.
impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = JwtAuthMiddleware<S>;

    /// Creates a new instance of the `JwtAuthMiddleware` service
    ///
    /// This is called once during application startup for each service
    /// that this middleware wraps. It passes the necessary configuration
    /// to the `JwtAuthMiddleware`.
    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtAuthMiddleware {
            service: Rc::new(service),
            jwks_manager: self.jwks_manager.clone(),
        })
    }
}

/// `JwtAuthMiddleware` is the actual middleware service that processes each request
///
/// This middleware examines each request and applies the appropriate authentication logic:
pub struct JwtAuthMiddleware<S> {
    /// The next service in the middleware chain
    service: Rc<S>,
    /// Optional JWT configuration for JWT-based authentication
    jwks_manager: Arc<JwksManager>,
}

/// Implementation of the Service trait, which defines how requests are processed
///
/// This is where the actual authentication logic happens for each incoming request.
impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
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

    /// Processes each request by applying appropriate authentication
    ///
    /// Authentication is performed in the following order:
    /// 1. If certificate authentication is already done (`PeerCommonName` exists), skip further auth
    /// 2. If JWT configurations exist, try JWT-based authentication
    /// 3. If both authentication methods fail, return an unauthorized response
    fn call(&self, req: ServiceRequest) -> Self::Future {
        trace!("JWT Middleware: Processing incoming request for authentication");
        let service = self.service.clone();

        // If JWT configurations exist, try JWT-based authentication
        let jwks_manager = self.jwks_manager.clone();
        Box::pin(async move {
            if req.extensions().contains::<AuthenticatedClientScheme>() {
                debug!("Request already authenticated, skipping JWT middleware");
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            }
            // Get realm from request extensions
            let Some(realm) = req.extensions().get::<Realm>().cloned() else {
                debug!(
                    "UsernamePassword: No realm found in request extensions; cannot authenticate"
                );
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            };

            let Some(jwt_params) = realm.auth_params.jwt_params.clone() else {
                debug!(
                    "JWT: No JWT parameters found for realm {}; cannot authenticate",
                    &realm.id
                );
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            };

            // ensure the JWKS for the realm is managed before attempting authentication
            ensure_realm_jwks_is_managed(&jwks_manager, &realm.id, &jwt_params).await?;

            match handle_jwt(&jwks_manager, &realm.id, &jwt_params, &req).await {
                Ok(auth_claim) => {
                    // Authentication successful, insert the claim into request extensions
                    // and proceed with the request
                    req.extensions_mut().insert(auth_claim);
                }
                Err(e) => {
                    debug!(
                        "JWT authentication failed: {e:?}. Continuing without JWT authentication."
                    );
                }
            }

            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}

async fn ensure_realm_jwks_is_managed(
    jwks_manager: &Arc<JwksManager>,
    realm_id: &str,
    jwt_params: &JwtParams,
) -> AuthResult<()> {
    // Check if the realm already exists in the JWKS manager
    if jwks_manager.has_realm(realm_id).await? {
        return Ok(());
    }

    // If not, add it
    jwks_manager
        .upsert_realm(
            realm_id,
            jwt_params
                .idp_params
                .iter()
                .map(|idp| idp.jwks_uri.clone())
                .collect::<Vec<_>>(),
            jwt_params.smallest_refresh_interval_seconds,
        )
        .await?;
    Ok(())
}

async fn handle_jwt(
    jwks_manager: &Arc<JwksManager>,
    realm_id: &str,
    params: &JwtParams,
    req: &ServiceRequest,
) -> AuthResult<AuthenticatedClientScheme> {
    trace!("JWT Authentication...");

    let authorization_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok().map(ToString::to_string))
        .unwrap_or_default();

    // Try to extract and validate the user claim
    let user_claim = super::client_claim::try_client_claims_from_token(
        jwks_manager,
        realm_id,
        params,
        &authorization_header,
    )
    .await?;

    if let Some(sub) = &user_claim.registered.sub {
        debug!("JWT Access granted to {sub}!");
        Ok(AuthenticatedClientScheme {
            username: sub.to_owned(),
            auth_scheme: AuthScheme::Jwt,
        })
    } else {
        debug!(
            "{:?} {} 401 unauthorized, no subject in JWT",
            req.method(),
            req.path()
        );
        Err(AuthError::JWT("No subject in JWT".to_owned()))
    }
}
