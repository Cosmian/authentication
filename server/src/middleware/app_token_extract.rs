//! app token extraction middleware.
//!
//! Reads the `X-Vault-Token` header, SHA-256-hashes it, performs a DB lookup
//! (with no caching — caching lives in the KMS layer), and injects a
//! `AppTokenClaims` into the request extensions for downstream handlers.
//!
//! This middleware is used on the token self-service endpoints only (lookup-self,
//! renew-self, revoke-self). It does **not** use the `_ea_` cookie or the normal
//! session store.

use crate::{
    AuthError,
    database::{AppToken, Database},
};
use actix_web::{
    Error, HttpMessage, HttpRequest,
    body::{BoxBody, EitherBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use cosmian_logger::{error, trace};
use futures::{
    Future,
    future::{Ready, ok},
};
use sha2::{Digest, Sha256};
use std::{
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

/// The header name that AppRole-compatible clients use to carry their token.
pub const APP_TOKEN_HEADER: &str = "X-Vault-Token";

/// Claims injected into request extensions after a successful token lookup.
#[derive(Clone, Debug)]
pub struct AppTokenClaims {
    pub entity: String,
    pub policies: Vec<String>,
    pub renewable: bool,
    pub ttl: i64,
    pub token_hash: Vec<u8>,
}

impl AppTokenClaims {
    fn from_db(token: &AppToken) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            entity: token.entity.clone(),
            policies: token.policies.clone(),
            renewable: token.renewable,
            ttl: if token.expiry == 0 {
                token.lease_duration_secs
            } else {
                (token.expiry - now).max(0)
            },
            token_hash: token.token_hash.clone(),
        }
    }
}

/// Helper: extract and hash the token from a request, returning `None` if absent.
pub fn extract_app_token_hash(req: &HttpRequest) -> Option<Vec<u8>> {
    let raw = req.headers().get(APP_TOKEN_HEADER)?.to_str().ok()?;
    let hash = Sha256::digest(raw.as_bytes()).to_vec();
    Some(hash)
}

// ── Middleware infrastructure ─────────────────────────────────────────────────

/// `AppTokenExtract` middleware — authenticates a request via `X-Vault-Token`.
#[derive(Clone)]
pub struct AppTokenExtract {
    database: Arc<dyn Database>,
}

impl AppTokenExtract {
    #[must_use]
    pub fn new(database: Arc<dyn Database>) -> Self {
        Self { database }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AppTokenExtract
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = AppTokenExtractMiddleware<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AppTokenExtractMiddleware {
            service: Rc::new(service),
            database: self.database.clone(),
        })
    }
}

pub struct AppTokenExtractMiddleware<S> {
    service: Rc<S>,
    database: Arc<dyn Database>,
}

impl<S, B> Service<ServiceRequest> for AppTokenExtractMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Error = Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<ServiceResponse<EitherBody<B, BoxBody>>, Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let database = self.database.clone();

        Box::pin(async move {
            let token_hash = match extract_app_token_hash(req.request()) {
                Some(h) => h,
                None => {
                    trace!("AppTokenExtract: missing X-Vault-Token header");
                    let err = AuthError::Forbidden("missing X-Vault-Token header".to_string());
                    let (req, _) = req.into_parts();
                    return Ok(ServiceResponse::new(
                        req,
                        actix_web::HttpResponse::Forbidden()
                            .json(serde_json::json!({"errors": [err.to_string()]}))
                            .map_into_right_body(),
                    ));
                }
            };

            match database.lookup_app_token(&token_hash).await {
                Ok(Some(token)) => {
                    let claims = AppTokenClaims::from_db(&token);
                    req.extensions_mut().insert(claims);
                    let res = service.call(req).await?;
                    Ok(res.map_into_left_body())
                }
                Ok(None) => {
                    trace!("AppTokenExtract: token not found or expired");
                    let (req, _) = req.into_parts();
                    Ok(ServiceResponse::new(
                        req,
                        actix_web::HttpResponse::Forbidden()
                            .json(serde_json::json!({"errors": ["permission denied"]}))
                            .map_into_right_body(),
                    ))
                }
                Err(e) => {
                    error!("AppTokenExtract: database error during token lookup: {e}");
                    Err(actix_web::error::ErrorInternalServerError(
                        "authentication service error",
                    ))
                }
            }
        })
    }
}
