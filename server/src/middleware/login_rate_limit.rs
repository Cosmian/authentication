//! Per-IP rate limiting middleware for the `/login` endpoint.
//!
//! Built directly on the MIT-licensed `governor` crate to avoid the
//! GPL-3.0-only `actix-governor` dependency.

use std::{
    net::IpAddr,
    num::NonZeroU32,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use actix_web::{
    Error, HttpResponse,
    body::{BoxBody, EitherBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use futures::{
    Future,
    future::{Ready, ok},
};
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::keyed::DefaultKeyedStateStore,
};

type Limiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock, NoOpMiddleware>;

/// Per-IP rate limiter for the `/login` endpoint.
///
/// Uses a token-bucket algorithm (via `governor`) keyed by the connecting peer
/// IP address.  Requests exceeding the quota receive `429 Too Many Requests`.
///
/// # Example
/// ```ignore
/// // 5 req/s with a burst capacity of 10
/// let rl = LoginRateLimit::new(5, 10);
/// let scope = web::scope("/login").wrap(rl);
/// ```
#[derive(Clone)]
pub struct LoginRateLimit {
    limiter: Arc<Limiter>,
}

impl LoginRateLimit {
    /// Creates a new rate limiter.
    ///
    /// * `requests_per_second` — sustained throughput per IP (must be ≥ 1).
    /// * `burst_size` — maximum burst above the sustained rate (must be ≥ 1).
    #[must_use]
    pub fn new(requests_per_second: u32, burst_size: u32) -> Self {
        let period = Duration::from_secs(1) / requests_per_second.max(1);
        let quota = Quota::with_period(period)
            .expect("valid non-zero period")
            .allow_burst(NonZeroU32::new(burst_size.max(1)).expect("nonzero burst"));
        Self {
            limiter: Arc::new(RateLimiter::keyed(quota)),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for LoginRateLimit
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = LoginRateLimitMiddleware<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(LoginRateLimitMiddleware {
            service: Rc::new(service),
            limiter: self.limiter.clone(),
        })
    }
}

/// Inner service produced by [`LoginRateLimit`].
pub struct LoginRateLimitMiddleware<S> {
    service: Rc<S>,
    limiter: Arc<Limiter>,
}

impl<S, B> Service<ServiceRequest> for LoginRateLimitMiddleware<S>
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

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let limiter = self.limiter.clone();

        Box::pin(async move {
            // Peer IP: prefer the connection IP (not a forwarded header, which
            // can be spoofed) for the rate-limit key.
            let peer_ip: IpAddr = req
                .peer_addr()
                .map(|addr| addr.ip())
                .unwrap_or(IpAddr::from([127, 0, 0, 1]));

            if limiter.check_key(&peer_ip).is_err() {
                let (request, _payload) = req.into_parts();
                let response = HttpResponse::TooManyRequests()
                    .body("Rate limit exceeded — please slow down.")
                    .map_into_right_body();
                return Ok(ServiceResponse::new(request, response));
            }

            service.call(req).await.map(|res| res.map_into_left_body())
        })
    }
}
