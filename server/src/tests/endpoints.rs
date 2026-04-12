use actix_web::{HttpRequest, HttpResponse, web::Data};
use cosmian_logger::info;
use std::sync::Arc;

use crate::{AuthError, tests::IdP};

pub async fn jwks_endpoint(
    _req: HttpRequest,
    dummy_idp: Data<Arc<dyn IdP + Send + Sync>>,
) -> Result<HttpResponse, AuthError> {
    info!("Received request for JWKS endpoint");
    let jwks = dummy_idp.get_jwks();
    Ok(HttpResponse::Ok().json(jwks))
}
