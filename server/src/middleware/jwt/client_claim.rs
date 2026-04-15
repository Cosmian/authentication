use cosmian_logger::{debug, trace};
#[cfg(feature = "no_jwt_validation")]
use jsonwebtoken::dangerous::insecure_decode;
#[cfg(not(feature = "no_jwt_validation"))]
use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
#[cfg(not(feature = "no_jwt_validation"))]
use jsonwebtoken::{DecodingKey, Validation};
use std::sync::Arc;

use crate::{
    AuthError, AuthResult, ClientClaims, IdpParams, JwtParams, middleware::jwt::JwksManager,
};

/// Attempts to extract and validate a client claim from a JWT token
pub async fn try_client_claims_from_token(
    jwks_manager: &Arc<JwksManager>,
    realm_id: &str,
    params: &JwtParams,
    authorization_header: &str,
) -> AuthResult<ClientClaims> {
    let bearer: Vec<&str> = authorization_header.splitn(2, ' ').collect();

    // Extract Bearer token from authorization header
    let token = match bearer.as_slice() {
        ["Bearer", token] if !token.is_empty() => token,
        ["Bearer", _] => {
            return Err(AuthError::JWT("token is empty".to_owned()));
        }
        _ => {
            return Err(AuthError::JWT(
                "Bad authorization header content (expected 'Bearer <token>')".to_owned(),
            ));
        }
    };

    // try each provided JWT configuration until one successfully validates the token or all configurations fail.
    let mut jwt_log_errors = Vec::new();
    for idp_params in &params.idp_params {
        match decode_bearer_header(jwks_manager, realm_id, idp_params, token).await {
            Ok(client_claim) => return Ok(client_claim),
            Err(error) => {
                jwt_log_errors.push(error);
            }
        }
    }
    // If all configurations failed, return the collected errors
    Err(AuthError::JWT(format!(
        "All JWT configurations failed to validate the token: {:?}",
        jwt_log_errors
    )))
}

/// Decodes and validates the JWT token using the provided identity provider parameters.
async fn decode_bearer_header(
    jwks_manager: &Arc<JwksManager>,
    realm_id: &str,
    idp_params: &IdpParams,
    token: &str,
) -> AuthResult<ClientClaims> {
    trace!(
        "validating authentication token, expected JWT issuer: {}",
        idp_params.jwt_issuer_uri
    );

    let header = decode_header(token)
        .map_err(|e| AuthError::JWT(format!("Failed to decode token header: {e}")))?;

    // Extract key ID from token header to locate the correct JWK
    let kid = header
        .kid
        .ok_or_else(|| AuthError::JWT("No 'kid' claim present in token".to_owned()))?;

    let jwk = jwks_manager
        .find_jwk(realm_id, &kid)
        .await?
        .ok_or_else(|| {
            AuthError::JWT(format!(
                "Realm: {realm_id}: specified kid `{kid}` not found in JWKS set"
            ))
        })?;

    trace!("JWK has been found:\n{jwk:?}");

    #[cfg(not(feature = "no_jwt_validation"))]
    let token_data = {
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&idp_params.jwt_issuer_uri]);
        validation.validate_exp = true;
        validation.set_required_spec_claims(&["sub"]);

        if let Some(jwt_audience) = &idp_params.jwt_audience {
            validation.set_audience(&[jwt_audience]);
        }

        // Create decoding key from JWK
        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|e| AuthError::JWT(format!("Failed to create decoding key from JWK: {e}")))?;

        // Decode and validate the token
        decode::<ClientClaims>(token, &decoding_key, &validation)
            .map_err(|err| AuthError::JWT(format!("Cannot validate token: {err:?}")))?
    };

    #[cfg(feature = "no_jwt_validation")]
    let token_data = insecure_decode::<ClientClaims>(token)
        .map_err(|err| AuthError::JWT(format!("Cannot insecurely decode token: {err:?}")))?;

    let client_claims = token_data.claims;

    debug!("Client Claims: {client_claims:?}");

    Ok(client_claims)
}
