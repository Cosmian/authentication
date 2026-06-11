use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::{AuthError, AuthScheme, models::ClientClaims};

pub struct JwtTokenConfig {
    pub algorithm: Algorithm,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
}

impl JwtTokenConfig {
    pub fn new(algorithm: Algorithm, encoding_key: EncodingKey, decoding_key: DecodingKey) -> Self {
        Self {
            algorithm,
            encoding_key,
            decoding_key,
        }
    }
}

pub fn issue_token(
    subject: &str,
    auth_scheme: AuthScheme,
    realm_id: &str,
    public_key_pem: Option<String>,
    roles: Vec<String>,
    jwt_config: &JwtTokenConfig,
    expiration_seconds: i64,
) -> Result<String, AuthError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AuthError::Unexpected(format!("System time error when issuing token: {e}")))?
        .as_secs() as i64;

    let claims = ClientClaims {
        registered: crate::models::RegisteredClaims {
            sub: Some(subject.to_string()),
            exp: Some(now + expiration_seconds),
            iat: Some(now),
            ..Default::default()
        },
        authorization: crate::models::AuthorizationClaims {
            roles: if roles.is_empty() { None } else { Some(roles) },
        },
        private: crate::models::AuthPrivateClaims {
            auth_scheme: Some(auth_scheme),
            public_key: public_key_pem,
            realm_id: Some(realm_id.to_string()),
            domain: Some(realm_id.to_string()),
        },
        ..Default::default()
    };

    let header = Header::new(jwt_config.algorithm);
    encode(&header, &claims, &jwt_config.encoding_key)
        .map_err(|e| AuthError::Unexpected(format!("Failed to issue token: {e}")))
}

pub fn validate_token(
    token: &str,
    algorithm: Algorithm,
    decoding_key: &DecodingKey,
) -> Result<ClientClaims, AuthError> {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.leeway = 1; // 1 second leeway for clock skew

    let token_data = decode::<ClientClaims>(token, decoding_key, &validation)
        .map_err(|e| AuthError::Unexpected(format!("Failed to validate token: {e}")))?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use cosmian_logger::info;

    use crate::AuthScheme;

    use super::*;

    #[test]
    fn test_token_roundtrip_hs256() {
        let secret = b"secret";
        let expiration_seconds = 3600;
        let config = JwtTokenConfig::new(
            Algorithm::HS256,
            EncodingKey::from_secret(secret),
            DecodingKey::from_secret(secret),
        );

        let token = issue_token(
            "user123",
            AuthScheme::UsernamePassword,
            "realm123",
            None,
            vec!["CryptoOfficer".to_string()],
            &config,
            expiration_seconds,
        )
        .unwrap();
        let claims = validate_token(&token, config.algorithm, &config.decoding_key).unwrap();
        assert_eq!(claims.registered.sub, Some("user123".to_string()));
        assert_eq!(claims.private.realm_id, Some("realm123".to_string()));
        // Verify roles and domain are present in issued tokens.
        assert_eq!(
            claims.authorization.roles,
            Some(vec!["CryptoOfficer".to_string()])
        );
        assert_eq!(claims.private.domain, Some("realm123".to_string()));
    }

    #[test]
    fn test_token_expiration() {
        let secret = b"secret";
        let expiration_seconds = 1;
        let config = JwtTokenConfig::new(
            Algorithm::HS256,
            EncodingKey::from_secret(secret),
            DecodingKey::from_secret(secret),
        );
        let token = issue_token(
            "user123",
            AuthScheme::UsernamePassword,
            "realm123",
            None,
            Vec::new(),
            &config,
            expiration_seconds,
        )
        .unwrap();
        let claims = validate_token(&token, config.algorithm, &config.decoding_key).unwrap();
        assert_eq!(claims.registered.sub, Some("user123".to_string()));
        assert_eq!(claims.private.realm_id, Some("realm123".to_string()));
        // we have 1 second leeway, so we wait 2 seconds to ensure the token is expired
        std::thread::sleep(std::time::Duration::from_secs(3));
        let result = validate_token(&token, config.algorithm, &config.decoding_key);
        info!("Validation result after expiration: {result:?}");
        assert!(result.is_err());
    }

    #[test]
    fn test_token_invalid_signature() {
        let secret = b"secret";
        let wrong_secret = b"wrong_secret";
        let expiration_seconds = 3600;
        let config = JwtTokenConfig::new(
            Algorithm::HS256,
            EncodingKey::from_secret(secret),
            DecodingKey::from_secret(wrong_secret),
        );
        let token = issue_token(
            "user123",
            AuthScheme::UsernamePassword,
            "realm123",
            None,
            Vec::new(),
            &config,
            expiration_seconds,
        )
        .unwrap();
        let result = validate_token(&token, config.algorithm, &config.decoding_key);
        assert!(result.is_err());
    }
}
