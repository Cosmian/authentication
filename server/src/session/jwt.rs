use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::{AuthError, AuthScheme, models::ClientClaims};

/// Pre-built JWKS document served at `/.well-known/jwks.json`.
pub struct JwksData(pub serde_json::Value);

/// Build a JWKS document from a PEM string (either an X.509 certificate or a
/// SubjectPublicKeyInfo / `BEGIN PUBLIC KEY` file). The resulting set contains a
/// single EC P-256 `sig` key with a deterministic `kid` derived from the
/// SHA-256 digest of the raw x‖y bytes.
///
/// Supported PEM types: `BEGIN CERTIFICATE`, `BEGIN PUBLIC KEY`.
#[cfg(feature = "openssl")]
pub fn build_jwks_from_pem(pem: &str) -> crate::AuthResult<JwksData> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    let xy = ec_xy_from_pem_openssl(pem)?;

    let kid = hex::encode(Sha256::digest(&xy));
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(&xy[0..32]),
        "y": URL_SAFE_NO_PAD.encode(&xy[32..64]),
    });
    Ok(JwksData(serde_json::json!({ "keys": [jwk] })))
}

#[cfg(feature = "openssl")]
fn ec_xy_from_pem_openssl(pem: &str) -> crate::AuthResult<Vec<u8>> {
    if pem.contains("BEGIN CERTIFICATE") {
        let der = pem_to_der_bytes(pem, "CERTIFICATE")?;
        let cert = openssl::x509::X509::from_der(&der)
            .map_err(|e| AuthError::Config(format!("Failed to parse X.509 certificate: {e}")))?;
        let pkey = cert
            .public_key()
            .map_err(|e| AuthError::Config(format!("Failed to extract public key: {e}")))?;
        ec_xy_from_pkey(&pkey)
    } else {
        let der = pem_to_der_bytes(pem, "PUBLIC KEY")?;
        let pkey = openssl::pkey::PKey::public_key_from_der(&der)
            .map_err(|e| AuthError::Config(format!("Failed to parse public key DER: {e}")))?;
        ec_xy_from_pkey(&pkey)
    }
}

#[cfg(feature = "openssl")]
fn ec_xy_from_pkey(
    pkey: &openssl::pkey::PKey<openssl::pkey::Public>,
) -> crate::AuthResult<Vec<u8>> {
    let ec = pkey
        .ec_key()
        .map_err(|e| AuthError::Config(format!("JWT key is not an EC key: {e}")))?;
    let group = ec.group();
    let point = ec.public_key();
    let mut ctx = openssl::bn::BigNumContext::new()
        .map_err(|e| AuthError::Config(format!("Failed to create BigNum context: {e}")))?;
    let bytes = point
        .to_bytes(
            group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .map_err(|e| AuthError::Config(format!("Failed to export EC point: {e}")))?;
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(AuthError::Config(format!(
            "Expected 65-byte uncompressed P-256 point, got {} bytes",
            bytes.len()
        )));
    }
    Ok(bytes[1..].to_vec()) // 64 bytes: x‖y
}

/// Build a JWKS document from a PEM string.
///
/// This is the `rustls`-only (no OpenSSL) implementation. It parses the raw DER
/// bytes to locate the uncompressed EC public-key point directly.
#[cfg(all(feature = "rustls", not(feature = "openssl")))]
pub fn build_jwks_from_pem(pem: &str) -> crate::AuthResult<JwksData> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    let xy = ec_xy_from_pem_der(pem)?;

    let kid = hex::encode(Sha256::digest(&xy));
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(&xy[0..32]),
        "y": URL_SAFE_NO_PAD.encode(&xy[32..64]),
    });
    Ok(JwksData(serde_json::json!({ "keys": [jwk] })))
}

/// Locate the 64-byte x‖y from a P-256 EC key embedded in raw DER bytes.
///
/// The uncompressed-point marker `0x04` is always the last content byte of the
/// BitString that encodes the SubjectPublicKeyInfo's public key. In a P-256
/// SubjectPublicKeyInfo the DER is exactly 91 bytes and `0x04` is at byte 26.
/// In an X.509 certificate the same BitString appears near the end of the
/// TBSCertificate, so scanning backwards for `0x00 0x04` (no unused bits +
/// uncompressed marker) followed by exactly 64 bytes is reliable.
#[cfg(all(feature = "rustls", not(feature = "openssl")))]
fn ec_xy_from_pem_der(pem: &str) -> crate::AuthResult<[u8; 64]> {
    let label = if pem.contains("BEGIN CERTIFICATE") {
        "CERTIFICATE"
    } else {
        "PUBLIC KEY"
    };
    let der = pem_to_der_bytes(pem, label)?;

    // Search for the last occurrence of [0x00, 0x04] (BitString no-unused-bits +
    // uncompressed EC point marker) where 64 bytes follow.
    let pos = der
        .windows(2)
        .enumerate()
        .rev()
        .find(|(i, w)| w[0] == 0x00 && w[1] == 0x04 && i + 2 + 64 <= der.len())
        .map(|(i, _)| i + 2) // first byte of x
        .ok_or_else(|| {
            AuthError::Config("Cannot locate P-256 uncompressed point in DER".to_string())
        })?;

    let mut xy = [0u8; 64];
    xy.copy_from_slice(&der[pos..pos + 64]);
    Ok(xy)
}

fn pem_to_der_bytes(pem: &str, label: &str) -> crate::AuthResult<Vec<u8>> {
    use base64::Engine as _;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .ok_or_else(|| AuthError::Config(format!("Missing BEGIN {label} marker in PEM")))?
        + begin.len();
    let end_idx = pem
        .find(&end)
        .ok_or_else(|| AuthError::Config(format!("Missing END {label} marker in PEM")))?;
    let b64: String = pem[start..end_idx]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| AuthError::Config(format!("Failed to base64-decode PEM body: {e}")))
}

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
        // Verify roles are present in issued tokens.
        assert_eq!(
            claims.authorization.roles,
            Some(vec!["CryptoOfficer".to_string()])
        );
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
