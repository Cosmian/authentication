use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use x509_cert::Certificate;
use x509_cert::der::DecodePem;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use crate::{AuthError, AuthScheme, models::ClientClaims};

/// Pre-built JWKS document served at `/.well-known/jwks.json`.
pub struct JwksData(pub serde_json::Value);

/// Build a JWKS document from a PEM string (either an X.509 certificate or a
/// SubjectPublicKeyInfo / `BEGIN PUBLIC KEY` file). The resulting set contains a
/// single EC P-256 `sig` key with a deterministic `kid` derived from the
/// SHA-256 digest of the raw x‖y bytes.
///
/// PEM parsing is delegated to the RustCrypto `x509-cert`/`spki` crates rather
/// than hand-rolled DER scanning, so this implementation is identical regardless
/// of the TLS backend feature (`openssl` or `rustls`).
///
/// Supported PEM types: `BEGIN CERTIFICATE`, `BEGIN PUBLIC KEY`.
pub fn build_jwks_from_pem(pem: &str) -> crate::AuthResult<JwksData> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    let spki = spki_from_pem(pem)?;
    let (x, y) = ec_p256_xy(&spki)?;

    let mut xy = Vec::with_capacity(64);
    xy.extend_from_slice(x);
    xy.extend_from_slice(y);
    let kid = hex::encode(Sha256::digest(&xy));

    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
    });
    Ok(JwksData(serde_json::json!({ "keys": [jwk] })))
}

/// Extract the `SubjectPublicKeyInfo` from either an X.509 certificate PEM or a
/// bare public-key PEM, reusing the RustCrypto parsers.
fn spki_from_pem(pem: &str) -> crate::AuthResult<SubjectPublicKeyInfoOwned> {
    if pem.contains("BEGIN CERTIFICATE") {
        let cert = Certificate::from_pem(pem)
            .map_err(|e| AuthError::Config(format!("Failed to parse X.509 certificate: {e}")))?;
        Ok(cert.tbs_certificate.subject_public_key_info)
    } else {
        SubjectPublicKeyInfoOwned::from_pem(pem)
            .map_err(|e| AuthError::Config(format!("Failed to parse public key PEM: {e}")))
    }
}

/// Return the `(x, y)` 32-byte coordinates of an EC P-256 public key.
///
/// The `subject_public_key` BIT STRING of an EC `SubjectPublicKeyInfo` is the
/// uncompressed point `0x04 ‖ x ‖ y` (RFC 5480 §2.2). A 65-byte length is unique
/// to P-256, so non-P-256 keys (and non-EC keys such as RSA) are rejected here.
fn ec_p256_xy(spki: &SubjectPublicKeyInfoOwned) -> crate::AuthResult<(&[u8], &[u8])> {
    let point = spki.subject_public_key.as_bytes().ok_or_else(|| {
        AuthError::Config("EC public key BIT STRING is not byte-aligned".to_string())
    })?;
    if point.len() != 65 || point[0] != 0x04 {
        return Err(AuthError::Config(format!(
            "Expected 65-byte uncompressed P-256 point, got {} bytes",
            point.len()
        )));
    }
    Ok((&point[1..33], &point[33..65]))
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
            Vec::new(),
            &config,
            expiration_seconds,
        )
        .unwrap();
        let result = validate_token(&token, config.algorithm, &config.decoding_key);
        assert!(result.is_err());
    }

    // A P-256 public key and a self-signed certificate carrying the *same* key.
    const P256_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf4Qf+T241nT/Si3iYnKu0OdbyHYK\n\
85nmNXsIULqwoRKchjztGT09/HQTwqFjST830dgYs39o+JAnr1JavtpK4A==\n\
-----END PUBLIC KEY-----\n";

    const P256_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBfTCCASOgAwIBAgIUTXCH/ZiZBXgovaTauCujoOKmJYwwCgYIKoZIzj0EAwIw\n\
FDESMBAGA1UEAwwJandrcy10ZXN0MB4XDTI2MDcwOTEzMTE1NFoXDTM2MDcwNjEz\n\
MTE1NFowFDESMBAGA1UEAwwJandrcy10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n\
AQcDQgAEf4Qf+T241nT/Si3iYnKu0OdbyHYK85nmNXsIULqwoRKchjztGT09/HQT\n\
wqFjST830dgYs39o+JAnr1JavtpK4KNTMFEwHQYDVR0OBBYEFDHJN0reH/ztPE8v\n\
tmMw0bR9ORQ0MB8GA1UdIwQYMBaAFDHJN0reH/ztPE8vtmMw0bR9ORQ0MA8GA1Ud\n\
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJmBKHffIbYIACSdI6I7oXnB\n\
9ccJ09vdLBdUcthO61hqAiBGz7Q6UFBkl2+9njGSHMdj67Bny4x1Gv/+QRG8kBO0\n\
nQ==\n\
-----END CERTIFICATE-----\n";

    fn assert_valid_p256_jwk(jwks: &serde_json::Value) {
        let jwk = &jwks["keys"][0];
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "ES256");
        // kid is the hex SHA-256 of x‖y (64 bytes → 32-byte digest → 64 hex chars).
        assert_eq!(jwk["kid"].as_str().unwrap().len(), 64);
        // x and y are base64url(no-pad) of 32-byte coordinates (43 chars each).
        assert_eq!(jwk["x"].as_str().unwrap().len(), 43);
        assert_eq!(jwk["y"].as_str().unwrap().len(), 43);
    }

    #[test]
    fn test_build_jwks_from_public_key_pem() {
        let jwks = build_jwks_from_pem(P256_PUBLIC_KEY_PEM).unwrap();
        assert_valid_p256_jwk(&jwks.0);
    }

    #[test]
    fn test_build_jwks_from_certificate_pem() {
        let jwks = build_jwks_from_pem(P256_CERTIFICATE_PEM).unwrap();
        assert_valid_p256_jwk(&jwks.0);
    }

    #[test]
    fn test_jwks_from_cert_matches_public_key() {
        // The certificate embeds the same public key, so both inputs must yield
        // identical JWK coordinates and key id.
        let from_key = build_jwks_from_pem(P256_PUBLIC_KEY_PEM).unwrap().0;
        let from_cert = build_jwks_from_pem(P256_CERTIFICATE_PEM).unwrap().0;
        assert_eq!(from_key["keys"][0]["x"], from_cert["keys"][0]["x"]);
        assert_eq!(from_key["keys"][0]["y"], from_cert["keys"][0]["y"]);
        assert_eq!(from_key["keys"][0]["kid"], from_cert["keys"][0]["kid"]);
    }

    #[test]
    fn test_build_jwks_rejects_non_ec_pem() {
        // An RSA/garbage PEM must not be accepted as a P-256 key.
        let result = build_jwks_from_pem(
            "-----BEGIN PUBLIC KEY-----\nbm90LWEta2V5\n-----END PUBLIC KEY-----\n",
        );
        assert!(matches!(result, Err(AuthError::Config(_))));
    }
}
