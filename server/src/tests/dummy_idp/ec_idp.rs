//! Dummy Identity Provider for Testing
//!
//! This module provides a simple Identity Provider (IdP) implementation for testing purposes.
//! It uses the EC P-256 certificates from the `certificates` directory to:
//! - Provide a JWKS (JSON Web Key Set) endpoint
//! - Issue JWT tokens signed with ES256 (ECDSA with P-256 and SHA-256)
//!
//! # Features
//! - Generates JWKS from EC P-256 certificates
//! - Issues JWT tokens with customizable claims
//! - Uses `alcoholic_jwt` library for JWKS format compatibility
//! - Signs tokens with OpenSSL using ES256 algorithm
//!
//! # Example
//! ```rust
//! use auth_authentication::{EcIdp, IdP};
//!
//! // Create a dummy IDP
//! let idp = EcIdp::new("https://my-issuer.com")?;;
//!
//! // Get JWKS (as would be served at /.well-known/jwks.json)
//! let jwks_json = idp.get_jwks_json()?;
//!
//! // Issue a JWT token
//! let token = idp.issue_token("alice@example.com", "my-api", 3600)?;
//! // Token format: Bearer eyJhbGci...
//! # Ok::<(), auth_authentication::AuthError>(())
//! ```
//!
//! # Note
//! The `alcoholic_jwt` library only supports RS256 (RSA) validation, not ES256 (ECDSA).
//! The tokens issued by this IDP are valid ES256 JWTs but cannot be validated using
//! `alcoholic_jwt`. For validation, use libraries like `jsonwebtoken` or `jose`.

use crate::{AuthError, AuthResult, tests::dummy_idp::IdP};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

const CERTIFICATES_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/certificates/ec");

/// JWT Header for ES256 (ECDSA with P-256 and SHA-256)
#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    email: String,
}

/// Dummy Identity Provider
#[derive(Clone)]
pub struct EcIdp {
    /// The JWKS (JSON Web Key Set) as a JSON value
    jwks_json: serde_json::Value,
    /// Private key for signing (PEM format)
    private_key_pem: String,
    /// Issuer URI
    issuer: String,
}

impl EcIdp {
    /// Create a new EcIdp from the certificates directory
    pub fn new(issuer: &str) -> AuthResult<Self> {
        let cert_path = format!("{}/auth.server.cert.pem", CERTIFICATES_PATH);
        let key_path = format!("{}/auth.server.key.pem", CERTIFICATES_PATH);

        // Read the certificate
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| AuthError::Config(format!("Failed to read certificate: {}", e)))?;

        // Read the private key
        let private_key_pem = std::fs::read_to_string(&key_path)
            .map_err(|e| AuthError::Config(format!("Failed to read private key: {}", e)))?;

        // Parse the certificate to extract public key
        let cert_der = parse_pem_cert(&cert_pem)?;

        // Create JWK from the certificate as a JSON value
        let jwk = create_jwk_from_cert(&cert_der)?;

        // Create JWKS JSON
        let jwks_json = json!({
            "keys": [jwk]
        });

        Ok(Self {
            jwks_json,
            private_key_pem,
            issuer: issuer.to_owned(),
        })
    }
}

impl IdP for EcIdp {
    /// Get the JWKS in JSON format
    fn get_jwks_json(&self) -> AuthResult<String> {
        serde_json::to_string_pretty(&self.jwks_json)
            .map_err(|e| AuthError::JWKS(format!("Failed to serialize JWKS: {}", e)))
    }

    /// Issue a JWT token for a given email/subject
    fn issue_token(&self, email: &str, audience: &str, validity_secs: u64) -> AuthResult<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::JWT(format!("System time error: {}", e)))?
            .as_secs();

        let header = JwtHeader {
            alg: "ES256".to_string(),
            typ: "JWT".to_string(),
            kid: "auth-server-key".to_string(),
        };

        let claims = JwtClaims {
            iss: self.issuer.clone(),
            sub: email.to_string(),
            aud: audience.to_string(),
            exp: now + validity_secs,
            iat: now,
            email: email.to_string(),
        };

        // Create the JWT
        let token = create_jwt(&header, &claims, &self.private_key_pem)?;

        Ok(token)
    }

    fn issue_definitely_expired_token(&self, email: &str, audience: &str) -> AuthResult<String> {
        // Set exp to Unix epoch + 1 — so far in the past that even a generous
        // leeway (default 60 s in jsonwebtoken) cannot save the token.
        let header = JwtHeader {
            alg: "ES256".to_string(),
            typ: "JWT".to_string(),
            kid: "auth-server-key".to_string(),
        };

        let claims = JwtClaims {
            iss: self.issuer.clone(),
            sub: email.to_string(),
            aud: audience.to_string(),
            exp: 1, // January 1, 1970 00:00:01 UTC
            iat: 1,
            email: email.to_string(),
        };

        create_jwt(&header, &claims, &self.private_key_pem)
    }

    /// Get the JWKS as a JSON value
    fn get_jwks(&self) -> &serde_json::Value {
        &self.jwks_json
    }

    /// Get the issuer URI
    fn get_issuer(&self) -> &str {
        &self.issuer
    }
}

/// Parse PEM certificate to DER format
fn parse_pem_cert(pem: &str) -> AuthResult<Vec<u8>> {
    let cert_start = "-----BEGIN CERTIFICATE-----";
    let cert_end = "-----END CERTIFICATE-----";

    let start_idx = pem
        .find(cert_start)
        .ok_or_else(|| AuthError::Config("Invalid PEM: missing BEGIN marker".to_string()))?;
    let end_idx = pem
        .find(cert_end)
        .ok_or_else(|| AuthError::Config("Invalid PEM: missing END marker".to_string()))?;

    let base64_content = &pem[start_idx + cert_start.len()..end_idx]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();

    STANDARD
        .decode(base64_content)
        .map_err(|e| AuthError::Config(format!("Failed to decode base64 certificate: {}", e)))
}

/// Create a JWK from a certificate DER
fn create_jwk_from_cert(cert_der: &[u8]) -> AuthResult<serde_json::Value> {
    use openssl::x509::X509;

    // Parse the X.509 certificate
    let cert = X509::from_der(cert_der)
        .map_err(|e| AuthError::Config(format!("Failed to parse X.509 certificate: {}", e)))?;

    // Get the public key
    let public_key = cert
        .public_key()
        .map_err(|e| AuthError::Config(format!("Failed to extract public key: {}", e)))?;

    // Get EC key
    let ec_key = public_key
        .ec_key()
        .map_err(|e| AuthError::Config(format!("Not an EC key: {}", e)))?;

    // Get the public key point
    let group = ec_key.group();
    let point = ec_key.public_key();

    // Convert point to uncompressed form (0x04 || x || y)
    let mut ctx = openssl::bn::BigNumContext::new()
        .map_err(|e| AuthError::Config(format!("Failed to create BigNum context: {}", e)))?;

    let bytes = point
        .to_bytes(
            group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .map_err(|e| AuthError::Config(format!("Failed to convert point to bytes: {}", e)))?;

    // For P-256, the uncompressed form is 65 bytes: 0x04 || x (32 bytes) || y (32 bytes)
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(AuthError::Config(format!(
            "Invalid public key format: expected 65 bytes starting with 0x04, got {} bytes",
            bytes.len()
        )));
    }

    let x = &bytes[1..33];
    let y = &bytes[33..65];

    // Base64 URL encode without padding
    let x_b64 = URL_SAFE_NO_PAD.encode(x);
    let y_b64 = URL_SAFE_NO_PAD.encode(y);

    // Create JWK as a JSON value
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x_b64,
        "y": y_b64,
        "use": "sig",
        "kid": "auth-server-key",
        "alg": "ES256"
    });

    Ok(jwk)
}

/// Create a JWT token signed with ES256
fn create_jwt(header: &JwtHeader, claims: &JwtClaims, private_key_pem: &str) -> AuthResult<String> {
    use openssl::ec::EcKey;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    // Encode header and claims
    let header_json = serde_json::to_string(header)
        .map_err(|e| AuthError::JWT(format!("Failed to serialize header: {}", e)))?;
    let claims_json = serde_json::to_string(claims)
        .map_err(|e| AuthError::JWT(format!("Failed to serialize claims: {}", e)))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

    let message = format!("{}.{}", header_b64, claims_b64);

    // Load private key
    let ec_key = EcKey::private_key_from_pem(private_key_pem.as_bytes())
        .map_err(|e| AuthError::JWT(format!("Failed to parse private key: {}", e)))?;

    let pkey = PKey::from_ec_key(ec_key)
        .map_err(|e| AuthError::JWT(format!("Failed to create PKey: {}", e)))?;

    // Sign the message
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
        .map_err(|e| AuthError::JWT(format!("Failed to create signer: {}", e)))?;

    signer
        .update(message.as_bytes())
        .map_err(|e| AuthError::JWT(format!("Failed to update signer: {}", e)))?;

    let signature = signer
        .sign_to_vec()
        .map_err(|e| AuthError::JWT(format!("Failed to sign: {}", e)))?;

    // The signature from OpenSSL is in DER format, we need to convert it to raw r||s format
    let (r, s) = parse_der_signature(&signature)?;

    // Concatenate r and s (each should be 32 bytes for P-256)
    let mut raw_signature = Vec::with_capacity(64);
    raw_signature.extend_from_slice(&r);
    raw_signature.extend_from_slice(&s);

    let signature_b64 = URL_SAFE_NO_PAD.encode(&raw_signature);

    Ok(format!("{}.{}", message, signature_b64))
}

/// Parse DER-encoded ECDSA signature to extract r and s components
fn parse_der_signature(der: &[u8]) -> AuthResult<(Vec<u8>, Vec<u8>)> {
    // DER SEQUENCE format: 0x30 <length> 0x02 <r_length> <r> 0x02 <s_length> <s>
    if der.len() < 8 || der[0] != 0x30 {
        return Err(AuthError::JWT("Invalid DER signature format".to_string()));
    }

    let mut idx = 2; // Skip 0x30 and total length

    // Parse r
    if der[idx] != 0x02 {
        return Err(AuthError::JWT(
            "Invalid DER signature: expected INTEGER tag for r".to_string(),
        ));
    }
    idx += 1;

    let r_len = der[idx] as usize;
    idx += 1;

    let r_bytes = &der[idx..idx + r_len];
    idx += r_len;

    // Parse s
    if der[idx] != 0x02 {
        return Err(AuthError::JWT(
            "Invalid DER signature: expected INTEGER tag for s".to_string(),
        ));
    }
    idx += 1;

    let s_len = der[idx] as usize;
    idx += 1;

    let s_bytes = &der[idx..idx + s_len];

    // Remove leading zero bytes if present (DER encoding adds them for positive numbers with high bit set)
    let r = if r_bytes[0] == 0 && r_bytes.len() > 32 {
        r_bytes[1..].to_vec()
    } else if r_bytes.len() < 32 {
        // Pad with zeros if needed
        let mut padded = vec![0; 32 - r_bytes.len()];
        padded.extend_from_slice(r_bytes);
        padded
    } else {
        r_bytes.to_vec()
    };

    let s = if s_bytes[0] == 0 && s_bytes.len() > 32 {
        s_bytes[1..].to_vec()
    } else if s_bytes.len() < 32 {
        // Pad with zeros if needed
        let mut padded = vec![0; 32 - s_bytes.len()];
        padded.extend_from_slice(s_bytes);
        padded
    } else {
        s_bytes.to_vec()
    };

    Ok((r, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_idp_creation() {
        let idp = EcIdp::new("https://auth.acme.com").unwrap();
        assert_eq!(idp.get_issuer(), "https://auth.acme.com");
    }

    #[test]
    fn test_jwks_generation() {
        let idp = EcIdp::new("https://auth.acme.com").unwrap();
        let jwks_json = idp.get_jwks_json().unwrap();

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&jwks_json).unwrap();
        assert!(parsed["keys"].is_array());
        assert_eq!(parsed["keys"][0]["kty"], "EC");
        assert_eq!(parsed["keys"][0]["crv"], "P-256");
        assert_eq!(parsed["keys"][0]["alg"], "ES256");
    }

    #[test]
    fn test_token_issuance() {
        let idp = EcIdp::new("https://auth.acme.com").unwrap();
        let token = idp
            .issue_token("user@example.com", "auth-api", 3600)
            .unwrap();

        // Basic JWT structure check (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode and verify header
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");

        // Decode and verify claims
        let claims_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_json).unwrap();
        assert_eq!(claims["email"], "user@example.com");
        assert_eq!(claims["iss"], "https://auth.acme.com");
        assert_eq!(claims["aud"], "auth-api");
    }

    // Note: alcoholic_jwt only supports RS256 (RSA), not ES256 (ECDSA), so we cannot
    // validate ES256 tokens using alcoholic_jwt. The tokens are valid ES256 JWTs though,
    // and can be validated using other libraries like jsonwebtoken or jose.

    #[test]
    fn test_example_usage() {
        // Example: Create a EcIdp, get JWKS, and issue a token
        let idp = EcIdp::new("https://my-issuer.com").unwrap();

        // Get JWKS endpoint response (as would be served at /.well-known/jwks.json)
        let jwks_json = idp.get_jwks_json().unwrap();
        println!("JWKS JSON:\n{}", jwks_json);

        // Issue a JWT token
        let token = idp
            .issue_token("alice@example.com", "my-api", 3600)
            .unwrap();

        assert!(!token.is_empty());
    }

    #[test]
    fn test_multiple_tokens() {
        // Test that we can issue multiple tokens with different claims
        let idp = EcIdp::new("https://auth.acme.com").unwrap();

        let token1 = idp.issue_token("user1@example.com", "api1", 3600).unwrap();
        let token2 = idp.issue_token("user2@example.com", "api2", 7200).unwrap();

        // Tokens should be different
        assert_ne!(token1, token2);

        // Verify different claims
        let parts1: Vec<&str> = token1.split('.').collect();
        let claims1_json = URL_SAFE_NO_PAD.decode(parts1[1]).unwrap();
        let claims1: serde_json::Value = serde_json::from_slice(&claims1_json).unwrap();

        let parts2: Vec<&str> = token2.split('.').collect();
        let claims2_json = URL_SAFE_NO_PAD.decode(parts2[1]).unwrap();
        let claims2: serde_json::Value = serde_json::from_slice(&claims2_json).unwrap();

        assert_eq!(claims1["email"], "user1@example.com");
        assert_eq!(claims1["aud"], "api1");

        assert_eq!(claims2["email"], "user2@example.com");
        assert_eq!(claims2["aud"], "api2");
    }
}
