//! Dummy Identity Provider for Testing (RSA)
//!
//! This module provides a simple Identity Provider (IdP) implementation for testing purposes.
//! It uses the RSA 4096 certificates from the `certificates/rsa` directory to:
//! - Provide a JWKS (JSON Web Key Set) endpoint
//! - Issue JWT tokens signed with RS256 (RSA with SHA-256)
//!
//! # Features
//! - Generates JWKS from RSA 4096 certificates
//! - Issues JWT tokens with customizable claims
//! - Uses `alcoholic_jwt` library compatible JWKS format
//! - Signs tokens with OpenSSL using RS256 algorithm
//!
//! # Example
//! ```rust
//! use auth_authentication::{RsaIdp, IdP};
//!
//! // Create a dummy IDP
//! let idp = RsaIdp::new("https://my-issuer.com")?;;
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
//! The `alcoholic_jwt` library supports RS256 (RSA) validation, so tokens issued by this
//! IDP can be validated using `alcoholic_jwt` or other JWT libraries.

use crate::{AuthError, AuthResult, tests::dummy_idp::IdP};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use cosmian_logger::trace;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

const RSA_CERTIFICATES_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/certificates/rsa");

/// JWT Header for RS256 (RSA with SHA-256)
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

/// Dummy Identity Provider using RSA keys
#[derive(Clone)]
pub struct RsaIdp {
    /// The JWKS (JSON Web Key Set) as a JSON value
    jwks_json: serde_json::Value,
    /// Private key for signing (PEM format)
    private_key_pem: String,
    /// Issuer URI
    issuer: String,
}

impl RsaIdp {
    /// Create a new RsaIdp from the RSA certificates directory
    pub fn new(issuer: &str) -> AuthResult<Self> {
        let cert_path = format!("{}/auth.server.cert.pem", RSA_CERTIFICATES_PATH);
        let key_path = format!("{}/auth.server.key.pem", RSA_CERTIFICATES_PATH);

        // Read the certificate
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| AuthError::Config(format!("Failed to read certificate: {}", e)))?;

        // Read the private key
        let private_key_pem = std::fs::read_to_string(&key_path)
            .map_err(|e| AuthError::Config(format!("Failed to read private key: {}", e)))?;

        // Parse the certificate to extract public key
        let cert_der = parse_pem_cert(&cert_pem)?;

        // Create JWK from the certificate as a JSON value
        let jwk = create_rsa_jwk_from_cert(&cert_der)?;

        // Create JWKS JSON
        let jwks_json = json!({
            "keys": [jwk]
        });

        trace!("Created a dummy RsaIdp with issuer: {}", issuer);

        Ok(Self {
            jwks_json,
            private_key_pem,
            issuer: issuer.to_owned(),
        })
    }
}

impl IdP for RsaIdp {
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
            alg: "RS256".to_string(),
            typ: "JWT".to_string(),
            kid: "auth-rsa-server-key".to_string(),
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
        let token = create_rsa_jwt(&header, &claims, &self.private_key_pem)?;

        Ok(token)
    }

    fn issue_definitely_expired_token(&self, email: &str, audience: &str) -> AuthResult<String> {
        // Set exp to Unix epoch + 1 — so far in the past that even a generous
        // leeway (default 60 s in jsonwebtoken) cannot save the token.
        let header = JwtHeader {
            alg: "RS256".to_string(),
            typ: "JWT".to_string(),
            kid: "auth-rsa-server-key".to_string(),
        };

        let claims = JwtClaims {
            iss: self.issuer.clone(),
            sub: email.to_string(),
            aud: audience.to_string(),
            exp: 1, // January 1, 1970 00:00:01 UTC
            iat: 1,
            email: email.to_string(),
        };

        create_rsa_jwt(&header, &claims, &self.private_key_pem)
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

/// Create a JWK from an RSA certificate DER
fn create_rsa_jwk_from_cert(cert_der: &[u8]) -> AuthResult<serde_json::Value> {
    use openssl::x509::X509;

    // Parse the X.509 certificate
    let cert = X509::from_der(cert_der)
        .map_err(|e| AuthError::Config(format!("Failed to parse X.509 certificate: {}", e)))?;

    // Get the public key
    let public_key = cert
        .public_key()
        .map_err(|e| AuthError::Config(format!("Failed to extract public key: {}", e)))?;

    // Get RSA key
    let rsa_key = public_key
        .rsa()
        .map_err(|e| AuthError::Config(format!("Not an RSA key: {}", e)))?;

    // Get modulus (n) and exponent (e)
    let n = rsa_key.n();
    let e = rsa_key.e();

    // Convert to bytes
    let n_bytes = n.to_vec();
    let e_bytes = e.to_vec();

    // Base64 URL encode without padding
    let n_b64 = URL_SAFE_NO_PAD.encode(&n_bytes);
    let e_b64 = URL_SAFE_NO_PAD.encode(&e_bytes);

    // Create JWK as a JSON value
    let jwk = json!({
        "kty": "RSA",
        "n": n_b64,
        "e": e_b64,
        "use": "sig",
        "kid": "auth-rsa-server-key",
        "alg": "RS256"
    });

    Ok(jwk)
}

/// Create a JWT token signed with RS256
fn create_rsa_jwt(
    header: &JwtHeader,
    claims: &JwtClaims,
    private_key_pem: &str,
) -> AuthResult<String> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
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
    let rsa_key = Rsa::private_key_from_pem(private_key_pem.as_bytes())
        .map_err(|e| AuthError::JWT(format!("Failed to parse RSA private key: {}", e)))?;

    let pkey = PKey::from_rsa(rsa_key)
        .map_err(|e| AuthError::JWT(format!("Failed to create PKey: {}", e)))?;

    // Sign the message with SHA-256
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
        .map_err(|e| AuthError::JWT(format!("Failed to create signer: {}", e)))?;

    signer
        .update(message.as_bytes())
        .map_err(|e| AuthError::JWT(format!("Failed to update signer: {}", e)))?;

    let signature = signer
        .sign_to_vec()
        .map_err(|e| AuthError::JWT(format!("Failed to sign: {}", e)))?;

    // RS256 signature is already in the correct format (no DER conversion needed like ECDSA)
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{}.{}", message, signature_b64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_idp_creation() {
        let idp = RsaIdp::new("https://auth.acme.com").unwrap();
        assert_eq!(idp.get_issuer(), "https://auth.acme.com");
    }

    #[test]
    fn test_rsa_jwks_generation() {
        let idp = RsaIdp::new("https://auth.acme.com").unwrap();
        let jwks_json = idp.get_jwks_json().unwrap();

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&jwks_json).unwrap();
        assert!(parsed["keys"].is_array());
        assert_eq!(parsed["keys"][0]["kty"], "RSA");
        assert_eq!(parsed["keys"][0]["alg"], "RS256");
        assert!(parsed["keys"][0]["n"].is_string());
        assert!(parsed["keys"][0]["e"].is_string());
    }

    #[test]
    fn test_rsa_token_issuance() {
        let idp = RsaIdp::new("https://auth.acme.com").unwrap();
        let token = idp
            .issue_token("user@example.com", "auth-api", 3600)
            .unwrap();

        // Basic JWT structure check (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode and verify header
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");

        // Decode and verify claims
        let claims_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_json).unwrap();
        assert_eq!(claims["email"], "user@example.com");
        assert_eq!(claims["iss"], "https://auth.acme.com");
        assert_eq!(claims["aud"], "auth-api");
    }

    #[test]
    fn test_rsa_example_usage() {
        // Example: Create a RsaIdp, get JWKS, and issue a token
        let idp = RsaIdp::new("https://my-issuer.com").unwrap();

        // Get JWKS endpoint response (as would be served at /.well-known/jwks.json)
        let jwks_json = idp.get_jwks_json().unwrap();
        println!("JWKS JSON:\n{}", jwks_json);

        // Issue a JWT token
        let token = idp
            .issue_token("alice@example.com", "test_audience", 3600)
            .unwrap();
        println!("\nJWT Token:\n{}", token);
        assert!(!token.is_empty());
    }

    #[test]
    fn test_rsa_multiple_tokens() {
        // Test that we can issue multiple tokens with different claims
        let idp = RsaIdp::new("https://auth.acme.com").unwrap();

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
