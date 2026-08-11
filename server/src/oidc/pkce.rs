//! PKCE (Proof Key for Code Exchange, RFC 7636) verification.
//!
//! Only the `S256` challenge method is supported; the `plain` method is
//! deliberately rejected as it provides no protection against code interception.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// The only PKCE challenge method accepted by this provider.
pub const S256: &str = "S256";

/// Verify a PKCE `code_verifier` against a stored `code_challenge`.
///
/// Per RFC 7636 §4.6: `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))` must
/// equal the stored challenge (which MUST have used the `S256` method).
///
/// Also enforces the RFC 7636 §4.1 length constraint (43–128 characters) on the
/// verifier.
pub fn verify_s256(code_verifier: &str, code_challenge: &str, challenge_method: &str) -> bool {
    if challenge_method != S256 {
        return false;
    }
    if code_verifier.len() < 43 || code_verifier.len() > 128 {
        return false;
    }
    let digest = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    // Constant-time-ish comparison is unnecessary here (public challenge), but
    // keep an exact match on the base64url form.
    computed == code_challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_roundtrip() {
        // Verifier/challenge pair from RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_s256(verifier, challenge, "S256"));
    }

    #[test]
    fn rejects_plain_method() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(!verify_s256(verifier, verifier, "plain"));
    }

    #[test]
    fn rejects_wrong_verifier() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(!verify_s256(
            "wrong-verifier-that-is-at-least-forty-three-chars!!",
            challenge,
            "S256"
        ));
    }

    #[test]
    fn rejects_too_short_verifier() {
        assert!(!verify_s256("short", "anything", "S256"));
    }
}
