use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHash, SaltString, rand_core::OsRng},
};
use auth_client::{AuthError, AuthResult};

/// Hash a password using Argon2id with a cryptographically random salt.
///
/// The returned bytes are the full PHC string (e.g.
/// `$argon2id$v=19$m=19456,t=2,p=1$<b64-salt>$<b64-hash>`), which
/// encodes both the salt and the hash. Use [`verify_password_argon2`] to
/// authenticate an incoming password against the stored value.
pub fn hash_password_with_argon2(password: &str) -> AuthResult<Vec<u8>> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::Unexpected(format!("Failed to hash password with Argon2: {e}")))?
        .to_string()
        .into_bytes();
    Ok(password_hash)
}

/// Validate that `hash` is a well-formed Argon2 PHC string, without verifying it against
/// any password. Used to accept a caller-supplied pre-hashed password (`hashed_password`)
/// as-is instead of hashing a plaintext one, while still rejecting garbage input.
pub fn validate_argon2_phc_string(hash: &str) -> AuthResult<()> {
    PasswordHash::new(hash)
        .map_err(|e| AuthError::BadRequest(format!("not a valid Argon2 PHC string: {e}")))?;
    Ok(())
}

/// Verify a plaintext `password` against a stored Argon2 PHC string.
///
/// Returns `Ok(())` on success, or an error if the password is wrong or
/// the stored hash is malformed.
pub fn verify_password_argon2(stored: &[u8], password: &str) -> AuthResult<()> {
    let stored_str = std::str::from_utf8(stored).map_err(|_| {
        AuthError::Unexpected("stored password hash is not valid UTF-8".to_string())
    })?;
    let parsed_hash = PasswordHash::new(stored_str)
        .map_err(|e| AuthError::Unexpected(format!("Invalid stored password hash: {e}")))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AuthError::Session("invalid credentials".to_string()))
}
