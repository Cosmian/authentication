use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use auth_client::{AuthError, AuthResult};
use sha2::Digest;

pub fn hash_password_with_argon2(username: &str, password: &str) -> AuthResult<Vec<u8>> {
    // the specification for Argon2 mandates a salt of at least 16 bytes and max 64 bytes, hence hashing using SHA-256

    let hash = sha2::Sha256::digest(username.as_bytes());
    let salt = SaltString::b64_encode(hash.as_ref())
        .map_err(|e| AuthError::Unexpected(format!("Invalid salt: {username}, for Argon2: {e}")))?;

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::Unexpected(format!("Failed to hash password with Argon2: {e}")))?
        .to_string()
        .into_bytes();

    Ok(password_hash)
}
