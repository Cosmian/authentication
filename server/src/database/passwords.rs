use argon2::{
    Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version,
    password_hash::{PasswordHash, SaltString, rand_core::OsRng},
};
use auth_client::{AuthError, AuthResult};

/// This server's Argon2id cost parameters: RFC 9106 §4's second RECOMMENDED option
/// (`t=3, m=65536 KiB (64 MiB), p=4`), for deployments without a secret pepper key.
/// The single source of truth for both hashing and validating a pre-hashed password —
/// [`hash_password_with_argon2`] and [`validate_argon2_phc_string`] both derive from it, so
/// the two can never drift apart.
fn server_argon2_params() -> Params {
    Params::new(65536, 3, 4, None).expect("hard-coded Argon2 parameters are always valid")
}

fn server_argon2() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, server_argon2_params())
}

/// Hash a password using this server's Argon2id preset with a cryptographically random salt.
///
/// The returned string is the full PHC string (e.g.
/// `$argon2id$v=19$m=65536,t=3,p=4$<b64-salt>$<b64-hash>`), which encodes both the salt and
/// the hash. Use [`verify_password_argon2`] to authenticate an incoming password against the
/// stored value.
pub fn hash_password_with_argon2(password: &str) -> AuthResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = server_argon2()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::Unexpected(format!("Failed to hash password with Argon2: {e}")))?
        .to_string();
    Ok(password_hash)
}

/// Validate that `hash` is a well-formed Argon2id PHC string using exactly the algorithm,
/// version, and cost parameters (`m`, `t`, `p`) this server's own
/// [`hash_password_with_argon2`] would have produced, without verifying it against any
/// password. Used to accept a caller-supplied pre-hashed password (`PasswordInput::Hashed`)
/// as-is instead of hashing a plaintext one.
///
/// The PHC string format is a generic, algorithm-agnostic envelope (see the
/// [PHC string spec](https://github.com/P-H-C/phc-string-format)) — `PasswordHash::new` on its
/// own only validates that envelope's syntax, not which algorithm or cost parameters it
/// encodes. Left unchecked, a caller could provision `argon2i`/`argon2d` (weaker than
/// `argon2id`) or an arbitrarily large `m` cost: [`verify_password_argon2`]'s underlying
/// `PasswordVerifier` derives its cost parameters from the *stored* string, so an oversized `m`
/// would make every subsequent (unauthenticated) login attempt for that username allocate that
/// much memory before the password comparison even runs. Requiring an exact match against this
/// server's own preset closes both.
pub fn validate_argon2_phc_string(hash: &str) -> AuthResult<()> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AuthError::BadRequest(format!("not a valid Argon2 PHC string: {e}")))?;

    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return Err(AuthError::BadRequest(format!(
            "unsupported password hash algorithm '{}': only {} is accepted",
            parsed.algorithm,
            Algorithm::Argon2id
        )));
    }

    if parsed.version != Some(Version::V0x13 as u32) {
        return Err(AuthError::BadRequest(format!(
            "unsupported Argon2 version {}: only version {} is accepted",
            parsed
                .version
                .map_or_else(|| "none".to_string(), |v| v.to_string()),
            Version::V0x13 as u32
        )));
    }

    let params = Params::try_from(&parsed)
        .map_err(|e| AuthError::BadRequest(format!("unreadable Argon2 parameters: {e}")))?;
    let server_params = server_argon2_params();
    if params.m_cost() != server_params.m_cost()
        || params.t_cost() != server_params.t_cost()
        || params.p_cost() != server_params.p_cost()
    {
        return Err(AuthError::BadRequest(format!(
            "Argon2 parameters must match this server's own preset (m={}, t={}, p={}); got m={}, t={}, p={}",
            server_params.m_cost(),
            server_params.t_cost(),
            server_params.p_cost(),
            params.m_cost(),
            params.t_cost(),
            params.p_cost(),
        )));
    }

    Ok(())
}

/// Verify a plaintext `password` against a stored Argon2 PHC string.
///
/// Returns `Ok(())` on success, or an error if the password is wrong or
/// the stored hash is malformed.
pub fn verify_password_argon2(stored: &str, password: &str) -> AuthResult<()> {
    let parsed_hash = PasswordHash::new(stored)
        .map_err(|e| AuthError::Unexpected(format!("Invalid stored password hash: {e}")))?;
    server_argon2()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AuthError::Session("invalid credentials".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_argon2_phc_string_accepts_this_servers_own_output() {
        let hash = hash_password_with_argon2("sabrina").unwrap();
        assert!(validate_argon2_phc_string(&hash).is_ok());
    }

    #[test]
    fn validate_argon2_phc_string_rejects_non_argon2id_variant() {
        // argon2i instead of argon2id, otherwise well-formed with matching cost parameters.
        let hash = "$argon2i$v=19$m=4096,t=3,p=1$EJmjwWmJFveB+R4/RgcMrQ$bWRu6JUc2085pVPQfhCbg8vroxpSJIR/JSRfGdo29gs";
        let err = validate_argon2_phc_string(hash).expect_err("argon2i must be rejected");
        assert!(matches!(err, AuthError::BadRequest(ref m) if m.contains("argon2i")));
    }

    #[test]
    fn validate_argon2_phc_string_rejects_old_version() {
        // v=16 (0x10) instead of v=19 (0x13) — the pre-2016 construction — otherwise
        // well-formed with matching algorithm and cost parameters.
        let hash = "$argon2id$v=16$m=65536,t=3,p=4$EJmjwWmJFveB+R4/RgcMrQ$bWRu6JUc2085pVPQfhCbg8vroxpSJIR/JSRfGdo29gs";
        let err = validate_argon2_phc_string(hash).expect_err("v=16 must be rejected");
        assert!(matches!(err, AuthError::BadRequest(ref m) if m.contains("version")));
    }

    #[test]
    fn validate_argon2_phc_string_rejects_oversized_cost_parameters() {
        // A caller-chosen m/t/p far above this server's own preset — the DoS-shaped input:
        // verify_password_argon2 would allocate this much memory on every login attempt.
        let hash = "$argon2id$v=19$m=4194304,t=10,p=4$EJmjwWmJFveB+R4/RgcMrQ$bWRu6JUc2085pVPQfhCbg8vroxpSJIR/JSRfGdo29gs";
        let err = validate_argon2_phc_string(hash).expect_err("oversized cost must be rejected");
        assert!(matches!(err, AuthError::BadRequest(ref m) if m.contains("parameters must match")));
    }

    #[test]
    fn validate_argon2_phc_string_rejects_non_phc_garbage() {
        let err =
            validate_argon2_phc_string("not-a-phc-string").expect_err("garbage must be rejected");
        assert!(matches!(err, AuthError::BadRequest(_)));
    }
}
