//! App-lock password verifier (Argon2id PHC string), used when secrets are in the
//! OS keyring. With the encrypted vault, unlocking the vault is the verification.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};

fn argon2() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(64 * 1024, 3, 4, None).expect("valid argon2 params"))
}

pub fn hash_password(password: &SecretString) -> Result<String, argon2::password_hash::Error> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).expect("OS random number generator unavailable");
    let salt = SaltString::encode_b64(&salt)?;
    Ok(argon2().hash_password(password.expose_secret().as_bytes(), &salt)?.to_string())
}

pub fn verify_password(password: &SecretString, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| argon2().verify_password(password.expose_secret().as_bytes(), &h).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies() {
        let h = hash_password(&SecretString::from("open sesame")).unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password(&SecretString::from("open sesame"), &h));
        assert!(!verify_password(&SecretString::from("open sesame!"), &h));
        assert!(!verify_password(&SecretString::from("x"), "garbage"));
    }
}
