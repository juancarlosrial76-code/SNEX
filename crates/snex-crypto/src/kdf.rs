use argon2::{Argon2, Algorithm, Version, Params};
use crate::error::{CryptoError, Result};
use zeroize::Zeroizing;

pub const ARGON2_MEMORY_KIB: u32 = 65536;
pub const ARGON2_PASSES: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const RECOVERY_PHRASE_WORDS: usize = 24;

pub fn argon2id_params() -> Params {
    Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_PARALLELISM, Some(32))
        .expect("Valid Argon2 params")
}

pub fn derive_key_argon2id(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let params = argon2id_params();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2.hash_password_into(password, salt, &mut out)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(out)
}

pub fn derive_key_argon2id_custom(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    passes: u32,
    parallelism: u32,
) -> Result<[u8; 32]> {
    let params = Params::new(memory_kib, passes, parallelism, Some(32))
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2.hash_password_into(password, salt, &mut out)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(out)
}

pub fn generate_salt() -> [u8; 16] {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

pub fn verify_argon2id(password: &[u8], salt: &[u8], expected: &[u8; 32]) -> Result<bool> {
    let derived = derive_key_argon2id(password, salt)?;
    Ok(constant_time_eq::constant_time_eq(&derived, expected))
}

pub fn recovery_phrase_to_seed(phrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != RECOVERY_PHRASE_WORDS {
        return Err(CryptoError::InvalidParameter(
            format!("Recovery phrase must have {} words", RECOVERY_PHRASE_WORDS)
        ));
    }
    let joined = words.join(" ");
    let salt = b"SNEX Recovery Phrase v1";
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&derive_key_argon2id(joined.as_bytes(), salt)?);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_derive() {
        let password = b"test password";
        let salt = generate_salt();
        let key1 = derive_key_argon2id(password, &salt).unwrap();
        let key2 = derive_key_argon2id(password, &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_argon2id_different_salts() {
        let password = b"test password";
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let key1 = derive_key_argon2id(password, &salt1).unwrap();
        let key2 = derive_key_argon2id(password, &salt2).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_recovery_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = recovery_phrase_to_seed(phrase).unwrap();
        assert_eq!(seed.len(), 32);
    }
}