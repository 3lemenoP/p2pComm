use super::{CryptoError, CryptoResult, SALT_SIZE};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Password-derived key with salt
#[derive(Clone, Debug, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct DerivedKey {
    #[wasm_bindgen(skip)]
    pub key: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub salt: Vec<u8>,
}

#[wasm_bindgen]
impl DerivedKey {
    /// Get the derived key
    #[wasm_bindgen(getter)]
    pub fn get_key(&self) -> Vec<u8> {
        self.key.clone()
    }

    /// Get the salt
    #[wasm_bindgen(getter)]
    pub fn get_salt(&self) -> Vec<u8> {
        self.salt.clone()
    }
}

/// Derive a key from a password using Argon2id
pub fn derive_key_from_password(password: &str, salt: Option<&[u8]>) -> CryptoResult<DerivedKey> {
    let salt_bytes = if let Some(s) = salt {
        if s.len() != SALT_SIZE {
            return Err(CryptoError::PasswordDerivationError(
                format!("Salt must be {} bytes", SALT_SIZE),
            ));
        }
        s.to_vec()
    } else {
        // Generate new random salt
        let mut new_salt = vec![0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut new_salt);
        new_salt
    };

    // Use Argon2id with strong parameters
    let argon2 = Argon2::default();

    // Convert salt to SaltString for argon2
    let salt_str =
        SaltString::encode_b64(&salt_bytes).map_err(|e| {
            CryptoError::PasswordDerivationError(format!("Salt encoding failed: {}", e))
        })?;

    // Derive key
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_str)
        .map_err(|e| {
            CryptoError::PasswordDerivationError(format!("Key derivation failed: {}", e))
        })?;

    // Extract the derived key (32 bytes)
    let hash_string = password_hash.hash.ok_or_else(|| {
        CryptoError::PasswordDerivationError("No hash generated".to_string())
    })?;

    // Convert Output to bytes
    let key_bytes = hash_string.as_bytes();

    Ok(DerivedKey {
        key: key_bytes.to_vec(),
        salt: salt_bytes,
    })
}

/// Derive a fixed-length key from a password
pub fn derive_key_from_password_fixed(
    password: &str,
    salt: &[u8],
    output_length: usize,
) -> CryptoResult<Vec<u8>> {
    use argon2::{Algorithm, Params, Version};

    if salt.len() != SALT_SIZE {
        return Err(CryptoError::PasswordDerivationError(
            format!("Salt must be {} bytes", SALT_SIZE),
        ));
    }

    // Strong Argon2id parameters
    // m=65536 (64 MB), t=3 iterations, p=4 parallelism
    let params = Params::new(65536, 3, 4, Some(output_length))
        .map_err(|e| CryptoError::PasswordDerivationError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; output_length];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| CryptoError::PasswordDerivationError(e.to_string()))?;

    Ok(output)
}

/// Hash a password for storage/verification (not for encryption keys)
pub fn hash_password(password: &str) -> CryptoResult<String> {
    let argon2 = Argon2::default();

    // Generate random salt
    let mut salt_bytes = vec![0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt_bytes);

    let salt_str = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| CryptoError::PasswordDerivationError(e.to_string()))?;

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_str)
        .map_err(|e| CryptoError::PasswordDerivationError(e.to_string()))?;

    Ok(password_hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> CryptoResult<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| CryptoError::PasswordDerivationError(e.to_string()))?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_from_password() {
        let password = "super_secret_password_123";
        let derived = derive_key_from_password(password, None).unwrap();

        assert!(derived.key.len() >= 32);
        assert_eq!(derived.salt.len(), SALT_SIZE);
    }

    #[test]
    fn test_derive_key_with_same_salt() {
        let password = "test_password";
        let salt = [42u8; SALT_SIZE];

        let derived1 = derive_key_from_password(password, Some(&salt)).unwrap();
        let derived2 = derive_key_from_password(password, Some(&salt)).unwrap();

        // Same password and salt should produce same key
        assert_eq!(derived1.key, derived2.key);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = "test_password";

        let derived1 = derive_key_from_password(password, None).unwrap();
        let derived2 = derive_key_from_password(password, None).unwrap();

        // Different salts should produce different keys
        assert_ne!(derived1.key, derived2.key);
        assert_ne!(derived1.salt, derived2.salt);
    }

    #[test]
    fn test_derive_key_fixed_length() {
        let password = "my_password";
        let salt = [1u8; SALT_SIZE];

        let key = derive_key_from_password_fixed(password, &salt, 32).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hash_and_verify_password() {
        let password = "correct_password";
        let hash = hash_password(password).unwrap();

        // Correct password should verify
        assert!(verify_password(password, &hash).unwrap());

        // Wrong password should not verify
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_different_passwords_different_hashes() {
        let password1 = "password1";
        let password2 = "password2";

        let hash1 = hash_password(password1).unwrap();
        let hash2 = hash_password(password2).unwrap();

        assert_ne!(hash1, hash2);
    }
}
