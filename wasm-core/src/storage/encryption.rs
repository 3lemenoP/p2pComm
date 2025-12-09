// Storage Encryption Layer
// Provides helpers for encrypting data at rest

use serde::{Deserialize, Serialize};

use crate::crypto::{
    encrypt_symmetric, decrypt_symmetric, derive_key_from_password_fixed,
};

use super::{StorageError, StorageResult};

/// Encrypted data structure for storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Version for future compatibility
    pub version: u8,
    /// Salt used for key derivation
    pub salt: Vec<u8>,
    /// Encrypted data (nonce + ciphertext combined)
    pub encrypted_bytes: Vec<u8>,
}

/// Current encryption version
pub const ENCRYPTION_VERSION: u8 = 1;

/// Encrypt data for storage using password-based encryption
///
/// # Arguments
/// * `data` - The data to encrypt (will be serialized)
/// * `password` - The password to derive the encryption key from
///
/// # Returns
/// Serialized encrypted data that can be stored
pub fn encrypt_for_storage<T: Serialize>(
    data: &T,
    password: &str,
) -> StorageResult<Vec<u8>> {
    // Serialize the data
    let serialized = bincode::serialize(data)
        .map_err(|e| StorageError::SerializationError(e.to_string()))?;

    // Generate random salt (32 bytes)
    let salt = generate_salt();

    // Derive encryption key from password using Argon2id
    let encryption_key = derive_key_from_password_fixed(password, &salt, 32)
        .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

    // Encrypt the serialized data (includes nonce prepended to ciphertext)
    let encrypted_bytes = encrypt_symmetric(&serialized, &encryption_key)
        .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

    // Create EncryptedData structure
    let encrypted_data = EncryptedData {
        version: ENCRYPTION_VERSION,
        salt,
        encrypted_bytes,
    };

    // Serialize the encrypted data structure
    bincode::serialize(&encrypted_data)
        .map_err(|e| StorageError::SerializationError(e.to_string()))
}

/// Decrypt data from storage using password-based encryption
///
/// # Arguments
/// * `encrypted_bytes` - The encrypted data from storage
/// * `password` - The password to derive the decryption key from
///
/// # Returns
/// The decrypted and deserialized data
pub fn decrypt_from_storage<T: for<'de> Deserialize<'de>>(
    encrypted_bytes: &[u8],
    password: &str,
) -> StorageResult<T> {
    // Deserialize the EncryptedData structure
    let encrypted_data: EncryptedData = bincode::deserialize(encrypted_bytes)
        .map_err(|e| StorageError::SerializationError(e.to_string()))?;

    // Check version compatibility
    if encrypted_data.version != ENCRYPTION_VERSION {
        return Err(StorageError::InvalidData(
            format!("Unsupported encryption version: {}", encrypted_data.version)
        ));
    }

    // Derive decryption key from password
    let decryption_key = derive_key_from_password_fixed(password, &encrypted_data.salt, 32)
        .map_err(|e| StorageError::DecryptionError(e.to_string()))?;

    // Decrypt the data
    let decrypted = decrypt_symmetric(&encrypted_data.encrypted_bytes, &decryption_key)
        .map_err(|e| {
            // Check if it's an authentication error (wrong password)
            let err_str = e.to_string();
            if err_str.contains("authentication") || err_str.contains("aead") || err_str.contains("tag") {
                StorageError::InvalidPassword
            } else {
                StorageError::DecryptionError(err_str)
            }
        })?;

    // Deserialize the decrypted data
    bincode::deserialize(&decrypted)
        .map_err(|e| StorageError::SerializationError(e.to_string()))
}

/// Generate a random salt for key derivation
fn generate_salt() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut salt = vec![0u8; 32];
    rng.fill(&mut salt[..]);
    salt
}

/// Verify that a password can decrypt the given encrypted data
///
/// This is useful for password verification without fully decrypting/deserializing
pub fn verify_password(encrypted_bytes: &[u8], password: &str) -> bool {
    // Try to deserialize the encrypted data structure
    let encrypted_data: EncryptedData = match bincode::deserialize(encrypted_bytes) {
        Ok(data) => data,
        Err(_) => return false,
    };

    // Derive decryption key
    let decryption_key = match derive_key_from_password_fixed(password, &encrypted_data.salt, 32) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Try to decrypt (this will fail if password is wrong due to AEAD authentication)
    decrypt_symmetric(&encrypted_data.encrypted_bytes, &decryption_key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let test_data = "Hello, World!".to_string();
        let password = "super_secret_password";

        // Encrypt
        let encrypted = encrypt_for_storage(&test_data, password).unwrap();

        // Decrypt
        let decrypted: String = decrypt_from_storage(&encrypted, password).unwrap();

        assert_eq!(test_data, decrypted);
    }

    #[test]
    fn test_wrong_password_fails() {
        let test_data = "Secret data".to_string();
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let encrypted = encrypt_for_storage(&test_data, password).unwrap();

        let result: Result<String, _> = decrypt_from_storage(&encrypted, wrong_password);
        assert!(result.is_err());

        // Should specifically be an InvalidPassword error
        match result {
            Err(StorageError::InvalidPassword) => (),
            other => panic!("Expected InvalidPassword error, got: {:?}", other),
        }
    }

    #[test]
    fn test_different_salt_each_time() {
        let test_data = "Test data".to_string();
        let password = "password123";

        let encrypted1 = encrypt_for_storage(&test_data, password).unwrap();
        let encrypted2 = encrypt_for_storage(&test_data, password).unwrap();

        // Encrypted blobs should be different due to random salt and nonce
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same data
        let decrypted1: String = decrypt_from_storage(&encrypted1, password).unwrap();
        let decrypted2: String = decrypt_from_storage(&encrypted2, password).unwrap();

        assert_eq!(decrypted1, decrypted2);
        assert_eq!(decrypted1, test_data);
    }

    #[test]
    fn test_verify_password() {
        let test_data = "Test".to_string();
        let password = "correct";

        let encrypted = encrypt_for_storage(&test_data, password).unwrap();

        assert!(verify_password(&encrypted, "correct"));
        assert!(!verify_password(&encrypted, "wrong"));
    }

    #[test]
    fn test_complex_data_type() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            name: String,
            age: u32,
            active: bool,
        }

        let test_data = TestStruct {
            name: "Alice".to_string(),
            age: 30,
            active: true,
        };

        let password = "test_password";

        let encrypted = encrypt_for_storage(&test_data, password).unwrap();
        let decrypted: TestStruct = decrypt_from_storage(&encrypted, password).unwrap();

        assert_eq!(test_data, decrypted);
    }
}
