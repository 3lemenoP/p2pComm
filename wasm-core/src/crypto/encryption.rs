use super::{CryptoError, CryptoResult, NONCE_SIZE, TAG_SIZE};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};

use super::hashing::derive_key;

/// Encrypted message envelope
#[derive(Clone, Debug, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct EncryptedMessage {
    /// Ephemeral public key for forward secrecy
    #[wasm_bindgen(skip)]
    pub ephemeral_public_key: Vec<u8>,

    /// Nonce used for encryption
    #[wasm_bindgen(skip)]
    pub nonce: Vec<u8>,

    /// Encrypted ciphertext
    #[wasm_bindgen(skip)]
    pub ciphertext: Vec<u8>,

    /// Additional authenticated data (optional)
    #[wasm_bindgen(skip)]
    pub aad: Vec<u8>,
}

#[wasm_bindgen]
impl EncryptedMessage {
    /// Create a new encrypted message
    #[wasm_bindgen(constructor)]
    pub fn new(
        ephemeral_public_key: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> EncryptedMessage {
        EncryptedMessage {
            ephemeral_public_key,
            nonce,
            ciphertext,
            aad: Vec::new(),
        }
    }

    /// Get the ephemeral public key
    #[wasm_bindgen(getter, js_name = ephemeralPublicKey)]
    pub fn get_ephemeral_public_key(&self) -> Vec<u8> {
        self.ephemeral_public_key.clone()
    }

    /// Get the nonce
    #[wasm_bindgen(getter)]
    pub fn get_nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    /// Get the ciphertext
    #[wasm_bindgen(getter)]
    pub fn get_ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    /// Serialize to bytes
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        bincode::serialize(self).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deserialize from bytes
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<EncryptedMessage, JsValue> {
        bincode::deserialize(bytes).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// Encrypt a message using X25519 + ChaCha20-Poly1305 with forward secrecy
pub fn encrypt(
    plaintext: &[u8],
    recipient_public_key: &X25519PublicKey,
    sender_private_key: &X25519PrivateKey,
    aad: Option<&[u8]>,
) -> CryptoResult<EncryptedMessage> {
    // Generate ephemeral keypair for forward secrecy
    let ephemeral_private = X25519PrivateKey::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_private);

    // Perform ECDH with sender's long-term key
    let shared_secret_1 = sender_private_key.diffie_hellman(recipient_public_key);

    // Perform ECDH with ephemeral key
    let shared_secret_2 = ephemeral_private.diffie_hellman(recipient_public_key);

    // Combine both shared secrets for enhanced security
    let mut combined_secret = Vec::new();
    combined_secret.extend_from_slice(shared_secret_1.as_bytes());
    combined_secret.extend_from_slice(shared_secret_2.as_bytes());

    // Derive encryption key
    let encryption_key = derive_key(&combined_secret, b"message_encryption", 32)?;

    // Generate random nonce
    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Perform encryption
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key[..32])
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    // Use first 12 bytes of nonce (ChaCha20Poly1305 uses 96-bit nonces)
    let nonce = Nonce::from_slice(&nonce_bytes[..12]);

    let payload = if let Some(aad_data) = aad {
        Payload {
            msg: plaintext,
            aad: aad_data,
        }
    } else {
        Payload {
            msg: plaintext,
            aad: b"",
        }
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    Ok(EncryptedMessage {
        ephemeral_public_key: ephemeral_public.to_bytes().to_vec(),
        nonce: nonce_bytes,
        ciphertext,
        aad: aad.unwrap_or(b"").to_vec(),
    })
}

/// Decrypt a message using X25519 + ChaCha20-Poly1305
pub fn decrypt(
    encrypted: &EncryptedMessage,
    sender_public_key: &X25519PublicKey,
    recipient_private_key: &X25519PrivateKey,
) -> CryptoResult<Vec<u8>> {
    // Parse ephemeral public key
    let ephemeral_public = {
        if encrypted.ephemeral_public_key.len() != 32 {
            return Err(CryptoError::DecryptionError(
                "Invalid ephemeral public key length".to_string(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&encrypted.ephemeral_public_key);
        X25519PublicKey::from(bytes)
    };

    // Perform ECDH with sender's long-term key
    let shared_secret_1 = recipient_private_key.diffie_hellman(sender_public_key);

    // Perform ECDH with ephemeral key
    let shared_secret_2 = recipient_private_key.diffie_hellman(&ephemeral_public);

    // Combine both shared secrets
    let mut combined_secret = Vec::new();
    combined_secret.extend_from_slice(shared_secret_1.as_bytes());
    combined_secret.extend_from_slice(shared_secret_2.as_bytes());

    // Derive decryption key
    let decryption_key = derive_key(&combined_secret, b"message_encryption", 32)?;

    // Perform decryption
    let cipher = ChaCha20Poly1305::new_from_slice(&decryption_key[..32])
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    // Use first 12 bytes of nonce
    let nonce = Nonce::from_slice(&encrypted.nonce[..12]);

    let payload = Payload {
        msg: &encrypted.ciphertext,
        aad: &encrypted.aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    Ok(plaintext)
}

/// Simple symmetric encryption for local storage
pub fn encrypt_symmetric(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::EncryptionError(
            "Key must be 32 bytes".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::new();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Simple symmetric decryption for local storage
pub fn decrypt_symmetric(ciphertext_with_nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::DecryptionError(
            "Key must be 32 bytes".to_string(),
        ));
    }

    if ciphertext_with_nonce.len() < 12 {
        return Err(CryptoError::DecryptionError(
            "Ciphertext too short".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&ciphertext_with_nonce[..12]);
    let ciphertext = &ciphertext_with_nonce[12..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::X25519KeyPair;

    #[test]
    fn test_encrypt_decrypt() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let plaintext = b"Hello, Bob! This is a secret message.";

        let encrypted = encrypt(
            plaintext,
            &bob.public_key,
            &alice.private_key,
            Some(b"additional_data"),
        )
        .unwrap();

        let decrypted =
            decrypt(&encrypted, &alice.public_key, &bob.private_key).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_forward_secrecy() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let plaintext = b"Secret message";

        let encrypted1 = encrypt(plaintext, &bob.public_key, &alice.private_key, None).unwrap();
        let encrypted2 = encrypt(plaintext, &bob.public_key, &alice.private_key, None).unwrap();

        // Different ephemeral keys should produce different ciphertexts
        assert_ne!(
            encrypted1.ephemeral_public_key,
            encrypted2.ephemeral_public_key
        );
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_symmetric_encryption() {
        let key = [42u8; 32];
        let plaintext = b"Symmetric encryption test";

        let ciphertext = encrypt_symmetric(plaintext, &key).unwrap();
        let decrypted = decrypt_symmetric(&ciphertext, &key).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_decryption_fails_with_wrong_key() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        let eve = X25519KeyPair::generate().unwrap();

        let plaintext = b"Secret message";

        let encrypted = encrypt(plaintext, &bob.public_key, &alice.private_key, None).unwrap();

        // Eve should not be able to decrypt
        let result = decrypt(&encrypted, &alice.public_key, &eve.private_key);
        assert!(result.is_err());
    }
}
