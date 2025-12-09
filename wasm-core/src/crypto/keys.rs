use super::{CryptoError, CryptoResult};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};

/// Ed25519 keypair for digital signatures
#[derive(Clone)]
#[wasm_bindgen]
pub struct Ed25519KeyPair {
    #[wasm_bindgen(skip)]
    pub signing_key: SigningKey,
    #[wasm_bindgen(skip)]
    pub verifying_key: VerifyingKey,
}

// Custom Serialize/Deserialize for Ed25519KeyPair
impl Serialize for Ed25519KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.signing_key.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ed25519KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Ed25519KeyPair {
            signing_key,
            verifying_key,
        })
    }
}

#[wasm_bindgen]
impl Ed25519KeyPair {
    /// Generate a new Ed25519 keypair for signing
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Ed25519KeyPair, JsValue> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Ok(Ed25519KeyPair {
            signing_key,
            verifying_key,
        })
    }

    /// Get the public key as bytes
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }

    /// Get the private key as bytes
    #[wasm_bindgen(js_name = privateKeyBytes)]
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Get the public key as hex string
    #[wasm_bindgen(js_name = publicKeyHex)]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Get the private key as hex string
    #[wasm_bindgen(js_name = privateKeyHex)]
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    /// Create from existing key bytes
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(private_key_bytes: &[u8]) -> Result<Ed25519KeyPair, JsValue> {
        if private_key_bytes.len() != 32 {
            return Err(JsValue::from_str("Invalid private key length"));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(private_key_bytes);

        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Ed25519KeyPair {
            signing_key,
            verifying_key,
        })
    }
}

impl Ed25519KeyPair {
    /// Generate a new Ed25519 keypair (internal use)
    pub fn generate() -> CryptoResult<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Ok(Ed25519KeyPair {
            signing_key,
            verifying_key,
        })
    }

    /// Create from private key bytes
    pub fn from_private_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat(
                "Private key must be 32 bytes".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Ed25519KeyPair {
            signing_key,
            verifying_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the private key
    pub fn private_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// X25519 keypair for Diffie-Hellman key exchange and encryption
#[derive(Clone)]
#[wasm_bindgen]
pub struct X25519KeyPair {
    #[wasm_bindgen(skip)]
    pub private_key: X25519PrivateKey,
    #[wasm_bindgen(skip)]
    pub public_key: X25519PublicKey,
}

// Custom Serialize/Deserialize for X25519KeyPair
impl Serialize for X25519KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.private_key.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for X25519KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        let private_key = X25519PrivateKey::from(bytes);
        let public_key = X25519PublicKey::from(&private_key);
        Ok(X25519KeyPair {
            private_key,
            public_key,
        })
    }
}

#[wasm_bindgen]
impl X25519KeyPair {
    /// Generate a new X25519 keypair for encryption
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<X25519KeyPair, JsValue> {
        let private_key = X25519PrivateKey::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);

        Ok(X25519KeyPair {
            private_key,
            public_key,
        })
    }

    /// Get the public key as bytes
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    /// Get the private key as bytes
    #[wasm_bindgen(js_name = privateKeyBytes)]
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.private_key.to_bytes().to_vec()
    }

    /// Get the public key as hex string
    #[wasm_bindgen(js_name = publicKeyHex)]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.to_bytes())
    }

    /// Get the private key as hex string
    #[wasm_bindgen(js_name = privateKeyHex)]
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key.to_bytes())
    }

    /// Create from existing key bytes
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(private_key_bytes: &[u8]) -> Result<X25519KeyPair, JsValue> {
        if private_key_bytes.len() != 32 {
            return Err(JsValue::from_str("Invalid private key length"));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(private_key_bytes);

        let private_key = X25519PrivateKey::from(bytes);
        let public_key = X25519PublicKey::from(&private_key);

        Ok(X25519KeyPair {
            private_key,
            public_key,
        })
    }
}

impl X25519KeyPair {
    /// Generate a new X25519 keypair (internal use)
    pub fn generate() -> CryptoResult<Self> {
        let private_key = X25519PrivateKey::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);

        Ok(X25519KeyPair {
            private_key,
            public_key,
        })
    }

    /// Create from private key bytes
    pub fn from_private_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat(
                "Private key must be 32 bytes".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let private_key = X25519PrivateKey::from(key_bytes);
        let public_key = X25519PublicKey::from(&private_key);

        Ok(X25519KeyPair {
            private_key,
            public_key,
        })
    }

    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> [u8; 32] {
        let shared_secret = self.private_key.diffie_hellman(their_public);
        shared_secret.to_bytes()
    }
}

/// Combined keypair for both signing and encryption
#[derive(Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct IdentityKeyPair {
    #[wasm_bindgen(skip)]
    pub signing_keypair: Ed25519KeyPair,
    #[wasm_bindgen(skip)]
    pub encryption_keypair: X25519KeyPair,
}

#[wasm_bindgen]
impl IdentityKeyPair {
    /// Generate a new identity with both signing and encryption keypairs
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<IdentityKeyPair, JsValue> {
        let signing_keypair = Ed25519KeyPair::new()?;
        let encryption_keypair = X25519KeyPair::new()?;

        Ok(IdentityKeyPair {
            signing_keypair,
            encryption_keypair,
        })
    }

    /// Get the signing keypair
    #[wasm_bindgen(js_name = getSigningKeyPair)]
    pub fn get_signing_keypair(&self) -> Ed25519KeyPair {
        self.signing_keypair.clone()
    }

    /// Get the encryption keypair
    #[wasm_bindgen(js_name = getEncryptionKeyPair)]
    pub fn get_encryption_keypair(&self) -> X25519KeyPair {
        self.encryption_keypair.clone()
    }
}

impl IdentityKeyPair {
    /// Generate a new identity keypair (internal use)
    pub fn generate() -> CryptoResult<Self> {
        let signing_keypair = Ed25519KeyPair::generate()?;
        let encryption_keypair = X25519KeyPair::generate()?;

        Ok(IdentityKeyPair {
            signing_keypair,
            encryption_keypair,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_key_generation() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_bytes = keypair.public_key_bytes();
        let private_bytes = keypair.private_key_bytes();

        assert_eq!(public_bytes.len(), 32);
        assert_eq!(private_bytes.len(), 32);
    }

    #[test]
    fn test_x25519_key_generation() {
        let keypair = X25519KeyPair::generate().unwrap();
        let public_bytes = keypair.public_key_bytes();
        let private_bytes = keypair.private_key_bytes();

        assert_eq!(public_bytes.len(), 32);
        assert_eq!(private_bytes.len(), 32);
    }

    #[test]
    fn test_ed25519_from_bytes() {
        let keypair1 = Ed25519KeyPair::generate().unwrap();
        let private_bytes = keypair1.private_key_bytes();

        let keypair2 = Ed25519KeyPair::from_private_bytes(&private_bytes).unwrap();

        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_x25519_diffie_hellman() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let alice_shared = alice.diffie_hellman(&bob.public_key);
        let bob_shared = bob.diffie_hellman(&alice.public_key);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_identity_keypair() {
        let identity = IdentityKeyPair::generate().unwrap();

        assert_eq!(identity.signing_keypair.public_key_bytes().len(), 32);
        assert_eq!(identity.encryption_keypair.public_key_bytes().len(), 32);
    }
}
