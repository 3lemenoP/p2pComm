use super::{CryptoError, CryptoResult};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Ed25519 signature (64 bytes)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[wasm_bindgen]
pub struct Ed25519Signature {
    #[wasm_bindgen(skip)]
    pub bytes: Vec<u8>,
}

#[wasm_bindgen]
impl Ed25519Signature {
    /// Create a signature from bytes
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Ed25519Signature {
        Ed25519Signature { bytes }
    }

    /// Get the signature as bytes
    #[wasm_bindgen(getter)]
    pub fn get_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Get the signature as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Create from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<Ed25519Signature, JsValue> {
        let bytes = hex::decode(hex_str).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(Ed25519Signature { bytes })
    }
}

/// Sign a message using Ed25519
pub fn sign(message: &[u8], signing_key: &SigningKey) -> CryptoResult<Ed25519Signature> {
    let signature = signing_key.sign(message);
    Ok(Ed25519Signature {
        bytes: signature.to_bytes().to_vec(),
    })
}

/// Verify an Ed25519 signature
pub fn verify(
    message: &[u8],
    signature: &Ed25519Signature,
    verifying_key: &VerifyingKey,
) -> CryptoResult<bool> {
    if signature.bytes.len() != 64 {
        return Err(CryptoError::InvalidSignature(
            "Signature must be 64 bytes".to_string(),
        ));
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature.bytes);

    let sig = Signature::from_bytes(&sig_bytes);

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Sign a message and return the signature as bytes
pub fn sign_bytes(message: &[u8], signing_key: &SigningKey) -> CryptoResult<Vec<u8>> {
    let signature = sign(message, signing_key)?;
    Ok(signature.bytes)
}

/// Verify a signature from bytes
pub fn verify_bytes(
    message: &[u8],
    signature_bytes: &[u8],
    verifying_key: &VerifyingKey,
) -> CryptoResult<bool> {
    let signature = Ed25519Signature {
        bytes: signature_bytes.to_vec(),
    };
    verify(message, &signature, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Ed25519KeyPair;

    #[test]
    fn test_sign_and_verify() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"This is a test message";

        let signature = sign(message, &keypair.signing_key).unwrap();
        let is_valid = verify(message, &signature, &keypair.verifying_key).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_verify_fails_with_wrong_message() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Original message";
        let tampered_message = b"Tampered message";

        let signature = sign(message, &keypair.signing_key).unwrap();
        let is_valid = verify(tampered_message, &signature, &keypair.verifying_key).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_verify_fails_with_wrong_key() {
        let alice = Ed25519KeyPair::generate().unwrap();
        let bob = Ed25519KeyPair::generate().unwrap();
        let message = b"Test message";

        let signature = sign(message, &alice.signing_key).unwrap();
        let is_valid = verify(message, &signature, &bob.verifying_key).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_signature_hex_encoding() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Test";

        let signature = sign(message, &keypair.signing_key).unwrap();
        let hex_str = signature.to_hex();

        assert_eq!(hex_str.len(), 128); // 64 bytes * 2 hex chars per byte
    }
}
