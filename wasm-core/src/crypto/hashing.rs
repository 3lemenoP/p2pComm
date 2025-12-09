use super::{CryptoError, CryptoResult};
use blake3::{Hash, Hasher};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Blake3 hash (32 bytes)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[wasm_bindgen]
pub struct Blake3Hash {
    #[wasm_bindgen(skip)]
    pub bytes: [u8; 32],
}

#[wasm_bindgen]
impl Blake3Hash {
    /// Create a hash from bytes
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Result<Blake3Hash, JsValue> {
        if bytes.len() != 32 {
            return Err(JsValue::from_str("Hash must be 32 bytes"));
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);

        Ok(Blake3Hash { bytes: hash_bytes })
    }

    /// Get the hash as bytes
    #[wasm_bindgen(getter)]
    pub fn get_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    /// Get the hash as hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Create from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex_str: &str) -> Result<Blake3Hash, JsValue> {
        let bytes = hex::decode(hex_str).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Blake3Hash::new(bytes)
    }
}

/// Hash data using Blake3
pub fn hash(data: &[u8]) -> Blake3Hash {
    let hash = blake3::hash(data);
    Blake3Hash {
        bytes: *hash.as_bytes(),
    }
}

/// Hash multiple pieces of data
pub fn hash_multi(data_pieces: &[&[u8]]) -> Blake3Hash {
    let mut hasher = Hasher::new();
    for piece in data_pieces {
        hasher.update(piece);
    }
    let hash = hasher.finalize();
    Blake3Hash {
        bytes: *hash.as_bytes(),
    }
}

/// Derive a key from input material using Blake3
pub fn derive_key(input: &[u8], context: &[u8], output_len: usize) -> CryptoResult<Vec<u8>> {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.update(context);

    let hash = hasher.finalize();

    // For keys longer than 32 bytes, use XOF (eXtendable Output Function)
    if output_len <= 32 {
        Ok(hash.as_bytes()[..output_len].to_vec())
    } else {
        let mut output = vec![0u8; output_len];
        let mut current_hash = hash.as_bytes().to_owned();
        let mut offset = 0;

        while offset < output_len {
            let chunk_size = std::cmp::min(32, output_len - offset);
            output[offset..offset + chunk_size].copy_from_slice(&current_hash[..chunk_size]);
            offset += chunk_size;

            // For additional chunks, rehash
            if offset < output_len {
                let mut hasher = Hasher::new();
                hasher.update(&current_hash);
                let next_hash = hasher.finalize();
                current_hash = next_hash.as_bytes().to_owned();
            }
        }

        Ok(output)
    }
}

/// Create a keyed hash (MAC) using Blake3
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> Blake3Hash {
    let hash = blake3::keyed_hash(key, data);
    Blake3Hash {
        bytes: *hash.as_bytes(),
    }
}

/// Verify a keyed hash
pub fn verify_keyed_hash(key: &[u8; 32], data: &[u8], expected_hash: &Blake3Hash) -> bool {
    let computed_hash = keyed_hash(key, data);
    computed_hash == *expected_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"Hello, World!";
        let hash1 = hash(data);
        let hash2 = hash(data);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.bytes.len(), 32);
    }

    #[test]
    fn test_hash_different_inputs() {
        let data1 = b"Message 1";
        let data2 = b"Message 2";

        let hash1 = hash(data1);
        let hash2 = hash(data2);

        // Different inputs should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_multi() {
        let piece1 = b"Hello, ";
        let piece2 = b"World!";

        let hash1 = hash_multi(&[piece1, piece2]);
        let hash2 = hash(b"Hello, World!");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_derive_key() {
        let input = b"some secret input material";
        let context = b"encryption_key_v1";

        let key = derive_key(input, context, 32).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_long() {
        let input = b"input";
        let context = b"context";

        let key = derive_key(input, context, 64).unwrap();

        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_keyed_hash() {
        let key = [42u8; 32];
        let data = b"Message";

        let hash1 = keyed_hash(&key, data);
        let hash2 = keyed_hash(&key, data);

        assert_eq!(hash1, hash2);

        // Verify
        assert!(verify_keyed_hash(&key, data, &hash1));
    }

    #[test]
    fn test_keyed_hash_different_keys() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let data = b"Message";

        let hash1 = keyed_hash(&key1, data);
        let hash2 = keyed_hash(&key2, data);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_hex_encoding() {
        let data = b"Test";
        let hash = hash(data);
        let hex = hash.to_hex();

        assert_eq!(hex.len(), 64); // 32 bytes * 2 hex chars
    }
}
