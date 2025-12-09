use anyhow::{Result, Context};
use kaspa_hashes::{HasherBase, Hasher};
use serde_json::Value;

/// Hash data using SHA256 (for ECDSA signatures)
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use kaspa_hashes::TransactionSigningHashECDSA;
    let hash = TransactionSigningHashECDSA::hash(data);
    hash.as_bytes().to_vec()
}

/// Hash data using SHA256d (double SHA256)
pub fn sha256d(data: &[u8]) -> Vec<u8> {
    sha256(&sha256(data))
}

/// Hash data using BLAKE2b (Kaspa's primary hash function)
pub fn blake2b(data: &[u8]) -> Vec<u8> {
    use kaspa_hashes::TransactionHash;
    let hash = TransactionHash::hash(data);
    hash.as_bytes().to_vec()
}

/// Convert bytes to hex string
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Convert hex string to bytes
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).context("Failed to decode hex string")
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

/// Serialize JSON to bytes
pub fn json_to_bytes(json: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(json)?)
}

/// Deserialize bytes to JSON
pub fn bytes_to_json(bytes: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Calculate script hash for P2SH address
pub fn script_hash(script: &[u8]) -> Vec<u8> {
    // P2SH uses BLAKE2b hash in Kaspa
    blake2b(script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hex_conversion() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let hex = to_hex(&data);
        assert_eq!(hex, "01020304");

        let decoded = from_hex(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_blake2b() {
        let data = b"kaspa test";
        let hash = blake2b(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_json_serialization() {
        let json = serde_json::json!({
            "test": "value",
            "number": 42
        });

        let bytes = json_to_bytes(&json).unwrap();
        let restored = bytes_to_json(&bytes).unwrap();
        assert_eq!(json, restored);
    }
}
