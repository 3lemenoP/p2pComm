use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

mod keys;
mod encryption;
mod signing;
mod hashing;
mod password;

pub use keys::*;
pub use encryption::*;
pub use signing::*;
pub use hashing::*;
pub use password::*;

/// Cryptographic error types
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Signing failed: {0}")]
    SigningError(String),

    #[error("Verification failed: {0}")]
    VerificationError(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Password derivation failed: {0}")]
    PasswordDerivationError(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

/// Nonce for encryption (24 bytes for ChaCha20-Poly1305)
pub const NONCE_SIZE: usize = 24;

/// Salt size for password derivation
pub const SALT_SIZE: usize = 32;

/// Tag size for ChaCha20-Poly1305 authentication
pub const TAG_SIZE: usize = 16;
