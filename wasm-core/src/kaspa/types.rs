//! Common types for Kaspa blockchain integration

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

/// Protocol version for P2PComm messages
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Application identifier for payload recognition
pub const APP_ID: &str = "p2pcomm/v1";

/// Maximum payload size in bytes (Kaspa transaction limit)
pub const MAX_PAYLOAD_SIZE: usize = 98_000;

/// Dust amount in sompi (minimum output)
pub const DUST_AMOUNT: u64 = 1_000;

/// Sompi per KAS
pub const SOMPI_PER_KAS: u64 = 100_000_000;

/// Result type for Kaspa operations
pub type KaspaResult<T> = Result<T, KaspaError>;

/// Errors that can occur in Kaspa operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub enum KaspaErrorKind {
    /// Invalid envelope format
    InvalidEnvelope,
    /// Signature verification failed
    InvalidSignature,
    /// Payload too large
    PayloadTooLarge,
    /// Message expired
    MessageExpired,
    /// Unknown recipient
    UnknownRecipient,
    /// Network error
    NetworkError,
    /// Serialization error
    SerializationError,
    /// Queue full
    QueueFull,
    /// Peer not found
    PeerNotFound,
    /// Session error
    SessionError,
    /// RPC error
    RpcError,
}

#[derive(Debug, Clone)]
pub struct KaspaError {
    pub kind: KaspaErrorKind,
    pub message: String,
}

impl KaspaError {
    pub fn new(kind: KaspaErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn invalid_envelope(msg: impl Into<String>) -> Self {
        Self::new(KaspaErrorKind::InvalidEnvelope, msg)
    }

    pub fn payload_too_large(size: usize) -> Self {
        Self::new(
            KaspaErrorKind::PayloadTooLarge,
            format!("Payload size {} exceeds maximum {}", size, MAX_PAYLOAD_SIZE),
        )
    }

    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::new(KaspaErrorKind::SerializationError, msg)
    }
}

impl std::fmt::Display for KaspaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for KaspaError {}

// Convert to JsValue for wasm_bindgen compatibility
impl From<KaspaError> for JsValue {
    fn from(err: KaspaError) -> Self {
        JsValue::from_str(&err.to_string())
    }
}

/// Transaction metadata for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMeta {
    /// Transaction ID
    pub tx_id: String,
    /// Block hash (if confirmed)
    pub block_hash: Option<String>,
    /// Timestamp
    pub timestamp: u64,
    /// Confirmation count
    pub confirmations: u32,
}

/// UTXO entry for tracking unspent outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    /// Transaction ID
    pub tx_id: String,
    /// Output index
    pub index: u32,
    /// Amount in sompi
    pub amount: u64,
    /// Script public key (hex)
    pub script_public_key: String,
    /// Whether this is a dust output (likely carries data)
    pub is_dust: bool,
}

impl UtxoEntry {
    /// Check if this UTXO is likely a P2PComm message carrier
    pub fn is_message_carrier(&self) -> bool {
        self.is_dust || self.amount <= DUST_AMOUNT * 2
    }
}

/// Statistics for blockchain operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct KaspaStats {
    /// Messages sent via blockchain
    pub messages_sent: u32,
    /// Messages received
    pub messages_received: u32,
    /// Total transactions submitted
    pub transactions_submitted: u32,
    /// Total fees paid (sompi)
    pub total_fees_paid: u64,
    /// UTXOs monitored
    pub utxos_monitored: u32,
    /// Connection attempts
    pub connection_attempts: u32,
    /// Successful connections
    pub successful_connections: u32,
}

#[wasm_bindgen]
impl KaspaStats {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total messages (sent + received)
    pub fn total_messages(&self) -> u32 {
        self.messages_sent + self.messages_received
    }

    /// Get success rate as percentage
    pub fn connection_success_rate(&self) -> f64 {
        if self.connection_attempts == 0 {
            0.0
        } else {
            (self.successful_connections as f64 / self.connection_attempts as f64) * 100.0
        }
    }
}

/// Convert KAS to sompi
pub fn kas_to_sompi(kas: f64) -> u64 {
    (kas * SOMPI_PER_KAS as f64) as u64
}

/// Convert sompi to KAS
pub fn sompi_to_kas(sompi: u64) -> f64 {
    sompi as f64 / SOMPI_PER_KAS as f64
}

/// Generate a unique message ID
pub fn generate_message_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(bytes)
}

/// Get current timestamp in milliseconds
pub fn current_timestamp_ms() -> u64 {
    js_sys::Date::now() as u64
}

/// Get current timestamp in seconds
pub fn current_timestamp_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
