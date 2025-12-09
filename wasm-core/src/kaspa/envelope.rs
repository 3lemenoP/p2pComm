//! Kaspa Message Envelope Format
//!
//! Defines the envelope structure for embedding messages in Kaspa transactions.
//! This is the core format for all P2PComm blockchain messages.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use crate::kaspa::types::{APP_ID, KaspaError, KaspaResult, generate_message_id, current_timestamp_ms};

/// Envelope format version
pub const ENVELOPE_VERSION: u8 = 1;

/// Separator between multiple envelopes in a payload
pub const ENVELOPE_SEPARATOR: &[u8] = b"\n---\n";

/// Type of message contained in the envelope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[wasm_bindgen]
pub enum EnvelopeType {
    /// Direct text message
    DirectMessage = 0,
    /// Group message
    GroupMessage = 1,
    /// Peer announcement for discovery
    PeerAnnouncement = 2,
    /// WebRTC SDP offer
    SignalingOffer = 3,
    /// WebRTC SDP answer
    SignalingAnswer = 4,
    /// WebRTC ICE candidate(s)
    SignalingIce = 5,
    /// Delivery acknowledgment
    Acknowledgment = 6,
    /// Encrypted payload (type hidden)
    Encrypted = 7,
    /// Key exchange message
    KeyExchange = 8,
    /// Peer status update
    StatusUpdate = 9,
}

impl EnvelopeType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::DirectMessage),
            1 => Some(Self::GroupMessage),
            2 => Some(Self::PeerAnnouncement),
            3 => Some(Self::SignalingOffer),
            4 => Some(Self::SignalingAnswer),
            5 => Some(Self::SignalingIce),
            6 => Some(Self::Acknowledgment),
            7 => Some(Self::Encrypted),
            8 => Some(Self::KeyExchange),
            9 => Some(Self::StatusUpdate),
            _ => None,
        }
    }

    /// Check if this is a signaling message type
    pub fn is_signaling(&self) -> bool {
        matches!(
            self,
            Self::SignalingOffer | Self::SignalingAnswer | Self::SignalingIce
        )
    }

    /// Check if this is a discovery message type
    pub fn is_discovery(&self) -> bool {
        matches!(self, Self::PeerAnnouncement | Self::StatusUpdate)
    }
}

impl std::fmt::Display for EnvelopeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectMessage => write!(f, "direct_message"),
            Self::GroupMessage => write!(f, "group_message"),
            Self::PeerAnnouncement => write!(f, "peer_announcement"),
            Self::SignalingOffer => write!(f, "signaling_offer"),
            Self::SignalingAnswer => write!(f, "signaling_answer"),
            Self::SignalingIce => write!(f, "signaling_ice"),
            Self::Acknowledgment => write!(f, "acknowledgment"),
            Self::Encrypted => write!(f, "encrypted"),
            Self::KeyExchange => write!(f, "key_exchange"),
            Self::StatusUpdate => write!(f, "status_update"),
        }
    }
}

/// Message envelope for Kaspa blockchain transport
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct KaspaEnvelope {
    /// Protocol version
    pub version: u8,
    /// Application identifier
    pub app_id: String,
    /// Message type
    pub envelope_type: EnvelopeType,
    /// Sender peer ID
    pub sender_peer_id: String,
    /// Recipient peer ID (None for broadcasts)
    pub recipient_peer_id: Option<String>,
    /// Unique message identifier
    pub message_id: Option<String>,
    /// Timestamp (milliseconds since epoch)
    pub timestamp: u64,
    /// Time-to-live in seconds (0 = no expiry)
    pub ttl: u32,
    /// Message payload (JSON or binary as base64)
    pub payload: String,
    /// Whether payload is encrypted
    pub encrypted: bool,
    /// Ed25519 signature of the envelope (hex)
    pub signature: Option<String>,
    /// Sender's public key for verification (hex)
    pub sender_public_key: Option<String>,
}

#[wasm_bindgen]
impl KaspaEnvelope {
    /// Create a new envelope
    #[wasm_bindgen(constructor)]
    pub fn new(
        envelope_type: EnvelopeType,
        sender_peer_id: String,
        payload: String,
    ) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            app_id: APP_ID.to_string(),
            envelope_type,
            sender_peer_id,
            recipient_peer_id: None,
            message_id: Some(generate_message_id()),
            timestamp: current_timestamp_ms(),
            ttl: 86400, // 24 hours default
            payload,
            encrypted: false,
            signature: None,
            sender_public_key: None,
        }
    }

    /// Create envelope for direct message to specific recipient
    pub fn direct_message(sender: String, recipient: String, payload: String) -> Self {
        let mut env = Self::new(EnvelopeType::DirectMessage, sender, payload);
        env.recipient_peer_id = Some(recipient);
        env
    }

    /// Create envelope for peer announcement (broadcast)
    pub fn peer_announcement(sender: String, payload: String) -> Self {
        Self::new(EnvelopeType::PeerAnnouncement, sender, payload)
    }

    /// Create envelope for WebRTC signaling
    pub fn signaling(
        sender: String,
        recipient: String,
        signaling_type: EnvelopeType,
        payload: String,
    ) -> Self {
        let mut env = Self::new(signaling_type, sender, payload);
        env.recipient_peer_id = Some(recipient);
        env.ttl = 300; // 5 minutes for signaling
        env
    }

    /// Set recipient
    pub fn with_recipient(mut self, recipient: String) -> Self {
        self.recipient_peer_id = Some(recipient);
        self
    }

    /// Set TTL in seconds
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    /// Mark as encrypted
    pub fn with_encryption(mut self) -> Self {
        self.encrypted = true;
        self
    }

    /// Check if message has expired
    pub fn is_expired(&self) -> bool {
        if self.ttl == 0 {
            return false; // No expiry
        }
        let now = current_timestamp_ms();
        let expiry = self.timestamp + (self.ttl as u64 * 1000);
        now > expiry
    }

    /// Check if this envelope is for us
    pub fn is_for_peer(&self, our_peer_id: &str) -> bool {
        match &self.recipient_peer_id {
            Some(recipient) => recipient == our_peer_id,
            None => true, // Broadcast
        }
    }

    /// Check if envelope is valid
    pub fn validate(&self) -> KaspaResult<()> {
        if self.version != ENVELOPE_VERSION {
            return Err(KaspaError::invalid_envelope(format!(
                "Unknown version: {}",
                self.version
            )));
        }

        if self.app_id != APP_ID {
            return Err(KaspaError::invalid_envelope(format!(
                "Unknown app_id: {}",
                self.app_id
            )));
        }

        if self.sender_peer_id.is_empty() {
            return Err(KaspaError::invalid_envelope("Empty sender_peer_id"));
        }

        if self.is_expired() {
            return Err(KaspaError::invalid_envelope("Message expired"));
        }

        Ok(())
    }
}

impl KaspaEnvelope {
    /// Serialize to JSON bytes for embedding in transaction
    pub fn to_bytes(&self) -> KaspaResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| KaspaError::serialization(e.to_string()))
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> KaspaResult<Self> {
        serde_json::from_slice(bytes).map_err(|e| KaspaError::serialization(e.to_string()))
    }

    /// Get bytes that should be signed
    pub fn signable_bytes(&self) -> KaspaResult<Vec<u8>> {
        // Create a copy without signature for signing
        let signable = SignableEnvelope {
            version: self.version,
            app_id: &self.app_id,
            envelope_type: self.envelope_type,
            sender_peer_id: &self.sender_peer_id,
            recipient_peer_id: self.recipient_peer_id.as_deref(),
            message_id: self.message_id.as_deref(),
            timestamp: self.timestamp,
            ttl: self.ttl,
            payload: &self.payload,
            encrypted: self.encrypted,
        };

        serde_json::to_vec(&signable).map_err(|e| KaspaError::serialization(e.to_string()))
    }

    /// Add signature and public key
    pub fn sign(&mut self, signature: String, public_key: String) {
        self.signature = Some(signature);
        self.sender_public_key = Some(public_key);
    }
}

/// Helper struct for creating signable data (excludes signature fields)
#[derive(Serialize)]
struct SignableEnvelope<'a> {
    version: u8,
    app_id: &'a str,
    envelope_type: EnvelopeType,
    sender_peer_id: &'a str,
    recipient_peer_id: Option<&'a str>,
    message_id: Option<&'a str>,
    timestamp: u64,
    ttl: u32,
    payload: &'a str,
    encrypted: bool,
}

/// Extract envelopes from a transaction payload
pub fn extract_envelopes(payload: &[u8]) -> Vec<KaspaEnvelope> {
    let mut envelopes = Vec::new();

    // Check for P2PComm marker
    if !is_p2pcomm_payload(payload) {
        return envelopes;
    }

    // Try to find envelope separator
    let parts = split_payload(payload);

    for part in parts {
        if let Ok(envelope) = KaspaEnvelope::from_bytes(part) {
            if envelope.validate().is_ok() {
                envelopes.push(envelope);
            }
        }
    }

    envelopes
}

/// Check if payload is a P2PComm message
pub fn is_p2pcomm_payload(payload: &[u8]) -> bool {
    // Check for app_id in JSON
    let pattern = format!(r#""app_id":"{}""#, APP_ID);
    if let Ok(text) = std::str::from_utf8(payload) {
        return text.contains(&pattern);
    }
    false
}

/// Split payload by separator
fn split_payload(payload: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let mut start = 0;

    // Simple split on separator
    while let Some(pos) = find_separator(payload, start) {
        if start < pos {
            parts.push(&payload[start..pos]);
        }
        start = pos + ENVELOPE_SEPARATOR.len();
    }

    // Add remaining part
    if start < payload.len() {
        parts.push(&payload[start..]);
    }

    if parts.is_empty() {
        parts.push(payload);
    }

    parts
}

/// Find separator in payload
fn find_separator(payload: &[u8], start: usize) -> Option<usize> {
    if start + ENVELOPE_SEPARATOR.len() > payload.len() {
        return None;
    }

    for i in start..=(payload.len() - ENVELOPE_SEPARATOR.len()) {
        if &payload[i..i + ENVELOPE_SEPARATOR.len()] == ENVELOPE_SEPARATOR {
            return Some(i);
        }
    }

    None
}

/// Summarize an envelope for logging
pub fn summarize_envelope(envelope: &KaspaEnvelope) -> String {
    format!(
        "[{}] {} -> {} ({} bytes)",
        envelope.envelope_type,
        &envelope.sender_peer_id[..8.min(envelope.sender_peer_id.len())],
        envelope
            .recipient_peer_id
            .as_ref()
            .map(|r| &r[..8.min(r.len())])
            .unwrap_or("broadcast"),
        envelope.payload.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_creation() {
        let env = KaspaEnvelope::new(
            EnvelopeType::DirectMessage,
            "sender123".to_string(),
            "Hello, World!".to_string(),
        );

        assert_eq!(env.version, ENVELOPE_VERSION);
        assert_eq!(env.app_id, APP_ID);
        assert_eq!(env.sender_peer_id, "sender123");
        assert!(!env.is_expired());
    }

    #[test]
    fn test_envelope_serialization() {
        let env = KaspaEnvelope::direct_message(
            "sender".to_string(),
            "recipient".to_string(),
            "test payload".to_string(),
        );

        let bytes = env.to_bytes().unwrap();
        let restored = KaspaEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(restored.sender_peer_id, "sender");
        assert_eq!(restored.recipient_peer_id, Some("recipient".to_string()));
    }

    #[test]
    fn test_envelope_type_display() {
        assert_eq!(format!("{}", EnvelopeType::DirectMessage), "direct_message");
        assert_eq!(format!("{}", EnvelopeType::SignalingOffer), "signaling_offer");
    }

    #[test]
    fn test_is_signaling() {
        assert!(EnvelopeType::SignalingOffer.is_signaling());
        assert!(EnvelopeType::SignalingAnswer.is_signaling());
        assert!(EnvelopeType::SignalingIce.is_signaling());
        assert!(!EnvelopeType::DirectMessage.is_signaling());
    }
}
