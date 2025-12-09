/// Message Extractor for P2PComm
///
/// This module extracts and parses KaspaEnvelopes from transaction payloads:
/// - Deserialize envelope format from raw bytes
/// - Support multiple envelopes per transaction (batched messages)
/// - Validate envelope structure and version
/// - Extract message metadata and encrypted content

use anyhow::{Result, Context, bail};
use serde::{Serialize, Deserialize};

/// Current envelope version
pub const ENVELOPE_VERSION: u8 = 1;

/// Application identifier for P2PComm messages
pub const APP_ID: &str = "p2pcomm/v1";

/// Message envelope separator in batched payloads
pub const ENVELOPE_SEPARATOR: &[u8] = b"\n---\n";

/// Envelope type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EnvelopeType {
    /// Regular chat message
    Message = 0,
    /// WebRTC signaling offer (SDP)
    SignalingOffer = 1,
    /// WebRTC signaling answer (SDP)
    SignalingAnswer = 2,
    /// WebRTC ICE candidate
    SignalingIce = 3,
    /// Acknowledgment receipt
    Ack = 4,
    /// System/control message
    System = 5,
}

impl EnvelopeType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Message),
            1 => Some(Self::SignalingOffer),
            2 => Some(Self::SignalingAnswer),
            3 => Some(Self::SignalingIce),
            4 => Some(Self::Ack),
            5 => Some(Self::System),
            _ => None,
        }
    }

    /// Check if this is a signaling message
    pub fn is_signaling(&self) -> bool {
        matches!(
            self,
            Self::SignalingOffer | Self::SignalingAnswer | Self::SignalingIce
        )
    }
}

/// Kaspa message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KaspaEnvelope {
    /// Protocol version
    pub version: u8,
    /// Application identifier
    pub app_id: String,
    /// Envelope type
    pub envelope_type: EnvelopeType,
    /// Sender's peer ID (Blake3 hash of public key)
    pub sender_peer_id: String,
    /// Recipient's peer ID
    pub recipient_peer_id: String,
    /// Message timestamp (Unix milliseconds)
    pub timestamp: u64,
    /// Encrypted message data
    pub data: Vec<u8>,
    /// Ed25519 signature of the envelope (excluding signature field)
    pub signature: Vec<u8>,
    /// Optional message ID for deduplication
    pub message_id: Option<String>,
}

impl KaspaEnvelope {
    /// Create a new envelope
    pub fn new(
        envelope_type: EnvelopeType,
        sender_peer_id: String,
        recipient_peer_id: String,
        data: Vec<u8>,
    ) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            app_id: APP_ID.to_string(),
            envelope_type,
            sender_peer_id,
            recipient_peer_id,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            data,
            signature: Vec::new(),
            message_id: None,
        }
    }

    /// Serialize envelope to bytes (for signing/transmission)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Version (1 byte)
        bytes.push(self.version);

        // App ID length + data
        let app_id_bytes = self.app_id.as_bytes();
        bytes.push(app_id_bytes.len() as u8);
        bytes.extend_from_slice(app_id_bytes);

        // Envelope type (1 byte)
        bytes.push(self.envelope_type as u8);

        // Sender peer ID length + data
        let sender_bytes = self.sender_peer_id.as_bytes();
        bytes.push(sender_bytes.len() as u8);
        bytes.extend_from_slice(sender_bytes);

        // Recipient peer ID length + data
        let recipient_bytes = self.recipient_peer_id.as_bytes();
        bytes.push(recipient_bytes.len() as u8);
        bytes.extend_from_slice(recipient_bytes);

        // Timestamp (8 bytes, big-endian)
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());

        // Data length (4 bytes) + data
        bytes.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.data);

        // Signature length (2 bytes) + signature
        bytes.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.signature);

        // Optional message ID
        if let Some(ref msg_id) = self.message_id {
            let msg_id_bytes = msg_id.as_bytes();
            bytes.push(1); // Has message ID
            bytes.push(msg_id_bytes.len() as u8);
            bytes.extend_from_slice(msg_id_bytes);
        } else {
            bytes.push(0); // No message ID
        }

        Ok(bytes)
    }

    /// Deserialize envelope from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 10 {
            bail!("Envelope too short: {} bytes", bytes.len());
        }

        let mut pos = 0;

        // Version
        let version = bytes[pos];
        pos += 1;

        if version != ENVELOPE_VERSION {
            bail!("Unsupported envelope version: {} (expected {})", version, ENVELOPE_VERSION);
        }

        // App ID
        let app_id_len = bytes[pos] as usize;
        pos += 1;
        if pos + app_id_len > bytes.len() {
            bail!("Invalid app ID length");
        }
        let app_id = String::from_utf8(bytes[pos..pos + app_id_len].to_vec())
            .context("Invalid app ID encoding")?;
        pos += app_id_len;

        // Envelope type
        let envelope_type = EnvelopeType::from_u8(bytes[pos])
            .ok_or_else(|| anyhow::anyhow!("Invalid envelope type: {}", bytes[pos]))?;
        pos += 1;

        // Sender peer ID
        let sender_len = bytes[pos] as usize;
        pos += 1;
        if pos + sender_len > bytes.len() {
            bail!("Invalid sender peer ID length");
        }
        let sender_peer_id = String::from_utf8(bytes[pos..pos + sender_len].to_vec())
            .context("Invalid sender peer ID encoding")?;
        pos += sender_len;

        // Recipient peer ID
        let recipient_len = bytes[pos] as usize;
        pos += 1;
        if pos + recipient_len > bytes.len() {
            bail!("Invalid recipient peer ID length");
        }
        let recipient_peer_id = String::from_utf8(bytes[pos..pos + recipient_len].to_vec())
            .context("Invalid recipient peer ID encoding")?;
        pos += recipient_len;

        // Timestamp
        if pos + 8 > bytes.len() {
            bail!("Missing timestamp");
        }
        let timestamp = u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Data
        if pos + 4 > bytes.len() {
            bail!("Missing data length");
        }
        let data_len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + data_len > bytes.len() {
            bail!("Invalid data length");
        }
        let data = bytes[pos..pos + data_len].to_vec();
        pos += data_len;

        // Signature
        if pos + 2 > bytes.len() {
            bail!("Missing signature length");
        }
        let sig_len = u16::from_be_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if pos + sig_len > bytes.len() {
            bail!("Invalid signature length");
        }
        let signature = bytes[pos..pos + sig_len].to_vec();
        pos += sig_len;

        // Optional message ID
        let message_id = if pos < bytes.len() && bytes[pos] == 1 {
            pos += 1;
            let msg_id_len = bytes[pos] as usize;
            pos += 1;
            if pos + msg_id_len <= bytes.len() {
                Some(String::from_utf8(bytes[pos..pos + msg_id_len].to_vec())
                    .context("Invalid message ID encoding")?)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            version,
            app_id,
            envelope_type,
            sender_peer_id,
            recipient_peer_id,
            timestamp,
            data,
            signature,
            message_id,
        })
    }

    /// Get bytes to sign (envelope without signature)
    pub fn signable_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Version
        bytes.push(self.version);

        // App ID
        let app_id_bytes = self.app_id.as_bytes();
        bytes.push(app_id_bytes.len() as u8);
        bytes.extend_from_slice(app_id_bytes);

        // Envelope type
        bytes.push(self.envelope_type as u8);

        // Sender peer ID
        let sender_bytes = self.sender_peer_id.as_bytes();
        bytes.push(sender_bytes.len() as u8);
        bytes.extend_from_slice(sender_bytes);

        // Recipient peer ID
        let recipient_bytes = self.recipient_peer_id.as_bytes();
        bytes.push(recipient_bytes.len() as u8);
        bytes.extend_from_slice(recipient_bytes);

        // Timestamp
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());

        // Data
        bytes.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.data);

        Ok(bytes)
    }

    /// Validate envelope structure
    pub fn validate(&self) -> Result<()> {
        if self.version != ENVELOPE_VERSION {
            bail!("Invalid version: {} (expected {})", self.version, ENVELOPE_VERSION);
        }

        if self.app_id != APP_ID {
            bail!("Invalid app ID: {} (expected {})", self.app_id, APP_ID);
        }

        if self.sender_peer_id.is_empty() {
            bail!("Empty sender peer ID");
        }

        if self.recipient_peer_id.is_empty() {
            bail!("Empty recipient peer ID");
        }

        if self.data.is_empty() {
            bail!("Empty data");
        }

        if self.signature.is_empty() {
            bail!("Missing signature");
        }

        Ok(())
    }
}

/// Message extractor for parsing transaction payloads
pub struct MessageExtractor;

impl MessageExtractor {
    /// Extract all envelopes from a transaction payload
    pub fn extract_envelopes(payload: &[u8]) -> Result<Vec<KaspaEnvelope>> {
        if payload.is_empty() {
            return Ok(Vec::new());
        }

        let mut envelopes = Vec::new();

        // Check if this is a batched payload (contains separator)
        if payload.windows(ENVELOPE_SEPARATOR.len()).any(|w| w == ENVELOPE_SEPARATOR) {
            // Split by separator and parse each
            let parts: Vec<&[u8]> = payload
                .split(|&b| b == ENVELOPE_SEPARATOR[0])
                .filter(|p| !p.is_empty() && *p != &ENVELOPE_SEPARATOR[1..])
                .collect();

            for part in parts {
                // Skip separator remnants
                let clean_part = Self::clean_part(part);
                if !clean_part.is_empty() {
                    match KaspaEnvelope::from_bytes(clean_part) {
                        Ok(envelope) => envelopes.push(envelope),
                        Err(e) => {
                            log::warn!("Failed to parse envelope: {}", e);
                        }
                    }
                }
            }
        } else {
            // Single envelope
            match KaspaEnvelope::from_bytes(payload) {
                Ok(envelope) => envelopes.push(envelope),
                Err(e) => {
                    log::warn!("Failed to parse envelope: {}", e);
                }
            }
        }

        Ok(envelopes)
    }

    /// Clean part from separator remnants
    fn clean_part(part: &[u8]) -> &[u8] {
        let mut start = 0;
        let mut end = part.len();

        // Skip leading dashes and newlines
        while start < end && (part[start] == b'-' || part[start] == b'\n') {
            start += 1;
        }

        // Skip trailing dashes and newlines
        while end > start && (part[end - 1] == b'-' || part[end - 1] == b'\n') {
            end -= 1;
        }

        &part[start..end]
    }

    /// Check if payload appears to be a P2PComm message
    pub fn is_p2pcomm_payload(payload: &[u8]) -> bool {
        if payload.len() < 3 {
            return false;
        }

        // Check version byte
        if payload[0] != ENVELOPE_VERSION {
            return false;
        }

        // Check app ID prefix
        let app_id_len = payload[1] as usize;
        if payload.len() < 2 + app_id_len {
            return false;
        }

        let app_id = &payload[2..2 + app_id_len];
        app_id == APP_ID.as_bytes()
    }

    /// Get message summary for debugging
    pub fn summarize_envelope(envelope: &KaspaEnvelope) -> String {
        format!(
            "Envelope v{} type={:?} from={} to={} data={}bytes sig={}bytes",
            envelope.version,
            envelope.envelope_type,
            &envelope.sender_peer_id[..8.min(envelope.sender_peer_id.len())],
            &envelope.recipient_peer_id[..8.min(envelope.recipient_peer_id.len())],
            envelope.data.len(),
            envelope.signature.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_type_conversion() {
        assert_eq!(EnvelopeType::from_u8(0), Some(EnvelopeType::Message));
        assert_eq!(EnvelopeType::from_u8(1), Some(EnvelopeType::SignalingOffer));
        assert_eq!(EnvelopeType::from_u8(2), Some(EnvelopeType::SignalingAnswer));
        assert_eq!(EnvelopeType::from_u8(3), Some(EnvelopeType::SignalingIce));
        assert_eq!(EnvelopeType::from_u8(99), None);
    }

    #[test]
    fn test_envelope_is_signaling() {
        assert!(!EnvelopeType::Message.is_signaling());
        assert!(EnvelopeType::SignalingOffer.is_signaling());
        assert!(EnvelopeType::SignalingAnswer.is_signaling());
        assert!(EnvelopeType::SignalingIce.is_signaling());
    }

    #[test]
    fn test_envelope_roundtrip() {
        let original = KaspaEnvelope::new(
            EnvelopeType::Message,
            "sender_peer_id_12345".to_string(),
            "recipient_peer_id_67890".to_string(),
            b"Hello, World!".to_vec(),
        );

        // Add a dummy signature for testing
        let mut envelope = original.clone();
        envelope.signature = vec![1, 2, 3, 4, 5];

        let bytes = envelope.to_bytes().unwrap();
        let restored = KaspaEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version, envelope.version);
        assert_eq!(restored.app_id, envelope.app_id);
        assert_eq!(restored.envelope_type, envelope.envelope_type);
        assert_eq!(restored.sender_peer_id, envelope.sender_peer_id);
        assert_eq!(restored.recipient_peer_id, envelope.recipient_peer_id);
        assert_eq!(restored.data, envelope.data);
        assert_eq!(restored.signature, envelope.signature);
    }

    #[test]
    fn test_envelope_validation() {
        let mut envelope = KaspaEnvelope::new(
            EnvelopeType::Message,
            "sender".to_string(),
            "recipient".to_string(),
            b"data".to_vec(),
        );

        // Missing signature
        assert!(envelope.validate().is_err());

        // Add signature
        envelope.signature = vec![1, 2, 3];
        assert!(envelope.validate().is_ok());

        // Invalid app ID
        envelope.app_id = "wrong".to_string();
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn test_is_p2pcomm_payload() {
        let envelope = KaspaEnvelope::new(
            EnvelopeType::Message,
            "sender".to_string(),
            "recipient".to_string(),
            b"data".to_vec(),
        );

        let mut with_sig = envelope.clone();
        with_sig.signature = vec![1, 2, 3];
        let bytes = with_sig.to_bytes().unwrap();

        assert!(MessageExtractor::is_p2pcomm_payload(&bytes));
        assert!(!MessageExtractor::is_p2pcomm_payload(&[0, 0, 0]));
        assert!(!MessageExtractor::is_p2pcomm_payload(&[]));
    }

    #[test]
    fn test_extract_single_envelope() {
        let envelope = KaspaEnvelope::new(
            EnvelopeType::Message,
            "sender".to_string(),
            "recipient".to_string(),
            b"Hello!".to_vec(),
        );

        let mut with_sig = envelope.clone();
        with_sig.signature = vec![1, 2, 3, 4, 5];
        let bytes = with_sig.to_bytes().unwrap();

        let extracted = MessageExtractor::extract_envelopes(&bytes).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].sender_peer_id, "sender");
    }

    #[test]
    fn test_signable_bytes() {
        let envelope = KaspaEnvelope::new(
            EnvelopeType::Message,
            "sender".to_string(),
            "recipient".to_string(),
            b"data".to_vec(),
        );

        let signable1 = envelope.signable_bytes().unwrap();

        // Changing signature shouldn't affect signable bytes
        let mut with_sig = envelope.clone();
        with_sig.signature = vec![1, 2, 3, 4, 5];
        let signable2 = with_sig.signable_bytes().unwrap();

        assert_eq!(signable1, signable2);
    }
}
