// P2P Wire Protocol
// Defines message types for peer-to-peer communication

use serde::{Deserialize, Serialize};
use crate::identity::PeerId;
use crate::message::{Message, MessageId};

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Wire protocol message envelope
/// All P2P messages are wrapped in this envelope for routing and versioning
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Protocol version
    pub version: u8,
    /// Sender's peer ID
    pub from: PeerId,
    /// Recipient's peer ID
    pub to: PeerId,
    /// Message timestamp (milliseconds since epoch)
    pub timestamp: u64,
    /// Message payload
    pub payload: MessagePayload,
}

impl ProtocolMessage {
    /// Create a new protocol message
    pub fn new(from: PeerId, to: PeerId, payload: MessagePayload) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            from,
            to,
            timestamp: js_sys::Date::now() as u64,
            payload,
        }
    }

    /// Serialize to binary (bincode)
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self)
            .map_err(|e| format!("Failed to serialize protocol message: {}", e))
    }

    /// Deserialize from binary (bincode)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let msg: ProtocolMessage = bincode::deserialize(bytes)
            .map_err(|e| format!("Failed to deserialize protocol message: {}", e))?;

        // Validate version
        if msg.version > PROTOCOL_VERSION {
            return Err(format!(
                "Unsupported protocol version: {} (max supported: {})",
                msg.version,
                PROTOCOL_VERSION
            ));
        }

        Ok(msg)
    }

    /// Check if this message is expired (older than max_age_ms)
    pub fn is_expired(&self, max_age_ms: u64) -> bool {
        let now = js_sys::Date::now() as u64;
        now > self.timestamp + max_age_ms
    }
}

/// Message payload types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessagePayload {
    /// Handshake - initial connection setup
    Handshake(HandshakeMessage),

    /// Handshake acknowledgment
    HandshakeAck(HandshakeAckMessage),

    /// User message (chat message)
    UserMessage(UserMessagePayload),

    /// Message acknowledgment
    MessageAck(MessageAckPayload),

    /// Ping request (for keep-alive)
    Ping(PingMessage),

    /// Pong response (for keep-alive)
    Pong(PongMessage),

    /// Peer discovery request
    DiscoveryRequest(DiscoveryRequestMessage),

    /// Peer discovery response
    DiscoveryResponse(DiscoveryResponseMessage),

    /// Connection close notification
    Close(CloseMessage),

    /// Error notification
    Error(ErrorMessage),
}

/// Handshake message - sent when establishing a new connection
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeMessage {
    /// Protocol version
    pub protocol_version: u8,
    /// Public signing key (Ed25519)
    pub signing_public_key: Vec<u8>,
    /// Public encryption key (X25519)
    pub encryption_public_key: Vec<u8>,
    /// Supported features
    pub features: Vec<String>,
}

impl HandshakeMessage {
    /// Create a new handshake message
    pub fn new(
        signing_public_key: Vec<u8>,
        encryption_public_key: Vec<u8>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            signing_public_key,
            encryption_public_key,
            features: vec!["basic-messaging".to_string()],
        }
    }
}

/// Handshake acknowledgment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeAckMessage {
    /// Whether handshake was accepted
    pub accepted: bool,
    /// Reason if rejected
    pub reason: Option<String>,
}

/// User message payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserMessagePayload {
    /// The actual message
    pub message: Message,
}

/// Message acknowledgment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageAckPayload {
    /// ID of the message being acknowledged
    pub message_id: MessageId,
    /// Whether the message was successfully received
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Ping message for keep-alive
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingMessage {
    /// Ping ID for matching with pong
    pub ping_id: u64,
    /// Client timestamp for RTT calculation
    pub client_timestamp: u64,
}

impl PingMessage {
    /// Create a new ping message
    pub fn new() -> Self {
        let now = js_sys::Date::now() as u64;
        Self {
            ping_id: now, // Use timestamp as ping ID
            client_timestamp: now,
        }
    }
}

impl Default for PingMessage {
    fn default() -> Self {
        Self::new()
    }
}

/// Pong response to ping
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PongMessage {
    /// Ping ID being responded to
    pub ping_id: u64,
    /// Original client timestamp (echoed back)
    pub client_timestamp: u64,
    /// Server timestamp when pong was sent
    pub server_timestamp: u64,
}

impl PongMessage {
    /// Create a pong response from a ping
    pub fn from_ping(ping: &PingMessage) -> Self {
        Self {
            ping_id: ping.ping_id,
            client_timestamp: ping.client_timestamp,
            server_timestamp: js_sys::Date::now() as u64,
        }
    }

    /// Calculate round-trip time in milliseconds
    pub fn calculate_rtt(&self) -> u64 {
        let now = js_sys::Date::now() as u64;
        now.saturating_sub(self.client_timestamp)
    }
}

/// Peer discovery request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryRequestMessage {
    /// Number of peers requested
    pub count: u32,
}

/// Peer discovery response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryResponseMessage {
    /// List of known peer IDs
    pub peers: Vec<PeerId>,
}

/// Connection close message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloseMessage {
    /// Reason for closing
    pub reason: String,
    /// Whether this is a graceful close
    pub graceful: bool,
}

/// Error message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorMessage {
    /// Error code
    pub code: u32,
    /// Error description
    pub message: String,
}

/// Error codes
pub mod error_codes {
    pub const UNKNOWN_ERROR: u32 = 0;
    pub const PROTOCOL_VERSION_MISMATCH: u32 = 1;
    pub const INVALID_MESSAGE: u32 = 2;
    pub const AUTHENTICATION_FAILED: u32 = 3;
    pub const RATE_LIMIT_EXCEEDED: u32 = 4;
    pub const MESSAGE_TOO_LARGE: u32 = 5;
    pub const UNSUPPORTED_FEATURE: u32 = 6;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeyPair;
    use crate::message::MessageContent;

    #[test]
    fn test_protocol_message_serialization() {
        let keypair = IdentityKeyPair::generate().unwrap();
        let from = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let to = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());

        let payload = MessagePayload::Ping(PingMessage::new());
        let msg = ProtocolMessage::new(from.clone(), to.clone(), payload);

        // Serialize
        let bytes = msg.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        // Deserialize
        let decoded = ProtocolMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.from, msg.from);
        assert_eq!(decoded.to, msg.to);
        assert_eq!(decoded.version, PROTOCOL_VERSION);
    }

    #[test]
    fn test_handshake_message() {
        let keypair = IdentityKeyPair::generate().unwrap();
        let signing_pk = keypair.signing_keypair.verifying_key.to_bytes().to_vec();
        let encryption_pk = keypair.encryption_keypair.public_key.as_bytes().to_vec();

        let handshake = HandshakeMessage::new(signing_pk.clone(), encryption_pk.clone());

        assert_eq!(handshake.protocol_version, PROTOCOL_VERSION);
        assert_eq!(handshake.signing_public_key, signing_pk);
        assert_eq!(handshake.encryption_public_key, encryption_pk);
        assert!(!handshake.features.is_empty());
    }

    #[test]
    fn test_ping_pong() {
        let ping = PingMessage::new();
        let pong = PongMessage::from_ping(&ping);

        assert_eq!(pong.ping_id, ping.ping_id);
        assert_eq!(pong.client_timestamp, ping.client_timestamp);
        assert!(pong.server_timestamp >= ping.client_timestamp);

        // RTT should be small (near-zero for this test)
        let rtt = pong.calculate_rtt();
        assert!(rtt < 1000); // Less than 1 second
    }

    #[test]
    fn test_message_expiration() {
        let keypair = IdentityKeyPair::generate().unwrap();
        let from = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let to = from.clone();

        let payload = MessagePayload::Ping(PingMessage::new());
        let mut msg = ProtocolMessage::new(from, to, payload);

        // Not expired initially
        assert!(!msg.is_expired(1000));

        // Set timestamp to 2 seconds ago
        msg.timestamp = js_sys::Date::now() as u64 - 2000;

        // Should be expired with 1 second max age
        assert!(msg.is_expired(1000));

        // Should not be expired with 5 second max age
        assert!(!msg.is_expired(5000));
    }

    #[test]
    fn test_handshake_ack() {
        let ack_success = HandshakeAckMessage {
            accepted: true,
            reason: None,
        };
        assert!(ack_success.accepted);
        assert!(ack_success.reason.is_none());

        let ack_failed = HandshakeAckMessage {
            accepted: false,
            reason: Some("Protocol version mismatch".to_string()),
        };
        assert!(!ack_failed.accepted);
        assert!(ack_failed.reason.is_some());
    }

    #[test]
    fn test_message_ack() {
        let keypair = IdentityKeyPair::generate().unwrap();
        let from = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let to = from.clone();
        let content = MessageContent::Text {
            text: "Test".to_string(),
            reply_to: None,
        };

        // Create identity for message signing
        let identity = crate::identity::Identity {
            peer_id: from.clone(),
            display_name: "Test".to_string(),
            keypair,
            created_at: js_sys::Date::now() as u64,
        };

        let message = Message::new(from, to, content, &identity).unwrap();

        let ack = MessageAckPayload {
            message_id: message.id.clone(),
            success: true,
            error: None,
        };

        assert_eq!(ack.message_id, message.id);
        assert!(ack.success);
        assert!(ack.error.is_none());
    }

    #[test]
    fn test_error_message() {
        let error = ErrorMessage {
            code: error_codes::INVALID_MESSAGE,
            message: "Invalid message format".to_string(),
        };

        assert_eq!(error.code, error_codes::INVALID_MESSAGE);
        assert!(!error.message.is_empty());
    }

    #[test]
    fn test_close_message() {
        let close = CloseMessage {
            reason: "User requested disconnect".to_string(),
            graceful: true,
        };

        assert!(close.graceful);
        assert!(!close.reason.is_empty());
    }

    #[test]
    fn test_discovery_messages() {
        let request = DiscoveryRequestMessage { count: 10 };
        assert_eq!(request.count, 10);

        let keypair = IdentityKeyPair::generate().unwrap();
        let peer1 = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let peer2 = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());

        let response = DiscoveryResponseMessage {
            peers: vec![peer1, peer2],
        };
        assert_eq!(response.peers.len(), 2);
    }

    #[test]
    fn test_protocol_version_validation() {
        let keypair = IdentityKeyPair::generate().unwrap();
        let from = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let to = from.clone();

        let payload = MessagePayload::Ping(PingMessage::new());
        let mut msg = ProtocolMessage::new(from, to, payload);

        // Set unsupported version
        msg.version = 99;

        let bytes = msg.to_bytes().unwrap();
        let result = ProtocolMessage::from_bytes(&bytes);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported protocol version"));
    }
}
