// Storage Types
// Data structures specific to storage layer

use serde::{Deserialize, Serialize};
use crate::identity::{Identity, Contact, PeerId, IdentityResult};
use crate::message::{Message, MessageId, MessageResult};

/// Conversation metadata for quick access
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationMeta {
    /// Peer ID (as hex string for IndexedDB key)
    pub peer_id: String,
    /// Last message ID in this conversation
    pub last_message_id: String,
    /// Timestamp of last message
    pub last_message_timestamp: u64,
    /// Preview of last message (first 100 chars)
    pub last_message_preview: String,
    /// Number of unread messages
    pub unread_count: u32,
    /// Whether conversation is pinned
    pub pinned: bool,
    /// Whether conversation is muted
    pub muted: bool,
    /// Whether conversation is archived
    pub archived: bool,
}

impl ConversationMeta {
    /// Create a new conversation metadata from a message
    pub fn from_message(peer_id: &PeerId, message: &Message, preview: String) -> Self {
        Self {
            peer_id: peer_id.to_hex(),
            last_message_id: message.id.to_hex(),
            last_message_timestamp: message.timestamp,
            last_message_preview: preview,
            unread_count: 0,
            pinned: false,
            muted: false,
            archived: false,
        }
    }

    /// Update with a new message
    pub fn update_with_message(&mut self, message: &Message, preview: String) {
        self.last_message_id = message.id.to_hex();
        self.last_message_timestamp = message.timestamp;
        self.last_message_preview = preview;
    }

    /// Get the peer ID
    pub fn get_peer_id(&self) -> IdentityResult<PeerId> {
        PeerId::from_hex(&self.peer_id)
    }

    /// Get the last message ID
    pub fn get_last_message_id(&self) -> MessageResult<MessageId> {
        MessageId::from_hex(&self.last_message_id)
    }
}

/// Cached peer address with TTL
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedPeerAddress {
    /// Peer ID (as hex string for IndexedDB key)
    pub peer_id: String,
    /// List of addresses for this peer
    pub addresses: Vec<String>,
    /// When this cache entry was created
    pub cached_at: u64,
    /// When this cache entry expires (timestamp)
    pub expires_at: u64,
    /// Last successful connection timestamp
    pub last_seen: Option<u64>,
}

impl CachedPeerAddress {
    /// Create a new cached address with default TTL (24 hours)
    pub fn new(peer_id: &PeerId, addresses: Vec<String>, now: u64) -> Self {
        const DEFAULT_TTL: u64 = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
        Self {
            peer_id: peer_id.to_hex(),
            addresses,
            cached_at: now,
            expires_at: now + DEFAULT_TTL,
            last_seen: None,
        }
    }

    /// Create with custom TTL in milliseconds
    pub fn with_ttl(peer_id: &PeerId, addresses: Vec<String>, now: u64, ttl_ms: u64) -> Self {
        Self {
            peer_id: peer_id.to_hex(),
            addresses,
            cached_at: now,
            expires_at: now + ttl_ms,
            last_seen: None,
        }
    }

    /// Check if this cache entry is expired
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Update last seen timestamp
    pub fn mark_seen(&mut self, now: u64) {
        self.last_seen = Some(now);
    }

    /// Get the peer ID
    pub fn get_peer_id(&self) -> IdentityResult<PeerId> {
        PeerId::from_hex(&self.peer_id)
    }
}

/// Stored identity wrapper for IndexedDB
/// Identity is stored encrypted, but we need a wrapper with string ID for indexing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredIdentity {
    /// Peer ID as hex string (IndexedDB key)
    pub peer_id: String,
    /// Encrypted identity data
    pub encrypted_data: Vec<u8>,
    /// When this identity was created (for indexing)
    pub created_at: u64,
}

impl StoredIdentity {
    /// Create from encrypted identity data
    pub fn new(peer_id: &PeerId, encrypted_data: Vec<u8>, created_at: u64) -> Self {
        Self {
            peer_id: peer_id.to_hex(),
            encrypted_data,
            created_at,
        }
    }

    /// Get the peer ID
    pub fn get_peer_id(&self) -> IdentityResult<PeerId> {
        PeerId::from_hex(&self.peer_id)
    }
}

/// Stored contact wrapper for IndexedDB
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredContact {
    /// Peer ID as hex string (IndexedDB key)
    pub peer_id: String,
    /// Display name (for indexing)
    pub display_name: String,
    /// The actual contact data
    pub contact: Contact,
}

impl StoredContact {
    /// Create from a contact
    pub fn from_contact(contact: Contact) -> Self {
        Self {
            peer_id: contact.peer_id.to_hex(),
            display_name: contact.display_name.clone(),
            contact,
        }
    }

    /// Get the peer ID
    pub fn get_peer_id(&self) -> IdentityResult<PeerId> {
        PeerId::from_hex(&self.peer_id)
    }
}

/// Stored message wrapper for IndexedDB with string IDs for efficient indexing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    /// Message ID as hex string (IndexedDB key)
    pub id: String,
    /// From peer ID as hex string (for indexing)
    pub from_peer_id: String,
    /// To peer ID as hex string (for indexing)
    pub to_peer_id: String,
    /// Timestamp (for indexing)
    pub timestamp: u64,
    /// Encrypted message data
    pub encrypted_data: Vec<u8>,
}

impl StoredMessage {
    /// Create from encrypted message data
    pub fn new(message: &Message, encrypted_data: Vec<u8>) -> Self {
        Self {
            id: message.id.to_hex(),
            from_peer_id: message.from.to_hex(),
            to_peer_id: message.to.to_hex(),
            timestamp: message.timestamp,
            encrypted_data,
        }
    }

    /// Get the message ID
    pub fn get_message_id(&self) -> MessageResult<MessageId> {
        MessageId::from_hex(&self.id)
    }

    /// Get the from peer ID
    pub fn get_from_peer_id(&self) -> IdentityResult<PeerId> {
        PeerId::from_hex(&self.from_peer_id)
    }

    /// Get the to peer ID
    pub fn get_to_peer_id(&self) -> IdentityResult<PeerId> {
        PeerId::from_hex(&self.to_peer_id)
    }
}

/// Setting value types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SettingValue {
    String(String),
    Bool(bool),
    Number(f64),
    Json(serde_json::Value),
}

impl SettingValue {
    /// Try to get as string
    pub fn as_string(&self) -> Option<&str> {
        match self {
            SettingValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get as bool
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            SettingValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Try to get as number
    pub fn as_number(&self) -> Option<f64> {
        match self {
            SettingValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Try to get as JSON value
    pub fn as_json(&self) -> Option<&serde_json::Value> {
        match self {
            SettingValue::Json(v) => Some(v),
            _ => None,
        }
    }
}

impl From<String> for SettingValue {
    fn from(s: String) -> Self {
        SettingValue::String(s)
    }
}

impl From<&str> for SettingValue {
    fn from(s: &str) -> Self {
        SettingValue::String(s.to_string())
    }
}

impl From<bool> for SettingValue {
    fn from(b: bool) -> Self {
        SettingValue::Bool(b)
    }
}

impl From<f64> for SettingValue {
    fn from(n: f64) -> Self {
        SettingValue::Number(n)
    }
}

impl From<i32> for SettingValue {
    fn from(n: i32) -> Self {
        SettingValue::Number(n as f64)
    }
}

impl From<serde_json::Value> for SettingValue {
    fn from(v: serde_json::Value) -> Self {
        SettingValue::Json(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversation_meta_roundtrip() {
        let peer_id = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let message_id = MessageId::from_hex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").unwrap();

        let mut meta = ConversationMeta {
            peer_id: peer_id.to_hex(),
            last_message_id: message_id.to_hex(),
            last_message_timestamp: 123456,
            last_message_preview: "Hello".to_string(),
            unread_count: 5,
            pinned: true,
            muted: false,
            archived: false,
        };

        // Test peer_id roundtrip
        let recovered_peer_id = meta.get_peer_id().unwrap();
        assert_eq!(peer_id, recovered_peer_id);

        // Test message_id roundtrip
        let recovered_msg_id = meta.get_last_message_id().unwrap();
        assert_eq!(message_id, recovered_msg_id);
    }

    #[test]
    fn test_cached_peer_address_ttl() {
        let peer_id = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = 1000000;

        let cached = CachedPeerAddress::with_ttl(&peer_id, addresses, now, 5000);

        assert!(!cached.is_expired(now + 4999));
        assert!(cached.is_expired(now + 5000));
        assert!(cached.is_expired(now + 10000));
    }

    #[test]
    fn test_setting_value_conversions() {
        let string_val = SettingValue::from("test");
        assert_eq!(string_val.as_string(), Some("test"));
        assert_eq!(string_val.as_bool(), None);

        let bool_val = SettingValue::from(true);
        assert_eq!(bool_val.as_bool(), Some(true));
        assert_eq!(bool_val.as_string(), None);

        let num_val = SettingValue::from(42.5);
        assert_eq!(num_val.as_number(), Some(42.5));
        assert_eq!(num_val.as_bool(), None);

        let int_val = SettingValue::from(42i32);
        assert_eq!(int_val.as_number(), Some(42.0));
    }
}
