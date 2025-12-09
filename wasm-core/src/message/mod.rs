// Message Handler Module
// Processes incoming and outgoing messages

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use wasm_bindgen::prelude::*;

use crate::crypto::{
    encrypt, decrypt, sign, verify, EncryptedMessage as CryptoEncryptedMessage,
    Ed25519Signature, hash, Blake3Hash,
};
use crate::identity::{Contact, Identity, PeerId};

/// Error types for message operations
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("Invalid message format")]
    InvalidFormat,

    #[error("Message validation failed: {0}")]
    ValidationFailed(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Duplicate message")]
    DuplicateMessage,

    #[error("Message too large: {0} bytes (max {1})")]
    MessageTooLarge(usize, usize),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type MessageResult<T> = Result<T, MessageError>;

/// Maximum message size (1 MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Message ID (UUID)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MessageId {
    pub bytes: [u8; 16],
}

impl MessageId {
    /// Generate a new random message ID
    pub fn new() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        MessageId { bytes }
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        MessageId { bytes }
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Parse from hex string
    pub fn from_hex(hex: &str) -> MessageResult<Self> {
        let bytes = hex::decode(hex)
            .map_err(|_| MessageError::InvalidFormat)?;

        if bytes.len() != 16 {
            return Err(MessageError::InvalidFormat);
        }

        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&bytes);
        Ok(MessageId { bytes: id_bytes })
    }
}

/// Message content types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageContent {
    /// Text message
    Text {
        text: String,
        reply_to: Option<MessageId>,
    },
    // Future: Images, Files, etc.
}

impl MessageContent {
    /// Get the text content if this is a text message
    pub fn text(&self) -> Option<&str> {
        match self {
            MessageContent::Text { text, .. } => Some(text),
        }
    }

    /// Check if this is a reply
    pub fn is_reply(&self) -> bool {
        match self {
            MessageContent::Text { reply_to, .. } => reply_to.is_some(),
        }
    }
}

/// Core message structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId,
    pub version: u8,
    pub from: PeerId,
    pub to: PeerId,
    pub content: MessageContent,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl Message {
    /// Create a new message
    pub fn new(
        from: PeerId,
        to: PeerId,
        content: MessageContent,
        identity: &Identity,
    ) -> MessageResult<Self> {
        let id = MessageId::new();
        let version = PROTOCOL_VERSION;
        let timestamp = js_sys::Date::now() as u64;

        // Create message without signature
        let mut message = Message {
            id,
            version,
            from,
            to,
            content,
            timestamp,
            signature: Vec::new(),
        };

        // Sign the message
        let signature_data = message.signature_data();
        let signature = sign(&signature_data, &identity.keypair.signing_keypair.signing_key)
            .map_err(|e| MessageError::EncryptionFailed(e.to_string()))?;

        message.signature = signature.bytes;

        Ok(message)
    }

    /// Get the data to be signed
    fn signature_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[self.version]);
        data.extend_from_slice(self.from.as_bytes());
        data.extend_from_slice(self.to.as_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.id.bytes);

        // Add content hash
        let content_bytes = bincode::serialize(&self.content).unwrap_or_default();
        let content_hash = hash(&content_bytes);
        data.extend_from_slice(&content_hash.bytes);

        data
    }

    /// Verify the message signature
    pub fn verify(&self, sender_contact: &Contact) -> MessageResult<bool> {
        let signature_data = self.signature_data();
        let signing_key = sender_contact.get_signing_key()
            .map_err(|e| MessageError::ValidationFailed(e.to_string()))?;

        let signature = Ed25519Signature { bytes: self.signature.clone() };

        verify(&signature_data, &signature, &signing_key)
            .map_err(|e| MessageError::SignatureVerificationFailed)
    }

    /// Validate message integrity
    pub fn validate(&self) -> MessageResult<()> {
        // Check protocol version
        if self.version != PROTOCOL_VERSION {
            return Err(MessageError::ValidationFailed(
                format!("Unsupported protocol version: {}", self.version)
            ));
        }

        // Check timestamp is not too far in the future (allow 5 minutes)
        let now = js_sys::Date::now() as u64;
        if self.timestamp > now + 300_000 {
            return Err(MessageError::ValidationFailed(
                "Message timestamp is too far in the future".to_string()
            ));
        }

        // Check content size
        let content_bytes = bincode::serialize(&self.content)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;

        if content_bytes.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge(content_bytes.len(), MAX_MESSAGE_SIZE));
        }

        Ok(())
    }

    /// Encrypt the message for transmission
    pub fn encrypt(&self, recipient_contact: &Contact, sender_identity: &Identity) -> MessageResult<EncryptedMessageEnvelope> {
        // Serialize the message
        let serialized = bincode::serialize(self)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;

        // Get recipient's encryption key
        let recipient_pubkey = recipient_contact.get_encryption_key()
            .map_err(|e| MessageError::EncryptionFailed(e.to_string()))?;

        // Encrypt
        let encrypted = encrypt(
            &serialized,
            &recipient_pubkey,
            &sender_identity.keypair.encryption_keypair.private_key,
            Some(b"p2p_message"),
        ).map_err(|e| MessageError::EncryptionFailed(e.to_string()))?;

        Ok(EncryptedMessageEnvelope {
            version: PROTOCOL_VERSION,
            sender_pubkey_hash: hash(&sender_identity.keypair.encryption_keypair.public_key_bytes()),
            recipient_pubkey_hash: hash(&recipient_contact.encryption_public_key),
            encrypted_message: encrypted,
        })
    }

    /// Decrypt and verify a message
    pub fn decrypt(
        envelope: &EncryptedMessageEnvelope,
        sender_contact: &Contact,
        recipient_identity: &Identity,
    ) -> MessageResult<Self> {
        // Decrypt the message
        let sender_pubkey = sender_contact.get_encryption_key()
            .map_err(|e| MessageError::DecryptionFailed(e.to_string()))?;

        let decrypted = decrypt(
            &envelope.encrypted_message,
            &sender_pubkey,
            &recipient_identity.keypair.encryption_keypair.private_key,
        ).map_err(|e| MessageError::DecryptionFailed(e.to_string()))?;

        // Deserialize
        let message: Message = bincode::deserialize(&decrypted)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;

        // Validate
        message.validate()?;

        // Verify signature
        if !message.verify(sender_contact)? {
            return Err(MessageError::SignatureVerificationFailed);
        }

        Ok(message)
    }
}

/// Encrypted message envelope for wire transmission
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessageEnvelope {
    pub version: u8,
    pub sender_pubkey_hash: Blake3Hash,
    pub recipient_pubkey_hash: Blake3Hash,
    pub encrypted_message: CryptoEncryptedMessage,
}

impl EncryptedMessageEnvelope {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> MessageResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| MessageError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> MessageResult<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| MessageError::SerializationError(e.to_string()))
    }
}

/// Receipt status
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// Message received by peer's device
    Received,
    /// User has viewed the message
    Read,
}

/// Message receipt
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageReceipt {
    pub message_id: MessageId,
    pub status: ReceiptStatus,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl MessageReceipt {
    /// Create a new receipt
    pub fn new(
        message_id: MessageId,
        status: ReceiptStatus,
        identity: &Identity,
    ) -> MessageResult<Self> {
        let timestamp = js_sys::Date::now() as u64;

        let mut receipt = MessageReceipt {
            message_id,
            status,
            timestamp,
            signature: Vec::new(),
        };

        // Sign the receipt
        let signature_data = receipt.signature_data();
        let signature = sign(&signature_data, &identity.keypair.signing_keypair.signing_key)
            .map_err(|e| MessageError::EncryptionFailed(e.to_string()))?;

        receipt.signature = signature.bytes;

        Ok(receipt)
    }

    /// Get the data to be signed
    fn signature_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.message_id.bytes);

        let status_byte = match self.status {
            ReceiptStatus::Received => 1u8,
            ReceiptStatus::Read => 2u8,
        };
        data.push(status_byte);

        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }

    /// Verify the receipt signature
    pub fn verify(&self, signer_contact: &Contact) -> MessageResult<bool> {
        let signature_data = self.signature_data();
        let signing_key = signer_contact.get_signing_key()
            .map_err(|e| MessageError::ValidationFailed(e.to_string()))?;

        let signature = Ed25519Signature { bytes: self.signature.clone() };

        verify(&signature_data, &signature, &signing_key)
            .map_err(|_| MessageError::SignatureVerificationFailed)
    }
}

/// P2P Protocol Messages
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2PMessage {
    /// Initial handshake
    Hello {
        version: u8,
        peer_id: PeerId,
        public_key: Vec<u8>,
        capabilities: Vec<String>,
    },

    /// Handshake acknowledgment
    HelloAck {
        peer_id: PeerId,
        accepted: bool,
    },

    /// Chat message
    ChatMessage {
        envelope: EncryptedMessageEnvelope,
    },

    /// Message receipt
    Receipt {
        receipt: MessageReceipt,
    },

    /// Ping for keepalive
    Ping {
        timestamp: u64,
    },

    /// Pong response
    Pong {
        timestamp: u64,
    },

    /// Address update for reconnection
    AddressUpdate {
        new_addresses: Vec<String>,
        timestamp: u64,
        signature: Vec<u8>,
    },
}

impl P2PMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> MessageResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| MessageError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> MessageResult<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| MessageError::SerializationError(e.to_string()))
    }
}

/// Message Handler - processes messages and tracks state
pub struct MessageHandler {
    /// Set of seen message IDs to prevent duplicates
    seen_messages: HashSet<MessageId>,
    /// Maximum number of message IDs to track
    max_seen_messages: usize,
}

impl MessageHandler {
    /// Create a new message handler
    pub fn new() -> Self {
        MessageHandler {
            seen_messages: HashSet::new(),
            max_seen_messages: 10000,
        }
    }

    /// Create a new message handler with custom capacity
    pub fn with_capacity(max_seen: usize) -> Self {
        MessageHandler {
            seen_messages: HashSet::with_capacity(max_seen),
            max_seen_messages: max_seen,
        }
    }

    /// Check if a message has been seen before
    pub fn is_duplicate(&self, message_id: &MessageId) -> bool {
        self.seen_messages.contains(message_id)
    }

    /// Mark a message as seen
    pub fn mark_seen(&mut self, message_id: MessageId) -> MessageResult<()> {
        // Prevent the set from growing too large
        if self.seen_messages.len() >= self.max_seen_messages {
            // Remove oldest entries (in this simple impl, just clear half)
            let to_remove: Vec<MessageId> = self.seen_messages
                .iter()
                .take(self.max_seen_messages / 2)
                .cloned()
                .collect();

            for id in to_remove {
                self.seen_messages.remove(&id);
            }
        }

        if self.seen_messages.insert(message_id) {
            Ok(())
        } else {
            Err(MessageError::DuplicateMessage)
        }
    }

    /// Process an incoming encrypted message
    pub fn process_incoming(
        &mut self,
        envelope: &EncryptedMessageEnvelope,
        sender_contact: &Contact,
        recipient_identity: &Identity,
    ) -> MessageResult<Message> {
        // Decrypt and verify
        let message = Message::decrypt(envelope, sender_contact, recipient_identity)?;

        // Check for duplicates
        if self.is_duplicate(&message.id) {
            return Err(MessageError::DuplicateMessage);
        }

        // Mark as seen
        self.mark_seen(message.id.clone())?;

        Ok(message)
    }

    /// Create an outgoing message
    pub fn create_message(
        &mut self,
        recipient: &Contact,
        content: MessageContent,
        sender_identity: &Identity,
    ) -> MessageResult<(Message, EncryptedMessageEnvelope)> {
        // Create message
        let message = Message::new(
            sender_identity.peer_id.clone(),
            recipient.peer_id.clone(),
            content,
            sender_identity,
        )?;

        // Mark as seen (our own message)
        self.mark_seen(message.id.clone())?;

        // Encrypt for transmission
        let envelope = message.encrypt(recipient, sender_identity)?;

        Ok((message, envelope))
    }

    /// Create a receipt for a message
    pub fn create_receipt(
        &self,
        message_id: MessageId,
        status: ReceiptStatus,
        identity: &Identity,
    ) -> MessageResult<MessageReceipt> {
        MessageReceipt::new(message_id, status, identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn test_message_id() {
        let id1 = MessageId::new();
        let id2 = MessageId::new();

        assert_ne!(id1, id2);
        assert_eq!(id1.bytes.len(), 16);
    }

    #[test]
    fn test_message_creation_and_signing() {
        let alice = Identity::new("Alice".to_string()).unwrap();
        let bob = Identity::new("Bob".to_string()).unwrap();

        let content = MessageContent::Text {
            text: "Hello, Bob!".to_string(),
            reply_to: None,
        };

        let message = Message::new(
            alice.peer_id.clone(),
            bob.peer_id.clone(),
            content,
            &alice,
        ).unwrap();

        assert_eq!(message.from, alice.peer_id);
        assert_eq!(message.to, bob.peer_id);
        assert!(!message.signature.is_empty());
    }

    #[test]
    fn test_message_verification() {
        let alice = Identity::new("Alice".to_string()).unwrap();
        let bob = Identity::new("Bob".to_string()).unwrap();

        let alice_public = alice.public_info();
        let alice_contact = crate::identity::Contact::from_public_identity(alice_public);

        let content = MessageContent::Text {
            text: "Test message".to_string(),
            reply_to: None,
        };

        let message = Message::new(
            alice.peer_id.clone(),
            bob.peer_id.clone(),
            content,
            &alice,
        ).unwrap();

        // Verify with correct contact
        assert!(message.verify(&alice_contact).unwrap());
    }

    #[test]
    fn test_message_encryption_decryption() {
        let alice = Identity::new("Alice".to_string()).unwrap();
        let bob = Identity::new("Bob".to_string()).unwrap();

        let bob_public = bob.public_info();
        let bob_contact = crate::identity::Contact::from_public_identity(bob_public);

        let alice_public = alice.public_info();
        let alice_contact = crate::identity::Contact::from_public_identity(alice_public);

        let content = MessageContent::Text {
            text: "Secret message".to_string(),
            reply_to: None,
        };

        let message = Message::new(
            alice.peer_id.clone(),
            bob.peer_id.clone(),
            content.clone(),
            &alice,
        ).unwrap();

        // Encrypt
        let envelope = message.encrypt(&bob_contact, &alice).unwrap();

        // Decrypt
        let decrypted = Message::decrypt(&envelope, &alice_contact, &bob).unwrap();

        assert_eq!(message.id, decrypted.id);
        assert_eq!(message.from, decrypted.from);
        assert_eq!(message.to, decrypted.to);
    }

    #[test]
    fn test_message_receipt() {
        let alice = Identity::new("Alice".to_string()).unwrap();
        let alice_public = alice.public_info();
        let alice_contact = crate::identity::Contact::from_public_identity(alice_public);

        let message_id = MessageId::new();

        let receipt = MessageReceipt::new(
            message_id.clone(),
            ReceiptStatus::Received,
            &alice,
        ).unwrap();

        assert_eq!(receipt.message_id, message_id);
        assert_eq!(receipt.status, ReceiptStatus::Received);
        assert!(receipt.verify(&alice_contact).unwrap());
    }

    #[test]
    fn test_message_handler_duplicate_detection() {
        let mut handler = MessageHandler::new();
        let id = MessageId::new();

        assert!(!handler.is_duplicate(&id));

        handler.mark_seen(id.clone()).unwrap();

        assert!(handler.is_duplicate(&id));

        let result = handler.mark_seen(id.clone());
        assert!(result.is_err());
    }

    #[test]
    fn test_p2p_message_serialization() {
        let alice = Identity::new("Alice".to_string()).unwrap();

        let hello = P2PMessage::Hello {
            version: PROTOCOL_VERSION,
            peer_id: alice.peer_id.clone(),
            public_key: alice.keypair.signing_keypair.public_key_bytes(),
            capabilities: vec!["text_messaging".to_string()],
        };

        let bytes = hello.to_bytes().unwrap();
        let deserialized = P2PMessage::from_bytes(&bytes).unwrap();

        match deserialized {
            P2PMessage::Hello { peer_id, .. } => {
                assert_eq!(peer_id, alice.peer_id);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_message_handler_create_and_process() {
        let mut handler = MessageHandler::new();

        let alice = Identity::new("Alice".to_string()).unwrap();
        let bob = Identity::new("Bob".to_string()).unwrap();

        let bob_public = bob.public_info();
        let bob_contact = crate::identity::Contact::from_public_identity(bob_public);

        let alice_public = alice.public_info();
        let alice_contact = crate::identity::Contact::from_public_identity(alice_public);

        let content = MessageContent::Text {
            text: "Hello from Alice!".to_string(),
            reply_to: None,
        };

        // Alice creates message
        let (_message, envelope) = handler.create_message(
            &bob_contact,
            content,
            &alice,
        ).unwrap();

        // Bob processes incoming message
        let mut bob_handler = MessageHandler::new();
        let received_message = bob_handler.process_incoming(
            &envelope,
            &alice_contact,
            &bob,
        ).unwrap();

        assert_eq!(received_message.from, alice.peer_id);
        assert_eq!(received_message.to, bob.peer_id);

        // Try processing again - should fail as duplicate
        let result = bob_handler.process_incoming(
            &envelope,
            &alice_contact,
            &bob,
        );
        assert!(result.is_err());
    }
}
