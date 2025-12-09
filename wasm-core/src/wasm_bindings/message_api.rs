// Message API for JavaScript
// Provides message creation, encryption, and handling

use wasm_bindgen::prelude::*;
use crate::message::{Message, MessageContent, MessageId};
use crate::identity::{PeerId, Identity, Contact};

/// Create a new text message
/// Note: This creates and signs the message automatically
#[wasm_bindgen]
pub fn create_text_message(
    from_peer_id: String,
    to_peer_id: String,
    text: String,
    reply_to: Option<String>,
    signing_private_key_hex: String,
) -> Result<String, String> {
    // Parse peer IDs
    let from = PeerId::from_hex(&from_peer_id)
        .map_err(|e| format!("Invalid from peer ID: {:?}", e))?;
    let to = PeerId::from_hex(&to_peer_id)
        .map_err(|e| format!("Invalid to peer ID: {:?}", e))?;

    // Parse reply_to if provided
    let reply_to_id = if let Some(id_hex) = reply_to {
        Some(MessageId::from_hex(&id_hex)
            .map_err(|e| format!("Invalid reply_to message ID: {:?}", e))?)
    } else {
        None
    };

    // Create content
    let content = MessageContent::Text {
        text,
        reply_to: reply_to_id,
    };

    // Parse signing key
    let signing_key_bytes = hex::decode(&signing_private_key_hex)
        .map_err(|e| format!("Invalid signing key hex: {}", e))?;

    if signing_key_bytes.len() != 32 {
        return Err("Invalid signing key length".to_string());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&signing_key_bytes);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

    // Create message with inline identity (for signing only)
    use crate::crypto::IdentityKeyPair;
    let keypair = IdentityKeyPair {
        signing_keypair: crate::crypto::Ed25519KeyPair::from_bytes(&key_bytes)
            .map_err(|e| format!("Invalid signing key: {:?}", e))?,
        encryption_keypair: crate::crypto::X25519KeyPair::new()
            .map_err(|e| format!("Failed to create temp encryption key: {:?}", e))?,
    };

    let temp_identity = Identity {
        peer_id: from.clone(),
        display_name: String::new(),  // Not needed for signing
        keypair,
        created_at: 0,  // Not needed for signing
    };

    // Create message (automatically signs it)
    let message = Message::new(from, to, content, &temp_identity)
        .map_err(|e| format!("Failed to create message: {:?}", e))?;

    // Serialize to JSON
    serde_json::to_string(&message)
        .map_err(|e| format!("Failed to serialize message: {}", e))
}

/// Verify message signature using sender's contact
#[wasm_bindgen]
pub fn verify_message_signature(
    message_json: String,
    sender_contact_json: String,
) -> Result<bool, String> {
    let message: Message = serde_json::from_str(&message_json)
        .map_err(|e| format!("Failed to deserialize message: {}", e))?;

    let contact: Contact = serde_json::from_str(&sender_contact_json)
        .map_err(|e| format!("Failed to deserialize contact: {}", e))?;

    match message.verify(&contact) {
        Ok(valid) => Ok(valid),
        Err(e) => Err(format!("Verification failed: {:?}", e)),
    }
}

/// Get message ID
#[wasm_bindgen]
pub fn get_message_id(message_json: String) -> Result<String, String> {
    let message: Message = serde_json::from_str(&message_json)
        .map_err(|e| format!("Failed to deserialize message: {}", e))?;

    Ok(message.id.to_hex())
}

/// Get message text content
#[wasm_bindgen]
pub fn get_message_text(message_json: String) -> Result<String, String> {
    let message: Message = serde_json::from_str(&message_json)
        .map_err(|e| format!("Failed to deserialize message: {}", e))?;

    match message.content {
        MessageContent::Text { text, .. } => Ok(text),
    }
}

/// Check if message is a reply
#[wasm_bindgen]
pub fn is_reply(message_json: String) -> Result<bool, String> {
    let message: Message = serde_json::from_str(&message_json)
        .map_err(|e| format!("Failed to deserialize message: {}", e))?;

    match message.content {
        MessageContent::Text { reply_to, .. } => Ok(reply_to.is_some()),
    }
}

/// Get message timestamp
#[wasm_bindgen]
pub fn get_message_timestamp(message_json: String) -> Result<f64, String> {
    let message: Message = serde_json::from_str(&message_json)
        .map_err(|e| format!("Failed to deserialize message: {}", e))?;

    Ok(message.timestamp as f64)
}

/// Validate message (check size, timestamp, etc.)
#[wasm_bindgen]
pub fn validate_message(message_json: String) -> Result<bool, String> {
    let message: Message = serde_json::from_str(&message_json)
        .map_err(|e| format!("Failed to deserialize message: {}", e))?;

    match message.validate() {
        Ok(_) => Ok(true),
        Err(e) => Err(format!("Message validation failed: {:?}", e)),
    }
}
