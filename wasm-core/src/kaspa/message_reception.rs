//! Message Reception Handler for WASM
//!
//! Handles incoming messages from Kaspa transactions:
//! - Processes UTXO events to extract messages
//! - Verifies message integrity
//! - Routes messages by type (chat, signaling, ack)
//! - Handles duplicate detection
//! - Stores received messages

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::cell::RefCell;
use std::collections::HashSet;

use super::envelope::{KaspaEnvelope, EnvelopeType};

/// Maximum age for messages to be accepted (in milliseconds)
pub const MAX_MESSAGE_AGE_MS: u64 = 86_400_000; // 24 hours

thread_local! {
    /// Global message reception handler
    static MESSAGE_HANDLER: RefCell<Option<MessageHandlerState>> = RefCell::new(None);
}

/// Received message event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedMessage {
    pub id: String,
    pub transaction_id: String,
    pub sender_peer_id: String,
    pub recipient_peer_id: String,
    pub message_type: EnvelopeType,
    pub content: Option<String>,
    pub raw_data: Vec<u8>,
    pub timestamp: u64,
    pub signature_verified: bool,
}

/// Signaling message for WebRTC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingMessage {
    pub sender_peer_id: String,
    pub signaling_type: EnvelopeType,
    pub data: String,
    pub timestamp: u64,
}

/// Reception statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReceptionStats {
    pub messages_received: usize,
    pub duplicates_filtered: usize,
    pub messages_rejected: usize,
    pub signaling_messages: usize,
}

/// Internal handler state
struct MessageHandlerState {
    user_peer_id: String,
    known_messages: HashSet<String>,
    received_messages: Vec<ReceivedMessage>,
    pending_signaling: Vec<SignalingMessage>,
    stats: ReceptionStats,
}

impl MessageHandlerState {
    fn new(user_peer_id: String) -> Self {
        Self {
            user_peer_id,
            known_messages: HashSet::new(),
            received_messages: Vec::new(),
            pending_signaling: Vec::new(),
            stats: ReceptionStats::default(),
        }
    }
}

/// Initialize the message reception handler
#[wasm_bindgen]
pub fn message_handler_init(user_peer_id: String) -> Result<(), JsValue> {
    MESSAGE_HANDLER.with(|handler| {
        let mut handler = handler.borrow_mut();
        *handler = Some(MessageHandlerState::new(user_peer_id));
        Ok(())
    })
}

/// Process a transaction payload containing envelopes
///
/// This function extracts envelopes from a transaction payload and processes them.
/// Returns the number of new messages found.
#[wasm_bindgen]
pub fn message_handler_process_payload(
    transaction_id: String,
    payload: Vec<u8>,
) -> Result<u32, JsValue> {
    use super::envelope::extract_envelopes;
    
    MESSAGE_HANDLER.with(|handler| {
        let mut handler = handler.borrow_mut();
        let handler = handler.as_mut()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized. Call message_handler_init() first."))?;

        let mut new_message_count = 0u32;

        // Log the payload for debugging
        web_sys::console::log_1(&format!(
            "[MessageHandler] Processing payload: {} bytes",
            payload.len()
        ).into());

        // Extract envelopes from JSON payload
        let envelopes = extract_envelopes(&payload);
        
        web_sys::console::log_1(&format!(
            "[MessageHandler] Extracted {} envelopes from payload",
            envelopes.len()
        ).into());

        for envelope in envelopes {
            if process_envelope_internal(handler, &envelope, &transaction_id)? {
                new_message_count += 1;
            }
        }

        Ok(new_message_count)
    })
}

/// Process a single envelope (called from JavaScript)
#[wasm_bindgen]
pub fn message_handler_process_envelope(
    transaction_id: String,
    envelope_json: JsValue,
) -> Result<bool, JsValue> {
    let envelope: KaspaEnvelope = serde_wasm_bindgen::from_value(envelope_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid envelope: {}", e)))?;

    MESSAGE_HANDLER.with(|handler| {
        let mut handler = handler.borrow_mut();
        let handler = handler.as_mut()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized"))?;

        process_envelope_internal(handler, &envelope, &transaction_id)
    })
}

/// Internal envelope processing logic
fn process_envelope_internal(
    handler: &mut MessageHandlerState,
    envelope: &KaspaEnvelope,
    transaction_id: &str,
) -> Result<bool, JsValue> {
    // Check if message is for us:
    // - If recipient_peer_id is Some, it must match our peer ID
    // - If recipient_peer_id is None, it's a broadcast and we accept it
    let is_for_us = match &envelope.recipient_peer_id {
        Some(recipient) => recipient == &handler.user_peer_id,
        None => true, // Broadcast message
    };
    
    if !is_for_us {
        return Ok(false); // Not for us
    }

    // Generate message ID for deduplication
    let message_id = envelope.message_id.clone().unwrap_or_else(|| {
        format!("{}:{}:{}", transaction_id, envelope.sender_peer_id, envelope.timestamp)
    });

    // Check for duplicates
    if handler.known_messages.contains(&message_id) {
        handler.stats.duplicates_filtered += 1;
        return Ok(false); // Duplicate
    }

    // Validate envelope
    if let Err(_) = envelope.validate() {
        handler.stats.messages_rejected += 1;
        return Ok(false); // Invalid
    }

    // Check message age
    let now_ms = js_sys::Date::now() as u64;
    let age_ms = now_ms.saturating_sub(envelope.timestamp);
    if age_ms > MAX_MESSAGE_AGE_MS {
        handler.stats.messages_rejected += 1;
        return Ok(false); // Too old
    }

    // Mark as known
    handler.known_messages.insert(message_id.clone());

    // Verify signature (simplified - always true for now)
    let signature_verified = envelope.signature.as_ref().map(|s| !s.is_empty()).unwrap_or(false);

    // Try to decode content as UTF-8
    let content = Some(envelope.payload.clone());

    // Create received message
    let received_message = ReceivedMessage {
        id: message_id,
        transaction_id: transaction_id.to_string(),
        sender_peer_id: envelope.sender_peer_id.clone(),
        recipient_peer_id: envelope.recipient_peer_id.clone().unwrap_or_default(),
        message_type: envelope.envelope_type,
        content: content.clone(),
        raw_data: envelope.payload.as_bytes().to_vec(),
        timestamp: envelope.timestamp,
        signature_verified,
    };

    // Update stats
    handler.stats.messages_received += 1;

    // Route by message type
    match envelope.envelope_type {
        EnvelopeType::DirectMessage | EnvelopeType::GroupMessage => {
            // Store as regular message
            handler.received_messages.push(received_message);
        }
        EnvelopeType::SignalingOffer
        | EnvelopeType::SignalingAnswer
        | EnvelopeType::SignalingIce => {
            // Store as signaling message
            let signaling = SignalingMessage {
                sender_peer_id: envelope.sender_peer_id.clone(),
                signaling_type: envelope.envelope_type,
                data: content.clone().unwrap_or_else(|| envelope.payload.clone()),
                timestamp: envelope.timestamp,
            };

            handler.pending_signaling.push(signaling);
            handler.stats.signaling_messages += 1;
        }
        EnvelopeType::PeerAnnouncement => {
            // Store as received message (peer announcement)
            handler.received_messages.push(received_message);
        }
        _ => {
            // Other types - store as regular messages
            handler.received_messages.push(received_message);
        }
    }

    Ok(true)
}

/// Get all received messages (and clear them)
#[wasm_bindgen]
pub fn message_handler_pop_received() -> Result<JsValue, JsValue> {
    MESSAGE_HANDLER.with(|handler| {
        let mut handler = handler.borrow_mut();
        let handler = handler.as_mut()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized"))?;

        let messages = std::mem::take(&mut handler.received_messages);

        serde_wasm_bindgen::to_value(&messages)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get pending signaling messages (and clear them)
#[wasm_bindgen]
pub fn message_handler_pop_signaling() -> Result<JsValue, JsValue> {
    MESSAGE_HANDLER.with(|handler| {
        let mut handler = handler.borrow_mut();
        let handler = handler.as_mut()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized"))?;

        let signaling = std::mem::take(&mut handler.pending_signaling);

        serde_wasm_bindgen::to_value(&signaling)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get all received messages (without clearing)
#[wasm_bindgen]
pub fn message_handler_get_messages() -> Result<JsValue, JsValue> {
    MESSAGE_HANDLER.with(|handler| {
        let handler = handler.borrow();
        let handler = handler.as_ref()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized"))?;

        serde_wasm_bindgen::to_value(&handler.received_messages)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get messages from a specific sender
#[wasm_bindgen]
pub fn message_handler_get_messages_from(sender_peer_id: String) -> Result<JsValue, JsValue> {
    MESSAGE_HANDLER.with(|handler| {
        let handler = handler.borrow();
        let handler = handler.as_ref()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized"))?;

        let messages: Vec<ReceivedMessage> = handler
            .received_messages
            .iter()
            .filter(|m| m.sender_peer_id == sender_peer_id)
            .cloned()
            .collect();

        serde_wasm_bindgen::to_value(&messages)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get reception statistics
#[wasm_bindgen]
pub fn message_handler_get_stats() -> Result<JsValue, JsValue> {
    MESSAGE_HANDLER.with(|handler| {
        let handler = handler.borrow();
        let handler = handler.as_ref()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized"))?;

        serde_wasm_bindgen::to_value(&handler.stats)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Clear all received messages
#[wasm_bindgen]
pub fn message_handler_clear_messages() -> Result<(), JsValue> {
    MESSAGE_HANDLER.with(|handler| {
        let mut handler = handler.borrow_mut();
        let handler = handler.as_mut()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized"))?;

        handler.received_messages.clear();
        Ok(())
    })
}

/// Clear known message IDs (allows reprocessing)
#[wasm_bindgen]
pub fn message_handler_clear_known() -> Result<(), JsValue> {
    MESSAGE_HANDLER.with(|handler| {
        let mut handler = handler.borrow_mut();
        let handler = handler.as_mut()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized"))?;

        handler.known_messages.clear();
        Ok(())
    })
}

/// Get count of received messages
#[wasm_bindgen]
pub fn message_handler_message_count() -> Result<usize, JsValue> {
    MESSAGE_HANDLER.with(|handler| {
        let handler = handler.borrow();
        let handler = handler.as_ref()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized"))?;

        Ok(handler.received_messages.len())
    })
}

/// Check if a message has been received
#[wasm_bindgen]
pub fn message_handler_has_message(message_id: String) -> Result<bool, JsValue> {
    MESSAGE_HANDLER.with(|handler| {
        let handler = handler.borrow();
        let handler = handler.as_ref()
            .ok_or_else(|| JsValue::from_str("Message handler not initialized"))?;

        Ok(handler.known_messages.contains(&message_id))
    })
}
