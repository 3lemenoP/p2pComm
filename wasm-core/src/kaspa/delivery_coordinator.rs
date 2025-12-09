//! Delivery Coordinator for WASM
//!
//! Provides intelligent message delivery:
//! - Batches multiple messages to save fees
//! - Smart delivery based on message priority
//! - Configurable batching strategy
//! - Statistics tracking

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::cell::RefCell;
use std::collections::HashMap;

use super::payload::{QueuedMessage, MessagePriority};

/// Maximum number of messages to batch in a single transaction
pub const MAX_BATCH_SIZE: usize = 10;

/// Maximum wait time for batching (milliseconds)
pub const MAX_BATCH_WAIT_MS: u64 = 30_000; // 30 seconds

/// Maximum payload size for Kaspa transactions (bytes)
pub const MAX_PAYLOAD_SIZE: usize = 98_000;

thread_local! {
    /// Global delivery coordinator
    static DELIVERY_COORDINATOR: RefCell<Option<DeliveryCoordinatorState>> = RefCell::new(None);
}

/// Delivery mode configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryMode {
    /// Send messages immediately as they come
    Immediate,
    /// Batch messages together to save fees
    Batched,
    /// Smart mode: batch when economical, immediate when urgent
    Smart,
}

/// Batching strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchingStrategy {
    pub mode: DeliveryMode,
    pub max_batch_size: usize,
    pub max_wait_ms: u64,
}

impl Default for BatchingStrategy {
    fn default() -> Self {
        Self {
            mode: DeliveryMode::Smart,
            max_batch_size: MAX_BATCH_SIZE,
            max_wait_ms: MAX_BATCH_WAIT_MS,
        }
    }
}

/// Delivery batch ready for sending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryBatch {
    pub batch_id: String,
    pub messages: Vec<QueuedMessage>,
    pub recipient: String,
    pub total_size: usize,
    pub created_at: u64, // timestamp in ms
}

impl DeliveryBatch {
    fn new(recipient: String) -> Self {
        let batch_id = format!("batch_{}", js_sys::Date::now() as u64);
        Self {
            batch_id,
            messages: Vec::new(),
            recipient,
            total_size: 0,
            created_at: js_sys::Date::now() as u64,
        }
    }

    fn add_message(&mut self, message: QueuedMessage) {
        self.total_size += message.envelope.payload.len();
        self.messages.push(message);
    }

    fn can_add_message(&self, message_size: usize) -> bool {
        self.total_size + message_size <= MAX_PAYLOAD_SIZE
    }

    fn has_waited_too_long(&self, max_wait_ms: u64) -> bool {
        let now = js_sys::Date::now() as u64;
        now - self.created_at > max_wait_ms
    }

    fn age_ms(&self) -> u64 {
        let now = js_sys::Date::now() as u64;
        now.saturating_sub(self.created_at)
    }
}

/// Delivery statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeliveryStats {
    pub messages_sent: usize,
    pub batches_sent: usize,
    pub transactions_created: usize,
    pub total_fees_paid: u64,
    pub fees_saved_by_batching: u64,
    pub failed_deliveries: usize,
}

/// Internal coordinator state
struct DeliveryCoordinatorState {
    strategy: BatchingStrategy,
    pending_batches: HashMap<String, DeliveryBatch>,
    ready_batches: Vec<DeliveryBatch>,
    stats: DeliveryStats,
}

impl DeliveryCoordinatorState {
    fn new(strategy: BatchingStrategy) -> Self {
        Self {
            strategy,
            pending_batches: HashMap::new(),
            ready_batches: Vec::new(),
            stats: DeliveryStats::default(),
        }
    }
}

/// Initialize the delivery coordinator
#[wasm_bindgen]
pub fn delivery_coordinator_init(strategy_json: JsValue) -> Result<(), JsValue> {
    let strategy = if strategy_json.is_undefined() || strategy_json.is_null() {
        BatchingStrategy::default()
    } else {
        serde_wasm_bindgen::from_value(strategy_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid strategy: {}", e)))?
    };

    DELIVERY_COORDINATOR.with(|coord| {
        let mut coord = coord.borrow_mut();
        *coord = Some(DeliveryCoordinatorState::new(strategy));
        Ok(())
    })
}

/// Queue a message for delivery
///
/// The message will be added to a batch or sent immediately based on the delivery mode.
/// Returns the batch ID if the message was batched, or null if it's ready to send immediately.
#[wasm_bindgen]
pub fn delivery_coordinator_queue_message(message_json: JsValue) -> Result<JsValue, JsValue> {
    let message: QueuedMessage = serde_wasm_bindgen::from_value(message_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid message: {}", e)))?;

    DELIVERY_COORDINATOR.with(|coord| {
        let mut coord = coord.borrow_mut();
        let coord = coord.as_mut()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized. Call delivery_coordinator_init() first."))?;

        let recipient = message.recipient_peer_id.clone();
        let priority = message.priority;
        let size = message.envelope.payload.len();

        match coord.strategy.mode {
            DeliveryMode::Immediate => {
                // Send immediately - create single-message batch
                let mut batch = DeliveryBatch::new(recipient);
                batch.add_message(message);
                coord.ready_batches.push(batch);
                Ok(JsValue::NULL)
            }
            DeliveryMode::Batched => {
                // Always batch - add to pending batch
                add_to_batch(coord, message, recipient, size)
            }
            DeliveryMode::Smart => {
                // Smart: immediate for high priority, batch for normal/low
                if priority >= MessagePriority::High {
                    let mut batch = DeliveryBatch::new(recipient);
                    batch.add_message(message);
                    coord.ready_batches.push(batch);
                    Ok(JsValue::NULL)
                } else {
                    add_to_batch(coord, message, recipient, size)
                }
            }
        }
    })
}

/// Helper function to add message to a batch
fn add_to_batch(
    coord: &mut DeliveryCoordinatorState,
    message: QueuedMessage,
    recipient: String,
    size: usize,
) -> Result<JsValue, JsValue> {
    let batch = coord.pending_batches
        .entry(recipient.clone())
        .or_insert_with(|| DeliveryBatch::new(recipient));

    // Check if batch is full
    if !batch.can_add_message(size) || batch.messages.len() >= coord.strategy.max_batch_size {
        // Finalize this batch and create a new one
        let full_batch = coord.pending_batches.remove(&message.recipient_peer_id).unwrap();
        coord.ready_batches.push(full_batch);

        // Create new batch for this message
        let mut new_batch = DeliveryBatch::new(message.recipient_peer_id.clone());
        new_batch.add_message(message);
        coord.pending_batches.insert(new_batch.recipient.clone(), new_batch.clone());

        serde_wasm_bindgen::to_value(&new_batch.batch_id)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    } else {
        // Add to existing batch
        batch.add_message(message);

        serde_wasm_bindgen::to_value(&batch.batch_id)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}

/// Process pending batches and finalize those that have waited too long
///
/// Call this periodically (e.g., every second) to check for batches that should be sent.
#[wasm_bindgen]
pub fn delivery_coordinator_process_waiting_batches() -> Result<u32, JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let mut coord = coord.borrow_mut();
        let coord = coord.as_mut()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        let mut finalized_count = 0;
        let max_wait_ms = coord.strategy.max_wait_ms;
        let mut to_finalize = Vec::new();

        for (recipient, batch) in &coord.pending_batches {
            if batch.has_waited_too_long(max_wait_ms) {
                to_finalize.push(recipient.clone());
            }
        }

        for recipient in to_finalize {
            if let Some(batch) = coord.pending_batches.remove(&recipient) {
                coord.ready_batches.push(batch);
                finalized_count += 1;
            }
        }

        Ok(finalized_count)
    })
}

/// Get ready batches for sending
///
/// Returns an array of batches that are ready to be sent and clears them from the queue.
#[wasm_bindgen]
pub fn delivery_coordinator_get_ready_batches() -> Result<JsValue, JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let mut coord = coord.borrow_mut();
        let coord = coord.as_mut()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        let batches = std::mem::take(&mut coord.ready_batches);

        serde_wasm_bindgen::to_value(&batches)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Force flush a specific batch by recipient
#[wasm_bindgen]
pub fn delivery_coordinator_flush_batch(recipient: String) -> Result<JsValue, JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let mut coord = coord.borrow_mut();
        let coord = coord.as_mut()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        if let Some(batch) = coord.pending_batches.remove(&recipient) {
            coord.ready_batches.push(batch.clone());

            serde_wasm_bindgen::to_value(&batch)
                .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
        } else {
            Ok(JsValue::NULL)
        }
    })
}

/// Force flush all pending batches
#[wasm_bindgen]
pub fn delivery_coordinator_flush_all() -> Result<u32, JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let mut coord = coord.borrow_mut();
        let coord = coord.as_mut()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        let count = coord.pending_batches.len() as u32;

        for (_, batch) in coord.pending_batches.drain() {
            coord.ready_batches.push(batch);
        }

        Ok(count)
    })
}

/// Record a successful delivery
#[wasm_bindgen]
pub fn delivery_coordinator_record_success(
    batch_id: String,
    fee_paid: u64,
) -> Result<(), JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let mut coord = coord.borrow_mut();
        let coord = coord.as_mut()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        coord.stats.transactions_created += 1;
        coord.stats.batches_sent += 1;
        coord.stats.total_fees_paid += fee_paid;

        Ok(())
    })
}

/// Record a failed delivery
#[wasm_bindgen]
pub fn delivery_coordinator_record_failure() -> Result<(), JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let mut coord = coord.borrow_mut();
        let coord = coord.as_mut()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        coord.stats.failed_deliveries += 1;

        Ok(())
    })
}

/// Get delivery statistics
#[wasm_bindgen]
pub fn delivery_coordinator_get_stats() -> Result<JsValue, JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let coord = coord.borrow();
        let coord = coord.as_ref()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        serde_wasm_bindgen::to_value(&coord.stats)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get number of pending batches
#[wasm_bindgen]
pub fn delivery_coordinator_pending_count() -> Result<usize, JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let coord = coord.borrow();
        let coord = coord.as_ref()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        Ok(coord.pending_batches.len())
    })
}

/// Get number of ready batches
#[wasm_bindgen]
pub fn delivery_coordinator_ready_count() -> Result<usize, JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let coord = coord.borrow();
        let coord = coord.as_ref()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        Ok(coord.ready_batches.len())
    })
}

/// Clear all pending batches
#[wasm_bindgen]
pub fn delivery_coordinator_clear_pending() -> Result<(), JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let mut coord = coord.borrow_mut();
        let coord = coord.as_mut()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        coord.pending_batches.clear();
        Ok(())
    })
}

/// Get information about pending batches
#[wasm_bindgen]
pub fn delivery_coordinator_get_pending_info() -> Result<JsValue, JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let coord = coord.borrow();
        let coord = coord.as_ref()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        let batches: Vec<&DeliveryBatch> = coord.pending_batches.values().collect();

        serde_wasm_bindgen::to_value(&batches)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

// ============================================================================
// Internal Rust API (for use from Rust code, not exposed to WASM)
// ============================================================================

/// Internal Rust API: Queue a message for delivery
///
/// This is meant to be called from Rust code (like NetworkManager) without
/// going through the WASM boundary. Returns true if the message was batched,
/// false if it's ready to send immediately.
pub fn queue_message_internal(message: QueuedMessage) -> Result<bool, String> {
    DELIVERY_COORDINATOR.with(|coord| {
        let mut coord = coord.borrow_mut();
        let coord = coord.as_mut()
            .ok_or_else(|| "Delivery coordinator not initialized. Call delivery_coordinator_init() first.".to_string())?;

        let recipient = message.recipient_peer_id.clone();
        let priority = message.priority;
        let size = message.envelope.payload.len();

        match coord.strategy.mode {
            DeliveryMode::Immediate => {
                // Send immediately - create single-message batch
                let mut batch = DeliveryBatch::new(recipient);
                batch.add_message(message);
                coord.ready_batches.push(batch);
                Ok(false) // Not batched, ready immediately
            }
            DeliveryMode::Batched => {
                // Always batch - add to pending batch
                add_to_batch_internal(coord, message, recipient, size)?;
                Ok(true) // Batched
            }
            DeliveryMode::Smart => {
                // Smart: immediate for high priority, batch for normal/low
                if priority >= MessagePriority::High {
                    let mut batch = DeliveryBatch::new(recipient);
                    batch.add_message(message);
                    coord.ready_batches.push(batch);
                    Ok(false) // Not batched, ready immediately
                } else {
                    add_to_batch_internal(coord, message, recipient, size)?;
                    Ok(true) // Batched
                }
            }
        }
    })
}

/// Helper function for internal batching
fn add_to_batch_internal(
    coord: &mut DeliveryCoordinatorState,
    message: QueuedMessage,
    recipient: String,
    size: usize,
) -> Result<(), String> {
    let batch = coord.pending_batches
        .entry(recipient.clone())
        .or_insert_with(|| DeliveryBatch::new(recipient));

    // Check if batch is full
    if !batch.can_add_message(size) || batch.messages.len() >= coord.strategy.max_batch_size {
        // Finalize this batch and create a new one
        let full_batch = coord.pending_batches.remove(&message.recipient_peer_id).unwrap();
        coord.ready_batches.push(full_batch);

        // Create new batch for this message
        let mut new_batch = DeliveryBatch::new(message.recipient_peer_id.clone());
        new_batch.add_message(message);
        coord.pending_batches.insert(new_batch.recipient.clone(), new_batch);
    } else {
        // Add to existing batch
        batch.add_message(message);
    }

    Ok(())
}

/// Internal Rust API: Check if coordinator is initialized
pub fn is_initialized() -> bool {
    DELIVERY_COORDINATOR.with(|coord| {
        coord.borrow().is_some()
    })
}

// ============================================================================
// Simplified WASM API for JavaScript Integration
// ============================================================================

/// Queue a simple direct message for delivery (convenience function)
///
/// This is a simplified API that creates the envelope internally.
/// Use this instead of `delivery_coordinator_queue_message` when you have
/// simple string payloads and don't need to construct envelopes manually.
///
/// # Arguments
/// * `sender_peer_id` - The local peer ID
/// * `recipient_peer_id` - The target peer ID
/// * `payload_json` - The message payload as JSON string
/// * `immediate` - If true, sends with High priority (bypasses batching)
///
/// # Returns
/// The message ID for tracking delivery status
#[wasm_bindgen]
pub fn delivery_coordinator_queue_direct_message(
    sender_peer_id: String,
    recipient_peer_id: String,
    payload_json: String,
    immediate: bool,
) -> Result<String, JsValue> {
    use super::envelope::KaspaEnvelope;

    // Create the envelope
    let envelope = KaspaEnvelope::direct_message(
        sender_peer_id,
        recipient_peer_id.clone(),
        payload_json,
    );

    // Create queued message with appropriate priority
    let priority = if immediate { MessagePriority::High } else { MessagePriority::Normal };
    let message = QueuedMessage::new(recipient_peer_id, envelope, priority);
    let message_id = message.id.clone();

    // Queue it via the existing infrastructure
    let message_json = serde_wasm_bindgen::to_value(&message)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    delivery_coordinator_queue_message(message_json)?;

    Ok(message_id)
}

/// Queue a signaling message for delivery (for WebRTC signaling via blockchain)
///
/// # Arguments
/// * `sender_peer_id` - The local peer ID
/// * `recipient_peer_id` - The target peer ID
/// * `signaling_type` - The signaling type (3=Offer, 4=Answer, 5=ICE)
/// * `payload_json` - The signaling payload as JSON string
///
/// # Returns
/// The message ID for tracking delivery status
#[wasm_bindgen]
pub fn delivery_coordinator_queue_signaling(
    sender_peer_id: String,
    recipient_peer_id: String,
    signaling_type: u8,
    payload_json: String,
) -> Result<String, JsValue> {
    use super::envelope::{KaspaEnvelope, EnvelopeType};

    // Convert signaling type
    let envelope_type = match signaling_type {
        3 => EnvelopeType::SignalingOffer,
        4 => EnvelopeType::SignalingAnswer,
        5 => EnvelopeType::SignalingIce,
        _ => return Err(JsValue::from_str(&format!("Invalid signaling type: {}", signaling_type))),
    };

    // Create the envelope
    let envelope = KaspaEnvelope::signaling(
        sender_peer_id,
        recipient_peer_id.clone(),
        envelope_type,
        payload_json,
    );

    // Signaling is always high priority (immediate)
    let message = QueuedMessage::new(recipient_peer_id, envelope, MessagePriority::High);
    let message_id = message.id.clone();

    // Queue it
    let message_json = serde_wasm_bindgen::to_value(&message)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    delivery_coordinator_queue_message(message_json)?;

    Ok(message_id)
}

/// Queue a peer announcement for broadcast
///
/// # Arguments
/// * `sender_peer_id` - The local peer ID
/// * `payload_json` - The announcement payload as JSON string
///
/// # Returns
/// The message ID for tracking delivery status
#[wasm_bindgen]
pub fn delivery_coordinator_queue_announcement(
    sender_peer_id: String,
    payload_json: String,
) -> Result<String, JsValue> {
    use super::envelope::KaspaEnvelope;

    // Create the announcement envelope (no recipient, broadcast)
    let envelope = KaspaEnvelope::peer_announcement(
        sender_peer_id.clone(),
        payload_json,
    );

    // Announcements are high priority
    let message = QueuedMessage::new(sender_peer_id, envelope, MessagePriority::High);
    let message_id = message.id.clone();

    // Queue it
    let message_json = serde_wasm_bindgen::to_value(&message)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    delivery_coordinator_queue_message(message_json)?;

    Ok(message_id)
}

/// Get delivery status for a message
///
/// # Returns
/// JSON object with status info, or null if not found
#[wasm_bindgen]
pub fn delivery_coordinator_get_message_status(message_id: String) -> Result<JsValue, JsValue> {
    DELIVERY_COORDINATOR.with(|coord| {
        let coord = coord.borrow();
        let coord = coord.as_ref()
            .ok_or_else(|| JsValue::from_str("Delivery coordinator not initialized"))?;

        // Check ready batches
        for batch in &coord.ready_batches {
            for msg in &batch.messages {
                if msg.id == message_id {
                    let status = serde_json::json!({
                        "status": "ready",
                        "batch_id": batch.batch_id,
                        "created_at": msg.created_at
                    });
                    return serde_wasm_bindgen::to_value(&status)
                        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)));
                }
            }
        }

        // Check pending batches
        for (_, batch) in &coord.pending_batches {
            for msg in &batch.messages {
                if msg.id == message_id {
                    let status = serde_json::json!({
                        "status": "pending",
                        "batch_id": batch.batch_id,
                        "batch_age_ms": batch.age_ms(),
                        "created_at": msg.created_at
                    });
                    return serde_wasm_bindgen::to_value(&status)
                        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)));
                }
            }
        }

        Ok(JsValue::NULL)
    })
}
