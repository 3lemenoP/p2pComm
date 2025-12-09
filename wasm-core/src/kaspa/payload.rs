//! Payload Management for Kaspa Blockchain Messaging
//!
//! Handles message queuing, batching, and delivery tracking
//! for blockchain-based message delivery.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use std::collections::{HashMap, VecDeque};
use crate::kaspa::envelope::{KaspaEnvelope, EnvelopeType};
use crate::kaspa::types::{MAX_PAYLOAD_SIZE, KaspaError, KaspaResult, KaspaErrorKind, generate_message_id, current_timestamp_ms};

/// Maximum messages in queue
pub const MAX_QUEUE_SIZE: usize = 1000;

/// Maximum retry attempts
pub const MAX_RETRIES: u32 = 3;

/// Message priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[wasm_bindgen]
pub enum MessagePriority {
    /// Low priority, can be batched
    Low = 0,
    /// Normal priority
    Normal = 1,
    /// High priority, send immediately
    High = 2,
    /// Critical, skip batching
    Critical = 3,
}

impl Default for MessagePriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Status of a queued message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[wasm_bindgen]
pub enum MessageStatus {
    /// Waiting to be sent
    Pending,
    /// Currently being processed
    Processing,
    /// Successfully sent
    Sent,
    /// Confirmed on blockchain
    Confirmed,
    /// Send failed
    Failed,
    /// Acknowledged by recipient
    Acknowledged,
}

/// A message waiting to be sent via blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct QueuedMessage {
    /// Unique message identifier
    pub id: String,
    /// Recipient peer ID
    pub recipient_peer_id: String,
    /// Message envelope
    pub envelope: KaspaEnvelope,
    /// Current status
    pub status: MessageStatus,
    /// Priority level
    pub priority: MessagePriority,
    /// Creation timestamp
    pub created_at: u64,
    /// Last status update timestamp
    pub updated_at: u64,
    /// Retry count
    pub retry_count: u32,
    /// Transaction ID (if sent)
    pub transaction_id: Option<String>,
}

#[wasm_bindgen]
impl QueuedMessage {
    /// Check if message should be retried
    pub fn should_retry(&self) -> bool {
        self.status == MessageStatus::Failed && self.retry_count < MAX_RETRIES
    }

    /// Get payload size
    pub fn payload_size(&self) -> usize {
        self.envelope.payload.len()
    }
}

impl QueuedMessage {
    /// Create a new queued message
    pub fn new(recipient_peer_id: String, envelope: KaspaEnvelope, priority: MessagePriority) -> Self {
        let now = current_timestamp_ms();
        Self {
            id: generate_message_id(),
            recipient_peer_id,
            envelope,
            status: MessageStatus::Pending,
            priority,
            created_at: now,
            updated_at: now,
            retry_count: 0,
            transaction_id: None,
        }
    }

    /// Mark as processing
    pub fn mark_processing(&mut self) {
        self.status = MessageStatus::Processing;
        self.updated_at = current_timestamp_ms();
    }

    /// Mark as sent
    pub fn mark_sent(&mut self, transaction_id: String) {
        self.status = MessageStatus::Sent;
        self.transaction_id = Some(transaction_id);
        self.updated_at = current_timestamp_ms();
    }

    /// Mark as confirmed
    pub fn mark_confirmed(&mut self) {
        self.status = MessageStatus::Confirmed;
        self.updated_at = current_timestamp_ms();
    }

    /// Mark as failed
    pub fn mark_failed(&mut self) {
        self.status = MessageStatus::Failed;
        self.retry_count += 1;
        self.updated_at = current_timestamp_ms();
    }

    /// Mark as acknowledged
    pub fn mark_acknowledged(&mut self) {
        self.status = MessageStatus::Acknowledged;
        self.updated_at = current_timestamp_ms();
    }

    /// Reset for retry
    pub fn reset_for_retry(&mut self) {
        self.status = MessageStatus::Pending;
        self.transaction_id = None;
        self.updated_at = current_timestamp_ms();
    }
}

/// Queue statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct QueueStats {
    pub total_queued: u32,
    pub pending_count: u32,
    pub sent_count: u32,
    pub confirmed_count: u32,
    pub failed_count: u32,
    pub acknowledged_count: u32,
    pub bytes_queued: u64,
    pub bytes_sent: u64,
}

/// Message queue for outgoing blockchain messages
#[wasm_bindgen]
pub struct MessageQueue {
    /// Sender peer ID
    local_peer_id: String,
    /// Messages by ID
    messages: HashMap<String, QueuedMessage>,
    /// Queue ordered by priority and time
    queue_order: VecDeque<String>,
    /// Maximum queue size
    max_size: usize,
    /// Statistics
    stats: QueueStats,
}

#[wasm_bindgen]
impl MessageQueue {
    /// Create a new message queue
    #[wasm_bindgen(constructor)]
    pub fn new(local_peer_id: String) -> Self {
        Self {
            local_peer_id,
            messages: HashMap::new(),
            queue_order: VecDeque::new(),
            max_size: MAX_QUEUE_SIZE,
            stats: QueueStats::default(),
        }
    }

    /// Get queue size
    pub fn size(&self) -> usize {
        self.messages.len()
    }

    /// Get pending count
    pub fn pending_count(&self) -> usize {
        self.messages
            .values()
            .filter(|m| m.status == MessageStatus::Pending)
            .count()
    }

    /// Get statistics
    pub fn get_stats(&self) -> QueueStats {
        self.stats.clone()
    }

    /// Check if queue is full
    pub fn is_full(&self) -> bool {
        self.messages.len() >= self.max_size
    }
}

impl MessageQueue {
    /// Queue a direct message
    pub fn queue_direct_message(
        &mut self,
        recipient: String,
        content: String,
        priority: MessagePriority,
    ) -> KaspaResult<String> {
        let envelope = KaspaEnvelope::direct_message(
            self.local_peer_id.clone(),
            recipient.clone(),
            content,
        );
        self.queue_envelope(recipient, envelope, priority)
    }

    /// Queue a signaling message
    pub fn queue_signaling(
        &mut self,
        recipient: String,
        signaling_type: EnvelopeType,
        data: String,
        priority: MessagePriority,
    ) -> KaspaResult<String> {
        let envelope = KaspaEnvelope::signaling(
            self.local_peer_id.clone(),
            recipient.clone(),
            signaling_type,
            data,
        );
        self.queue_envelope(recipient, envelope, priority)
    }

    /// Queue an envelope
    pub fn queue_envelope(
        &mut self,
        recipient: String,
        envelope: KaspaEnvelope,
        priority: MessagePriority,
    ) -> KaspaResult<String> {
        // Check size
        if self.is_full() {
            return Err(KaspaError::new(
                KaspaErrorKind::QueueFull,
                "Message queue is full",
            ));
        }

        let payload_size = envelope.payload.len();
        if payload_size > MAX_PAYLOAD_SIZE {
            return Err(KaspaError::payload_too_large(payload_size));
        }

        let message = QueuedMessage::new(recipient, envelope, priority);
        let id = message.id.clone();

        // Update stats
        self.stats.total_queued += 1;
        self.stats.pending_count += 1;
        self.stats.bytes_queued += payload_size as u64;

        // Insert into priority position
        self.insert_by_priority(&id, priority);
        self.messages.insert(id.clone(), message);

        Ok(id)
    }

    /// Insert message ID at correct priority position
    fn insert_by_priority(&mut self, id: &str, priority: MessagePriority) {
        // Higher priority goes to front
        if priority >= MessagePriority::High {
            self.queue_order.push_front(id.to_string());
        } else {
            self.queue_order.push_back(id.to_string());
        }
    }

    /// Get next message to send
    pub fn get_next(&mut self) -> Option<&QueuedMessage> {
        // Find first pending message
        for id in &self.queue_order {
            if let Some(msg) = self.messages.get(id) {
                if msg.status == MessageStatus::Pending {
                    return Some(msg);
                }
            }
        }
        None
    }

    /// Take next message to send (marks as processing)
    pub fn take_next(&mut self) -> Option<QueuedMessage> {
        // Find first pending message
        for id in &self.queue_order {
            if let Some(msg) = self.messages.get(id) {
                if msg.status == MessageStatus::Pending {
                    let msg = self.messages.get_mut(id).unwrap();
                    msg.mark_processing();
                    self.stats.pending_count = self.stats.pending_count.saturating_sub(1);
                    return Some(msg.clone());
                }
            }
        }
        None
    }

    /// Get message by ID
    pub fn get(&self, id: &str) -> Option<&QueuedMessage> {
        self.messages.get(id)
    }

    /// Mark message as sent
    pub fn mark_sent(&mut self, id: &str, transaction_id: String) -> KaspaResult<()> {
        if let Some(msg) = self.messages.get_mut(id) {
            let size = msg.payload_size();
            msg.mark_sent(transaction_id);
            self.stats.sent_count += 1;
            self.stats.bytes_sent += size as u64;
            Ok(())
        } else {
            Err(KaspaError::new(KaspaErrorKind::PeerNotFound, "Message not found"))
        }
    }

    /// Mark message as confirmed
    pub fn mark_confirmed(&mut self, id: &str) -> KaspaResult<()> {
        if let Some(msg) = self.messages.get_mut(id) {
            msg.mark_confirmed();
            self.stats.confirmed_count += 1;
            Ok(())
        } else {
            Err(KaspaError::new(KaspaErrorKind::PeerNotFound, "Message not found"))
        }
    }

    /// Mark message as failed
    pub fn mark_failed(&mut self, id: &str) -> KaspaResult<()> {
        if let Some(msg) = self.messages.get_mut(id) {
            msg.mark_failed();
            self.stats.failed_count += 1;

            // Re-queue for retry if possible
            if msg.should_retry() {
                msg.reset_for_retry();
                self.stats.pending_count += 1;
            }
            Ok(())
        } else {
            Err(KaspaError::new(KaspaErrorKind::PeerNotFound, "Message not found"))
        }
    }

    /// Mark message as acknowledged
    pub fn mark_acknowledged(&mut self, id: &str) -> KaspaResult<()> {
        if let Some(msg) = self.messages.get_mut(id) {
            msg.mark_acknowledged();
            self.stats.acknowledged_count += 1;
            Ok(())
        } else {
            Err(KaspaError::new(KaspaErrorKind::PeerNotFound, "Message not found"))
        }
    }

    /// Get messages for recipient
    pub fn get_for_recipient(&self, recipient: &str) -> Vec<&QueuedMessage> {
        self.messages
            .values()
            .filter(|m| m.recipient_peer_id == recipient)
            .collect()
    }

    /// Get pending messages by priority
    pub fn get_pending_by_priority(&self, priority: MessagePriority) -> Vec<&QueuedMessage> {
        self.messages
            .values()
            .filter(|m| m.status == MessageStatus::Pending && m.priority == priority)
            .collect()
    }

    /// Remove completed messages
    pub fn cleanup_completed(&mut self) {
        let to_remove: Vec<String> = self.messages
            .iter()
            .filter(|(_, m)| {
                matches!(m.status, MessageStatus::Acknowledged | MessageStatus::Confirmed)
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in to_remove {
            self.messages.remove(&id);
            self.queue_order.retain(|i| i != &id);
        }
    }

    /// Remove old failed messages
    pub fn cleanup_old_failed(&mut self, max_age_ms: u64) {
        let now = current_timestamp_ms();
        let threshold = now.saturating_sub(max_age_ms);

        let to_remove: Vec<String> = self.messages
            .iter()
            .filter(|(_, m)| {
                m.status == MessageStatus::Failed && m.updated_at < threshold
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in to_remove {
            self.messages.remove(&id);
            self.queue_order.retain(|i| i != &id);
        }
    }

    /// Clear all messages
    pub fn clear(&mut self) {
        self.messages.clear();
        self.queue_order.clear();
        self.stats = QueueStats::default();
    }
}

/// Batch multiple messages for fee efficiency
#[derive(Debug, Clone)]
pub struct MessageBatch {
    /// Messages in the batch
    pub messages: Vec<QueuedMessage>,
    /// Target recipient (if single recipient batch)
    pub recipient: Option<String>,
    /// Total payload size
    pub total_size: usize,
    /// Creation time
    pub created_at: u64,
}

impl MessageBatch {
    /// Create a new batch
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            recipient: None,
            total_size: 0,
            created_at: current_timestamp_ms(),
        }
    }

    /// Add message to batch
    pub fn add(&mut self, message: QueuedMessage) -> bool {
        let msg_size = message.payload_size();

        // Check if batch would exceed size limit
        if self.total_size + msg_size > MAX_PAYLOAD_SIZE {
            return false;
        }

        // Check if recipient matches (for single-recipient batches)
        if let Some(ref recipient) = self.recipient {
            if &message.recipient_peer_id != recipient {
                return false;
            }
        } else if !self.messages.is_empty() {
            self.recipient = Some(message.recipient_peer_id.clone());
        }

        self.total_size += msg_size;
        self.messages.push(message);
        true
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Get message count
    pub fn count(&self) -> usize {
        self.messages.len()
    }

    /// Combine envelopes into single payload
    pub fn combine_payloads(&self) -> Vec<u8> {
        let mut combined = Vec::new();
        let separator = b"\n---\n";

        for (i, msg) in self.messages.iter().enumerate() {
            if i > 0 {
                combined.extend_from_slice(separator);
            }
            if let Ok(bytes) = msg.envelope.to_bytes() {
                combined.extend(bytes);
            }
        }

        combined
    }
}

impl Default for MessageBatch {
    fn default() -> Self {
        Self::new()
    }
}
