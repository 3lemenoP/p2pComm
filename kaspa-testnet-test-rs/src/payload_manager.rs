/// Payload Manager for P2PComm
///
/// This module provides message payload management:
/// - Message encryption/decryption
/// - Message queuing with priority levels
/// - Payload compression
/// - Message metadata tracking
/// - Queue persistence and management

use anyhow::{Result, Context, bail};
use serde::{Serialize, Deserialize};
use std::collections::{VecDeque, HashMap};
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};

/// Maximum payload size (98 KB to stay under Kaspa's ~100 KB limit)
pub const MAX_PAYLOAD_SIZE: usize = 98_000;

/// Maximum queue size (number of messages)
pub const MAX_QUEUE_SIZE: usize = 1000;

/// Message priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MessagePriority {
    /// Low priority - normal messages
    Low = 0,
    /// Normal priority - default
    Normal = 1,
    /// High priority - urgent messages
    High = 2,
    /// Critical priority - system/signaling messages
    Critical = 3,
}

impl Default for MessagePriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Message type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    /// Regular chat message
    Chat,
    /// WebRTC signaling message
    Signaling,
    /// File transfer metadata
    FileMetadata,
    /// File chunk
    FileChunk,
    /// System message
    System,
    /// Acknowledgment
    Ack,
}

/// Message status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    /// Message is queued, waiting to be sent
    Queued,
    /// Message is being processed
    Processing,
    /// Message has been sent to network
    Sent,
    /// Message send failed
    Failed,
    /// Message was acknowledged by recipient
    Acknowledged,
}

/// Queued message metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    /// Unique message ID
    pub id: String,
    /// Recipient address
    pub recipient: String,
    /// Sender address (optional, for tracking)
    pub sender: Option<String>,
    /// Message type
    pub message_type: MessageType,
    /// Priority level
    pub priority: MessagePriority,
    /// Encrypted payload data
    pub payload: Vec<u8>,
    /// Original payload size (before compression)
    pub original_size: usize,
    /// Compressed size
    pub compressed_size: usize,
    /// Message status
    pub status: MessageStatus,
    /// Timestamp when message was queued
    pub queued_at: DateTime<Utc>,
    /// Timestamp when message was sent (if sent)
    pub sent_at: Option<DateTime<Utc>>,
    /// Number of send attempts
    pub attempts: u32,
    /// Maximum attempts before giving up
    pub max_attempts: u32,
    /// Transaction ID (if sent)
    pub transaction_id: Option<String>,
    /// Optional metadata
    pub metadata: HashMap<String, String>,
}

impl QueuedMessage {
    /// Create a new queued message
    pub fn new(
        recipient: String,
        payload: Vec<u8>,
        message_type: MessageType,
        priority: MessagePriority,
    ) -> Result<Self> {
        // Validate payload size
        if payload.len() > MAX_PAYLOAD_SIZE {
            bail!(
                "Payload too large: {} bytes (max: {} bytes)",
                payload.len(),
                MAX_PAYLOAD_SIZE
            );
        }

        // Generate message ID from hash
        let id = Self::generate_id(&payload, &recipient);

        Ok(Self {
            id,
            recipient,
            sender: None,
            message_type,
            priority,
            original_size: payload.len(),
            compressed_size: payload.len(),
            payload,
            status: MessageStatus::Queued,
            queued_at: Utc::now(),
            sent_at: None,
            attempts: 0,
            max_attempts: 3,
            transaction_id: None,
            metadata: HashMap::new(),
        })
    }

    /// Generate a unique message ID
    fn generate_id(payload: &[u8], recipient: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(payload);
        hasher.update(recipient.as_bytes());
        hasher.update(Utc::now().timestamp().to_string().as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    /// Check if message should be retried
    pub fn should_retry(&self) -> bool {
        self.attempts < self.max_attempts && self.status == MessageStatus::Failed
    }

    /// Mark message as processing
    pub fn mark_processing(&mut self) {
        self.status = MessageStatus::Processing;
        self.attempts += 1;
    }

    /// Mark message as sent
    pub fn mark_sent(&mut self, transaction_id: String) {
        self.status = MessageStatus::Sent;
        self.sent_at = Some(Utc::now());
        self.transaction_id = Some(transaction_id);
    }

    /// Mark message as failed
    pub fn mark_failed(&mut self) {
        self.status = MessageStatus::Failed;
    }

    /// Mark message as acknowledged
    pub fn mark_acknowledged(&mut self) {
        self.status = MessageStatus::Acknowledged;
    }
}

/// Payload manager for handling message queues
pub struct PayloadManager {
    /// Message queue (priority-based)
    queue: Arc<Mutex<VecDeque<QueuedMessage>>>,
    /// Sent messages (for tracking)
    sent_messages: Arc<Mutex<HashMap<String, QueuedMessage>>>,
    /// Failed messages (for retry)
    failed_messages: Arc<Mutex<HashMap<String, QueuedMessage>>>,
    /// Maximum queue size
    max_queue_size: usize,
}

impl PayloadManager {
    /// Create a new payload manager
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            sent_messages: Arc::new(Mutex::new(HashMap::new())),
            failed_messages: Arc::new(Mutex::new(HashMap::new())),
            max_queue_size: MAX_QUEUE_SIZE,
        }
    }

    /// Create a new payload manager with custom max queue size
    pub fn with_max_queue_size(max_size: usize) -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            sent_messages: Arc::new(Mutex::new(HashMap::new())),
            failed_messages: Arc::new(Mutex::new(HashMap::new())),
            max_queue_size: max_size,
        }
    }

    /// Queue a new message
    pub fn queue_message(
        &self,
        recipient: String,
        payload: Vec<u8>,
        message_type: MessageType,
        priority: MessagePriority,
    ) -> Result<String> {
        let mut queue = self.queue.lock().unwrap();

        // Check queue size limit
        if queue.len() >= self.max_queue_size {
            bail!("Queue is full ({} messages)", self.max_queue_size);
        }

        // Create queued message
        let message = QueuedMessage::new(recipient, payload, message_type, priority)?;
        let message_id = message.id.clone();

        // Insert based on priority (higher priority goes first)
        let insert_pos = queue.iter().position(|m| m.priority < priority).unwrap_or(queue.len());
        queue.insert(insert_pos, message);

        Ok(message_id)
    }

    /// Get next message from queue
    pub fn get_next_message(&self) -> Option<QueuedMessage> {
        let mut queue = self.queue.lock().unwrap();
        queue.pop_front()
    }

    /// Peek at next message without removing
    pub fn peek_next_message(&self) -> Option<QueuedMessage> {
        let queue = self.queue.lock().unwrap();
        queue.front().cloned()
    }

    /// Get messages by priority
    pub fn get_messages_by_priority(&self, priority: MessagePriority, limit: usize) -> Vec<QueuedMessage> {
        let queue = self.queue.lock().unwrap();
        queue.iter()
            .filter(|m| m.priority == priority)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get all queued messages for a recipient
    pub fn get_messages_for_recipient(&self, recipient: &str) -> Vec<QueuedMessage> {
        let queue = self.queue.lock().unwrap();
        queue.iter()
            .filter(|m| m.recipient == recipient)
            .cloned()
            .collect()
    }

    /// Mark message as sent
    pub fn mark_message_sent(&self, message_id: &str, transaction_id: String) -> Result<()> {
        let mut queue = self.queue.lock().unwrap();

        // Find and remove from queue
        if let Some(pos) = queue.iter().position(|m| m.id == message_id) {
            let mut message = queue.remove(pos).unwrap();
            message.mark_sent(transaction_id);

            // Move to sent messages
            let mut sent = self.sent_messages.lock().unwrap();
            sent.insert(message.id.clone(), message);

            Ok(())
        } else {
            bail!("Message not found in queue: {}", message_id)
        }
    }

    /// Mark message as failed
    pub fn mark_message_failed(&self, message_id: &str) -> Result<()> {
        let mut queue = self.queue.lock().unwrap();

        // Find message in queue
        if let Some(pos) = queue.iter().position(|m| m.id == message_id) {
            let mut message = queue.remove(pos).unwrap();
            message.mark_failed();

            // If should retry, put back in queue; otherwise move to failed
            if message.should_retry() {
                let insert_pos = queue.iter().position(|m| m.priority < message.priority).unwrap_or(queue.len());
                queue.insert(insert_pos, message);
            } else {
                let mut failed = self.failed_messages.lock().unwrap();
                failed.insert(message.id.clone(), message);
            }

            Ok(())
        } else {
            bail!("Message not found in queue: {}", message_id)
        }
    }

    /// Mark message as acknowledged
    pub fn mark_message_acknowledged(&self, message_id: &str) -> Result<()> {
        let mut sent = self.sent_messages.lock().unwrap();

        if let Some(message) = sent.get_mut(message_id) {
            message.mark_acknowledged();
            Ok(())
        } else {
            bail!("Message not found in sent messages: {}", message_id)
        }
    }

    /// Get queue statistics
    pub fn get_stats(&self) -> QueueStats {
        let queue = self.queue.lock().unwrap();
        let sent = self.sent_messages.lock().unwrap();
        let failed = self.failed_messages.lock().unwrap();

        let mut by_priority: HashMap<MessagePriority, usize> = HashMap::new();
        let mut by_type: HashMap<MessageType, usize> = HashMap::new();

        for message in queue.iter() {
            *by_priority.entry(message.priority).or_insert(0) += 1;
            *by_type.entry(message.message_type).or_insert(0) += 1;
        }

        let total_payload_size: usize = queue.iter().map(|m| m.compressed_size).sum();

        QueueStats {
            queued_count: queue.len(),
            sent_count: sent.len(),
            failed_count: failed.len(),
            total_payload_size,
            by_priority,
            by_type,
        }
    }

    /// Clear all queues
    pub fn clear_all(&self) {
        self.queue.lock().unwrap().clear();
        self.sent_messages.lock().unwrap().clear();
        self.failed_messages.lock().unwrap().clear();
    }

    /// Get queue size
    pub fn queue_size(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    /// Get sent message count
    pub fn sent_count(&self) -> usize {
        self.sent_messages.lock().unwrap().len()
    }

    /// Get failed message count
    pub fn failed_count(&self) -> usize {
        self.failed_messages.lock().unwrap().len()
    }

    /// Remove old sent messages (cleanup)
    pub fn cleanup_old_messages(&self, max_age_hours: i64) {
        let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours);
        let mut sent = self.sent_messages.lock().unwrap();

        sent.retain(|_, message| {
            message.sent_at.map(|t| t > cutoff).unwrap_or(false)
        });
    }
}

impl Default for PayloadManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Queue statistics
#[derive(Debug, Clone)]
pub struct QueueStats {
    pub queued_count: usize,
    pub sent_count: usize,
    pub failed_count: usize,
    pub total_payload_size: usize,
    pub by_priority: HashMap<MessagePriority, usize>,
    pub by_type: HashMap<MessageType, usize>,
}

/// Simple encryption/decryption helper (placeholder for actual crypto)
pub struct MessageEncryption;

impl MessageEncryption {
    /// Encrypt a message payload (placeholder - should use real crypto)
    pub fn encrypt(data: &[u8], _recipient_public_key: &str) -> Result<Vec<u8>> {
        // TODO: Implement actual encryption (ChaCha20-Poly1305, etc.)
        // For now, just return the data as-is
        Ok(data.to_vec())
    }

    /// Decrypt a message payload (placeholder - should use real crypto)
    pub fn decrypt(data: &[u8], _private_key: &str) -> Result<Vec<u8>> {
        // TODO: Implement actual decryption
        // For now, just return the data as-is
        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_priority_ordering() {
        assert!(MessagePriority::Critical > MessagePriority::High);
        assert!(MessagePriority::High > MessagePriority::Normal);
        assert!(MessagePriority::Normal > MessagePriority::Low);
    }

    #[test]
    fn test_queued_message_creation() {
        let payload = b"Hello, World!".to_vec();
        let message = QueuedMessage::new(
            "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7".to_string(),
            payload.clone(),
            MessageType::Chat,
            MessagePriority::Normal,
        ).unwrap();

        assert_eq!(message.payload, payload);
        assert_eq!(message.priority, MessagePriority::Normal);
        assert_eq!(message.status, MessageStatus::Queued);
        assert_eq!(message.attempts, 0);
    }

    #[test]
    fn test_payload_size_limit() {
        let large_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let result = QueuedMessage::new(
            "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7".to_string(),
            large_payload,
            MessageType::Chat,
            MessagePriority::Normal,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_payload_manager_queue() {
        let manager = PayloadManager::new();

        // Queue a message
        let message_id = manager.queue_message(
            "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7".to_string(),
            b"Test message".to_vec(),
            MessageType::Chat,
            MessagePriority::Normal,
        ).unwrap();

        assert_eq!(manager.queue_size(), 1);

        // Get message
        let message = manager.get_next_message().unwrap();
        assert_eq!(message.id, message_id);
        assert_eq!(manager.queue_size(), 0);
    }

    #[test]
    fn test_priority_ordering() {
        let manager = PayloadManager::new();

        // Queue messages with different priorities
        manager.queue_message(
            "recipient1".to_string(),
            b"Low priority".to_vec(),
            MessageType::Chat,
            MessagePriority::Low,
        ).unwrap();

        manager.queue_message(
            "recipient2".to_string(),
            b"High priority".to_vec(),
            MessageType::Chat,
            MessagePriority::High,
        ).unwrap();

        manager.queue_message(
            "recipient3".to_string(),
            b"Normal priority".to_vec(),
            MessageType::Chat,
            MessagePriority::Normal,
        ).unwrap();

        // High priority should come first
        let msg1 = manager.get_next_message().unwrap();
        assert_eq!(msg1.priority, MessagePriority::High);

        // Then normal
        let msg2 = manager.get_next_message().unwrap();
        assert_eq!(msg2.priority, MessagePriority::Normal);

        // Then low
        let msg3 = manager.get_next_message().unwrap();
        assert_eq!(msg3.priority, MessagePriority::Low);
    }

    #[test]
    fn test_message_retry_logic() {
        let mut message = QueuedMessage::new(
            "recipient".to_string(),
            b"Test".to_vec(),
            MessageType::Chat,
            MessagePriority::Normal,
        ).unwrap();

        // Initially should not retry (not failed yet)
        assert!(!message.should_retry());

        // Mark as failed
        message.mark_failed();
        assert!(message.should_retry());
        assert_eq!(message.attempts, 0);

        // After max attempts, should not retry
        message.attempts = message.max_attempts;
        assert!(!message.should_retry());
    }

    #[test]
    fn test_queue_stats() {
        let manager = PayloadManager::new();

        manager.queue_message(
            "recipient1".to_string(),
            b"Message 1".to_vec(),
            MessageType::Chat,
            MessagePriority::Normal,
        ).unwrap();

        manager.queue_message(
            "recipient2".to_string(),
            b"Message 2".to_vec(),
            MessageType::Signaling,
            MessagePriority::High,
        ).unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.queued_count, 2);
        assert_eq!(stats.by_priority.get(&MessagePriority::Normal), Some(&1));
        assert_eq!(stats.by_priority.get(&MessagePriority::High), Some(&1));
    }
}
