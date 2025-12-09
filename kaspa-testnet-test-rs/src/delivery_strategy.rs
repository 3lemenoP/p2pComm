/// Delivery Strategy for P2PComm
///
/// This module provides intelligent message delivery:
/// - Batching multiple messages to save fees
/// - Fee optimization strategies
/// - Delivery scheduling and timing
/// - Transaction creation and submission coordination
/// - Integration with wallet, transaction builder, and RPC client

use anyhow::{Result, Context, bail};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};

use crate::payload_manager::{PayloadManager, QueuedMessage, MessagePriority};
use crate::transaction_builder::{TransactionBuilder, DUST_AMOUNT};
use crate::wallet_manager::P2PCommWallet;
use crate::rpc_client::KaspaTestnetClient;

/// Maximum number of messages to batch in a single transaction
pub const MAX_BATCH_SIZE: usize = 10;

/// Minimum fee savings percentage to warrant batching (e.g., 20%)
pub const MIN_BATCH_SAVINGS: f64 = 0.2;

/// Maximum wait time for batching before sending anyway (seconds)
pub const MAX_BATCH_WAIT_SECONDS: i64 = 30;

/// Delivery mode configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// Send messages immediately as they come
    Immediate,
    /// Batch messages together to save fees
    Batched,
    /// Smart mode: batch when economical, immediate when urgent
    Smart,
}

/// Batching strategy
#[derive(Debug, Clone)]
pub struct BatchingStrategy {
    /// Delivery mode
    pub mode: DeliveryMode,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Maximum wait time for batching
    pub max_wait_duration: Duration,
    /// Minimum savings percentage to batch
    pub min_savings_percentage: f64,
}

impl Default for BatchingStrategy {
    fn default() -> Self {
        Self {
            mode: DeliveryMode::Smart,
            max_batch_size: MAX_BATCH_SIZE,
            max_wait_duration: Duration::seconds(MAX_BATCH_WAIT_SECONDS),
            min_savings_percentage: MIN_BATCH_SAVINGS,
        }
    }
}

/// Batch of messages ready for delivery
#[derive(Debug, Clone)]
pub struct MessageBatch {
    /// Messages in this batch
    pub messages: Vec<QueuedMessage>,
    /// Recipient address
    pub recipient: String,
    /// Total payload size
    pub total_size: usize,
    /// Estimated fee for this batch
    pub estimated_fee: u64,
    /// Timestamp when batch was created
    pub created_at: DateTime<Utc>,
}

impl MessageBatch {
    /// Create a new message batch
    pub fn new(recipient: String) -> Self {
        Self {
            messages: Vec::new(),
            recipient,
            total_size: 0,
            estimated_fee: 0,
            created_at: Utc::now(),
        }
    }

    /// Add a message to the batch
    pub fn add_message(&mut self, message: QueuedMessage) {
        self.total_size += message.compressed_size;
        self.messages.push(message);
    }

    /// Check if batch can accept another message
    pub fn can_add_message(&self, message_size: usize, max_payload_size: usize) -> bool {
        self.total_size + message_size <= max_payload_size
    }

    /// Check if batch has waited too long
    pub fn has_waited_too_long(&self, max_wait: Duration) -> bool {
        Utc::now() - self.created_at > max_wait
    }

    /// Get age of batch in seconds
    pub fn age_seconds(&self) -> i64 {
        (Utc::now() - self.created_at).num_seconds()
    }
}

/// Delivery statistics
#[derive(Debug, Clone, Default)]
pub struct DeliveryStats {
    /// Total messages sent
    pub messages_sent: usize,
    /// Total batches sent
    pub batches_sent: usize,
    /// Total transactions created
    pub transactions_created: usize,
    /// Total fees paid (in sompis)
    pub total_fees_paid: u64,
    /// Total fees saved through batching (estimated, in sompis)
    pub fees_saved_by_batching: u64,
    /// Failed delivery attempts
    pub failed_deliveries: usize,
}

/// Message delivery coordinator
pub struct DeliveryCoordinator {
    /// Batching strategy
    strategy: BatchingStrategy,
    /// Current batches being assembled (by recipient)
    pending_batches: HashMap<String, MessageBatch>,
    /// Delivery statistics
    stats: DeliveryStats,
}

impl DeliveryCoordinator {
    /// Create a new delivery coordinator
    pub fn new(strategy: BatchingStrategy) -> Self {
        Self {
            strategy,
            pending_batches: HashMap::new(),
            stats: DeliveryStats::default(),
        }
    }

    /// Create with default strategy
    pub fn with_default_strategy() -> Self {
        Self::new(BatchingStrategy::default())
    }

    /// Process messages from queue and create batches
    pub fn process_queue(&mut self, payload_manager: &PayloadManager) -> Vec<MessageBatch> {
        let mut ready_batches = Vec::new();

        // Get all queued messages
        let queued = payload_manager.peek_next_message();
        if queued.is_none() {
            return ready_batches;
        }

        // Process based on delivery mode
        match self.strategy.mode {
            DeliveryMode::Immediate => {
                // Send each message immediately
                if let Some(msg) = payload_manager.get_next_message() {
                    let mut batch = MessageBatch::new(msg.recipient.clone());
                    batch.add_message(msg);
                    ready_batches.push(batch);
                }
            }
            DeliveryMode::Batched => {
                // Always try to batch messages
                self.create_batches_for_queue(payload_manager, &mut ready_batches);
            }
            DeliveryMode::Smart => {
                // Smart batching: immediate for high-priority, batch for normal
                self.smart_batch_processing(payload_manager, &mut ready_batches);
            }
        }

        // Check for batches that have waited too long
        self.finalize_waiting_batches(&mut ready_batches);

        ready_batches
    }

    /// Create batches from queued messages
    fn create_batches_for_queue(
        &mut self,
        payload_manager: &PayloadManager,
        ready_batches: &mut Vec<MessageBatch>,
    ) {
        while let Some(msg) = payload_manager.peek_next_message() {
            let recipient = msg.recipient.clone();

            // Get or create batch for this recipient
            let recipient_clone = recipient.clone();
            let batch = self.pending_batches
                .entry(recipient.clone())
                .or_insert_with(|| MessageBatch::new(recipient_clone));

            // Check if we can add this message to the batch
            if batch.can_add_message(msg.compressed_size, 98_000) &&
               batch.messages.len() < self.strategy.max_batch_size {
                // Add to batch
                if let Some(msg) = payload_manager.get_next_message() {
                    batch.add_message(msg);
                }
            } else {
                // Batch is full, finalize it
                if let Some(full_batch) = self.pending_batches.remove(&recipient) {
                    ready_batches.push(full_batch);
                }
            }
        }
    }

    /// Smart batching: immediate for high-priority, batch for normal
    fn smart_batch_processing(
        &mut self,
        payload_manager: &PayloadManager,
        ready_batches: &mut Vec<MessageBatch>,
    ) {
        while let Some(msg) = payload_manager.peek_next_message() {
            // High priority or critical messages go immediately
            if msg.priority >= MessagePriority::High {
                if let Some(msg) = payload_manager.get_next_message() {
                    let mut batch = MessageBatch::new(msg.recipient.clone());
                    batch.add_message(msg);
                    ready_batches.push(batch);
                }
            } else {
                // Normal/low priority messages can be batched
                let recipient = msg.recipient.clone();
                let recipient_clone = recipient.clone();
                let batch = self.pending_batches
                    .entry(recipient.clone())
                    .or_insert_with(|| MessageBatch::new(recipient_clone));

                if batch.can_add_message(msg.compressed_size, 98_000) &&
                   batch.messages.len() < self.strategy.max_batch_size {
                    if let Some(msg) = payload_manager.get_next_message() {
                        batch.add_message(msg);
                    }
                } else {
                    break;
                }
            }
        }
    }

    /// Finalize batches that have waited too long
    fn finalize_waiting_batches(&mut self, ready_batches: &mut Vec<MessageBatch>) {
        let max_wait = self.strategy.max_wait_duration;
        let mut to_finalize = Vec::new();

        for (recipient, batch) in &self.pending_batches {
            if batch.has_waited_too_long(max_wait) {
                to_finalize.push(recipient.clone());
            }
        }

        for recipient in to_finalize {
            if let Some(batch) = self.pending_batches.remove(&recipient) {
                ready_batches.push(batch);
            }
        }
    }

    /// Send a batch of messages
    pub async fn send_batch(
        &mut self,
        batch: &MessageBatch,
        wallet: &P2PCommWallet,
        _rpc_client: &KaspaTestnetClient,
    ) -> Result<String> {
        // Create transaction builder
        let mut tx_builder = TransactionBuilder::new();

        // Combine all message payloads
        let combined_payload = self.combine_payloads(&batch.messages)?;

        // Set payload
        tx_builder.set_payload(combined_payload)?;

        // Add dust output for recipient notification
        tx_builder.add_dust_output(&batch.recipient)?;

        // Set change address
        let sender_address = wallet.get_primary_address()?;
        tx_builder.set_change_address(&sender_address)?;

        // Calculate fee
        let fee = tx_builder.calculate_fee();

        // Build transaction (note: needs UTXOs which we don't have in test environment)
        // This would normally:
        // 1. Get UTXOs from wallet
        // 2. Add inputs to transaction
        // 3. Build and sign transaction
        // 4. Submit to network via RPC client

        // Update statistics
        self.stats.messages_sent += batch.messages.len();
        self.stats.batches_sent += 1;
        self.stats.transactions_created += 1;
        self.stats.total_fees_paid += fee;

        // Return mock transaction ID
        Ok(format!("tx_{}", chrono::Utc::now().timestamp()))
    }

    /// Combine multiple message payloads into one
    fn combine_payloads(&self, messages: &[QueuedMessage]) -> Result<Vec<u8>> {
        let mut combined = Vec::new();

        for msg in messages {
            // Add message separator
            combined.extend_from_slice(b"MSG:");
            // Add message ID
            combined.extend_from_slice(msg.id.as_bytes());
            combined.extend_from_slice(b":");
            // Add payload length
            let len_bytes = (msg.payload.len() as u32).to_be_bytes();
            combined.extend_from_slice(&len_bytes);
            combined.extend_from_slice(b":");
            // Add payload
            combined.extend_from_slice(&msg.payload);
            combined.extend_from_slice(b"\n");
        }

        // Verify combined size
        if combined.len() > 98_000 {
            bail!(
                "Combined payload too large: {} bytes (max: 98000 bytes)",
                combined.len()
            );
        }

        Ok(combined)
    }

    /// Calculate potential fee savings from batching
    pub fn calculate_batch_savings(&self, batch: &MessageBatch) -> u64 {
        let num_messages = batch.messages.len() as u64;

        // Estimate individual transaction fees
        let individual_fees = num_messages * (DUST_AMOUNT + 5_000); // rough estimate

        // Estimate batched fee (one transaction)
        let batched_fee = DUST_AMOUNT + 5_000 + (batch.total_size as u64 * 10);

        individual_fees.saturating_sub(batched_fee)
    }

    /// Get delivery statistics
    pub fn get_stats(&self) -> &DeliveryStats {
        &self.stats
    }

    /// Get number of pending batches
    pub fn pending_batch_count(&self) -> usize {
        self.pending_batches.len()
    }

    /// Clear pending batches
    pub fn clear_pending_batches(&mut self) {
        self.pending_batches.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload_manager::{MessageType, MessagePriority};

    #[test]
    fn test_message_batch_creation() {
        let mut batch = MessageBatch::new("recipient1".to_string());
        assert_eq!(batch.messages.len(), 0);
        assert_eq!(batch.total_size, 0);

        let msg = QueuedMessage::new(
            "recipient1".to_string(),
            b"Test message".to_vec(),
            MessageType::Chat,
            MessagePriority::Normal,
        ).unwrap();

        batch.add_message(msg);
        assert_eq!(batch.messages.len(), 1);
        assert!(batch.total_size > 0);
    }

    #[test]
    fn test_batch_can_add_message() {
        let mut batch = MessageBatch::new("recipient1".to_string());

        // Should be able to add small message
        assert!(batch.can_add_message(100, 98_000));

        // Add a large message
        batch.total_size = 97_000;

        // Should not be able to add message that would exceed limit
        assert!(!batch.can_add_message(2_000, 98_000));
    }

    #[test]
    fn test_delivery_modes() {
        let immediate = DeliveryMode::Immediate;
        let batched = DeliveryMode::Batched;
        let smart = DeliveryMode::Smart;

        assert_ne!(immediate, batched);
        assert_ne!(immediate, smart);
        assert_ne!(batched, smart);
    }

    #[test]
    fn test_delivery_coordinator_creation() {
        let coordinator = DeliveryCoordinator::with_default_strategy();
        assert_eq!(coordinator.strategy.mode, DeliveryMode::Smart);
        assert_eq!(coordinator.pending_batch_count(), 0);
    }

    #[test]
    fn test_batching_strategy_defaults() {
        let strategy = BatchingStrategy::default();
        assert_eq!(strategy.mode, DeliveryMode::Smart);
        assert_eq!(strategy.max_batch_size, MAX_BATCH_SIZE);
        assert!(strategy.min_savings_percentage > 0.0);
    }
}
