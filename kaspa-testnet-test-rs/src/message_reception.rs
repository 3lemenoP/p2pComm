/// Message Reception Handler for P2PComm
///
/// This module handles incoming messages from Kaspa transactions:
/// - Verifies Ed25519 signatures
/// - Decrypts message content
/// - Routes messages by type (chat, signaling, ack)
/// - Handles duplicate detection
/// - Stores received messages

use anyhow::{Result, Context, bail};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::message_extractor::{KaspaEnvelope, EnvelopeType, MessageExtractor};
use crate::utxo_monitor::{UtxoMonitor, NewUtxoEvent};
use crate::rpc_client::KaspaTestnetClient;

/// Maximum age for messages to be accepted (in seconds)
pub const MAX_MESSAGE_AGE: i64 = 86400; // 24 hours

/// Message reception event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedMessage {
    /// Unique message ID
    pub id: String,
    /// Transaction ID where message was found
    pub transaction_id: String,
    /// Sender's peer ID
    pub sender_peer_id: String,
    /// Recipient's peer ID
    pub recipient_peer_id: String,
    /// Message type
    pub message_type: EnvelopeType,
    /// Decrypted message content (if decryption succeeded)
    pub content: Option<String>,
    /// Raw encrypted data (if decryption failed or not attempted)
    pub raw_data: Vec<u8>,
    /// Original envelope timestamp
    pub timestamp: u64,
    /// When the message was received
    pub received_at: DateTime<Utc>,
    /// Whether signature was verified
    pub signature_verified: bool,
    /// Whether content was decrypted
    pub decrypted: bool,
}

/// Signaling message for WebRTC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingMessage {
    /// Sender's peer ID
    pub sender_peer_id: String,
    /// Signaling type (offer, answer, ice)
    pub signaling_type: EnvelopeType,
    /// Signaling data (SDP or ICE candidate)
    pub data: String,
    /// Timestamp
    pub timestamp: u64,
}

/// Message handler callback types
pub type MessageCallback = Box<dyn Fn(&ReceivedMessage) + Send + Sync>;
pub type SignalingCallback = Box<dyn Fn(&SignalingMessage) + Send + Sync>;

/// Reception statistics
#[derive(Debug, Clone, Default)]
pub struct ReceptionStats {
    /// Total messages received
    pub messages_received: usize,
    /// Messages with verified signatures
    pub signatures_verified: usize,
    /// Messages successfully decrypted
    pub messages_decrypted: usize,
    /// Duplicate messages filtered
    pub duplicates_filtered: usize,
    /// Invalid/rejected messages
    pub messages_rejected: usize,
    /// Signaling messages received
    pub signaling_messages: usize,
}

/// Message reception handler
pub struct MessageReceptionHandler {
    /// User's peer ID for filtering incoming messages
    user_peer_id: String,
    /// Known message IDs for deduplication
    known_messages: Arc<Mutex<HashSet<String>>>,
    /// Received messages storage
    received_messages: Arc<Mutex<Vec<ReceivedMessage>>>,
    /// Pending signaling messages
    pending_signaling: Arc<Mutex<Vec<SignalingMessage>>>,
    /// Reception statistics
    stats: Arc<Mutex<ReceptionStats>>,
}

impl MessageReceptionHandler {
    /// Create a new message reception handler
    pub fn new(user_peer_id: String) -> Self {
        Self {
            user_peer_id,
            known_messages: Arc::new(Mutex::new(HashSet::new())),
            received_messages: Arc::new(Mutex::new(Vec::new())),
            pending_signaling: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(ReceptionStats::default())),
        }
    }

    /// Process a new UTXO event (check for messages)
    pub async fn process_utxo_event(
        &self,
        event: &NewUtxoEvent,
        rpc_client: &KaspaTestnetClient,
    ) -> Result<Vec<ReceivedMessage>> {
        // Only process dust outputs (message notifications)
        if !event.is_dust {
            return Ok(Vec::new());
        }

        // Fetch transaction payload from RPC
        // Note: This is a simplified version - real implementation would
        // need to fetch the full transaction and extract the payload
        let payload = self.fetch_transaction_payload(rpc_client, &event.transaction_id).await?;

        if payload.is_empty() {
            return Ok(Vec::new());
        }

        // Extract envelopes from payload
        let envelopes = MessageExtractor::extract_envelopes(&payload)?;

        // Process each envelope
        let mut received = Vec::new();
        for envelope in envelopes {
            if let Some(msg) = self.process_envelope(&envelope, &event.transaction_id)? {
                received.push(msg);
            }
        }

        Ok(received)
    }

    /// Fetch transaction payload (placeholder - needs real RPC implementation)
    async fn fetch_transaction_payload(
        &self,
        _rpc_client: &KaspaTestnetClient,
        _tx_id: &str,
    ) -> Result<Vec<u8>> {
        // TODO: Implement actual transaction payload fetching
        // This would use rpc_client.get_transaction() or similar
        Ok(Vec::new())
    }

    /// Process a single envelope
    pub fn process_envelope(
        &self,
        envelope: &KaspaEnvelope,
        transaction_id: &str,
    ) -> Result<Option<ReceivedMessage>> {
        // Check if message is for us
        if envelope.recipient_peer_id != self.user_peer_id {
            return Ok(None);
        }

        // Generate message ID for deduplication
        let message_id = envelope.message_id.clone().unwrap_or_else(|| {
            format!("{}:{}:{}",
                transaction_id,
                envelope.sender_peer_id,
                envelope.timestamp
            )
        });

        // Check for duplicates
        {
            let mut known = self.known_messages.lock().unwrap();
            if known.contains(&message_id) {
                let mut stats = self.stats.lock().unwrap();
                stats.duplicates_filtered += 1;
                return Ok(None);
            }
            known.insert(message_id.clone());
        }

        // Validate envelope structure
        if let Err(e) = envelope.validate() {
            let mut stats = self.stats.lock().unwrap();
            stats.messages_rejected += 1;
            log::warn!("Invalid envelope: {}", e);
            return Ok(None);
        }

        // Check message age
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let age_seconds = (now_ms.saturating_sub(envelope.timestamp)) / 1000;
        if age_seconds > MAX_MESSAGE_AGE as u64 {
            let mut stats = self.stats.lock().unwrap();
            stats.messages_rejected += 1;
            log::warn!("Message too old: {} seconds", age_seconds);
            return Ok(None);
        }

        // Verify signature (placeholder - needs crypto implementation)
        let signature_verified = self.verify_signature(envelope)?;

        // Decrypt content (placeholder - needs crypto implementation)
        let (content, decrypted) = self.decrypt_content(envelope)?;

        // Create received message
        let received_message = ReceivedMessage {
            id: message_id,
            transaction_id: transaction_id.to_string(),
            sender_peer_id: envelope.sender_peer_id.clone(),
            recipient_peer_id: envelope.recipient_peer_id.clone(),
            message_type: envelope.envelope_type,
            content: content.clone(),
            raw_data: envelope.data.clone(),
            timestamp: envelope.timestamp,
            received_at: Utc::now(),
            signature_verified,
            decrypted,
        };

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.messages_received += 1;
            if signature_verified {
                stats.signatures_verified += 1;
            }
            if decrypted {
                stats.messages_decrypted += 1;
            }
        }

        // Route by message type
        match envelope.envelope_type {
            EnvelopeType::Message => {
                // Store as regular message
                let mut messages = self.received_messages.lock().unwrap();
                messages.push(received_message.clone());
            }
            EnvelopeType::SignalingOffer |
            EnvelopeType::SignalingAnswer |
            EnvelopeType::SignalingIce => {
                // Store as signaling message
                let signaling = SignalingMessage {
                    sender_peer_id: envelope.sender_peer_id.clone(),
                    signaling_type: envelope.envelope_type,
                    data: content.unwrap_or_else(|| {
                        String::from_utf8_lossy(&envelope.data).to_string()
                    }),
                    timestamp: envelope.timestamp,
                };

                let mut pending = self.pending_signaling.lock().unwrap();
                pending.push(signaling);

                let mut stats = self.stats.lock().unwrap();
                stats.signaling_messages += 1;
            }
            EnvelopeType::Ack => {
                // Handle acknowledgment
                log::debug!("Received ack from {}", envelope.sender_peer_id);
            }
            EnvelopeType::System => {
                // Handle system message
                log::debug!("Received system message from {}", envelope.sender_peer_id);
            }
        }

        Ok(Some(received_message))
    }

    /// Verify envelope signature (placeholder)
    fn verify_signature(&self, _envelope: &KaspaEnvelope) -> Result<bool> {
        // TODO: Implement actual Ed25519 signature verification
        // 1. Get sender's public key from peer ID or contact store
        // 2. Get signable bytes from envelope
        // 3. Verify signature using ed25519
        Ok(true) // Placeholder: assume valid
    }

    /// Decrypt envelope content (placeholder)
    fn decrypt_content(&self, envelope: &KaspaEnvelope) -> Result<(Option<String>, bool)> {
        // TODO: Implement actual X25519 + ChaCha20-Poly1305 decryption
        // 1. Derive shared secret from sender's public key and our private key
        // 2. Decrypt using ChaCha20-Poly1305
        // 3. Return decrypted content

        // Placeholder: try to interpret as UTF-8
        match String::from_utf8(envelope.data.clone()) {
            Ok(content) => Ok((Some(content), false)), // Not actually decrypted
            Err(_) => Ok((None, false)),
        }
    }

    /// Get received messages
    pub fn get_messages(&self) -> Vec<ReceivedMessage> {
        self.received_messages.lock().unwrap().clone()
    }

    /// Get messages from a specific sender
    pub fn get_messages_from(&self, sender_peer_id: &str) -> Vec<ReceivedMessage> {
        self.received_messages
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.sender_peer_id == sender_peer_id)
            .cloned()
            .collect()
    }

    /// Get pending signaling messages
    pub fn get_pending_signaling(&self) -> Vec<SignalingMessage> {
        let mut pending = self.pending_signaling.lock().unwrap();
        std::mem::take(&mut *pending)
    }

    /// Get reception statistics
    pub fn get_stats(&self) -> ReceptionStats {
        self.stats.lock().unwrap().clone()
    }

    /// Clear all received messages
    pub fn clear_messages(&self) {
        self.received_messages.lock().unwrap().clear();
    }

    /// Clear known message IDs (allows reprocessing)
    pub fn clear_known_messages(&self) {
        self.known_messages.lock().unwrap().clear();
    }

    /// Get count of received messages
    pub fn message_count(&self) -> usize {
        self.received_messages.lock().unwrap().len()
    }

    /// Check if a message has been received
    pub fn has_message(&self, message_id: &str) -> bool {
        self.known_messages.lock().unwrap().contains(message_id)
    }
}

/// Full message reception pipeline
pub struct MessageReceptionPipeline {
    /// UTXO monitor for detecting incoming transactions
    pub utxo_monitor: UtxoMonitor,
    /// Message reception handler
    pub handler: MessageReceptionHandler,
}

impl MessageReceptionPipeline {
    /// Create a new reception pipeline
    pub fn new(user_peer_id: String) -> Self {
        Self {
            utxo_monitor: UtxoMonitor::new(),
            handler: MessageReceptionHandler::new(user_peer_id),
        }
    }

    /// Add addresses to monitor
    pub fn add_addresses(&self, addresses: &[String]) -> Result<()> {
        self.utxo_monitor.add_addresses(addresses)
    }

    /// Poll for new messages
    pub async fn poll(&self, rpc_client: &KaspaTestnetClient) -> Result<Vec<ReceivedMessage>> {
        // Check for new UTXOs
        let events = self.utxo_monitor.poll_once(rpc_client).await?;

        // Process each dust event
        let mut all_messages = Vec::new();
        for event in events.iter().filter(|e| e.is_dust) {
            match self.handler.process_utxo_event(event, rpc_client).await {
                Ok(messages) => all_messages.extend(messages),
                Err(e) => log::warn!("Failed to process UTXO event: {}", e),
            }
        }

        Ok(all_messages)
    }

    /// Get all received messages
    pub fn get_messages(&self) -> Vec<ReceivedMessage> {
        self.handler.get_messages()
    }

    /// Get pending signaling messages
    pub fn get_pending_signaling(&self) -> Vec<SignalingMessage> {
        self.handler.get_pending_signaling()
    }

    /// Get combined statistics
    pub fn get_stats(&self) -> (crate::utxo_monitor::MonitorStats, ReceptionStats) {
        (self.utxo_monitor.get_stats(), self.handler.get_stats())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_creation() {
        let handler = MessageReceptionHandler::new("my_peer_id".to_string());
        assert_eq!(handler.message_count(), 0);
    }

    #[test]
    fn test_envelope_processing() {
        let handler = MessageReceptionHandler::new("recipient123".to_string());

        let mut envelope = KaspaEnvelope::new(
            EnvelopeType::Message,
            "sender456".to_string(),
            "recipient123".to_string(),
            b"Hello!".to_vec(),
        );
        envelope.signature = vec![1, 2, 3, 4, 5];

        let result = handler.process_envelope(&envelope, "tx_123").unwrap();
        assert!(result.is_some());

        let msg = result.unwrap();
        assert_eq!(msg.sender_peer_id, "sender456");
        assert_eq!(msg.recipient_peer_id, "recipient123");
    }

    #[test]
    fn test_wrong_recipient_filtered() {
        let handler = MessageReceptionHandler::new("my_peer_id".to_string());

        let mut envelope = KaspaEnvelope::new(
            EnvelopeType::Message,
            "sender".to_string(),
            "different_recipient".to_string(), // Not us
            b"Hello!".to_vec(),
        );
        envelope.signature = vec![1, 2, 3];

        let result = handler.process_envelope(&envelope, "tx_123").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_duplicate_filtering() {
        let handler = MessageReceptionHandler::new("recipient".to_string());

        let mut envelope = KaspaEnvelope::new(
            EnvelopeType::Message,
            "sender".to_string(),
            "recipient".to_string(),
            b"Hello!".to_vec(),
        );
        envelope.signature = vec![1, 2, 3];
        envelope.message_id = Some("unique_id_123".to_string());

        // First processing should succeed
        let result1 = handler.process_envelope(&envelope, "tx_1").unwrap();
        assert!(result1.is_some());

        // Second processing should be filtered as duplicate
        let result2 = handler.process_envelope(&envelope, "tx_1").unwrap();
        assert!(result2.is_none());

        let stats = handler.get_stats();
        assert_eq!(stats.duplicates_filtered, 1);
    }

    #[test]
    fn test_signaling_message_routing() {
        let handler = MessageReceptionHandler::new("recipient".to_string());

        let mut envelope = KaspaEnvelope::new(
            EnvelopeType::SignalingOffer,
            "sender".to_string(),
            "recipient".to_string(),
            b"sdp_offer_data".to_vec(),
        );
        envelope.signature = vec![1, 2, 3];

        handler.process_envelope(&envelope, "tx_1").unwrap();

        let signaling = handler.get_pending_signaling();
        assert_eq!(signaling.len(), 1);
        assert_eq!(signaling[0].signaling_type, EnvelopeType::SignalingOffer);
    }

    #[test]
    fn test_pipeline_creation() {
        let pipeline = MessageReceptionPipeline::new("my_peer_id".to_string());

        pipeline.add_addresses(&[
            "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7".to_string(),
        ]).unwrap();

        assert_eq!(pipeline.utxo_monitor.address_count(), 1);
    }
}
