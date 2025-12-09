// Connection State Machine
// Manages individual peer connection lifecycle

use crate::identity::PeerId;
use super::{ConnectionState, ConnectionStats, NetworkResult, NetworkError};
use super::protocol::ProtocolMessage;
use super::reconnect::EnhancedReconnectionManager;
use std::collections::VecDeque;

/// Maximum queued messages before connection is established
const MAX_QUEUED_MESSAGES: usize = 100;

/// Ping interval in milliseconds
const PING_INTERVAL_MS: u64 = 30000; // 30 seconds

/// Connection timeout in milliseconds
const CONNECTION_TIMEOUT_MS: u64 = 60000; // 60 seconds

/// RTT history buffer size
const RTT_HISTORY_SIZE: usize = 10;

/// Connection to a single peer
pub struct Connection {
    /// Peer's identity
    peer_id: PeerId,

    /// Current connection state
    state: ConnectionState,

    /// Connection statistics
    stats: ConnectionStats,

    /// WebRTC connection handle (opaque ID for JS side)
    connection_id: Option<String>,

    /// Message queue (buffered before connection established)
    message_queue: VecDeque<ProtocolMessage>,

    /// Last ping timestamp
    last_ping_sent: Option<u64>,

    /// Last pong received timestamp
    last_pong_received: Option<u64>,

    /// RTT history for averaging
    rtt_history: VecDeque<f64>,

    /// Enhanced reconnection manager
    reconnection: EnhancedReconnectionManager,

    /// Connection established timestamp
    connected_at: Option<u64>,

    /// Last activity timestamp
    last_activity: u64,
}

impl Connection {
    /// Create a new connection
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id: peer_id.clone(),
            state: ConnectionState::Disconnected,
            stats: ConnectionStats::default(),
            connection_id: None,
            message_queue: VecDeque::new(),
            last_ping_sent: None,
            last_pong_received: None,
            rtt_history: VecDeque::with_capacity(RTT_HISTORY_SIZE),
            reconnection: EnhancedReconnectionManager::default(),
            connected_at: None,
            last_activity: js_sys::Date::now() as u64,
        }
    }

    /// Get peer ID
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get current connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get connection statistics
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Get connection ID (WebRTC handle)
    pub fn connection_id(&self) -> Option<&str> {
        self.connection_id.as_deref()
    }

    /// Set connection ID
    pub fn set_connection_id(&mut self, id: String) {
        self.connection_id = Some(id);
    }

    /// Check if connection is active
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Check if connection is in progress
    pub fn is_connecting(&self) -> bool {
        self.state == ConnectionState::Connecting
    }

    /// Check if connection has failed
    pub fn is_failed(&self) -> bool {
        self.state == ConnectionState::Failed
    }

    /// Check if connection is closed
    pub fn is_closed(&self) -> bool {
        self.state == ConnectionState::Closed
    }

    /// Initiate connection
    pub fn connect(&mut self) -> NetworkResult<()> {
        if self.state != ConnectionState::Disconnected {
            return Err(NetworkError::ConnectionFailed(
                "Connection already in progress or established".to_string()
            ));
        }

        self.state = ConnectionState::Connecting;
        self.last_activity = js_sys::Date::now() as u64;
        Ok(())
    }

    /// Mark connection as established
    pub fn on_connected(&mut self) {
        self.state = ConnectionState::Connected;
        self.connected_at = Some(js_sys::Date::now() as u64);
        self.stats.mark_connected();
        self.reconnection.record_success(&self.peer_id);
        self.last_activity = js_sys::Date::now() as u64;

        // Flush any queued messages
        self.flush_queue_internal();
    }

    /// Mark connection as failed
    pub fn on_failed(&mut self, reason: String) {
        self.state = ConnectionState::Failed;
        self.connection_id = None;
        self.last_activity = js_sys::Date::now() as u64;

        // Schedule reconnection with enhanced manager
        self.reconnection.schedule_reconnect(&self.peer_id, reason.clone());

        web_sys::console::error_1(&format!("Connection to {} failed: {}",
            self.peer_id.to_hex(), reason).into());
    }

    /// Close connection gracefully
    pub fn close(&mut self, reason: &str) {
        self.state = ConnectionState::Closed;
        self.connection_id = None;
        self.last_activity = js_sys::Date::now() as u64;

        web_sys::console::log_1(&format!("Connection to {} closed: {}",
            self.peer_id.to_hex(), reason).into());
    }

    /// Attempt to reconnect
    pub fn reconnect(&mut self) -> NetworkResult<()> {
        // Check if we should attempt now
        if !self.reconnection.should_attempt_now(&self.peer_id) {
            return Err(NetworkError::ConnectionFailed(
                "Not ready to reconnect yet".to_string()
            ));
        }

        self.state = ConnectionState::Connecting;
        self.connection_id = None;
        self.last_activity = js_sys::Date::now() as u64;

        Ok(())
    }

    /// Queue a message for sending
    pub fn queue_message(&mut self, message: ProtocolMessage) -> NetworkResult<()> {
        if self.message_queue.len() >= MAX_QUEUED_MESSAGES {
            return Err(NetworkError::SendFailed(
                "Message queue is full".to_string()
            ));
        }

        self.message_queue.push_back(message);
        Ok(())
    }

    /// Send a message immediately (if connected) or queue it
    pub fn send_message(&mut self, message: ProtocolMessage) -> NetworkResult<Vec<u8>> {
        if !self.is_connected() {
            // Queue for later
            self.queue_message(message)?;
            return Ok(Vec::new());
        }

        // Serialize message
        let bytes = message.to_bytes()
            .map_err(|e| NetworkError::SerializationError(e))?;

        // Update stats
        self.stats.record_sent(bytes.len() as u64);
        self.last_activity = js_sys::Date::now() as u64;

        Ok(bytes)
    }

    /// Process incoming message
    pub fn receive_message(&mut self, bytes: &[u8]) -> NetworkResult<ProtocolMessage> {
        // Deserialize message
        let message = ProtocolMessage::from_bytes(bytes)
            .map_err(|e| NetworkError::InvalidMessage(e))?;

        // Update stats
        self.stats.record_received(bytes.len() as u64);
        self.last_activity = js_sys::Date::now() as u64;

        Ok(message)
    }

    /// Flush queued messages
    pub fn flush_queue(&mut self) -> Vec<ProtocolMessage> {
        let mut messages = Vec::new();
        while let Some(msg) = self.message_queue.pop_front() {
            messages.push(msg);
        }
        messages
    }

    /// Internal queue flush (updates stats)
    fn flush_queue_internal(&mut self) {
        let count = self.message_queue.len();
        if count > 0 {
            web_sys::console::log_1(&format!(
                "Flushing {} queued messages to {}",
                count,
                self.peer_id.to_hex()
            ).into());
        }
    }

    /// Send ping (keep-alive)
    pub fn send_ping(&mut self) -> bool {
        let now = js_sys::Date::now() as u64;

        // Check if we need to send a ping
        if let Some(last_ping) = self.last_ping_sent {
            if now - last_ping < PING_INTERVAL_MS {
                return false; // Too soon
            }
        }

        self.last_ping_sent = Some(now);
        true
    }

    /// Record pong received and update RTT
    pub fn on_pong_received(&mut self, rtt_ms: f64) {
        self.last_pong_received = Some(js_sys::Date::now() as u64);

        // Update RTT history
        self.rtt_history.push_back(rtt_ms);
        if self.rtt_history.len() > RTT_HISTORY_SIZE {
            self.rtt_history.pop_front();
        }

        // Update average RTT in stats
        let avg_rtt: f64 = self.rtt_history.iter().sum::<f64>() / self.rtt_history.len() as f64;
        self.stats.avg_rtt_ms = Some(avg_rtt);
    }

    /// Check if connection is healthy
    pub fn is_healthy(&self) -> bool {
        if !self.is_connected() {
            return false;
        }

        let now = js_sys::Date::now() as u64;

        // Check for recent activity
        if now - self.last_activity > CONNECTION_TIMEOUT_MS {
            return false;
        }

        // Check for recent pong (if we've sent pings)
        if let Some(last_ping) = self.last_ping_sent {
            if let Some(last_pong) = self.last_pong_received {
                // Pong should be within reasonable time of last ping
                if last_ping > last_pong && (now - last_ping) > (PING_INTERVAL_MS * 2) {
                    return false; // No pong received for 2x ping interval
                }
            }
        }

        true
    }

    /// Check if we should attempt reconnection
    pub fn should_reconnect(&self) -> bool {
        if !self.is_failed() {
            return false;
        }

        self.reconnection.should_attempt_now(&self.peer_id)
    }

    /// Get reconnection delay in milliseconds (time until next attempt)
    pub fn get_reconnect_delay(&self) -> u64 {
        if let Some(next_attempt) = self.reconnection.get_next_attempt_time(&self.peer_id) {
            let now = js_sys::Date::now() as u64;
            if next_attempt > now {
                return next_attempt - now;
            }
        }
        0
    }

    /// Reset reconnection attempts (call on successful connection)
    pub fn reset_reconnection(&mut self) {
        self.reconnection.clear_peer(&self.peer_id);
    }

    /// Get number of queued messages
    pub fn queued_message_count(&self) -> usize {
        self.message_queue.len()
    }

    /// Update connection duration
    pub fn update_stats(&mut self) {
        self.stats.update_duration();
    }

    /// Get reconnection attempts (for testing)
    #[cfg(test)]
    pub fn get_reconnection_attempts(&self) -> u32 {
        self.reconnection.get_attempts(&self.peer_id)
    }

    /// Force set next reconnection attempt time (for testing)
    #[cfg(test)]
    pub fn set_next_reconnect_time(&mut self, timestamp: u64) {
        if let Some(state) = self.reconnection.peer_states.get_mut(&self.peer_id) {
            state.next_attempt = timestamp;
        }
    }

    /// Schedule reconnection manually (for testing)
    #[cfg(test)]
    pub fn schedule_reconnect(&mut self, reason: String) {
        self.reconnection.schedule_reconnect(&self.peer_id, reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeyPair;

    fn create_test_peer_id() -> PeerId {
        let keypair = IdentityKeyPair::generate().unwrap();
        PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes())
    }

    #[test]
    fn test_connection_creation() {
        let peer_id = create_test_peer_id();
        let conn = Connection::new(peer_id.clone());

        assert_eq!(*conn.peer_id(), peer_id);
        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert!(!conn.is_connected());
        assert!(!conn.is_connecting());
    }

    #[test]
    fn test_connection_state_transitions() {
        let peer_id = create_test_peer_id();
        let mut conn = Connection::new(peer_id);

        // Connect
        assert!(conn.connect().is_ok());
        assert_eq!(conn.state(), ConnectionState::Connecting);
        assert!(conn.is_connecting());

        // Mark as connected
        conn.on_connected();
        assert_eq!(conn.state(), ConnectionState::Connected);
        assert!(conn.is_connected());

        // Close
        conn.close("Test close");
        assert_eq!(conn.state(), ConnectionState::Closed);
        assert!(conn.is_closed());
    }

    #[test]
    fn test_connection_failure_and_reconnect() {
        let peer_id = create_test_peer_id();
        let mut conn = Connection::new(peer_id.clone());

        conn.connect().unwrap();
        conn.on_failed("Test failure".to_string());

        assert!(conn.is_failed());

        // Should be scheduled for reconnection
        assert!(conn.reconnection.get_attempts(&peer_id) > 0);

        // Manually set next_attempt to past so we can reconnect
        if let Some(state) = conn.reconnection.peer_states.get_mut(&peer_id) {
            state.next_attempt = 0;
        }

        assert!(conn.should_reconnect());

        // Reconnect
        assert!(conn.reconnect().is_ok());
    }

    #[test]
    fn test_message_queueing() {
        let peer_id = create_test_peer_id();
        let mut conn = Connection::new(peer_id.clone());

        // Create test message
        use super::super::protocol::{ProtocolMessage, MessagePayload, PingMessage};
        let msg = ProtocolMessage::new(
            peer_id.clone(),
            peer_id.clone(),
            MessagePayload::Ping(PingMessage::new())
        );

        // Queue message while disconnected
        assert!(conn.queue_message(msg.clone()).is_ok());
        assert_eq!(conn.queued_message_count(), 1);

        // Flush queue
        let messages = conn.flush_queue();
        assert_eq!(messages.len(), 1);
        assert_eq!(conn.queued_message_count(), 0);
    }

    #[test]
    fn test_rtt_tracking() {
        let peer_id = create_test_peer_id();
        let mut conn = Connection::new(peer_id);

        conn.on_pong_received(50.0);
        conn.on_pong_received(60.0);
        conn.on_pong_received(55.0);

        let avg_rtt = conn.stats().avg_rtt_ms.unwrap();
        assert!((avg_rtt - 55.0).abs() < 0.1);
    }

    #[test]
    fn test_connection_health_check() {
        let peer_id = create_test_peer_id();
        let mut conn = Connection::new(peer_id);

        // Not healthy when disconnected
        assert!(!conn.is_healthy());

        // Connect and mark as connected
        conn.connect().unwrap();
        conn.on_connected();

        // Should be healthy initially
        assert!(conn.is_healthy());
    }
}
