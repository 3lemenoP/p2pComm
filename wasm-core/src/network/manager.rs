// Network Manager
// Central coordinator for all P2P connections

use crate::identity::PeerId;
use super::{NetworkResult, NetworkError, ConnectionState};
use super::connection::Connection;
use super::protocol::{ProtocolMessage, MessagePayload, PingMessage, PongMessage};
use std::collections::HashMap;

/// Maximum concurrent connections
const MAX_CONNECTIONS: usize = 50;

/// Network manager for coordinating P2P connections
pub struct NetworkManager {
    /// Active peer connections
    connections: HashMap<PeerId, Connection>,

    /// Local peer ID
    local_peer_id: Option<PeerId>,
}

impl NetworkManager {
    /// Create a new network manager
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            local_peer_id: None,
        }
    }

    /// Set the local peer ID
    pub fn set_local_peer_id(&mut self, peer_id: PeerId) {
        self.local_peer_id = Some(peer_id);
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> Option<&PeerId> {
        self.local_peer_id.as_ref()
    }

    /// Add a new connection
    pub fn add_connection(&mut self, peer_id: PeerId) -> NetworkResult<()> {
        if self.connections.len() >= MAX_CONNECTIONS {
            return Err(NetworkError::ConnectionFailed(
                "Maximum connections reached".to_string()
            ));
        }

        if self.connections.contains_key(&peer_id) {
            return Err(NetworkError::ConnectionFailed(
                "Connection already exists".to_string()
            ));
        }

        let connection = Connection::new(peer_id.clone());
        self.connections.insert(peer_id, connection);

        Ok(())
    }

    /// Remove a connection
    pub fn remove_connection(&mut self, peer_id: &PeerId) -> bool {
        self.connections.remove(peer_id).is_some()
    }

    /// Get a connection by peer ID
    pub fn get_connection(&self, peer_id: &PeerId) -> Option<&Connection> {
        self.connections.get(peer_id)
    }

    /// Get a mutable connection by peer ID
    pub fn get_connection_mut(&mut self, peer_id: &PeerId) -> Option<&mut Connection> {
        self.connections.get_mut(peer_id)
    }

    /// Get all active connections
    pub fn get_active_connections(&self) -> Vec<&Connection> {
        self.connections
            .values()
            .filter(|c| c.is_connected())
            .collect()
    }

    /// Get all peer IDs
    pub fn get_peer_ids(&self) -> Vec<PeerId> {
        self.connections.keys().cloned().collect()
    }

    /// Connect to a peer
    pub fn connect_to_peer(&mut self, peer_id: PeerId) -> NetworkResult<()> {
        // Add connection if it doesn't exist
        if !self.connections.contains_key(&peer_id) {
            self.add_connection(peer_id.clone())?;
        }

        // Initiate connection
        if let Some(conn) = self.get_connection_mut(&peer_id) {
            conn.connect()?;
        }

        Ok(())
    }

    /// Disconnect from a peer
    pub fn disconnect_peer(&mut self, peer_id: &PeerId, reason: &str) -> NetworkResult<()> {
        if let Some(conn) = self.get_connection_mut(peer_id) {
            conn.close(reason);
        }

        Ok(())
    }

    /// Disconnect all peers
    pub fn disconnect_all(&mut self, reason: &str) {
        for conn in self.connections.values_mut() {
            conn.close(reason);
        }
    }

    /// Send a message to a specific peer
    pub fn send_to_peer(
        &mut self,
        peer_id: &PeerId,
        message: ProtocolMessage
    ) -> NetworkResult<Vec<u8>> {
        let conn = self.get_connection_mut(peer_id)
            .ok_or_else(|| NetworkError::PeerNotFound(peer_id.to_hex()))?;

        conn.send_message(message)
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast(&mut self, create_message: impl Fn(&PeerId) -> ProtocolMessage) -> usize {
        let peer_ids: Vec<PeerId> = self.get_active_connections()
            .iter()
            .map(|c| c.peer_id().clone())
            .collect();

        let mut sent_count = 0;
        for peer_id in peer_ids {
            let message = create_message(&peer_id);
            if self.send_to_peer(&peer_id, message).is_ok() {
                sent_count += 1;
            }
        }

        sent_count
    }

    /// Handle incoming message from a peer
    pub fn handle_incoming_message(
        &mut self,
        peer_id: &PeerId,
        bytes: &[u8]
    ) -> NetworkResult<ProtocolMessage> {
        let conn = self.get_connection_mut(peer_id)
            .ok_or_else(|| NetworkError::PeerNotFound(peer_id.to_hex()))?;

        conn.receive_message(bytes)
    }

    /// Mark a connection as established
    pub fn mark_connected(&mut self, peer_id: &PeerId) {
        if let Some(conn) = self.get_connection_mut(peer_id) {
            conn.on_connected();
        }
    }

    /// Mark a connection as failed
    pub fn mark_failed(&mut self, peer_id: &PeerId, reason: String) {
        if let Some(conn) = self.get_connection_mut(peer_id) {
            conn.on_failed(reason);
        }
    }

    /// Set WebRTC connection ID for a peer
    pub fn set_connection_id(&mut self, peer_id: &PeerId, connection_id: String) {
        if let Some(conn) = self.get_connection_mut(peer_id) {
            conn.set_connection_id(connection_id);
        }
    }

    /// Send ping to all connected peers
    pub fn send_keepalive_pings(&mut self) -> NetworkResult<Vec<(PeerId, PingMessage)>> {
        let local_peer_id = self.local_peer_id
            .as_ref()
            .ok_or_else(|| NetworkError::ProtocolError(
                "Local peer ID not set".to_string()
            ))?
            .clone();

        let mut pings = Vec::new();

        for (peer_id, conn) in self.connections.iter_mut() {
            if !conn.is_connected() {
                continue;
            }

            if conn.send_ping() {
                let ping = PingMessage::new();
                let message = ProtocolMessage::new(
                    local_peer_id.clone(),
                    peer_id.clone(),
                    MessagePayload::Ping(ping.clone())
                );

                match conn.send_message(message) {
                    Ok(_) => pings.push((peer_id.clone(), ping)),
                    Err(e) => {
                        web_sys::console::warn_1(&format!(
                            "Failed to send ping to {}: {:?}",
                            peer_id.to_hex(),
                            e
                        ).into());
                    }
                }
            }
        }

        Ok(pings)
    }

    /// Handle pong response
    pub fn handle_pong(&mut self, peer_id: &PeerId, pong: &PongMessage) {
        if let Some(conn) = self.get_connection_mut(peer_id) {
            let rtt = pong.calculate_rtt() as f64;
            conn.on_pong_received(rtt);
        }
    }

    /// Check and handle reconnections
    pub fn check_reconnections(&mut self) -> Vec<PeerId> {
        let mut to_reconnect = Vec::new();

        for (peer_id, conn) in self.connections.iter_mut() {
            if conn.should_reconnect() {
                let delay = conn.get_reconnect_delay();
                if delay == 0 {
                    continue; // Max retries reached
                }

                // In a real implementation, this would schedule based on delay
                // For now, we just collect peers that need reconnection
                to_reconnect.push(peer_id.clone());
            }
        }

        to_reconnect
    }

    /// Attempt to reconnect to a peer
    pub fn reconnect_to_peer(&mut self, peer_id: &PeerId) -> NetworkResult<()> {
        let conn = self.get_connection_mut(peer_id)
            .ok_or_else(|| NetworkError::PeerNotFound(peer_id.to_hex()))?;

        conn.reconnect()
    }

    /// Clean up closed and failed connections
    pub fn cleanup_connections(&mut self) -> usize {
        let mut to_remove = Vec::new();

        for (peer_id, conn) in self.connections.iter() {
            if conn.is_closed() || (conn.is_failed() && !conn.should_reconnect()) {
                to_remove.push(peer_id.clone());
            }
        }

        let count = to_remove.len();
        for peer_id in to_remove {
            self.remove_connection(&peer_id);
        }

        count
    }

    /// Check connection health and mark unhealthy ones as failed
    pub fn check_connection_health(&mut self) -> Vec<PeerId> {
        let mut unhealthy = Vec::new();

        for (peer_id, conn) in self.connections.iter_mut() {
            if conn.is_connected() && !conn.is_healthy() {
                conn.on_failed("Connection timeout".to_string());
                unhealthy.push(peer_id.clone());
            }
        }

        unhealthy
    }

    /// Get connection count
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get active connection count
    pub fn active_connection_count(&self) -> usize {
        self.connections
            .values()
            .filter(|c| c.is_connected())
            .count()
    }

    /// Get connection state for a peer
    pub fn get_connection_state(&self, peer_id: &PeerId) -> Option<ConnectionState> {
        self.get_connection(peer_id).map(|c| c.state())
    }

    /// Get aggregate statistics
    pub fn get_aggregate_stats(&self) -> NetworkManagerStats {
        let mut stats = NetworkManagerStats::default();

        stats.total_connections = self.connection_count();
        stats.active_connections = self.active_connection_count();

        for conn in self.connections.values() {
            let conn_stats = conn.stats();
            stats.total_messages_sent += conn_stats.messages_sent;
            stats.total_messages_received += conn_stats.messages_received;
            stats.total_bytes_sent += conn_stats.bytes_sent;
            stats.total_bytes_received += conn_stats.bytes_received;

            if let Some(rtt) = conn_stats.avg_rtt_ms {
                stats.rtt_samples.push(rtt);
            }
        }

        // Calculate average RTT
        if !stats.rtt_samples.is_empty() {
            stats.avg_rtt_ms = Some(
                stats.rtt_samples.iter().sum::<f64>() / stats.rtt_samples.len() as f64
            );
        }

        stats
    }

    /// Update all connection stats
    pub fn update_stats(&mut self) {
        for conn in self.connections.values_mut() {
            conn.update_stats();
        }
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate network statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkManagerStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub avg_rtt_ms: Option<f64>,
    pub rtt_samples: Vec<f64>,
}

impl Default for NetworkManagerStats {
    fn default() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            total_messages_sent: 0,
            total_messages_received: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            avg_rtt_ms: None,
            rtt_samples: Vec::new(),
        }
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
    fn test_manager_creation() {
        let manager = NetworkManager::new();
        assert_eq!(manager.connection_count(), 0);
        assert_eq!(manager.active_connection_count(), 0);
    }

    #[test]
    fn test_add_remove_connection() {
        let mut manager = NetworkManager::new();
        let peer_id = create_test_peer_id();

        // Add connection
        assert!(manager.add_connection(peer_id.clone()).is_ok());
        assert_eq!(manager.connection_count(), 1);

        // Remove connection
        assert!(manager.remove_connection(&peer_id));
        assert_eq!(manager.connection_count(), 0);
    }

    #[test]
    fn test_duplicate_connection() {
        let mut manager = NetworkManager::new();
        let peer_id = create_test_peer_id();

        assert!(manager.add_connection(peer_id.clone()).is_ok());
        assert!(manager.add_connection(peer_id).is_err());
    }

    #[test]
    fn test_connect_to_peer() {
        let mut manager = NetworkManager::new();
        let peer_id = create_test_peer_id();

        assert!(manager.connect_to_peer(peer_id.clone()).is_ok());

        let conn = manager.get_connection(&peer_id).unwrap();
        assert!(conn.is_connecting());
    }

    #[test]
    fn test_mark_connected() {
        let mut manager = NetworkManager::new();
        let peer_id = create_test_peer_id();

        manager.connect_to_peer(peer_id.clone()).unwrap();
        manager.mark_connected(&peer_id);

        let conn = manager.get_connection(&peer_id).unwrap();
        assert!(conn.is_connected());
        assert_eq!(manager.active_connection_count(), 1);
    }

    #[test]
    fn test_disconnect() {
        let mut manager = NetworkManager::new();
        let peer_id = create_test_peer_id();

        manager.connect_to_peer(peer_id.clone()).unwrap();
        manager.mark_connected(&peer_id);
        manager.disconnect_peer(&peer_id, "Test").unwrap();

        let conn = manager.get_connection(&peer_id).unwrap();
        assert!(conn.is_closed());
    }

    #[test]
    fn test_cleanup_connections() {
        let mut manager = NetworkManager::new();
        let peer1 = create_test_peer_id();
        let peer2 = create_test_peer_id();

        manager.connect_to_peer(peer1.clone()).unwrap();
        manager.connect_to_peer(peer2.clone()).unwrap();

        // Close one connection
        manager.disconnect_peer(&peer1, "Test").unwrap();

        // Cleanup should remove the closed connection
        let removed = manager.cleanup_connections();
        assert_eq!(removed, 1);
        assert_eq!(manager.connection_count(), 1);
    }

    #[test]
    fn test_aggregate_stats() {
        let mut manager = NetworkManager::new();
        let peer_id = create_test_peer_id();

        manager.connect_to_peer(peer_id.clone()).unwrap();
        manager.mark_connected(&peer_id);

        let stats = manager.get_aggregate_stats();
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.active_connections, 1);
    }
}
