// Network Module
// Handles P2P connections, message routing, and reconnection logic

pub mod protocol;
pub mod connection;
pub mod manager;
pub mod router;
pub mod reconnect;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::identity::PeerId;

/// Network error types
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Connection closed: {0}")]
    ConnectionClosed(String),

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("WebRTC error: {0}")]
    WebRTCError(String),

    #[error("Ice connection failed")]
    IceConnectionFailed,

    #[error("Data channel error: {0}")]
    DataChannelError(String),
}

pub type NetworkResult<T> = Result<T, NetworkError>;

/// Connection status (legacy - kept for compatibility)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[wasm_bindgen]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Failed,
}

/// Connection state (new enum with more states)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Not connected, idle
    Disconnected,
    /// Attempting to connect
    Connecting,
    /// Fully connected and operational
    Connected,
    /// Connection failed
    Failed,
    /// Connection closed gracefully
    Closed,
}

/// Peer connection info
#[derive(Clone, Debug, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct PeerConnection {
    #[wasm_bindgen(skip)]
    pub peer_id: PeerId,
    #[wasm_bindgen(skip)]
    pub status: ConnectionStatus,
    #[wasm_bindgen(skip)]
    pub last_seen: u64,
}

impl PeerConnection {
    /// Get peer ID (internal use)
    pub fn get_peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get peer ID as hex string (for wasm_bindgen)
    pub fn peer_id_hex(&self) -> String {
        self.peer_id.to_hex()
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Number of messages sent
    pub messages_sent: u64,
    /// Number of messages received
    pub messages_received: u64,
    /// Number of bytes sent
    pub bytes_sent: u64,
    /// Number of bytes received
    pub bytes_received: u64,
    /// Connection established timestamp
    pub connected_at: Option<u64>,
    /// Connection duration in milliseconds
    pub connection_duration_ms: Option<u64>,
    /// Average round-trip time in milliseconds
    pub avg_rtt_ms: Option<f64>,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            connected_at: None,
            connection_duration_ms: None,
            avg_rtt_ms: None,
        }
    }
}

impl ConnectionStats {
    /// Update with a sent message
    pub fn record_sent(&mut self, bytes: u64) {
        self.messages_sent += 1;
        self.bytes_sent += bytes;
    }

    /// Update with a received message
    pub fn record_received(&mut self, bytes: u64) {
        self.messages_received += 1;
        self.bytes_received += bytes;
    }

    /// Mark connection as established
    pub fn mark_connected(&mut self) {
        self.connected_at = Some(js_sys::Date::now() as u64);
    }

    /// Update connection duration
    pub fn update_duration(&mut self) {
        if let Some(connected_at) = self.connected_at {
            let now = js_sys::Date::now() as u64;
            self.connection_duration_ms = Some(now - connected_at);
        }
    }
}
