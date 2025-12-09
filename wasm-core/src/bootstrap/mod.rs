// Bootstrap Module
// Handles initial peer discovery via QR codes, mDNS, and invite links

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::identity::PeerId;

pub mod qr;
pub mod invite;
pub mod cache;

/// Connection method used for establishing P2P connection
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum BootstrapMethod {
    QRCode,          // Scanned QR code
    InviteLink,      // Clicked invite link
    LocalNetwork,    // mDNS discovery
    Cached,          // Previously connected peer
}

/// Connection information for WebRTC establishment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// ICE candidates (STUN/TURN server addresses)
    pub ice_servers: Vec<IceServer>,
    /// Direct IP addresses (if available)
    pub direct_addresses: Vec<String>,
    /// Timestamp when this info was generated
    pub timestamp: u64,
}

impl ConnectionInfo {
    /// Create new connection info with default ICE servers
    pub fn new() -> Self {
        Self {
            ice_servers: vec![
                IceServer {
                    urls: vec!["stun:stun.l.google.com:19302".to_string()],
                    username: None,
                    credential: None,
                },
                IceServer {
                    urls: vec!["stun:stun1.l.google.com:19302".to_string()],
                    username: None,
                    credential: None,
                },
            ],
            direct_addresses: Vec::new(),
            timestamp: js_sys::Date::now() as u64,
        }
    }

    /// Add a direct address (IP:port)
    pub fn add_address(&mut self, address: String) {
        if !self.direct_addresses.contains(&address) {
            self.direct_addresses.push(address);
        }
    }

    /// Add an ICE server
    pub fn add_ice_server(&mut self, server: IceServer) {
        self.ice_servers.push(server);
    }
}

impl Default for ConnectionInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// ICE server configuration (STUN/TURN)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IceServer {
    /// Server URLs
    pub urls: Vec<String>,
    /// Username (for TURN servers)
    pub username: Option<String>,
    /// Credential (for TURN servers)
    pub credential: Option<String>,
}

/// Complete peer information for bootstrap
#[derive(Clone, Debug, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct PeerInfo {
    /// Version of the PeerInfo format
    pub version: u8,
    /// Peer's unique identifier
    #[wasm_bindgen(skip)]
    pub peer_id: PeerId,
    /// Peer's Ed25519 signing public key
    #[wasm_bindgen(skip)]
    pub signing_public_key: Vec<u8>,
    /// Peer's X25519 encryption public key
    #[wasm_bindgen(skip)]
    pub encryption_public_key: Vec<u8>,
    /// Connection information
    #[wasm_bindgen(skip)]
    pub connection_info: ConnectionInfo,
    /// Timestamp when this info was created
    pub timestamp: u64,
}

impl PeerInfo {
    /// Current version of PeerInfo format
    pub const VERSION: u8 = 1;

    /// Create new PeerInfo
    pub fn new(
        peer_id: PeerId,
        signing_public_key: Vec<u8>,
        encryption_public_key: Vec<u8>,
        connection_info: ConnectionInfo,
    ) -> Self {
        Self {
            version: Self::VERSION,
            peer_id,
            signing_public_key,
            encryption_public_key,
            connection_info,
            timestamp: js_sys::Date::now() as u64,
        }
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self)
            .map_err(|e| format!("Failed to serialize PeerInfo: {}", e))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("Failed to deserialize PeerInfo: {}", e))
    }

    /// Serialize to binary (bincode)
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self)
            .map_err(|e| format!("Failed to serialize PeerInfo to bytes: {}", e))
    }

    /// Deserialize from binary (bincode)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes)
            .map_err(|e| format!("Failed to deserialize PeerInfo from bytes: {}", e))
    }

    /// Get peer ID (internal use)
    pub fn get_peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get peer ID as hex string (for wasm_bindgen)
    pub fn peer_id_hex(&self) -> String {
        self.peer_id.to_hex()
    }

    /// Get signing public key
    pub fn get_signing_public_key(&self) -> &[u8] {
        &self.signing_public_key
    }

    /// Get encryption public key
    pub fn get_encryption_public_key(&self) -> &[u8] {
        &self.encryption_public_key
    }

    /// Check if this PeerInfo is expired (older than 24 hours by default)
    pub fn is_expired(&self, max_age_ms: Option<u64>) -> bool {
        let max_age = max_age_ms.unwrap_or(24 * 60 * 60 * 1000); // 24 hours default
        let now = js_sys::Date::now() as u64;
        now > self.timestamp + max_age
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeyPair;

    #[test]
    fn test_connection_info() {
        let mut info = ConnectionInfo::new();
        assert_eq!(info.ice_servers.len(), 2); // Default STUN servers
        assert_eq!(info.direct_addresses.len(), 0);

        info.add_address("192.168.1.100:5000".to_string());
        assert_eq!(info.direct_addresses.len(), 1);

        // Adding same address again should not duplicate
        info.add_address("192.168.1.100:5000".to_string());
        assert_eq!(info.direct_addresses.len(), 1);

        info.add_ice_server(IceServer {
            urls: vec!["stun:custom.server.com:3478".to_string()],
            username: None,
            credential: None,
        });
        assert_eq!(info.ice_servers.len(), 3);
    }

    #[test]
    fn test_peer_info_creation() {
        let keypair = IdentityKeyPair::generate().unwrap();
        let peer_id = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let signing_pk = keypair.signing_keypair.verifying_key.to_bytes().to_vec();
        let encryption_pk = keypair.encryption_keypair.public_key.as_bytes().to_vec();

        let conn_info = ConnectionInfo::new();
        let peer_info = PeerInfo::new(peer_id.clone(), signing_pk, encryption_pk, conn_info);

        assert_eq!(peer_info.version, PeerInfo::VERSION);
        assert_eq!(peer_info.peer_id, peer_id);
        assert!(!peer_info.is_expired(None));
    }

    #[test]
    fn test_peer_info_json_serialization() {
        let keypair = IdentityKeyPair::generate().unwrap();
        let peer_id = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let signing_pk = keypair.signing_keypair.verifying_key.to_bytes().to_vec();
        let encryption_pk = keypair.encryption_keypair.public_key.as_bytes().to_vec();

        let conn_info = ConnectionInfo::new();
        let peer_info = PeerInfo::new(peer_id.clone(), signing_pk, encryption_pk, conn_info);

        // Serialize to JSON
        let json = peer_info.to_json().unwrap();
        assert!(!json.is_empty());

        // Deserialize back
        let decoded = PeerInfo::from_json(&json).unwrap();
        assert_eq!(decoded.peer_id, peer_info.peer_id);
        assert_eq!(decoded.version, peer_info.version);
    }

    #[test]
    fn test_peer_info_binary_serialization() {
        let keypair = IdentityKeyPair::generate().unwrap();
        let peer_id = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let signing_pk = keypair.signing_keypair.verifying_key.to_bytes().to_vec();
        let encryption_pk = keypair.encryption_keypair.public_key.as_bytes().to_vec();

        let conn_info = ConnectionInfo::new();
        let peer_info = PeerInfo::new(peer_id.clone(), signing_pk, encryption_pk, conn_info);

        // Serialize to bytes
        let bytes = peer_info.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        // Deserialize back
        let decoded = PeerInfo::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.peer_id, peer_info.peer_id);
        assert_eq!(decoded.version, peer_info.version);
    }

    #[test]
    fn test_peer_info_expiration() {
        let keypair = IdentityKeyPair::generate().unwrap();
        let peer_id = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let signing_pk = keypair.signing_keypair.verifying_key.to_bytes().to_vec();
        let encryption_pk = keypair.encryption_keypair.public_key.as_bytes().to_vec();

        let conn_info = ConnectionInfo::new();
        let mut peer_info = PeerInfo::new(peer_id, signing_pk, encryption_pk, conn_info);

        // Should not be expired with short max age
        assert!(!peer_info.is_expired(Some(1000000000)));

        // Set timestamp to 25 hours ago
        peer_info.timestamp = js_sys::Date::now() as u64 - (25 * 60 * 60 * 1000);

        // Should be expired (default 24 hours)
        assert!(peer_info.is_expired(None));

        // Should not be expired with longer max age
        assert!(!peer_info.is_expired(Some(48 * 60 * 60 * 1000)));
    }
}
