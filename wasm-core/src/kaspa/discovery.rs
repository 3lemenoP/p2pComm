//! Peer Discovery via Kaspa Blockchain
//!
//! Enables peers to discover each other by broadcasting announcements
//! through blockchain transactions and monitoring for new peers.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use std::collections::HashMap;
use crate::kaspa::envelope::{KaspaEnvelope, EnvelopeType};
use crate::kaspa::types::{PROTOCOL_VERSION, current_timestamp_ms, current_timestamp_secs, generate_message_id};

/// Announcement validity period in seconds (24 hours)
pub const ANNOUNCEMENT_VALIDITY: u64 = 86400;

/// Minimum time between announcements in seconds
pub const ANNOUNCEMENT_COOLDOWN: u64 = 3600;

/// Reputation score bounds
pub const MIN_REPUTATION: i32 = -100;
pub const MAX_REPUTATION: i32 = 100;

/// Reputation threshold for auto-blocking
pub const BLOCK_THRESHOLD: i32 = -50;

/// Peer connection status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[wasm_bindgen]
pub enum PeerStatus {
    /// Discovered but not connected
    Discovered,
    /// Attempting to connect
    Connecting,
    /// Successfully connected
    Connected,
    /// Connection attempt failed
    Failed,
    /// Peer went offline
    Offline,
    /// Blocked by user or reputation
    Banned,
}

impl std::fmt::Display for PeerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovered => write!(f, "discovered"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Failed => write!(f, "failed"),
            Self::Offline => write!(f, "offline"),
            Self::Banned => write!(f, "banned"),
        }
    }
}

/// Peer announcement broadcast via blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct PeerAnnouncement {
    /// Unique peer identifier
    pub peer_id: String,
    /// Kaspa address for receiving messages
    pub kaspa_address: String,
    /// Optional display name
    pub display_name: Option<String>,
    /// Ed25519 public key for encryption (hex)
    pub public_key: String,
    /// Capabilities supported by this peer
    pub capabilities: Vec<String>,
    /// Protocol version
    pub protocol_version: String,
    /// Announcement timestamp
    pub timestamp: u64,
    /// Signature of announcement (hex)
    pub signature: Vec<u8>,
}

#[wasm_bindgen]
impl PeerAnnouncement {
    /// Create a new peer announcement
    #[wasm_bindgen(constructor)]
    pub fn new(
        peer_id: String,
        kaspa_address: String,
        public_key: String,
    ) -> Self {
        Self {
            peer_id,
            kaspa_address,
            display_name: None,
            public_key,
            capabilities: vec!["messaging".to_string(), "webrtc".to_string()],
            protocol_version: PROTOCOL_VERSION.to_string(),
            timestamp: current_timestamp_secs(),
            signature: Vec::new(),
        }
    }

    /// Set display name
    pub fn with_display_name(mut self, name: String) -> Self {
        self.display_name = Some(name);
        self
    }

    /// Add capability
    pub fn with_capability(mut self, capability: String) -> Self {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
        }
        self
    }

    /// Check if announcement is still valid
    pub fn is_valid(&self) -> bool {
        let now = current_timestamp_secs();
        now.saturating_sub(self.timestamp) < ANNOUNCEMENT_VALIDITY
    }

    /// Get remaining validity in seconds
    pub fn validity_remaining(&self) -> u64 {
        let now = current_timestamp_secs();
        let age = now.saturating_sub(self.timestamp);
        ANNOUNCEMENT_VALIDITY.saturating_sub(age)
    }
}

impl PeerAnnouncement {
    /// Convert to KaspaEnvelope for sending
    pub fn to_envelope(&self, sender_peer_id: &str) -> KaspaEnvelope {
        let payload = serde_json::to_string(self).unwrap();
        KaspaEnvelope::peer_announcement(sender_peer_id.to_string(), payload)
    }

    /// Parse from envelope payload
    pub fn from_envelope_payload(payload: &str) -> Option<Self> {
        serde_json::from_str(payload).ok()
    }
}

/// Information about a discovered peer (Kaspa-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    /// Peer identifier
    pub peer_id: String,
    /// Last announcement received
    pub announcement: PeerAnnouncement,
    /// Current status
    pub status: PeerStatus,
    /// Reputation score (-100 to 100)
    pub reputation: i32,
    /// Successful connection count
    pub successful_connections: u32,
    /// Failed connection count
    pub failed_connections: u32,
    /// Last successful connection timestamp
    pub last_connected: Option<u64>,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Whether manually blocked
    pub manually_blocked: bool,
    /// User-assigned tags
    pub tags: Vec<String>,
}

impl DiscoveredPeer {
    /// Update reputation
    pub fn adjust_reputation(&mut self, delta: i32) {
        self.reputation = (self.reputation + delta).clamp(MIN_REPUTATION, MAX_REPUTATION);

        // Auto-block if reputation too low
        if self.reputation <= BLOCK_THRESHOLD {
            self.status = PeerStatus::Banned;
        }
    }

    /// Record successful connection
    pub fn record_success(&mut self) {
        self.successful_connections += 1;
        self.last_connected = Some(current_timestamp_ms());
        self.status = PeerStatus::Connected;
        self.adjust_reputation(5);
    }

    /// Record failed connection
    pub fn record_failure(&mut self) {
        self.failed_connections += 1;
        self.status = PeerStatus::Failed;
        self.adjust_reputation(-10);
    }

    /// Check if peer should be auto-connected
    pub fn should_auto_connect(&self) -> bool {
        // Don't connect if banned, already connected, or bad reputation
        if self.manually_blocked || self.reputation < 0 {
            return false;
        }

        matches!(self.status, PeerStatus::Discovered | PeerStatus::Offline)
    }

    /// Get connection success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_connections + self.failed_connections;
        if total == 0 {
            0.5 // Default 50% for new peers
        } else {
            self.successful_connections as f64 / total as f64
        }
    }
}

impl DiscoveredPeer {
    /// Create from announcement
    pub fn from_announcement(announcement: PeerAnnouncement) -> Self {
        Self {
            peer_id: announcement.peer_id.clone(),
            last_seen: current_timestamp_ms(),
            status: PeerStatus::Discovered,
            reputation: 50, // Start neutral-positive
            successful_connections: 0,
            failed_connections: 0,
            last_connected: None,
            manually_blocked: false,
            tags: Vec::new(),
            announcement,
        }
    }

    /// Update with new announcement
    pub fn update_announcement(&mut self, announcement: PeerAnnouncement) {
        self.announcement = announcement;
        self.last_seen = current_timestamp_ms();

        // Peer came back, update status if offline
        if self.status == PeerStatus::Offline {
            self.status = PeerStatus::Discovered;
        }
    }
}

/// Discovery statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct DiscoveryStats {
    pub peers_discovered: u32,
    pub announcements_received: u32,
    pub announcements_broadcast: u32,
    pub connections_initiated: u32,
    pub connections_established: u32,
    pub connections_failed: u32,
    pub peers_banned: u32,
}

/// Manager for peer discovery via blockchain
#[wasm_bindgen]
pub struct PeerDiscoveryManager {
    /// Our peer ID
    local_peer_id: String,
    /// Known peers
    peers: HashMap<String, DiscoveredPeer>,
    /// Last announcement broadcast time
    last_announcement: Option<u64>,
    /// Statistics
    stats: DiscoveryStats,
}

#[wasm_bindgen]
impl PeerDiscoveryManager {
    /// Create a new discovery manager
    #[wasm_bindgen(constructor)]
    pub fn new(local_peer_id: String) -> Self {
        Self {
            local_peer_id,
            peers: HashMap::new(),
            last_announcement: None,
            stats: DiscoveryStats::default(),
        }
    }

    /// Get our peer ID
    pub fn local_peer_id(&self) -> String {
        self.local_peer_id.clone()
    }

    /// Get number of known peers
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get number of connected peers
    pub fn connected_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.status == PeerStatus::Connected)
            .count()
    }

    /// Get statistics
    pub fn get_stats(&self) -> DiscoveryStats {
        self.stats.clone()
    }

    /// Check if we can broadcast announcement
    pub fn can_announce(&self) -> bool {
        match self.last_announcement {
            None => true,
            Some(last) => {
                let now = current_timestamp_secs();
                now.saturating_sub(last) >= ANNOUNCEMENT_COOLDOWN
            }
        }
    }
}

impl PeerDiscoveryManager {
    /// Process incoming announcement
    pub fn process_announcement(&mut self, announcement: PeerAnnouncement) -> bool {
        // Ignore our own announcements
        if announcement.peer_id == self.local_peer_id {
            return false;
        }

        // Validate announcement
        if !announcement.is_valid() {
            return false;
        }

        self.stats.announcements_received += 1;

        // Update or add peer
        if let Some(peer) = self.peers.get_mut(&announcement.peer_id) {
            peer.update_announcement(announcement);
        } else {
            let peer_info = DiscoveredPeer::from_announcement(announcement);
            self.peers.insert(peer_info.peer_id.clone(), peer_info);
            self.stats.peers_discovered += 1;
        }

        true
    }

    /// Get peer by ID
    pub fn get_peer(&self, peer_id: &str) -> Option<&DiscoveredPeer> {
        self.peers.get(peer_id)
    }

    /// Get mutable peer by ID
    pub fn get_peer_mut(&mut self, peer_id: &str) -> Option<&mut DiscoveredPeer> {
        self.peers.get_mut(peer_id)
    }

    /// Get all peers
    pub fn get_all_peers(&self) -> Vec<&DiscoveredPeer> {
        self.peers.values().collect()
    }

    /// Get peers suitable for auto-connection
    pub fn get_auto_connect_candidates(&self, limit: usize) -> Vec<&DiscoveredPeer> {
        let mut candidates: Vec<_> = self.peers
            .values()
            .filter(|p| p.should_auto_connect())
            .collect();

        // Sort by reputation (highest first)
        candidates.sort_by(|a, b| b.reputation.cmp(&a.reputation));

        candidates.into_iter().take(limit).collect()
    }

    /// Block a peer
    pub fn block_peer(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.manually_blocked = true;
            peer.status = PeerStatus::Banned;
            self.stats.peers_banned += 1;
        }
    }

    /// Unblock a peer
    pub fn unblock_peer(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.manually_blocked = false;
            if peer.reputation > BLOCK_THRESHOLD {
                peer.status = PeerStatus::Discovered;
            }
        }
    }

    /// Add tag to peer
    pub fn add_peer_tag(&mut self, peer_id: &str, tag: String) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            if !peer.tags.contains(&tag) {
                peer.tags.push(tag);
            }
        }
    }

    /// Mark announcement as broadcast
    pub fn mark_announced(&mut self) {
        self.last_announcement = Some(current_timestamp_secs());
        self.stats.announcements_broadcast += 1;
    }

    /// Update peer status
    pub fn update_peer_status(&mut self, peer_id: &str, status: PeerStatus) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.status = status;

            match status {
                PeerStatus::Connected => {
                    peer.record_success();
                    self.stats.connections_established += 1;
                }
                PeerStatus::Failed => {
                    peer.record_failure();
                    self.stats.connections_failed += 1;
                }
                PeerStatus::Connecting => {
                    self.stats.connections_initiated += 1;
                }
                _ => {}
            }
        }
    }

    /// Get peers by status
    pub fn get_peers_by_status(&self, status: PeerStatus) -> Vec<&DiscoveredPeer> {
        self.peers
            .values()
            .filter(|p| p.status == status)
            .collect()
    }

    /// Remove stale peers that haven't been seen for a while
    pub fn cleanup_stale_peers(&mut self, max_age_secs: u64) {
        let now = current_timestamp_ms();
        let threshold = now.saturating_sub(max_age_secs * 1000);

        self.peers.retain(|_, peer| {
            peer.last_seen > threshold || peer.status == PeerStatus::Connected
        });
    }

    /// Create announcement for broadcasting
    pub fn create_announcement(
        &self,
        kaspa_address: String,
        public_key: String,
        display_name: Option<String>,
    ) -> PeerAnnouncement {
        let mut announcement = PeerAnnouncement::new(
            self.local_peer_id.clone(),
            kaspa_address,
            public_key,
        );

        if let Some(name) = display_name {
            announcement = announcement.with_display_name(name);
        }

        announcement
    }
}

/// Process discovery envelopes from blockchain
pub fn process_discovery_envelope(
    manager: &mut PeerDiscoveryManager,
    envelope: &KaspaEnvelope,
) -> bool {
    if envelope.envelope_type != EnvelopeType::PeerAnnouncement {
        return false;
    }

    if let Some(announcement) = PeerAnnouncement::from_envelope_payload(&envelope.payload) {
        return manager.process_announcement(announcement);
    }

    false
}

// ============================================================================
// WASM Bindings for Global Discovery Manager
// ============================================================================

use std::cell::RefCell;

thread_local! {
    static DISCOVERY_MANAGER: RefCell<Option<PeerDiscoveryManager>> = RefCell::new(None);
}

/// Initialize the global discovery manager
#[wasm_bindgen]
pub fn kaspa_discovery_init(local_peer_id: String) -> Result<(), JsValue> {
    DISCOVERY_MANAGER.with(|manager| {
        *manager.borrow_mut() = Some(PeerDiscoveryManager::new(local_peer_id));
        Ok(())
    })
}

/// Get discovered peers
#[wasm_bindgen]
pub fn kaspa_discovery_get_peers() -> Result<JsValue, JsValue> {
    DISCOVERY_MANAGER.with(|manager| {
        let manager = manager.borrow();
        let manager = manager.as_ref()
            .ok_or_else(|| JsValue::from_str("Discovery manager not initialized"))?;

        let peers: Vec<&DiscoveredPeer> = manager.peers.values().collect();
        serde_wasm_bindgen::to_value(&peers)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}
