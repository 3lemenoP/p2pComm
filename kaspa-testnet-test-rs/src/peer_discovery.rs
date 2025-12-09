/// Peer Discovery and Automated Connections for P2PComm
///
/// This module implements peer discovery over Kaspa blockchain:
/// - Peer announcements via transactions
/// - Discovery of other peers from blockchain
/// - Automated connection establishment
/// - Peer reputation and reliability tracking
/// - NAT traversal coordination

use anyhow::{Result, Context, bail};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::webrtc_signaling::{SignalingManager, SignalingState};

/// Peer announcement validity duration (seconds)
pub const ANNOUNCEMENT_TTL: i64 = 3600; // 1 hour

/// Maximum peers to track
pub const MAX_TRACKED_PEERS: usize = 1000;

/// Minimum reputation for auto-connect
pub const MIN_AUTO_CONNECT_REPUTATION: i32 = 0;

/// Announcement cooldown (seconds)
pub const ANNOUNCEMENT_COOLDOWN: i64 = 300; // 5 minutes

/// Peer status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    /// Discovered but not connected
    Discovered,
    /// Connection in progress
    Connecting,
    /// Successfully connected
    Connected,
    /// Connection failed
    Failed,
    /// Peer is offline/unreachable
    Offline,
    /// Peer banned due to bad behavior
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

/// Peer announcement data (broadcast via Kaspa transaction)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    /// Peer ID (Blake3 hash of public key)
    pub peer_id: String,
    /// Kaspa address for receiving signaling
    pub kaspa_address: String,
    /// Display name (optional)
    pub display_name: Option<String>,
    /// Public key for encryption
    pub public_key: String,
    /// Supported features/capabilities
    pub capabilities: Vec<String>,
    /// Protocol version
    pub protocol_version: String,
    /// Timestamp of announcement
    pub timestamp: u64,
    /// Signature of announcement data
    pub signature: Vec<u8>,
}

impl PeerAnnouncement {
    /// Create a new peer announcement
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
            capabilities: vec!["chat".to_string(), "signaling".to_string()],
            protocol_version: "p2pcomm/1.0".to_string(),
            timestamp: Utc::now().timestamp_millis() as u64,
            signature: Vec::new(),
        }
    }

    /// Set display name
    pub fn with_display_name(mut self, name: &str) -> Self {
        self.display_name = Some(name.to_string());
        self
    }

    /// Add capability
    pub fn with_capability(mut self, capability: &str) -> Self {
        if !self.capabilities.contains(&capability.to_string()) {
            self.capabilities.push(capability.to_string());
        }
        self
    }

    /// Serialize for signing/transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple serialization - in production would use a more robust format
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Check if announcement is still valid (not expired)
    pub fn is_valid(&self, ttl_seconds: i64) -> bool {
        let now_ms = Utc::now().timestamp_millis() as u64;
        let age_seconds = (now_ms.saturating_sub(self.timestamp)) / 1000;
        age_seconds <= ttl_seconds as u64
    }

    /// Check if peer supports a capability
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.contains(&capability.to_string())
    }
}

/// Information about a discovered peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: String,
    /// Latest announcement from this peer
    pub announcement: PeerAnnouncement,
    /// Current status
    pub status: PeerStatus,
    /// Reputation score (-100 to 100)
    pub reputation: i32,
    /// Number of successful connections
    pub successful_connections: u32,
    /// Number of failed connection attempts
    pub failed_connections: u32,
    /// Last connection attempt
    pub last_connection_attempt: Option<DateTime<Utc>>,
    /// Last successful connection
    pub last_connected: Option<DateTime<Utc>>,
    /// When this peer was first discovered
    pub discovered_at: DateTime<Utc>,
    /// When the peer info was last updated
    pub updated_at: DateTime<Utc>,
    /// Custom notes/tags
    pub tags: HashSet<String>,
}

impl PeerInfo {
    /// Create from announcement
    pub fn from_announcement(announcement: PeerAnnouncement) -> Self {
        let now = Utc::now();
        Self {
            peer_id: announcement.peer_id.clone(),
            announcement,
            status: PeerStatus::Discovered,
            reputation: 50, // Start with neutral reputation
            successful_connections: 0,
            failed_connections: 0,
            last_connection_attempt: None,
            last_connected: None,
            discovered_at: now,
            updated_at: now,
            tags: HashSet::new(),
        }
    }

    /// Update from new announcement
    pub fn update_announcement(&mut self, announcement: PeerAnnouncement) {
        self.announcement = announcement;
        self.updated_at = Utc::now();
    }

    /// Record successful connection
    pub fn record_connection_success(&mut self) {
        self.successful_connections += 1;
        self.status = PeerStatus::Connected;
        self.last_connected = Some(Utc::now());
        self.adjust_reputation(5); // Boost reputation
    }

    /// Record failed connection
    pub fn record_connection_failure(&mut self) {
        self.failed_connections += 1;
        self.status = PeerStatus::Failed;
        self.adjust_reputation(-10); // Penalize reputation
    }

    /// Adjust reputation (clamped to -100 to 100)
    pub fn adjust_reputation(&mut self, delta: i32) {
        self.reputation = (self.reputation + delta).clamp(-100, 100);
        if self.reputation <= -50 {
            self.status = PeerStatus::Banned;
        }
    }

    /// Check if we should auto-connect to this peer
    pub fn should_auto_connect(&self) -> bool {
        self.reputation >= MIN_AUTO_CONNECT_REPUTATION
            && !matches!(self.status, PeerStatus::Connected | PeerStatus::Connecting | PeerStatus::Banned)
    }

    /// Get connection success rate
    pub fn connection_success_rate(&self) -> f64 {
        let total = self.successful_connections + self.failed_connections;
        if total == 0 {
            1.0 // Assume good until proven otherwise
        } else {
            self.successful_connections as f64 / total as f64
        }
    }

    /// Add a tag to this peer
    pub fn add_tag(&mut self, tag: &str) {
        self.tags.insert(tag.to_string());
    }

    /// Check if peer has a tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }
}

/// Discovery statistics
#[derive(Debug, Clone, Default)]
pub struct DiscoveryStats {
    /// Total peers discovered
    pub peers_discovered: usize,
    /// Announcements broadcast
    pub announcements_broadcast: usize,
    /// Connections initiated
    pub connections_initiated: usize,
    /// Connections established
    pub connections_established: usize,
    /// Connections failed
    pub connections_failed: usize,
    /// Peers banned
    pub peers_banned: usize,
}

/// Peer discovery manager
pub struct PeerDiscoveryManager {
    /// Our peer ID
    local_peer_id: String,
    /// Our announcement
    local_announcement: Arc<Mutex<Option<PeerAnnouncement>>>,
    /// Known peers by peer ID
    known_peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    /// Blocked peer IDs
    blocked_peers: Arc<Mutex<HashSet<String>>>,
    /// Statistics
    stats: Arc<Mutex<DiscoveryStats>>,
    /// Last announcement time
    last_announcement: Arc<Mutex<Option<DateTime<Utc>>>>,
    /// Callback for new peer discovered
    on_peer_discovered: Arc<Mutex<Option<Box<dyn Fn(&PeerInfo) + Send + Sync>>>>,
    /// Callback for peer status change
    on_peer_status_change: Arc<Mutex<Option<Box<dyn Fn(&str, PeerStatus) + Send + Sync>>>>,
}

impl PeerDiscoveryManager {
    /// Create a new peer discovery manager
    pub fn new(local_peer_id: String) -> Self {
        Self {
            local_peer_id,
            local_announcement: Arc::new(Mutex::new(None)),
            known_peers: Arc::new(Mutex::new(HashMap::new())),
            blocked_peers: Arc::new(Mutex::new(HashSet::new())),
            stats: Arc::new(Mutex::new(DiscoveryStats::default())),
            last_announcement: Arc::new(Mutex::new(None)),
            on_peer_discovered: Arc::new(Mutex::new(None)),
            on_peer_status_change: Arc::new(Mutex::new(None)),
        }
    }

    /// Set callback for new peer discovered
    pub fn set_on_peer_discovered<F>(&self, callback: F)
    where
        F: Fn(&PeerInfo) + Send + Sync + 'static,
    {
        let mut on_discovered = self.on_peer_discovered.lock().unwrap();
        *on_discovered = Some(Box::new(callback));
    }

    /// Set callback for peer status change
    pub fn set_on_peer_status_change<F>(&self, callback: F)
    where
        F: Fn(&str, PeerStatus) + Send + Sync + 'static,
    {
        let mut on_status_change = self.on_peer_status_change.lock().unwrap();
        *on_status_change = Some(Box::new(callback));
    }

    /// Create and store local announcement
    pub fn create_announcement(
        &self,
        kaspa_address: String,
        public_key: String,
    ) -> PeerAnnouncement {
        let announcement = PeerAnnouncement::new(
            self.local_peer_id.clone(),
            kaspa_address,
            public_key,
        );

        let mut local = self.local_announcement.lock().unwrap();
        *local = Some(announcement.clone());

        announcement
    }

    /// Get the local announcement
    pub fn get_local_announcement(&self) -> Option<PeerAnnouncement> {
        self.local_announcement.lock().unwrap().clone()
    }

    /// Check if we can broadcast announcement (respects cooldown)
    pub fn can_announce(&self) -> bool {
        let last = self.last_announcement.lock().unwrap();
        match *last {
            Some(dt) => {
                let elapsed = Utc::now().signed_duration_since(dt);
                elapsed.num_seconds() >= ANNOUNCEMENT_COOLDOWN
            }
            None => true,
        }
    }

    /// Mark announcement as broadcast
    pub fn mark_announced(&self) {
        let mut last = self.last_announcement.lock().unwrap();
        *last = Some(Utc::now());

        let mut stats = self.stats.lock().unwrap();
        stats.announcements_broadcast += 1;
    }

    /// Process a discovered peer announcement
    pub fn process_announcement(&self, announcement: PeerAnnouncement) -> Result<bool> {
        // Don't process our own announcements
        if announcement.peer_id == self.local_peer_id {
            return Ok(false);
        }

        // Check if peer is blocked
        if self.is_blocked(&announcement.peer_id) {
            log::debug!("Ignoring announcement from blocked peer: {}", announcement.peer_id);
            return Ok(false);
        }

        // Check announcement validity
        if !announcement.is_valid(ANNOUNCEMENT_TTL) {
            log::debug!("Ignoring expired announcement from: {}", announcement.peer_id);
            return Ok(false);
        }

        let mut peers = self.known_peers.lock().unwrap();
        let is_new = !peers.contains_key(&announcement.peer_id);

        if is_new {
            // Enforce maximum peer limit
            if peers.len() >= MAX_TRACKED_PEERS {
                self.prune_peers(&mut peers);
            }

            let peer_info = PeerInfo::from_announcement(announcement);
            let peer_id = peer_info.peer_id.clone();

            peers.insert(peer_id.clone(), peer_info.clone());

            let mut stats = self.stats.lock().unwrap();
            stats.peers_discovered += 1;

            // Trigger callback
            drop(peers); // Release lock before callback
            if let Some(ref callback) = *self.on_peer_discovered.lock().unwrap() {
                callback(&peer_info);
            }

            log::info!("Discovered new peer: {}", peer_id);
            Ok(true)
        } else {
            // Update existing peer
            if let Some(peer) = peers.get_mut(&announcement.peer_id) {
                peer.update_announcement(announcement);
            }
            Ok(false)
        }
    }

    /// Prune old/low-reputation peers to make room
    fn prune_peers(&self, peers: &mut HashMap<String, PeerInfo>) {
        // Remove peers with lowest reputation first
        let mut peer_list: Vec<_> = peers.iter()
            .filter(|(_, p)| !matches!(p.status, PeerStatus::Connected))
            .map(|(id, p)| (id.clone(), p.reputation))
            .collect();

        peer_list.sort_by_key(|(_, rep)| *rep);

        // Remove bottom 10%
        let to_remove = (peer_list.len() / 10).max(1);
        for (peer_id, _) in peer_list.iter().take(to_remove) {
            peers.remove(peer_id);
        }
    }

    /// Get peer info by ID
    pub fn get_peer(&self, peer_id: &str) -> Option<PeerInfo> {
        self.known_peers.lock().unwrap().get(peer_id).cloned()
    }

    /// Get all known peers
    pub fn get_all_peers(&self) -> Vec<PeerInfo> {
        self.known_peers.lock().unwrap().values().cloned().collect()
    }

    /// Get peers by status
    pub fn get_peers_by_status(&self, status: PeerStatus) -> Vec<PeerInfo> {
        self.known_peers.lock().unwrap()
            .values()
            .filter(|p| p.status == status)
            .cloned()
            .collect()
    }

    /// Get peers suitable for auto-connect
    pub fn get_auto_connect_candidates(&self) -> Vec<PeerInfo> {
        self.known_peers.lock().unwrap()
            .values()
            .filter(|p| p.should_auto_connect())
            .cloned()
            .collect()
    }

    /// Get connected peers
    pub fn get_connected_peers(&self) -> Vec<PeerInfo> {
        self.get_peers_by_status(PeerStatus::Connected)
    }

    /// Get number of known peers
    pub fn peer_count(&self) -> usize {
        self.known_peers.lock().unwrap().len()
    }

    /// Get number of connected peers
    pub fn connected_count(&self) -> usize {
        self.known_peers.lock().unwrap()
            .values()
            .filter(|p| p.status == PeerStatus::Connected)
            .count()
    }

    /// Update peer status
    pub fn update_peer_status(&self, peer_id: &str, status: PeerStatus) -> Result<()> {
        let mut peers = self.known_peers.lock().unwrap();
        let peer = peers.get_mut(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown peer: {}", peer_id))?;

        let old_status = peer.status;
        peer.status = status;
        peer.updated_at = Utc::now();

        // Update stats
        let mut stats = self.stats.lock().unwrap();
        match status {
            PeerStatus::Connected => stats.connections_established += 1,
            PeerStatus::Failed => stats.connections_failed += 1,
            PeerStatus::Banned => stats.peers_banned += 1,
            _ => {}
        }

        // Trigger callback if status changed
        drop(peers);
        drop(stats);
        if old_status != status {
            if let Some(ref callback) = *self.on_peer_status_change.lock().unwrap() {
                callback(peer_id, status);
            }
        }

        Ok(())
    }

    /// Mark peer connection attempt
    pub fn mark_connecting(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.known_peers.lock().unwrap();
        let peer = peers.get_mut(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown peer: {}", peer_id))?;

        peer.status = PeerStatus::Connecting;
        peer.last_connection_attempt = Some(Utc::now());

        let mut stats = self.stats.lock().unwrap();
        stats.connections_initiated += 1;

        Ok(())
    }

    /// Record successful connection
    pub fn record_connection_success(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.known_peers.lock().unwrap();
        let peer = peers.get_mut(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown peer: {}", peer_id))?;

        peer.record_connection_success();

        let mut stats = self.stats.lock().unwrap();
        stats.connections_established += 1;

        Ok(())
    }

    /// Record failed connection
    pub fn record_connection_failure(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.known_peers.lock().unwrap();
        let peer = peers.get_mut(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown peer: {}", peer_id))?;

        peer.record_connection_failure();

        let mut stats = self.stats.lock().unwrap();
        stats.connections_failed += 1;

        Ok(())
    }

    /// Block a peer
    pub fn block_peer(&self, peer_id: &str) {
        self.blocked_peers.lock().unwrap().insert(peer_id.to_string());

        if let Ok(mut peers) = self.known_peers.lock() {
            if let Some(peer) = peers.get_mut(peer_id) {
                peer.status = PeerStatus::Banned;
                peer.reputation = -100;
            }
        }

        let mut stats = self.stats.lock().unwrap();
        stats.peers_banned += 1;
    }

    /// Unblock a peer
    pub fn unblock_peer(&self, peer_id: &str) {
        self.blocked_peers.lock().unwrap().remove(peer_id);

        if let Ok(mut peers) = self.known_peers.lock() {
            if let Some(peer) = peers.get_mut(peer_id) {
                peer.status = PeerStatus::Discovered;
                peer.reputation = 0; // Reset reputation
            }
        }
    }

    /// Check if peer is blocked
    pub fn is_blocked(&self, peer_id: &str) -> bool {
        self.blocked_peers.lock().unwrap().contains(peer_id)
    }

    /// Get blocked peers
    pub fn get_blocked_peers(&self) -> Vec<String> {
        self.blocked_peers.lock().unwrap().iter().cloned().collect()
    }

    /// Add tag to peer
    pub fn tag_peer(&self, peer_id: &str, tag: &str) -> Result<()> {
        let mut peers = self.known_peers.lock().unwrap();
        let peer = peers.get_mut(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown peer: {}", peer_id))?;
        peer.add_tag(tag);
        Ok(())
    }

    /// Get peers by tag
    pub fn get_peers_by_tag(&self, tag: &str) -> Vec<PeerInfo> {
        self.known_peers.lock().unwrap()
            .values()
            .filter(|p| p.has_tag(tag))
            .cloned()
            .collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> DiscoveryStats {
        self.stats.lock().unwrap().clone()
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> &str {
        &self.local_peer_id
    }

    /// Clean up expired announcements
    pub fn cleanup_expired(&self) {
        let mut peers = self.known_peers.lock().unwrap();
        let expired: Vec<_> = peers.iter()
            .filter(|(_, p)| !p.announcement.is_valid(ANNOUNCEMENT_TTL) && p.status != PeerStatus::Connected)
            .map(|(id, _)| id.clone())
            .collect();

        for peer_id in expired {
            peers.remove(&peer_id);
            log::debug!("Removed expired peer: {}", peer_id);
        }
    }
}

/// Connection coordinator - manages auto-connections
pub struct ConnectionCoordinator {
    /// Peer discovery manager
    discovery: Arc<PeerDiscoveryManager>,
    /// Signaling manager
    signaling: Arc<SignalingManager>,
    /// Maximum concurrent connection attempts
    max_concurrent_connections: usize,
    /// Active connection attempts
    active_connections: Arc<Mutex<HashSet<String>>>,
    /// Target number of connections
    target_connections: usize,
}

impl ConnectionCoordinator {
    /// Create a new connection coordinator
    pub fn new(
        discovery: Arc<PeerDiscoveryManager>,
        signaling: Arc<SignalingManager>,
    ) -> Self {
        Self {
            discovery,
            signaling,
            max_concurrent_connections: 5,
            active_connections: Arc::new(Mutex::new(HashSet::new())),
            target_connections: 10,
        }
    }

    /// Set maximum concurrent connection attempts
    pub fn set_max_concurrent(&mut self, max: usize) {
        self.max_concurrent_connections = max;
    }

    /// Set target number of connections
    pub fn set_target_connections(&mut self, target: usize) {
        self.target_connections = target;
    }

    /// Get number of active connection attempts
    pub fn active_connection_count(&self) -> usize {
        self.active_connections.lock().unwrap().len()
    }

    /// Check if we need more connections
    pub fn needs_connections(&self) -> bool {
        let connected = self.discovery.connected_count();
        let active = self.active_connection_count();
        connected + active < self.target_connections
    }

    /// Attempt to connect to more peers
    pub fn auto_connect(&self) -> Vec<String> {
        if !self.needs_connections() {
            return Vec::new();
        }

        let mut active = self.active_connections.lock().unwrap();
        if active.len() >= self.max_concurrent_connections {
            return Vec::new();
        }

        let candidates = self.discovery.get_auto_connect_candidates();
        let slots_available = self.max_concurrent_connections - active.len();
        let connections_needed = self.target_connections - self.discovery.connected_count() - active.len();
        let to_connect = slots_available.min(connections_needed).min(candidates.len());

        let mut initiated = Vec::new();

        // Sort candidates by reputation
        let mut sorted_candidates = candidates;
        sorted_candidates.sort_by(|a, b| b.reputation.cmp(&a.reputation));

        for candidate in sorted_candidates.into_iter().take(to_connect) {
            if active.contains(&candidate.peer_id) {
                continue;
            }

            // Initiate connection via signaling
            match self.signaling.initiate_connection(&candidate.peer_id) {
                Ok(_) => {
                    active.insert(candidate.peer_id.clone());
                    let _ = self.discovery.mark_connecting(&candidate.peer_id);
                    initiated.push(candidate.peer_id);
                }
                Err(e) => {
                    log::warn!("Failed to initiate connection to {}: {}", candidate.peer_id, e);
                }
            }
        }

        initiated
    }

    /// Handle connection established
    pub fn handle_connection_established(&self, peer_id: &str) {
        self.active_connections.lock().unwrap().remove(peer_id);
        let _ = self.discovery.record_connection_success(peer_id);
    }

    /// Handle connection failed
    pub fn handle_connection_failed(&self, peer_id: &str) {
        self.active_connections.lock().unwrap().remove(peer_id);
        let _ = self.discovery.record_connection_failure(peer_id);
    }

    /// Cancel connection attempt
    pub fn cancel_connection(&self, peer_id: &str) {
        self.active_connections.lock().unwrap().remove(peer_id);
    }

    /// Get list of active connection attempts
    pub fn get_active_connections(&self) -> Vec<String> {
        self.active_connections.lock().unwrap().iter().cloned().collect()
    }

    /// Sync connection states from signaling manager
    pub fn sync_connection_states(&self) {
        let sessions = self.signaling.get_active_sessions();
        let mut to_update = Vec::new();

        for session in sessions {
            match session.state {
                SignalingState::Connected => {
                    to_update.push((session.remote_peer_id.clone(), true));
                }
                SignalingState::Failed | SignalingState::Closed => {
                    to_update.push((session.remote_peer_id.clone(), false));
                }
                _ => {}
            }
        }

        for (peer_id, success) in to_update {
            if success {
                self.handle_connection_established(&peer_id);
            } else {
                self.handle_connection_failed(&peer_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_status_display() {
        assert_eq!(format!("{}", PeerStatus::Discovered), "discovered");
        assert_eq!(format!("{}", PeerStatus::Connected), "connected");
        assert_eq!(format!("{}", PeerStatus::Banned), "banned");
    }

    #[test]
    fn test_announcement_creation() {
        let announcement = PeerAnnouncement::new(
            "peer123".to_string(),
            "kaspatest:qp...".to_string(),
            "public_key_data".to_string(),
        );

        assert_eq!(announcement.peer_id, "peer123");
        assert!(announcement.has_capability("chat"));
        assert!(announcement.has_capability("signaling"));
        assert!(!announcement.has_capability("video"));
    }

    #[test]
    fn test_announcement_validity() {
        let announcement = PeerAnnouncement::new(
            "peer123".to_string(),
            "kaspatest:qp...".to_string(),
            "public_key".to_string(),
        );

        // Should be valid when just created
        assert!(announcement.is_valid(3600));
        assert!(announcement.is_valid(1));
    }

    #[test]
    fn test_peer_info_reputation() {
        let announcement = PeerAnnouncement::new(
            "peer123".to_string(),
            "kaspatest:qp...".to_string(),
            "pk".to_string(),
        );

        let mut peer = PeerInfo::from_announcement(announcement);
        assert_eq!(peer.reputation, 50);

        peer.adjust_reputation(30);
        assert_eq!(peer.reputation, 80);

        peer.adjust_reputation(50);
        assert_eq!(peer.reputation, 100); // Clamped

        peer.adjust_reputation(-200);
        assert_eq!(peer.reputation, -100); // Clamped
        assert_eq!(peer.status, PeerStatus::Banned);
    }

    #[test]
    fn test_peer_connection_recording() {
        let announcement = PeerAnnouncement::new(
            "peer123".to_string(),
            "kaspatest:qp...".to_string(),
            "pk".to_string(),
        );

        let mut peer = PeerInfo::from_announcement(announcement);

        peer.record_connection_success();
        assert_eq!(peer.successful_connections, 1);
        assert_eq!(peer.status, PeerStatus::Connected);
        assert!(peer.last_connected.is_some());

        peer.record_connection_failure();
        assert_eq!(peer.failed_connections, 1);
        assert_eq!(peer.status, PeerStatus::Failed);

        assert_eq!(peer.connection_success_rate(), 0.5);
    }

    #[test]
    fn test_discovery_manager_creation() {
        let manager = PeerDiscoveryManager::new("local_peer".to_string());
        assert_eq!(manager.local_peer_id(), "local_peer");
        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_create_announcement() {
        let manager = PeerDiscoveryManager::new("local_peer".to_string());

        let announcement = manager.create_announcement(
            "kaspatest:qp...".to_string(),
            "public_key".to_string(),
        );

        assert_eq!(announcement.peer_id, "local_peer");

        let stored = manager.get_local_announcement();
        assert!(stored.is_some());
    }

    #[test]
    fn test_process_announcement() {
        let manager = PeerDiscoveryManager::new("local_peer".to_string());

        let announcement = PeerAnnouncement::new(
            "remote_peer".to_string(),
            "kaspatest:qp...".to_string(),
            "pk".to_string(),
        );

        // First time should be new
        let is_new = manager.process_announcement(announcement.clone()).unwrap();
        assert!(is_new);
        assert_eq!(manager.peer_count(), 1);

        // Second time should not be new
        let is_new = manager.process_announcement(announcement).unwrap();
        assert!(!is_new);
        assert_eq!(manager.peer_count(), 1);
    }

    #[test]
    fn test_ignore_own_announcement() {
        let manager = PeerDiscoveryManager::new("local_peer".to_string());

        let announcement = PeerAnnouncement::new(
            "local_peer".to_string(), // Same as our ID
            "kaspatest:qp...".to_string(),
            "pk".to_string(),
        );

        let is_new = manager.process_announcement(announcement).unwrap();
        assert!(!is_new);
        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_block_peer() {
        let manager = PeerDiscoveryManager::new("local_peer".to_string());

        let announcement = PeerAnnouncement::new(
            "bad_peer".to_string(),
            "kaspatest:qp...".to_string(),
            "pk".to_string(),
        );

        manager.process_announcement(announcement.clone()).unwrap();
        manager.block_peer("bad_peer");

        assert!(manager.is_blocked("bad_peer"));

        // New announcements should be ignored
        let announcement2 = PeerAnnouncement::new(
            "bad_peer".to_string(),
            "kaspatest:qp2...".to_string(),
            "pk2".to_string(),
        );
        let is_new = manager.process_announcement(announcement2).unwrap();
        assert!(!is_new);
    }

    #[test]
    fn test_unblock_peer() {
        let manager = PeerDiscoveryManager::new("local_peer".to_string());

        manager.block_peer("some_peer");
        assert!(manager.is_blocked("some_peer"));

        manager.unblock_peer("some_peer");
        assert!(!manager.is_blocked("some_peer"));
    }

    #[test]
    fn test_peer_tagging() {
        let manager = PeerDiscoveryManager::new("local_peer".to_string());

        let announcement = PeerAnnouncement::new(
            "friend".to_string(),
            "kaspatest:qp...".to_string(),
            "pk".to_string(),
        );
        manager.process_announcement(announcement).unwrap();

        manager.tag_peer("friend", "trusted").unwrap();
        manager.tag_peer("friend", "family").unwrap();

        let friends = manager.get_peers_by_tag("trusted");
        assert_eq!(friends.len(), 1);
        assert_eq!(friends[0].peer_id, "friend");
    }

    #[test]
    fn test_auto_connect_candidates() {
        let manager = PeerDiscoveryManager::new("local_peer".to_string());

        // Add some peers
        for i in 0..5 {
            let announcement = PeerAnnouncement::new(
                format!("peer_{}", i),
                format!("kaspatest:qp{}...", i),
                format!("pk_{}", i),
            );
            manager.process_announcement(announcement).unwrap();
        }

        // All should be candidates initially
        let candidates = manager.get_auto_connect_candidates();
        assert_eq!(candidates.len(), 5);

        // Mark one as connected
        manager.update_peer_status("peer_0", PeerStatus::Connected).unwrap();

        let candidates = manager.get_auto_connect_candidates();
        assert_eq!(candidates.len(), 4);
    }

    #[test]
    fn test_announcement_cooldown() {
        let manager = PeerDiscoveryManager::new("local_peer".to_string());

        assert!(manager.can_announce());

        manager.mark_announced();
        assert!(!manager.can_announce()); // Should be in cooldown

        let stats = manager.get_stats();
        assert_eq!(stats.announcements_broadcast, 1);
    }

    #[test]
    fn test_connection_coordinator() {
        let discovery = Arc::new(PeerDiscoveryManager::new("local_peer".to_string()));
        let signaling = Arc::new(SignalingManager::new("local_peer".to_string()));

        let mut coordinator = ConnectionCoordinator::new(
            discovery.clone(),
            signaling.clone(),
        );

        coordinator.set_target_connections(3);
        coordinator.set_max_concurrent(2);

        // Add some peers
        for i in 0..5 {
            let announcement = PeerAnnouncement::new(
                format!("peer_{}", i),
                format!("kaspatest:qp{}...", i),
                format!("pk_{}", i),
            );
            discovery.process_announcement(announcement).unwrap();
        }

        assert!(coordinator.needs_connections());

        // Auto-connect should initiate some connections
        let initiated = coordinator.auto_connect();
        assert!(!initiated.is_empty());
        assert!(initiated.len() <= 2); // Max concurrent

        // Verify active connections tracked
        let active = coordinator.get_active_connections();
        assert_eq!(active.len(), initiated.len());
    }

    #[test]
    fn test_connection_success_handling() {
        let discovery = Arc::new(PeerDiscoveryManager::new("local_peer".to_string()));
        let signaling = Arc::new(SignalingManager::new("local_peer".to_string()));

        let coordinator = ConnectionCoordinator::new(
            discovery.clone(),
            signaling.clone(),
        );

        // Add and connect to peer
        let announcement = PeerAnnouncement::new(
            "peer_1".to_string(),
            "kaspatest:qp...".to_string(),
            "pk".to_string(),
        );
        discovery.process_announcement(announcement).unwrap();
        discovery.mark_connecting("peer_1").unwrap();

        coordinator.handle_connection_established("peer_1");

        let peer = discovery.get_peer("peer_1").unwrap();
        assert_eq!(peer.status, PeerStatus::Connected);
        assert_eq!(peer.successful_connections, 1);
    }

    #[test]
    fn test_statistics() {
        let manager = PeerDiscoveryManager::new("local_peer".to_string());

        // Add peers
        for i in 0..3 {
            let announcement = PeerAnnouncement::new(
                format!("peer_{}", i),
                format!("kaspatest:qp{}...", i),
                format!("pk_{}", i),
            );
            manager.process_announcement(announcement).unwrap();
        }

        let stats = manager.get_stats();
        assert_eq!(stats.peers_discovered, 3);

        manager.mark_announced();
        let stats = manager.get_stats();
        assert_eq!(stats.announcements_broadcast, 1);
    }
}
