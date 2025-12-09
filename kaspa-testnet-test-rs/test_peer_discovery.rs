/// Peer Discovery Test Suite
///
/// Tests peer discovery and automated connections:
/// - Peer announcement creation and validation
/// - Peer discovery from announcements
/// - Reputation tracking and management
/// - Auto-connect coordination
/// - Peer blocking and filtering

// Include the library modules
#[path = "src/message_extractor.rs"]
mod message_extractor;

#[path = "src/wallet_manager.rs"]
mod wallet_manager;

#[path = "src/transaction_builder.rs"]
mod transaction_builder;

#[path = "src/rpc_client.rs"]
mod rpc_client;

#[path = "src/payload_manager.rs"]
mod payload_manager;

#[path = "src/delivery_strategy.rs"]
mod delivery_strategy;

#[path = "src/utxo_monitor.rs"]
mod utxo_monitor;

#[path = "src/message_reception.rs"]
mod message_reception;

#[path = "src/webrtc_signaling.rs"]
mod webrtc_signaling;

#[path = "src/peer_discovery.rs"]
mod peer_discovery;

use peer_discovery::*;
use webrtc_signaling::SignalingManager;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use colored::*;

// Simple utility functions for test output
fn header(text: &str) {
    println!("\n{}", "=".repeat(60).bright_blue());
    println!("{}", text.bright_cyan().bold());
    println!("{}\n", "=".repeat(60).bright_blue());
}

fn section(text: &str) {
    println!("\n{} {}", "▶".bright_green(), text.bright_white().bold());
}

fn success(text: &str) {
    println!("{} {}", "✓".bright_green(), text);
}

fn error(text: &str) {
    println!("{} {}", "✗".bright_red(), text.red());
}

fn info(text: &str) {
    println!("{} {}", "ℹ".bright_blue(), text);
}

fn data(label: &str, value: &str) {
    println!("  {} {}", format!("{}:", label).bright_white(), value.cyan());
}

fn result_summary(passed: usize, failed: usize, total: usize) {
    println!("\n{}", "=".repeat(60).bright_blue());
    println!("  {} {}/{} tests passed", "✓".bright_green(), passed, total);
    if failed > 0 {
        println!("  {} {}/{} tests failed", "✗".bright_red(), failed, total);
    }
    println!("{}\n", "=".repeat(60).bright_blue());
}

fn main() {
    env_logger::init();

    header("Peer Discovery Test Suite");
    info("Testing peer discovery and automated connections");
    println!();

    let mut passed = 0;
    let mut failed = 0;

    // Run all tests
    let tests: Vec<(&str, fn() -> bool)> = vec![
        ("Peer Status Display", test_peer_status_display),
        ("Announcement Creation", test_announcement_creation),
        ("Announcement Validity", test_announcement_validity),
        ("Peer Info Reputation", test_peer_info_reputation),
        ("Connection Recording", test_connection_recording),
        ("Discovery Manager Creation", test_discovery_manager),
        ("Process Announcements", test_process_announcements),
        ("Ignore Own Announcements", test_ignore_own_announcements),
        ("Block and Unblock Peers", test_block_unblock),
        ("Peer Tagging", test_peer_tagging),
        ("Auto-Connect Candidates", test_auto_connect_candidates),
        ("Announcement Cooldown", test_announcement_cooldown),
        ("Connection Coordinator", test_connection_coordinator),
        ("Statistics Tracking", test_statistics),
        ("Callbacks", test_callbacks),
    ];

    for (name, test_fn) in tests {
        section(name);
        if test_fn() {
            success(&format!("{} passed", name));
            passed += 1;
        } else {
            error(&format!("{} FAILED", name));
            failed += 1;
        }
        println!();
    }

    // Summary
    header("Test Summary");
    result_summary(passed, failed, passed + failed);

    if failed == 0 {
        success("All peer discovery tests passed!");
    } else {
        error(&format!("{} test(s) failed", failed));
    }

    println!("\n=== Peer Discovery Tests Complete! ===\n");
    println!("=== Week 4 Implementation Complete! ===");
    println!("Next: Week 5 - Port validated code to wasm-core/\n");
}

fn test_peer_status_display() -> bool {
    info("Testing peer status display...");

    assert_eq!(format!("{}", PeerStatus::Discovered), "discovered");
    assert_eq!(format!("{}", PeerStatus::Connecting), "connecting");
    assert_eq!(format!("{}", PeerStatus::Connected), "connected");
    assert_eq!(format!("{}", PeerStatus::Failed), "failed");
    assert_eq!(format!("{}", PeerStatus::Offline), "offline");
    assert_eq!(format!("{}", PeerStatus::Banned), "banned");
    data("All statuses", "display correctly");

    true
}

fn test_announcement_creation() -> bool {
    info("Testing announcement creation...");

    let announcement = PeerAnnouncement::new(
        "peer_abc123".to_string(),
        "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7".to_string(),
        "ed25519_public_key_here".to_string(),
    );

    assert_eq!(announcement.peer_id, "peer_abc123");
    assert!(announcement.kaspa_address.starts_with("kaspatest:"));
    assert_eq!(announcement.protocol_version, "p2pcomm/1.0");
    data("Peer ID", &announcement.peer_id);
    data("Protocol", &announcement.protocol_version);

    // Check default capabilities
    assert!(announcement.has_capability("chat"));
    assert!(announcement.has_capability("signaling"));
    assert!(!announcement.has_capability("video"));
    data("Default capabilities", "chat, signaling");

    // Add capability
    let announcement = announcement.with_capability("video");
    assert!(announcement.has_capability("video"));
    data("Added capability", "video");

    // Add display name
    let announcement = announcement.with_display_name("Alice");
    assert_eq!(announcement.display_name, Some("Alice".to_string()));
    data("Display name", "Alice");

    true
}

fn test_announcement_validity() -> bool {
    info("Testing announcement validity...");

    let announcement = PeerAnnouncement::new(
        "peer123".to_string(),
        "kaspatest:qp...".to_string(),
        "pk".to_string(),
    );

    // Should be valid with long TTL
    assert!(announcement.is_valid(3600));
    data("Valid for 1 hour", "true");

    // Should be valid with short TTL (just created)
    assert!(announcement.is_valid(1));
    data("Valid for 1 second", "true");

    // Test serialization
    let bytes = announcement.to_bytes();
    assert!(!bytes.is_empty());
    data("Serialized size", &format!("{} bytes", bytes.len()));

    true
}

fn test_peer_info_reputation() -> bool {
    info("Testing peer reputation system...");

    let announcement = PeerAnnouncement::new(
        "peer123".to_string(),
        "kaspatest:qp...".to_string(),
        "pk".to_string(),
    );

    let mut peer = PeerInfo::from_announcement(announcement);
    assert_eq!(peer.reputation, 50);
    data("Initial reputation", "50");

    // Increase reputation
    peer.adjust_reputation(30);
    assert_eq!(peer.reputation, 80);
    data("After +30", "80");

    // Test clamping to max 100
    peer.adjust_reputation(50);
    assert_eq!(peer.reputation, 100);
    data("After +50 (clamped)", "100");

    // Test clamping to min -100
    peer.adjust_reputation(-250);
    assert_eq!(peer.reputation, -100);
    data("After -250 (clamped)", "-100");

    // Low reputation should ban
    assert_eq!(peer.status, PeerStatus::Banned);
    data("Low reputation status", "banned");

    true
}

fn test_connection_recording() -> bool {
    info("Testing connection recording...");

    let announcement = PeerAnnouncement::new(
        "peer123".to_string(),
        "kaspatest:qp...".to_string(),
        "pk".to_string(),
    );

    let mut peer = PeerInfo::from_announcement(announcement);

    // Record success
    peer.record_connection_success();
    assert_eq!(peer.successful_connections, 1);
    assert_eq!(peer.status, PeerStatus::Connected);
    assert!(peer.last_connected.is_some());
    data("After success", "status=connected, successes=1");

    // Record failure
    peer.record_connection_failure();
    assert_eq!(peer.failed_connections, 1);
    assert_eq!(peer.status, PeerStatus::Failed);
    data("After failure", "status=failed, failures=1");

    // Check success rate
    let rate = peer.connection_success_rate();
    assert!((rate - 0.5).abs() < 0.01);
    data("Success rate", "50%");

    true
}

fn test_discovery_manager() -> bool {
    info("Testing discovery manager creation...");

    let manager = PeerDiscoveryManager::new("local_peer_id".to_string());

    assert_eq!(manager.local_peer_id(), "local_peer_id");
    assert_eq!(manager.peer_count(), 0);
    assert_eq!(manager.connected_count(), 0);
    data("Local peer ID", manager.local_peer_id());
    data("Initial peer count", "0");

    // Create local announcement
    let announcement = manager.create_announcement(
        "kaspatest:qp...".to_string(),
        "public_key".to_string(),
    );
    assert_eq!(announcement.peer_id, "local_peer_id");
    data("Local announcement", "created");

    let stored = manager.get_local_announcement();
    assert!(stored.is_some());
    data("Announcement stored", "yes");

    true
}

fn test_process_announcements() -> bool {
    info("Testing announcement processing...");

    let manager = PeerDiscoveryManager::new("local_peer".to_string());

    // Process first announcement
    let announcement = PeerAnnouncement::new(
        "remote_peer_1".to_string(),
        "kaspatest:qp1...".to_string(),
        "pk1".to_string(),
    );

    let is_new = manager.process_announcement(announcement.clone()).unwrap();
    assert!(is_new);
    assert_eq!(manager.peer_count(), 1);
    data("First announcement", "new peer added");

    // Process duplicate
    let is_new = manager.process_announcement(announcement).unwrap();
    assert!(!is_new);
    assert_eq!(manager.peer_count(), 1);
    data("Duplicate announcement", "not added");

    // Process second peer
    let announcement2 = PeerAnnouncement::new(
        "remote_peer_2".to_string(),
        "kaspatest:qp2...".to_string(),
        "pk2".to_string(),
    );

    let is_new = manager.process_announcement(announcement2).unwrap();
    assert!(is_new);
    assert_eq!(manager.peer_count(), 2);
    data("Second peer", "added, total=2");

    // Get peer info
    let peer = manager.get_peer("remote_peer_1");
    assert!(peer.is_some());
    assert_eq!(peer.unwrap().status, PeerStatus::Discovered);
    data("Peer status", "discovered");

    true
}

fn test_ignore_own_announcements() -> bool {
    info("Testing own announcement filtering...");

    let manager = PeerDiscoveryManager::new("my_peer_id".to_string());

    let own_announcement = PeerAnnouncement::new(
        "my_peer_id".to_string(), // Same as local ID
        "kaspatest:qp...".to_string(),
        "pk".to_string(),
    );

    let is_new = manager.process_announcement(own_announcement).unwrap();
    assert!(!is_new);
    assert_eq!(manager.peer_count(), 0);
    data("Own announcement", "correctly ignored");

    true
}

fn test_block_unblock() -> bool {
    info("Testing peer blocking...");

    let manager = PeerDiscoveryManager::new("local_peer".to_string());

    // Add peer first
    let announcement = PeerAnnouncement::new(
        "bad_peer".to_string(),
        "kaspatest:qp...".to_string(),
        "pk".to_string(),
    );
    manager.process_announcement(announcement).unwrap();

    // Block peer
    manager.block_peer("bad_peer");
    assert!(manager.is_blocked("bad_peer"));
    data("Block peer", "successful");

    let peer = manager.get_peer("bad_peer").unwrap();
    assert_eq!(peer.status, PeerStatus::Banned);
    assert_eq!(peer.reputation, -100);
    data("Blocked peer status", "banned, reputation=-100");

    // New announcements from blocked peer should be ignored
    let new_announcement = PeerAnnouncement::new(
        "bad_peer".to_string(),
        "kaspatest:qp2...".to_string(),
        "pk2".to_string(),
    );
    let is_new = manager.process_announcement(new_announcement).unwrap();
    assert!(!is_new);
    data("Blocked peer announcement", "ignored");

    // Unblock
    manager.unblock_peer("bad_peer");
    assert!(!manager.is_blocked("bad_peer"));
    data("Unblock peer", "successful");

    // Get blocked peers list
    manager.block_peer("another_bad");
    let blocked = manager.get_blocked_peers();
    assert_eq!(blocked.len(), 1);
    assert!(blocked.contains(&"another_bad".to_string()));
    data("Blocked peers count", "1");

    true
}

fn test_peer_tagging() -> bool {
    info("Testing peer tagging...");

    let manager = PeerDiscoveryManager::new("local_peer".to_string());

    // Add peer
    let announcement = PeerAnnouncement::new(
        "friend_peer".to_string(),
        "kaspatest:qp...".to_string(),
        "pk".to_string(),
    );
    manager.process_announcement(announcement).unwrap();

    // Add tags
    manager.tag_peer("friend_peer", "trusted").unwrap();
    manager.tag_peer("friend_peer", "family").unwrap();
    data("Tags added", "trusted, family");

    // Get peers by tag
    let trusted = manager.get_peers_by_tag("trusted");
    assert_eq!(trusted.len(), 1);
    assert_eq!(trusted[0].peer_id, "friend_peer");
    data("Peers with 'trusted'", "1");

    let family = manager.get_peers_by_tag("family");
    assert_eq!(family.len(), 1);
    data("Peers with 'family'", "1");

    let unknown_tag = manager.get_peers_by_tag("unknown");
    assert!(unknown_tag.is_empty());
    data("Peers with 'unknown'", "0");

    true
}

fn test_auto_connect_candidates() -> bool {
    info("Testing auto-connect candidates...");

    let manager = PeerDiscoveryManager::new("local_peer".to_string());

    // Add multiple peers
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
    data("Initial candidates", "5");

    // Mark one as connected
    manager.update_peer_status("peer_0", PeerStatus::Connected).unwrap();
    let candidates = manager.get_auto_connect_candidates();
    assert_eq!(candidates.len(), 4);
    data("After 1 connected", "4 candidates");

    // Mark one as connecting
    manager.update_peer_status("peer_1", PeerStatus::Connecting).unwrap();
    let candidates = manager.get_auto_connect_candidates();
    assert_eq!(candidates.len(), 3);
    data("After 1 connecting", "3 candidates");

    // Ban one
    manager.block_peer("peer_2");
    let candidates = manager.get_auto_connect_candidates();
    assert_eq!(candidates.len(), 2);
    data("After 1 banned", "2 candidates");

    // Get connected peers
    let connected = manager.get_connected_peers();
    assert_eq!(connected.len(), 1);
    data("Connected peers", "1");

    true
}

fn test_announcement_cooldown() -> bool {
    info("Testing announcement cooldown...");

    let manager = PeerDiscoveryManager::new("local_peer".to_string());

    // Should be able to announce initially
    assert!(manager.can_announce());
    data("Initial state", "can announce");

    // Mark as announced
    manager.mark_announced();

    // Should not be able to announce (in cooldown)
    assert!(!manager.can_announce());
    data("After announcing", "in cooldown");

    let stats = manager.get_stats();
    assert_eq!(stats.announcements_broadcast, 1);
    data("Announcements broadcast", "1");

    true
}

fn test_connection_coordinator() -> bool {
    info("Testing connection coordinator...");

    let discovery = Arc::new(PeerDiscoveryManager::new("local_peer".to_string()));
    let signaling = Arc::new(SignalingManager::new("local_peer".to_string()));

    let mut coordinator = ConnectionCoordinator::new(
        discovery.clone(),
        signaling.clone(),
    );

    // Configure
    coordinator.set_target_connections(3);
    coordinator.set_max_concurrent(2);
    data("Target connections", "3");
    data("Max concurrent", "2");

    // Add some peers
    for i in 0..5 {
        let announcement = PeerAnnouncement::new(
            format!("peer_{}", i),
            format!("kaspatest:qp{}...", i),
            format!("pk_{}", i),
        );
        discovery.process_announcement(announcement).unwrap();
    }

    // Should need connections
    assert!(coordinator.needs_connections());
    data("Needs connections", "yes");

    // Auto-connect
    let initiated = coordinator.auto_connect();
    assert!(!initiated.is_empty());
    assert!(initiated.len() <= 2); // Max concurrent
    data("Connections initiated", &initiated.len().to_string());

    // Check active
    let active = coordinator.active_connection_count();
    assert_eq!(active, initiated.len());
    data("Active connections", &active.to_string());

    // Handle success
    if !initiated.is_empty() {
        coordinator.handle_connection_established(&initiated[0]);
        let active_after = coordinator.active_connection_count();
        assert_eq!(active_after, active - 1);
        data("After success", &format!("{} active", active_after));
    }

    true
}

fn test_statistics() -> bool {
    info("Testing statistics tracking...");

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
    data("Peers discovered", "3");

    // Broadcast announcement
    manager.mark_announced();
    let stats = manager.get_stats();
    assert_eq!(stats.announcements_broadcast, 1);
    data("Announcements broadcast", "1");

    // Record connections
    manager.mark_connecting("peer_0").unwrap();
    let stats = manager.get_stats();
    assert_eq!(stats.connections_initiated, 1);
    data("Connections initiated", "1");

    manager.record_connection_success("peer_0").unwrap();
    let stats = manager.get_stats();
    assert_eq!(stats.connections_established, 1);
    data("Connections established", "1");

    manager.mark_connecting("peer_1").unwrap();
    manager.record_connection_failure("peer_1").unwrap();
    let stats = manager.get_stats();
    assert_eq!(stats.connections_failed, 1);
    data("Connections failed", "1");

    manager.block_peer("peer_2");
    let stats = manager.get_stats();
    assert_eq!(stats.peers_banned, 1);
    data("Peers banned", "1");

    true
}

fn test_callbacks() -> bool {
    info("Testing callbacks...");

    let manager = PeerDiscoveryManager::new("local_peer".to_string());

    let discovered_count = Arc::new(AtomicUsize::new(0));
    let status_changes = Arc::new(AtomicUsize::new(0));

    let discovered_clone = discovered_count.clone();
    manager.set_on_peer_discovered(move |_peer| {
        discovered_clone.fetch_add(1, Ordering::SeqCst);
    });

    let status_clone = status_changes.clone();
    manager.set_on_peer_status_change(move |_peer_id, _status| {
        status_clone.fetch_add(1, Ordering::SeqCst);
    });

    // Discover peers
    for i in 0..3 {
        let announcement = PeerAnnouncement::new(
            format!("peer_{}", i),
            format!("kaspatest:qp{}...", i),
            format!("pk_{}", i),
        );
        manager.process_announcement(announcement).unwrap();
    }

    assert_eq!(discovered_count.load(Ordering::SeqCst), 3);
    data("Discovered callbacks", "3");

    // Status changes
    manager.update_peer_status("peer_0", PeerStatus::Connected).unwrap();
    manager.update_peer_status("peer_1", PeerStatus::Failed).unwrap();

    assert_eq!(status_changes.load(Ordering::SeqCst), 2);
    data("Status change callbacks", "2");

    true
}
