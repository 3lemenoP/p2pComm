// Integration Tests for Network Module
// Tests the interaction between Connection, Manager, Router, and Reconnection components

use super::*;
use super::connection::Connection;
use super::manager::NetworkManager;
use super::router::{MessageRouter, MessageHandler};
use super::protocol::*;
use crate::crypto::IdentityKeyPair;
use crate::identity::{PeerId, Contact};
use crate::message::{Message, MessageContent};

/// Test message handler that collects all events
struct TestMessageHandler {
    received_messages: Vec<Message>,
    connected_peers: Vec<PeerId>,
    disconnected_peers: Vec<PeerId>,
    discovery_responses: Vec<Vec<PeerId>>,
}

impl TestMessageHandler {
    fn new() -> Self {
        Self {
            received_messages: Vec::new(),
            connected_peers: Vec::new(),
            disconnected_peers: Vec::new(),
            discovery_responses: Vec::new(),
        }
    }
}

impl MessageHandler for TestMessageHandler {
    fn on_user_message(&mut self, _from: &PeerId, message: Message) {
        self.received_messages.push(message);
    }

    fn on_peer_connected(&mut self, peer_id: &PeerId, _contact: Contact) {
        self.connected_peers.push(peer_id.clone());
    }

    fn on_peer_disconnected(&mut self, peer_id: &PeerId) {
        self.disconnected_peers.push(peer_id.clone());
    }

    fn on_discovery_response(&mut self, peer_ids: Vec<PeerId>) {
        self.discovery_responses.push(peer_ids);
    }
}

/// Test network setup with two peers
struct TestNetworkSetup {
    manager1: NetworkManager,
    manager2: NetworkManager,
    router1: MessageRouter,
    router2: MessageRouter,
    peer_id1: PeerId,
    peer_id2: PeerId,
    identity1: IdentityKeyPair,
    identity2: IdentityKeyPair,
}

impl TestNetworkSetup {
    fn new() -> Self {
        let identity1 = IdentityKeyPair::generate().unwrap();
        let identity2 = IdentityKeyPair::generate().unwrap();

        let peer_id1 = PeerId::from_public_key(&identity1.signing_keypair.verifying_key.to_bytes());
        let peer_id2 = PeerId::from_public_key(&identity2.signing_keypair.verifying_key.to_bytes());

        let mut manager1 = NetworkManager::new();
        manager1.set_local_peer_id(peer_id1.clone());

        let mut manager2 = NetworkManager::new();
        manager2.set_local_peer_id(peer_id2.clone());

        let router1 = MessageRouter::new(peer_id1.clone());
        let router2 = MessageRouter::new(peer_id2.clone());

        Self {
            manager1,
            manager2,
            router1,
            router2,
            peer_id1,
            peer_id2,
            identity1,
            identity2,
        }
    }

    fn connect_peers(&mut self) -> NetworkResult<()> {
        // Peer1 initiates connection to Peer2
        self.manager1.connect_to_peer(self.peer_id2.clone())?;
        self.manager2.add_connection(self.peer_id1.clone())?;

        // Mark both as connected
        self.manager1.mark_connected(&self.peer_id2);
        self.manager2.mark_connected(&self.peer_id1);

        Ok(())
    }

    fn simulate_handshake(&mut self, handler1: &mut TestMessageHandler, handler2: &mut TestMessageHandler) -> NetworkResult<()> {
        // Peer1 sends handshake to Peer2
        let handshake = HandshakeMessage::new(
            self.identity1.signing_keypair.verifying_key.to_bytes().to_vec(),
            self.identity1.encryption_keypair.public_key.as_bytes().to_vec()
        );

        let handshake_msg = ProtocolMessage::new(
            self.peer_id1.clone(),
            self.peer_id2.clone(),
            MessagePayload::Handshake(handshake)
        );

        // Router2 processes handshake and generates ack
        let ack_response = self.router2.route_message(handshake_msg, handler2)?;

        // Send ack back to Peer1
        if let Some(ack_msg) = ack_response {
            self.router1.route_message(ack_msg, handler1)?;
        }

        Ok(())
    }
}

#[test]
fn test_full_connection_lifecycle() {
    let mut setup = TestNetworkSetup::new();
    let mut handler1 = TestMessageHandler::new();
    let mut handler2 = TestMessageHandler::new();

    // Initially disconnected
    assert_eq!(setup.manager1.connection_count(), 0);
    assert_eq!(setup.manager2.connection_count(), 0);

    // Establish connection
    setup.connect_peers().unwrap();

    // Verify connections exist and are in connecting state initially
    assert_eq!(setup.manager1.connection_count(), 1);
    assert_eq!(setup.manager2.connection_count(), 1);

    // Perform handshake
    setup.simulate_handshake(&mut handler1, &mut handler2).unwrap();

    // Verify handshake succeeded
    assert_eq!(handler2.connected_peers.len(), 1);
    assert_eq!(handler2.connected_peers[0], setup.peer_id1);

    // Verify active connections
    assert_eq!(setup.manager1.active_connection_count(), 1);
    assert_eq!(setup.manager2.active_connection_count(), 1);

    // Check stats
    let stats1 = setup.manager1.get_aggregate_stats();
    assert_eq!(stats1.active_connections, 1);
    assert_eq!(stats1.total_connections, 1);

    // Disconnect
    setup.manager1.disconnect_peer(&setup.peer_id2, "Test complete").unwrap();

    // Verify closed
    let state = setup.manager1.get_connection_state(&setup.peer_id2).unwrap();
    assert_eq!(state, ConnectionState::Closed);

    // Cleanup
    let removed = setup.manager1.cleanup_connections();
    assert_eq!(removed, 1);
    assert_eq!(setup.manager1.connection_count(), 0);
}

#[test]
fn test_message_send_receive_flow() {
    let mut setup = TestNetworkSetup::new();
    let mut handler1 = TestMessageHandler::new();
    let mut handler2 = TestMessageHandler::new();

    // Establish connection
    setup.connect_peers().unwrap();
    setup.simulate_handshake(&mut handler1, &mut handler2).unwrap();

    // Create a user message
    let content = MessageContent::Text {
        text: "Hello, Peer2!".to_string(),
        reply_to: None,
    };

    // Create identity from keypair
    let identity1 = crate::identity::Identity {
        peer_id: setup.peer_id1.clone(),
        display_name: "Test User 1".to_string(),
        keypair: setup.identity1.clone(),
        created_at: js_sys::Date::now() as u64,
    };

    let message = Message::new(
        setup.peer_id1.clone(),
        setup.peer_id2.clone(),
        content,
        &identity1
    ).unwrap(); // Unwrap the Result

    // Wrap in protocol message
    let user_msg_payload = UserMessagePayload {
        message: message.clone(),
    };
    let protocol_msg = ProtocolMessage::new(
        setup.peer_id1.clone(),
        setup.peer_id2.clone(),
        MessagePayload::UserMessage(user_msg_payload)
    );

    // Peer1 sends message
    let bytes = setup.manager1.send_to_peer(&setup.peer_id2, protocol_msg).unwrap();
    assert!(!bytes.is_empty());

    // Peer2 receives message
    let received_msg = setup.manager2.handle_incoming_message(&setup.peer_id1, &bytes).unwrap();

    // Router2 processes message
    let ack_response = setup.router2.route_message(received_msg, &mut handler2).unwrap();

    // Verify message received
    assert_eq!(handler2.received_messages.len(), 1);
    assert_eq!(handler2.received_messages[0].id, message.id);

    // Verify acknowledgment generated
    assert!(ack_response.is_some());
    if let Some(ack_msg) = ack_response {
        if let MessagePayload::MessageAck(ack) = ack_msg.payload {
            assert_eq!(ack.message_id, message.id);
            assert!(ack.success);
        } else {
            panic!("Expected MessageAck payload");
        }
    }

    // Verify stats updated
    let stats1 = setup.manager1.get_aggregate_stats();
    assert!(stats1.total_messages_sent > 0);
    assert!(stats1.total_bytes_sent > 0);

    let stats2 = setup.manager2.get_aggregate_stats();
    assert!(stats2.total_messages_received > 0);
    assert!(stats2.total_bytes_received > 0);
}

#[test]
fn test_reconnection_after_failure() {
    let mut setup = TestNetworkSetup::new();

    // Establish connection
    setup.connect_peers().unwrap();

    // Verify connected
    let state = setup.manager1.get_connection_state(&setup.peer_id2).unwrap();
    assert_eq!(state, ConnectionState::Connected);

    // Simulate connection failure
    setup.manager1.mark_failed(&setup.peer_id2, "Network timeout".to_string());

    // Verify failed state
    let state = setup.manager1.get_connection_state(&setup.peer_id2).unwrap();
    assert_eq!(state, ConnectionState::Failed);

    // Check reconnection is scheduled
    let conn = setup.manager1.get_connection(&setup.peer_id2).unwrap();
    let delay = conn.get_reconnect_delay();
    assert!(delay > 0, "Reconnection should be scheduled");

    // Manually trigger reconnect (in real scenario, this would be timer-based)
    // First, set the next_attempt to past to allow reconnection
    if let Some(conn) = setup.manager1.get_connection_mut(&setup.peer_id2) {
        conn.set_next_reconnect_time(0); // Set to past
    }

    // Now reconnection should be allowed
    let conn = setup.manager1.get_connection(&setup.peer_id2).unwrap();
    assert!(conn.should_reconnect());

    // Attempt reconnection
    setup.manager1.reconnect_to_peer(&setup.peer_id2).unwrap();

    // Verify back to connecting state
    let state = setup.manager1.get_connection_state(&setup.peer_id2).unwrap();
    assert_eq!(state, ConnectionState::Connecting);

    // Re-establish connection
    setup.manager1.mark_connected(&setup.peer_id2);

    // Verify reconnection attempts reset
    let conn = setup.manager1.get_connection(&setup.peer_id2).unwrap();
    assert_eq!(conn.get_reconnection_attempts(), 0);
}

#[test]
fn test_health_monitoring_ping_pong() {
    let mut setup = TestNetworkSetup::new();
    let mut handler1 = TestMessageHandler::new();

    // Establish connection
    setup.connect_peers().unwrap();

    // Send keepalive pings
    let pings = setup.manager1.send_keepalive_pings().unwrap();
    assert_eq!(pings.len(), 1, "Should send ping to 1 connected peer");

    let (peer_id, ping) = &pings[0];
    assert_eq!(*peer_id, setup.peer_id2);

    // Create pong response
    let pong = PongMessage::from_ping(ping);
    let pong_msg = ProtocolMessage::new(
        setup.peer_id2.clone(),
        setup.peer_id1.clone(),
        MessagePayload::Pong(pong.clone())
    );

    // Router1 processes pong
    setup.router1.route_message(pong_msg, &mut handler1).unwrap();

    // Manager1 records pong
    setup.manager1.handle_pong(&setup.peer_id2, &pong);

    // Verify RTT tracked
    let conn = setup.manager1.get_connection(&setup.peer_id2).unwrap();
    let stats = conn.stats();
    assert!(stats.avg_rtt_ms.is_some(), "RTT should be tracked");
    assert!(stats.avg_rtt_ms.unwrap() < 1000.0, "RTT should be reasonable");

    // Verify health check passes
    assert!(conn.is_healthy(), "Connection should be healthy after pong");

    // Verify no unhealthy connections detected
    let unhealthy = setup.manager1.check_connection_health();
    assert_eq!(unhealthy.len(), 0, "No connections should be unhealthy");
}

#[test]
fn test_rate_limiting() {
    let mut setup = TestNetworkSetup::new();
    let mut handler = TestMessageHandler::new();

    // Establish connection
    setup.connect_peers().unwrap();

    // Send 100 pings rapidly (within limit)
    for _ in 0..100 {
        let ping = PingMessage::new();
        let msg = ProtocolMessage::new(
            setup.peer_id1.clone(),
            setup.peer_id2.clone(),
            MessagePayload::Ping(ping)
        );

        let result = setup.router2.route_message(msg, &mut handler);
        assert!(result.is_ok(), "First 100 messages should succeed");
    }

    // 101st message should be rate limited
    let ping = PingMessage::new();
    let msg = ProtocolMessage::new(
        setup.peer_id1.clone(),
        setup.peer_id2.clone(),
        MessagePayload::Ping(ping)
    );

    let result = setup.router2.route_message(msg, &mut handler);
    assert!(result.is_err(), "101st message should be rate limited");

    if let Err(e) = result {
        assert!(matches!(e, NetworkError::ProtocolError(_)));
    }

    // Clear rate limiter (simulating 1 second passing)
    setup.router2.clear_rate_limiter();

    // Now message should succeed again
    let ping = PingMessage::new();
    let msg = ProtocolMessage::new(
        setup.peer_id1.clone(),
        setup.peer_id2.clone(),
        MessagePayload::Ping(ping)
    );

    let result = setup.router2.route_message(msg, &mut handler);
    assert!(result.is_ok(), "Message should succeed after rate limit reset");
}

#[test]
fn test_multi_peer_broadcast() {
    let identity1 = IdentityKeyPair::generate().unwrap();
    let peer_id1 = PeerId::from_public_key(&identity1.signing_keypair.verifying_key.to_bytes());

    let mut manager = NetworkManager::new();
    manager.set_local_peer_id(peer_id1.clone());

    // Create 3 peer connections
    let peer2 = PeerId::from_public_key(&IdentityKeyPair::generate().unwrap().signing_keypair.verifying_key.to_bytes());
    let peer3 = PeerId::from_public_key(&IdentityKeyPair::generate().unwrap().signing_keypair.verifying_key.to_bytes());
    let peer4 = PeerId::from_public_key(&IdentityKeyPair::generate().unwrap().signing_keypair.verifying_key.to_bytes());

    manager.connect_to_peer(peer2.clone()).unwrap();
    manager.connect_to_peer(peer3.clone()).unwrap();
    manager.connect_to_peer(peer4.clone()).unwrap();

    // Mark all as connected
    manager.mark_connected(&peer2);
    manager.mark_connected(&peer3);
    manager.mark_connected(&peer4);

    // Broadcast ping to all peers
    let sent_count = manager.broadcast(|peer_id| {
        let ping = PingMessage::new();
        ProtocolMessage::new(
            peer_id1.clone(),
            peer_id.clone(),
            MessagePayload::Ping(ping)
        )
    });

    assert_eq!(sent_count, 3, "Should broadcast to 3 connected peers");

    // Verify stats
    let stats = manager.get_aggregate_stats();
    assert_eq!(stats.active_connections, 3);
    assert_eq!(stats.total_messages_sent, 3);

    // Disconnect one peer
    manager.disconnect_peer(&peer2, "Test").unwrap();

    // Broadcast again
    let sent_count = manager.broadcast(|peer_id| {
        let ping = PingMessage::new();
        ProtocolMessage::new(
            peer_id1.clone(),
            peer_id.clone(),
            MessagePayload::Ping(ping)
        )
    });

    assert_eq!(sent_count, 2, "Should broadcast to 2 remaining connected peers");
}

#[test]
fn test_discovery_protocol() {
    let identity1 = IdentityKeyPair::generate().unwrap();
    let peer_id1 = PeerId::from_public_key(&identity1.signing_keypair.verifying_key.to_bytes());
    let peer_id2 = PeerId::from_public_key(&IdentityKeyPair::generate().unwrap().signing_keypair.verifying_key.to_bytes());

    let mut router = MessageRouter::new(peer_id1.clone());
    let mut handler = TestMessageHandler::new();

    // Add 5 known peers
    for _ in 0..5 {
        let peer = PeerId::from_public_key(&IdentityKeyPair::generate().unwrap().signing_keypair.verifying_key.to_bytes());
        router.add_known_peer(peer);
    }

    assert_eq!(router.known_peers().len(), 5);

    // Request 3 peers
    let discovery_req = DiscoveryRequestMessage { count: 3 };
    let msg = ProtocolMessage::new(
        peer_id2.clone(),
        peer_id1.clone(),
        MessagePayload::DiscoveryRequest(discovery_req)
    );

    let response = router.route_message(msg, &mut handler).unwrap();
    assert!(response.is_some());

    // Verify response contains 3 peers
    if let Some(resp_msg) = response {
        if let MessagePayload::DiscoveryResponse(resp) = resp_msg.payload {
            assert_eq!(resp.peers.len(), 3, "Should return 3 requested peers");
        } else {
            panic!("Expected DiscoveryResponse");
        }
    }

    // Request more peers than available
    let discovery_req = DiscoveryRequestMessage { count: 100 };
    let msg = ProtocolMessage::new(
        peer_id2.clone(),
        peer_id1.clone(),
        MessagePayload::DiscoveryRequest(discovery_req)
    );

    let response = router.route_message(msg, &mut handler).unwrap();

    if let Some(resp_msg) = response {
        if let MessagePayload::DiscoveryResponse(resp) = resp_msg.payload {
            assert_eq!(resp.peers.len(), 5, "Should return all 5 available peers");
        }
    }
}

#[test]
fn test_connection_cleanup() {
    let identity1 = IdentityKeyPair::generate().unwrap();
    let peer_id1 = PeerId::from_public_key(&identity1.signing_keypair.verifying_key.to_bytes());

    let mut manager = NetworkManager::new();
    manager.set_local_peer_id(peer_id1.clone());

    // Create 3 connections
    let peer2 = PeerId::from_public_key(&IdentityKeyPair::generate().unwrap().signing_keypair.verifying_key.to_bytes());
    let peer3 = PeerId::from_public_key(&IdentityKeyPair::generate().unwrap().signing_keypair.verifying_key.to_bytes());
    let peer4 = PeerId::from_public_key(&IdentityKeyPair::generate().unwrap().signing_keypair.verifying_key.to_bytes());

    manager.connect_to_peer(peer2.clone()).unwrap();
    manager.connect_to_peer(peer3.clone()).unwrap();
    manager.connect_to_peer(peer4.clone()).unwrap();

    // Mark peer2 as connected
    manager.mark_connected(&peer2);

    // Mark peer3 as closed
    manager.disconnect_peer(&peer3, "Test").unwrap();

    // Mark peer4 as failed (no reconnect)
    manager.mark_failed(&peer4, "Failed".to_string());

    // Set peer4's reconnection attempts to max so it won't reconnect
    if let Some(conn) = manager.get_connection_mut(&peer4) {
        for _ in 0..5 {
            conn.schedule_reconnect("Max retries".to_string());
        }
    }

    // Verify states
    assert_eq!(manager.connection_count(), 3);
    assert_eq!(manager.active_connection_count(), 1); // Only peer2 is connected

    // Cleanup should remove peer3 (closed) and peer4 (failed, no reconnect)
    let removed = manager.cleanup_connections();
    assert_eq!(removed, 2, "Should remove 2 dead connections");

    // Only peer2 should remain
    assert_eq!(manager.connection_count(), 1);
    assert!(manager.get_connection(&peer2).is_some());
    assert!(manager.get_connection(&peer3).is_none());
    assert!(manager.get_connection(&peer4).is_none());

    // Verify stats accurate
    let stats = manager.get_aggregate_stats();
    assert_eq!(stats.total_connections, 1);
    assert_eq!(stats.active_connections, 1);
}
