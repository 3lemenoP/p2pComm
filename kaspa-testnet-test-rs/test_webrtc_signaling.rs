/// WebRTC Signaling Test Suite
///
/// Tests the WebRTC signaling module for P2PComm:
/// - Signaling state machine transitions
/// - SDP offer/answer exchange
/// - ICE candidate handling and batching
/// - Session management and timeouts
/// - Integration with KaspaEnvelope system

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

use webrtc_signaling::*;
use message_extractor::EnvelopeType;
use message_reception::SignalingMessage;
use chrono::Utc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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

    header("WebRTC Signaling Test Suite");
    info("Testing WebRTC signaling over Kaspa blockchain");
    println!();

    let mut passed = 0;
    let mut failed = 0;

    // Run all tests
    let tests: Vec<(&str, fn() -> bool)> = vec![
        ("Signaling State Machine", test_signaling_state_machine),
        ("Session Creation", test_session_creation),
        ("Offer/Answer Flow", test_offer_answer_flow),
        ("ICE Candidate Handling", test_ice_candidate_handling),
        ("ICE Batching", test_ice_batching),
        ("Incoming Offer Processing", test_incoming_offer),
        ("Incoming Answer Processing", test_incoming_answer),
        ("Incoming ICE Processing", test_incoming_ice),
        ("Session Timeout", test_session_timeout),
        ("Duplicate Connection Prevention", test_duplicate_connection),
        ("Callbacks", test_callbacks),
        ("KaspaEnvelope Integration", test_envelope_integration),
        ("Full Connection Flow", test_full_connection_flow),
        ("Multi-Peer Sessions", test_multi_peer_sessions),
        ("Statistics Tracking", test_statistics),
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
        success("All WebRTC signaling tests passed!");
    } else {
        error(&format!("{} test(s) failed", failed));
    }

    println!("\n=== WebRTC Signaling Tests Complete! ===\n");
}

fn test_signaling_state_machine() -> bool {
    info("Testing signaling state transitions...");

    // Test state display
    assert_eq!(format!("{}", SignalingState::Idle), "idle");
    assert_eq!(format!("{}", SignalingState::CreatingOffer), "creating_offer");
    assert_eq!(format!("{}", SignalingState::OfferSent), "offer_sent");
    assert_eq!(format!("{}", SignalingState::OfferReceived), "offer_received");
    assert_eq!(format!("{}", SignalingState::AnswerSent), "answer_sent");
    assert_eq!(format!("{}", SignalingState::IceExchange), "ice_exchange");
    assert_eq!(format!("{}", SignalingState::Connected), "connected");
    assert_eq!(format!("{}", SignalingState::Closed), "closed");
    assert_eq!(format!("{}", SignalingState::Failed), "failed");
    data("All states", "display correctly");

    // Test SDP type display
    assert_eq!(format!("{}", SdpType::Offer), "offer");
    assert_eq!(format!("{}", SdpType::Answer), "answer");
    data("SDP types", "display correctly");

    true
}

fn test_session_creation() -> bool {
    info("Testing session creation...");

    // Test initiator session
    let initiator = SignalingSession::new_as_initiator("remote_peer".to_string());
    assert!(initiator.is_initiator);
    assert_eq!(initiator.state, SignalingState::CreatingOffer);
    assert!(initiator.session_id.starts_with("session_"));
    assert!(initiator.local_ice_candidates.is_empty());
    assert!(initiator.remote_ice_candidates.is_empty());
    assert!(!initiator.ice_gathering_complete);
    data("Initiator session", "created correctly");

    // Test responder session
    let responder = SignalingSession::new_as_responder(
        "remote_peer".to_string(),
        "session_abc123".to_string(),
    );
    assert!(!responder.is_initiator);
    assert_eq!(responder.state, SignalingState::OfferReceived);
    assert_eq!(responder.session_id, "session_abc123");
    data("Responder session", "created correctly");

    // Test can_accept_ice for different states
    let mut session = SignalingSession::new_as_initiator("peer".to_string());
    assert!(!session.can_accept_ice()); // CreatingOffer

    session.state = SignalingState::OfferSent;
    assert!(session.can_accept_ice());

    session.state = SignalingState::OfferReceived;
    assert!(session.can_accept_ice());

    session.state = SignalingState::AnswerSent;
    assert!(session.can_accept_ice());

    session.state = SignalingState::IceExchange;
    assert!(session.can_accept_ice());

    session.state = SignalingState::Connected;
    assert!(!session.can_accept_ice());

    session.state = SignalingState::Closed;
    assert!(!session.can_accept_ice());
    data("ICE acceptance", "state-dependent");

    true
}

fn test_offer_answer_flow() -> bool {
    info("Testing offer/answer flow...");

    let manager = SignalingManager::new("alice_peer".to_string());

    // Initiate connection
    let session_id = manager.initiate_connection("bob_peer").unwrap();
    data("Session initiated", &session_id);

    assert_eq!(
        manager.get_session_state("bob_peer"),
        Some(SignalingState::CreatingOffer)
    );

    // Set local offer
    let test_sdp = "v=0\r\no=- 123456 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n";
    manager.set_local_offer("bob_peer", test_sdp).unwrap();

    assert_eq!(
        manager.get_session_state("bob_peer"),
        Some(SignalingState::OfferSent)
    );
    data("Offer set", "state = offer_sent");

    // Check outgoing signal
    let signals = manager.take_outgoing_signals();
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].signal_type, SignalType::Offer);
    assert_eq!(signals[0].peer_id, "bob_peer");
    data("Outgoing offer", "queued correctly");

    // Verify SDP in signal
    let sdp_data: SdpData = serde_json::from_str(&signals[0].data).unwrap();
    assert_eq!(sdp_data.sdp_type, SdpType::Offer);
    assert!(sdp_data.sdp.contains("v=0"));
    data("SDP content", "serialized correctly");

    true
}

fn test_ice_candidate_handling() -> bool {
    info("Testing ICE candidate handling...");

    let manager = SignalingManager::new("alice_peer".to_string());

    // Setup session
    manager.initiate_connection("bob_peer").unwrap();
    manager.set_local_offer("bob_peer", "v=0...").unwrap();
    manager.take_outgoing_signals(); // Clear offer

    // Add single ICE candidate
    let candidate = IceCandidate {
        candidate: "candidate:1 1 UDP 2122252543 192.168.1.1 12345 typ host".to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_m_line_index: Some(0),
        username_fragment: Some("abc123".to_string()),
        session_id: "session_1".to_string(),
    };

    manager.add_local_ice_candidate("bob_peer", candidate.clone()).unwrap();
    data("ICE candidate", "added to session");

    // Complete gathering to flush
    manager.set_ice_gathering_complete("bob_peer").unwrap();
    data("ICE gathering", "complete");

    // Check signal was sent
    let signals = manager.take_outgoing_signals();
    assert!(!signals.is_empty());
    data("ICE signal", "sent");

    // Verify stats
    let stats = manager.get_stats();
    assert_eq!(stats.ice_candidates_sent, 1);
    data("ICE candidates sent", "1");

    true
}

fn test_ice_batching() -> bool {
    info("Testing ICE candidate batching...");

    let manager = SignalingManager::new("alice_peer".to_string());

    // Setup session
    manager.initiate_connection("bob_peer").unwrap();
    manager.set_local_offer("bob_peer", "v=0...").unwrap();
    manager.take_outgoing_signals(); // Clear offer

    // Add multiple candidates (should batch)
    for i in 0..5 {
        let candidate = IceCandidate {
            candidate: format!("candidate:{} 1 UDP 2122252543 192.168.1.{} 12345 typ host", i, i),
            sdp_mid: Some("0".to_string()),
            sdp_m_line_index: Some(0),
            username_fragment: None,
            session_id: "session_1".to_string(),
        };
        manager.add_local_ice_candidate("bob_peer", candidate).unwrap();
    }
    data("ICE candidates added", "5");

    // Complete gathering to flush
    manager.set_ice_gathering_complete("bob_peer").unwrap();

    // Should be batched into single signal
    let signals = manager.take_outgoing_signals();
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].signal_type, SignalType::IceBatch);
    data("Batch signal", "created");

    // Verify batch contains all candidates
    let batch: Vec<IceCandidate> = serde_json::from_str(&signals[0].data).unwrap();
    assert_eq!(batch.len(), 5);
    data("Batch size", "5 candidates");

    // Stats should show all sent
    let stats = manager.get_stats();
    assert_eq!(stats.ice_candidates_sent, 5);
    data("Stats ICE sent", "5");

    true
}

fn test_incoming_offer() -> bool {
    info("Testing incoming offer processing...");

    let manager = SignalingManager::new("bob_peer".to_string());

    let sdp_data = SdpData {
        sdp_type: SdpType::Offer,
        sdp: "v=0\r\no=- 123 1 IN IP4 0.0.0.0\r\n".to_string(),
        session_id: "session_from_alice".to_string(),
    };

    let message = SignalingMessage {
        sender_peer_id: "alice_peer".to_string(),
        signaling_type: EnvelopeType::SignalingOffer,
        data: serde_json::to_string(&sdp_data).unwrap(),
        timestamp: Utc::now().timestamp_millis() as u64,
    };

    manager.process_incoming(&message).unwrap();
    data("Offer received", "from alice_peer");

    // Check session was created
    assert_eq!(
        manager.get_session_state("alice_peer"),
        Some(SignalingState::OfferReceived)
    );
    data("Session state", "offer_received");

    // Check stats
    let stats = manager.get_stats();
    assert_eq!(stats.offers_received, 1);
    data("Stats offers received", "1");

    // Can now set answer
    manager.set_local_answer("alice_peer", "v=0\r\n...answer...").unwrap();
    assert_eq!(
        manager.get_session_state("alice_peer"),
        Some(SignalingState::AnswerSent)
    );
    data("Answer set", "state = answer_sent");

    true
}

fn test_incoming_answer() -> bool {
    info("Testing incoming answer processing...");

    let manager = SignalingManager::new("alice_peer".to_string());

    // First, alice sends offer
    manager.initiate_connection("bob_peer").unwrap();
    manager.set_local_offer("bob_peer", "v=0...offer...").unwrap();
    manager.take_outgoing_signals();

    // Now bob's answer arrives
    let sdp_data = SdpData {
        sdp_type: SdpType::Answer,
        sdp: "v=0\r\n...bob's answer...".to_string(),
        session_id: manager.get_session("bob_peer").unwrap().session_id,
    };

    let message = SignalingMessage {
        sender_peer_id: "bob_peer".to_string(),
        signaling_type: EnvelopeType::SignalingAnswer,
        data: serde_json::to_string(&sdp_data).unwrap(),
        timestamp: Utc::now().timestamp_millis() as u64,
    };

    manager.process_incoming(&message).unwrap();
    data("Answer received", "from bob_peer");

    // Should transition to ICE exchange
    assert_eq!(
        manager.get_session_state("bob_peer"),
        Some(SignalingState::IceExchange)
    );
    data("Session state", "ice_exchange");

    let stats = manager.get_stats();
    assert_eq!(stats.answers_received, 1);
    data("Stats answers received", "1");

    true
}

fn test_incoming_ice() -> bool {
    info("Testing incoming ICE candidate processing...");

    let manager = SignalingManager::new("alice_peer".to_string());

    // Setup session in ICE exchange state
    manager.initiate_connection("bob_peer").unwrap();
    manager.set_local_offer("bob_peer", "v=0...").unwrap();

    // Simulate answer received (manually set state)
    manager.set_session_state("bob_peer", SignalingState::IceExchange).unwrap();

    // Receive ICE candidate
    let candidate = IceCandidate {
        candidate: "candidate:1 1 UDP 12345 10.0.0.1 5000 typ host".to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_m_line_index: Some(0),
        username_fragment: None,
        session_id: "session_1".to_string(),
    };

    let message = SignalingMessage {
        sender_peer_id: "bob_peer".to_string(),
        signaling_type: EnvelopeType::SignalingIce,
        data: serde_json::to_string(&candidate).unwrap(),
        timestamp: Utc::now().timestamp_millis() as u64,
    };

    manager.process_incoming(&message).unwrap();
    data("ICE candidate", "received");

    let stats = manager.get_stats();
    assert_eq!(stats.ice_candidates_received, 1);
    data("Stats ICE received", "1");

    // Test ICE batch
    let candidates = vec![
        IceCandidate {
            candidate: "candidate:2 1 UDP 11111 10.0.0.2 5001 typ srflx".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_m_line_index: Some(0),
            username_fragment: None,
            session_id: "session_1".to_string(),
        },
        IceCandidate {
            candidate: "candidate:3 1 UDP 10000 10.0.0.3 5002 typ relay".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_m_line_index: Some(0),
            username_fragment: None,
            session_id: "session_1".to_string(),
        },
    ];

    let batch_message = SignalingMessage {
        sender_peer_id: "bob_peer".to_string(),
        signaling_type: EnvelopeType::SignalingIce,
        data: serde_json::to_string(&candidates).unwrap(),
        timestamp: Utc::now().timestamp_millis() as u64,
    };

    manager.process_incoming(&batch_message).unwrap();
    data("ICE batch", "2 candidates received");

    let stats = manager.get_stats();
    assert_eq!(stats.ice_candidates_received, 3);
    data("Stats total ICE received", "3");

    true
}

fn test_session_timeout() -> bool {
    info("Testing session timeout...");

    let manager = SignalingManager::new("alice_peer".to_string());
    manager.initiate_connection("bob_peer").unwrap();

    // Manually set old timestamp (120 seconds ago)
    manager.set_session_last_activity("bob_peer", 120).unwrap();

    assert_eq!(
        manager.get_session_state("bob_peer"),
        Some(SignalingState::CreatingOffer)
    );

    // Cleanup with 60 second timeout
    manager.cleanup_timed_out(60);

    // Should be marked as failed
    assert_eq!(
        manager.get_session_state("bob_peer"),
        Some(SignalingState::Failed)
    );
    data("Timed out session", "marked failed");

    let stats = manager.get_stats();
    assert_eq!(stats.sessions_timed_out, 1);
    data("Stats timeouts", "1");

    true
}

fn test_duplicate_connection() -> bool {
    info("Testing duplicate connection prevention...");

    let manager = SignalingManager::new("alice_peer".to_string());

    // First connection should succeed
    let result1 = manager.initiate_connection("bob_peer");
    assert!(result1.is_ok());
    data("First connection", "succeeded");

    // Second should fail
    let result2 = manager.initiate_connection("bob_peer");
    assert!(result2.is_err());
    data("Duplicate connection", "rejected");

    // After failure, should allow new connection
    manager.connection_failed("bob_peer", "test failure").unwrap();
    let result3 = manager.initiate_connection("bob_peer");
    assert!(result3.is_ok());
    data("After failure", "new connection allowed");

    true
}

fn test_callbacks() -> bool {
    info("Testing callbacks...");

    let manager = SignalingManager::new("alice_peer".to_string());

    // Track callback invocations
    let offer_count = Arc::new(AtomicUsize::new(0));
    let answer_count = Arc::new(AtomicUsize::new(0));
    let connected_count = Arc::new(AtomicUsize::new(0));
    let ice_count = Arc::new(AtomicUsize::new(0));

    let offer_clone = offer_count.clone();
    manager.set_on_create_offer(move |_session_id| {
        offer_clone.fetch_add(1, Ordering::SeqCst);
    });

    let answer_clone = answer_count.clone();
    manager.set_on_create_answer(move |_peer_id, _sdp| {
        answer_clone.fetch_add(1, Ordering::SeqCst);
    });

    let connected_clone = connected_count.clone();
    manager.set_on_connected(move |_peer_id, _session_id| {
        connected_clone.fetch_add(1, Ordering::SeqCst);
    });

    let ice_clone = ice_count.clone();
    manager.set_on_remote_ice(move |_peer_id, _candidate| {
        ice_clone.fetch_add(1, Ordering::SeqCst);
    });

    // Trigger offer callback
    manager.initiate_connection("bob_peer").unwrap();
    assert_eq!(offer_count.load(Ordering::SeqCst), 1);
    data("on_create_offer", "triggered");

    // Trigger answer callback
    let sdp_data = SdpData {
        sdp_type: SdpType::Offer,
        sdp: "v=0...".to_string(),
        session_id: "session_1".to_string(),
    };
    let message = SignalingMessage {
        sender_peer_id: "charlie_peer".to_string(),
        signaling_type: EnvelopeType::SignalingOffer,
        data: serde_json::to_string(&sdp_data).unwrap(),
        timestamp: Utc::now().timestamp_millis() as u64,
    };
    manager.process_incoming(&message).unwrap();
    assert_eq!(answer_count.load(Ordering::SeqCst), 1);
    data("on_create_answer", "triggered");

    // Trigger connected callback
    manager.set_local_offer("bob_peer", "v=0...").unwrap();
    manager.connection_established("bob_peer").unwrap();
    assert_eq!(connected_count.load(Ordering::SeqCst), 1);
    data("on_connected", "triggered");

    // Trigger ICE callback
    manager.set_local_answer("charlie_peer", "v=0...answer").unwrap();
    let candidate = IceCandidate {
        candidate: "candidate:1...".to_string(),
        sdp_mid: None,
        sdp_m_line_index: None,
        username_fragment: None,
        session_id: "session_1".to_string(),
    };
    let ice_message = SignalingMessage {
        sender_peer_id: "charlie_peer".to_string(),
        signaling_type: EnvelopeType::SignalingIce,
        data: serde_json::to_string(&candidate).unwrap(),
        timestamp: Utc::now().timestamp_millis() as u64,
    };
    manager.process_incoming(&ice_message).unwrap();
    assert_eq!(ice_count.load(Ordering::SeqCst), 1);
    data("on_remote_ice", "triggered");

    true
}

fn test_envelope_integration() -> bool {
    info("Testing KaspaEnvelope integration...");

    let builder = SignalingMessageBuilder::new("alice_peer".to_string());

    // Test offer envelope
    let offer_signal = OutgoingSignal {
        peer_id: "bob_peer".to_string(),
        signal_type: SignalType::Offer,
        data: r#"{"sdp_type":"Offer","sdp":"v=0...","session_id":"sess_1"}"#.to_string(),
        session_id: "sess_1".to_string(),
        created_at: Utc::now(),
    };

    let envelope = builder.build_envelope(&offer_signal);
    assert_eq!(envelope.envelope_type, EnvelopeType::SignalingOffer);
    assert_eq!(envelope.sender_peer_id, "alice_peer");
    assert_eq!(envelope.recipient_peer_id, "bob_peer");
    assert!(envelope.message_id.is_some());
    data("Offer envelope", "built correctly");

    // Test answer envelope
    let answer_signal = OutgoingSignal {
        peer_id: "bob_peer".to_string(),
        signal_type: SignalType::Answer,
        data: r#"{"sdp_type":"Answer","sdp":"v=0...","session_id":"sess_1"}"#.to_string(),
        session_id: "sess_1".to_string(),
        created_at: Utc::now(),
    };

    let envelope = builder.build_envelope(&answer_signal);
    assert_eq!(envelope.envelope_type, EnvelopeType::SignalingAnswer);
    data("Answer envelope", "built correctly");

    // Test ICE envelope
    let ice_signal = OutgoingSignal {
        peer_id: "bob_peer".to_string(),
        signal_type: SignalType::IceCandidate,
        data: r#"{"candidate":"...","session_id":"sess_1"}"#.to_string(),
        session_id: "sess_1".to_string(),
        created_at: Utc::now(),
    };

    let envelope = builder.build_envelope(&ice_signal);
    assert_eq!(envelope.envelope_type, EnvelopeType::SignalingIce);
    data("ICE envelope", "built correctly");

    // Test ICE batch envelope
    let batch_signal = OutgoingSignal {
        peer_id: "bob_peer".to_string(),
        signal_type: SignalType::IceBatch,
        data: r#"[{"candidate":"..."},{"candidate":"..."}]"#.to_string(),
        session_id: "sess_1".to_string(),
        created_at: Utc::now(),
    };

    let envelope = builder.build_envelope(&batch_signal);
    assert_eq!(envelope.envelope_type, EnvelopeType::SignalingIce);
    data("ICE batch envelope", "built correctly");

    true
}

fn test_full_connection_flow() -> bool {
    info("Testing full connection flow simulation...");

    // Alice and Bob managers
    let alice = SignalingManager::new("alice_peer".to_string());
    let bob = SignalingManager::new("bob_peer".to_string());

    // 1. Alice initiates
    alice.initiate_connection("bob_peer").unwrap();
    alice.set_local_offer("bob_peer", "v=0...alice_offer").unwrap();
    data("Step 1", "Alice created offer");

    // 2. Deliver offer to Bob
    let alice_signals = alice.take_outgoing_signals();
    let offer_msg = SignalingMessage {
        sender_peer_id: "alice_peer".to_string(),
        signaling_type: EnvelopeType::SignalingOffer,
        data: alice_signals[0].data.clone(),
        timestamp: Utc::now().timestamp_millis() as u64,
    };
    bob.process_incoming(&offer_msg).unwrap();
    data("Step 2", "Bob received offer");

    // 3. Bob creates answer
    bob.set_local_answer("alice_peer", "v=0...bob_answer").unwrap();
    data("Step 3", "Bob created answer");

    // 4. Deliver answer to Alice
    let bob_signals = bob.take_outgoing_signals();
    let answer_msg = SignalingMessage {
        sender_peer_id: "bob_peer".to_string(),
        signaling_type: EnvelopeType::SignalingAnswer,
        data: bob_signals[0].data.clone(),
        timestamp: Utc::now().timestamp_millis() as u64,
    };
    alice.process_incoming(&answer_msg).unwrap();
    data("Step 4", "Alice received answer");

    // 5. ICE exchange
    // Alice adds ICE candidate
    let alice_ice = IceCandidate {
        candidate: "candidate:alice_1...".to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_m_line_index: Some(0),
        username_fragment: None,
        session_id: "sess".to_string(),
    };
    alice.add_local_ice_candidate("bob_peer", alice_ice).unwrap();
    alice.set_ice_gathering_complete("bob_peer").unwrap();

    // Bob adds ICE candidate
    let bob_ice = IceCandidate {
        candidate: "candidate:bob_1...".to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_m_line_index: Some(0),
        username_fragment: None,
        session_id: "sess".to_string(),
    };
    bob.add_local_ice_candidate("alice_peer", bob_ice).unwrap();
    bob.set_ice_gathering_complete("alice_peer").unwrap();
    data("Step 5", "ICE candidates exchanged");

    // Exchange ICE
    let alice_ice_signals = alice.take_outgoing_signals();
    let bob_ice_signals = bob.take_outgoing_signals();

    if !alice_ice_signals.is_empty() {
        let ice_msg = SignalingMessage {
            sender_peer_id: "alice_peer".to_string(),
            signaling_type: EnvelopeType::SignalingIce,
            data: alice_ice_signals[0].data.clone(),
            timestamp: Utc::now().timestamp_millis() as u64,
        };
        bob.process_incoming(&ice_msg).unwrap();
    }

    if !bob_ice_signals.is_empty() {
        let ice_msg = SignalingMessage {
            sender_peer_id: "bob_peer".to_string(),
            signaling_type: EnvelopeType::SignalingIce,
            data: bob_ice_signals[0].data.clone(),
            timestamp: Utc::now().timestamp_millis() as u64,
        };
        alice.process_incoming(&ice_msg).unwrap();
    }

    // 6. Mark connections established
    alice.connection_established("bob_peer").unwrap();
    bob.connection_established("alice_peer").unwrap();
    data("Step 6", "Connections established");

    // Verify final states
    assert_eq!(alice.get_session_state("bob_peer"), Some(SignalingState::Connected));
    assert_eq!(bob.get_session_state("alice_peer"), Some(SignalingState::Connected));

    let alice_stats = alice.get_stats();
    let bob_stats = bob.get_stats();

    assert_eq!(alice_stats.offers_sent, 1);
    assert_eq!(alice_stats.answers_received, 1);
    assert_eq!(alice_stats.connections_established, 1);

    assert_eq!(bob_stats.offers_received, 1);
    assert_eq!(bob_stats.answers_sent, 1);
    assert_eq!(bob_stats.connections_established, 1);

    data("Both peers", "connected successfully");

    true
}

fn test_multi_peer_sessions() -> bool {
    info("Testing multi-peer sessions...");

    let manager = SignalingManager::new("alice_peer".to_string());

    // Connect to multiple peers
    manager.initiate_connection("bob_peer").unwrap();
    manager.initiate_connection("charlie_peer").unwrap();
    manager.initiate_connection("dave_peer").unwrap();
    data("Connections initiated", "3 peers");

    // Set offers for all
    manager.set_local_offer("bob_peer", "v=0...bob").unwrap();
    manager.set_local_offer("charlie_peer", "v=0...charlie").unwrap();
    manager.set_local_offer("dave_peer", "v=0...dave").unwrap();

    // Get active sessions
    let active = manager.get_active_sessions();
    assert_eq!(active.len(), 3);
    data("Active sessions", "3");

    // Close one
    manager.close_connection("charlie_peer").unwrap();

    let active = manager.get_active_sessions();
    assert_eq!(active.len(), 2);
    data("After close", "2 active");

    // Fail one
    manager.connection_failed("dave_peer", "network error").unwrap();

    let active = manager.get_active_sessions();
    assert_eq!(active.len(), 1);
    data("After failure", "1 active");

    true
}

fn test_statistics() -> bool {
    info("Testing statistics tracking...");

    let manager = SignalingManager::new("alice_peer".to_string());

    // Do various operations
    manager.initiate_connection("peer1").unwrap();
    manager.set_local_offer("peer1", "v=0...").unwrap();

    manager.initiate_connection("peer2").unwrap();
    manager.set_local_offer("peer2", "v=0...").unwrap();

    // Receive an offer
    let sdp_data = SdpData {
        sdp_type: SdpType::Offer,
        sdp: "v=0...".to_string(),
        session_id: "sess_3".to_string(),
    };
    let msg = SignalingMessage {
        sender_peer_id: "peer3".to_string(),
        signaling_type: EnvelopeType::SignalingOffer,
        data: serde_json::to_string(&sdp_data).unwrap(),
        timestamp: Utc::now().timestamp_millis() as u64,
    };
    manager.process_incoming(&msg).unwrap();
    manager.set_local_answer("peer3", "v=0...answer").unwrap();

    // ICE candidates
    for i in 0..3 {
        let candidate = IceCandidate {
            candidate: format!("candidate:{}", i),
            sdp_mid: None,
            sdp_m_line_index: None,
            username_fragment: None,
            session_id: "sess".to_string(),
        };
        manager.add_local_ice_candidate("peer1", candidate).unwrap();
    }
    manager.set_ice_gathering_complete("peer1").unwrap();

    // Establish and fail connections
    manager.connection_established("peer1").unwrap();
    manager.connection_failed("peer2", "error").unwrap();

    // Check all stats
    let stats = manager.get_stats();

    data("Offers sent", &stats.offers_sent.to_string());
    data("Offers received", &stats.offers_received.to_string());
    data("Answers sent", &stats.answers_sent.to_string());
    data("ICE sent", &stats.ice_candidates_sent.to_string());
    data("Connections OK", &stats.connections_established.to_string());
    data("Connections failed", &stats.connections_failed.to_string());

    assert_eq!(stats.offers_sent, 2);
    assert_eq!(stats.offers_received, 1);
    assert_eq!(stats.answers_sent, 1);
    assert_eq!(stats.ice_candidates_sent, 3);
    assert_eq!(stats.connections_established, 1);
    assert_eq!(stats.connections_failed, 1);

    true
}
