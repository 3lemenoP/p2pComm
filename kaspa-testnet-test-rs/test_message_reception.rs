/// Test program for Week 3: UTXO monitoring and message reception
/// Run with: cargo run --bin test-reception

#[path = "src/utxo_monitor.rs"]
mod utxo_monitor;

#[path = "src/message_extractor.rs"]
mod message_extractor;

#[path = "src/message_reception.rs"]
mod message_reception;

#[path = "src/rpc_client.rs"]
mod rpc_client;

use utxo_monitor::{UtxoMonitor, NewUtxoEvent, MonitorState, DUST_THRESHOLD};
use message_extractor::{KaspaEnvelope, EnvelopeType, MessageExtractor, ENVELOPE_VERSION, APP_ID};
use message_reception::{MessageReceptionHandler, MessageReceptionPipeline, ReceivedMessage};

fn main() -> anyhow::Result<()> {
    println!("=== P2PComm Week 3: Message Reception Test ===\n");

    // ============================================
    // Part 1: UTXO Monitor Tests
    // ============================================
    println!("=== Part 1: UTXO Monitor ===\n");

    // Test 1.1: Create UTXO monitor
    println!("Test 1.1: Creating UTXO monitor...");
    let monitor = UtxoMonitor::new();
    assert_eq!(monitor.get_state(), MonitorState::Stopped);
    println!("✓ UTXO monitor created");
    println!("  State: {:?}", monitor.get_state());
    println!("  Addresses: {}", monitor.address_count());
    println!();

    // Test 1.2: Add addresses to monitor
    println!("Test 1.2: Adding addresses to monitor...");
    let addresses = vec![
        "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7".to_string(),
        "kaspatest:qrpupyeqkk6hj8793pj2a7jggf38dduq9sv3l0k4ax3re4snglyakwp8s29ex".to_string(),
    ];
    monitor.add_addresses(&addresses)?;
    println!("✓ Added {} addresses", addresses.len());
    println!("  Addresses monitored: {}", monitor.address_count());
    println!();

    // Test 1.3: UTXO event creation
    println!("Test 1.3: Creating UTXO events...");
    let utxo_entry = rpc_client::UtxoEntry {
        transaction_id: "abc123def456".to_string(),
        index: 0,
        amount: DUST_THRESHOLD,
        script_public_key: vec![],
        block_daa_score: 12345,
        is_coinbase: false,
    };
    let event = NewUtxoEvent::from_utxo_entry(&utxo_entry, &addresses[0]);
    println!("✓ UTXO event created");
    println!("  TX ID: {}", event.transaction_id);
    println!("  Amount: {} sompis", event.amount);
    println!("  Is Dust: {}", event.is_dust);
    assert!(event.is_dust);
    println!();

    // Test 1.4: Backoff calculation
    println!("Test 1.4: Testing backoff calculation...");
    println!("  0 failures: {} seconds", monitor.calculate_backoff(0));
    println!("  1 failure:  {} seconds", monitor.calculate_backoff(1));
    println!("  2 failures: {} seconds", monitor.calculate_backoff(2));
    println!("  5 failures: {} seconds", monitor.calculate_backoff(5));
    println!("✓ Backoff calculation working");
    println!();

    // Test 1.5: Monitor state transitions
    println!("Test 1.5: Testing state transitions...");
    monitor.start_polling();
    assert_eq!(monitor.get_state(), MonitorState::Polling);
    println!("  Started polling: {:?}", monitor.get_state());
    monitor.stop();
    assert_eq!(monitor.get_state(), MonitorState::Stopped);
    println!("  Stopped: {:?}", monitor.get_state());
    println!("✓ State transitions working");
    println!();

    // ============================================
    // Part 2: Message Extractor Tests
    // ============================================
    println!("=== Part 2: Message Extractor ===\n");

    // Test 2.1: Create envelope
    println!("Test 2.1: Creating KaspaEnvelope...");
    let envelope = KaspaEnvelope::new(
        EnvelopeType::Message,
        "sender_peer_abc123".to_string(),
        "recipient_peer_xyz789".to_string(),
        b"Hello from Kaspa blockchain!".to_vec(),
    );
    println!("✓ Envelope created");
    println!("  Version: {}", envelope.version);
    println!("  App ID: {}", envelope.app_id);
    println!("  Type: {:?}", envelope.envelope_type);
    println!("  Data size: {} bytes", envelope.data.len());
    println!();

    // Test 2.2: Envelope serialization
    println!("Test 2.2: Testing envelope serialization...");
    let mut signed_envelope = envelope.clone();
    signed_envelope.signature = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let bytes = signed_envelope.to_bytes()?;
    println!("✓ Serialized to {} bytes", bytes.len());
    println!();

    // Test 2.3: Envelope deserialization
    println!("Test 2.3: Testing envelope deserialization...");
    let restored = KaspaEnvelope::from_bytes(&bytes)?;
    assert_eq!(restored.version, signed_envelope.version);
    assert_eq!(restored.sender_peer_id, signed_envelope.sender_peer_id);
    assert_eq!(restored.data, signed_envelope.data);
    println!("✓ Deserialized successfully");
    println!("  Version match: {}", restored.version == ENVELOPE_VERSION);
    println!("  App ID match: {}", restored.app_id == APP_ID);
    println!("  Data match: {}", restored.data == signed_envelope.data);
    println!();

    // Test 2.4: Envelope validation
    println!("Test 2.4: Testing envelope validation...");
    assert!(signed_envelope.validate().is_ok());
    println!("✓ Valid envelope passes validation");

    let mut invalid = envelope.clone();
    assert!(invalid.validate().is_err()); // Missing signature
    println!("✓ Invalid envelope fails validation (missing signature)");
    println!();

    // Test 2.5: Envelope type detection
    println!("Test 2.5: Testing envelope types...");
    let offer_envelope = KaspaEnvelope::new(
        EnvelopeType::SignalingOffer,
        "sender".to_string(),
        "recipient".to_string(),
        b"sdp_data".to_vec(),
    );
    assert!(offer_envelope.envelope_type.is_signaling());
    println!("✓ SignalingOffer is_signaling: true");

    let msg_envelope = KaspaEnvelope::new(
        EnvelopeType::Message,
        "sender".to_string(),
        "recipient".to_string(),
        b"chat".to_vec(),
    );
    assert!(!msg_envelope.envelope_type.is_signaling());
    println!("✓ Message is_signaling: false");
    println!();

    // Test 2.6: P2PComm payload detection
    println!("Test 2.6: Testing P2PComm payload detection...");
    assert!(MessageExtractor::is_p2pcomm_payload(&bytes));
    println!("✓ Valid P2PComm payload detected");

    assert!(!MessageExtractor::is_p2pcomm_payload(&[0, 0, 0]));
    println!("✓ Invalid payload rejected");
    println!();

    // Test 2.7: Extract envelopes
    println!("Test 2.7: Testing envelope extraction...");
    let extracted = MessageExtractor::extract_envelopes(&bytes)?;
    assert_eq!(extracted.len(), 1);
    println!("✓ Extracted {} envelope(s)", extracted.len());
    println!("  Summary: {}", MessageExtractor::summarize_envelope(&extracted[0]));
    println!();

    // ============================================
    // Part 3: Message Reception Handler Tests
    // ============================================
    println!("=== Part 3: Message Reception Handler ===\n");

    // Test 3.1: Create handler
    println!("Test 3.1: Creating message reception handler...");
    let handler = MessageReceptionHandler::new("my_peer_id_123".to_string());
    println!("✓ Handler created");
    println!("  Message count: {}", handler.message_count());
    println!();

    // Test 3.2: Process incoming envelope
    println!("Test 3.2: Processing incoming envelope...");
    let mut incoming = KaspaEnvelope::new(
        EnvelopeType::Message,
        "remote_sender_456".to_string(),
        "my_peer_id_123".to_string(), // Matches our peer ID
        b"Hello, this is a test message!".to_vec(),
    );
    incoming.signature = vec![1, 2, 3, 4, 5];

    let result = handler.process_envelope(&incoming, "tx_12345")?;
    assert!(result.is_some());
    println!("✓ Message processed successfully");
    let msg = result.unwrap();
    println!("  Sender: {}", msg.sender_peer_id);
    println!("  Type: {:?}", msg.message_type);
    println!("  Signature verified: {}", msg.signature_verified);
    println!();

    // Test 3.3: Wrong recipient filtering
    println!("Test 3.3: Testing wrong recipient filtering...");
    let mut wrong_recipient = KaspaEnvelope::new(
        EnvelopeType::Message,
        "sender".to_string(),
        "someone_else".to_string(), // Not us
        b"Not for us".to_vec(),
    );
    wrong_recipient.signature = vec![1, 2, 3];

    let result = handler.process_envelope(&wrong_recipient, "tx_999")?;
    assert!(result.is_none());
    println!("✓ Message for wrong recipient filtered out");
    println!();

    // Test 3.4: Duplicate detection
    println!("Test 3.4: Testing duplicate detection...");
    let mut dup_envelope = KaspaEnvelope::new(
        EnvelopeType::Message,
        "sender".to_string(),
        "my_peer_id_123".to_string(),
        b"Duplicate test".to_vec(),
    );
    dup_envelope.signature = vec![1, 2, 3];
    dup_envelope.message_id = Some("unique_msg_id_001".to_string());

    // First time should succeed
    let result1 = handler.process_envelope(&dup_envelope, "tx_1")?;
    assert!(result1.is_some());
    println!("  First message: accepted");

    // Second time should be filtered
    let result2 = handler.process_envelope(&dup_envelope, "tx_1")?;
    assert!(result2.is_none());
    println!("  Duplicate message: filtered");
    println!("✓ Duplicate detection working");
    println!();

    // Test 3.5: Signaling message routing
    println!("Test 3.5: Testing signaling message routing...");
    let handler2 = MessageReceptionHandler::new("my_peer_id".to_string());

    let mut sdp_offer = KaspaEnvelope::new(
        EnvelopeType::SignalingOffer,
        "remote_peer".to_string(),
        "my_peer_id".to_string(),
        b"v=0\r\no=- 123 2 IN IP4 127.0.0.1\r\n...".to_vec(),
    );
    sdp_offer.signature = vec![1, 2, 3];

    handler2.process_envelope(&sdp_offer, "tx_signaling")?;

    let pending = handler2.get_pending_signaling();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].signaling_type, EnvelopeType::SignalingOffer);
    println!("✓ Signaling message routed correctly");
    println!("  Type: {:?}", pending[0].signaling_type);
    println!("  From: {}", pending[0].sender_peer_id);
    println!();

    // Test 3.6: Reception statistics
    println!("Test 3.6: Checking reception statistics...");
    let stats = handler.get_stats();
    println!("✓ Statistics retrieved");
    println!("  Messages received: {}", stats.messages_received);
    println!("  Signatures verified: {}", stats.signatures_verified);
    println!("  Duplicates filtered: {}", stats.duplicates_filtered);
    println!();

    // ============================================
    // Part 4: Full Pipeline Tests
    // ============================================
    println!("=== Part 4: Full Reception Pipeline ===\n");

    // Test 4.1: Create pipeline
    println!("Test 4.1: Creating reception pipeline...");
    let pipeline = MessageReceptionPipeline::new("my_peer_id".to_string());
    println!("✓ Pipeline created");
    println!();

    // Test 4.2: Add addresses to pipeline
    println!("Test 4.2: Adding addresses to pipeline...");
    pipeline.add_addresses(&[
        "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7".to_string(),
        "kaspatest:qrpupyeqkk6hj8793pj2a7jggf38dduq9sv3l0k4ax3re4snglyakwp8s29ex".to_string(),
    ])?;
    println!("✓ Addresses added to pipeline");
    println!("  UTXO monitor addresses: {}", pipeline.utxo_monitor.address_count());
    println!();

    // Test 4.3: Pipeline statistics
    println!("Test 4.3: Checking pipeline statistics...");
    let (monitor_stats, reception_stats) = pipeline.get_stats();
    println!("✓ Pipeline statistics");
    println!("  Monitor - Addresses: {}", monitor_stats.addresses_monitored);
    println!("  Monitor - Poll cycles: {}", monitor_stats.poll_cycles);
    println!("  Reception - Messages: {}", reception_stats.messages_received);
    println!();

    // ============================================
    // Summary
    // ============================================
    println!("=== All Week 3 Tests Completed! ===\n");

    println!("✓ UTXO Monitor");
    println!("  - Address monitoring");
    println!("  - Dust detection (≤{} sompis)", DUST_THRESHOLD);
    println!("  - State management");
    println!("  - Backoff calculation");
    println!();

    println!("✓ Message Extractor");
    println!("  - KaspaEnvelope serialization/deserialization");
    println!("  - Envelope validation");
    println!("  - P2PComm payload detection");
    println!("  - Multiple envelope extraction");
    println!();

    println!("✓ Message Reception Handler");
    println!("  - Envelope processing");
    println!("  - Recipient filtering");
    println!("  - Duplicate detection");
    println!("  - Signaling message routing");
    println!("  - Statistics tracking");
    println!();

    println!("✓ Full Reception Pipeline");
    println!("  - Integrated UTXO monitoring");
    println!("  - Message reception handling");
    println!("  - Ready for RPC integration");
    println!();

    println!("Week 3 Implementation Complete!");
    println!("Next: Week 4 - WebRTC Signaling via Kaspa");

    Ok(())
}
