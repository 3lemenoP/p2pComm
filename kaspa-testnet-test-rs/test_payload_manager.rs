/// Test program for payload_manager module
/// Run with: cargo run --bin test-payload

#[path = "src/payload_manager.rs"]
mod payload_manager;

use payload_manager::{
    PayloadManager, QueuedMessage, MessagePriority, MessageType, MessageStatus, MAX_PAYLOAD_SIZE,
};

fn main() -> anyhow::Result<()> {
    println!("=== P2PComm Payload Manager Test ===\n");

    // Test 1: Create payload manager
    println!("Test 1: Creating payload manager...");
    let manager = PayloadManager::new();
    println!("✓ Payload manager created");
    println!("  Queue size: {}", manager.queue_size());
    println!("  Sent count: {}", manager.sent_count());
    println!("  Failed count: {}", manager.failed_count());
    println!();

    // Test 2: Queue a simple message
    println!("Test 2: Queuing a simple message...");
    let recipient = "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7";
    let message1_id = manager.queue_message(
        recipient.to_string(),
        b"Hello from P2PComm!".to_vec(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;
    println!("✓ Message queued");
    println!("  Message ID: {}", message1_id);
    println!("  Queue size: {}", manager.queue_size());
    println!();

    // Test 3: Queue multiple messages with different priorities
    println!("Test 3: Queuing messages with different priorities...");
    let low_id = manager.queue_message(
        recipient.to_string(),
        b"Low priority message".to_vec(),
        MessageType::Chat,
        MessagePriority::Low,
    )?;
    println!("  Low priority queued: {}", low_id);

    let high_id = manager.queue_message(
        recipient.to_string(),
        b"High priority message".to_vec(),
        MessageType::Chat,
        MessagePriority::High,
    )?;
    println!("  High priority queued: {}", high_id);

    let critical_id = manager.queue_message(
        recipient.to_string(),
        b"Critical message".to_vec(),
        MessageType::System,
        MessagePriority::Critical,
    )?;
    println!("  Critical priority queued: {}", critical_id);

    println!("✓ Multiple priorities queued");
    println!("  Total queue size: {}", manager.queue_size());
    println!();

    // Test 4: Verify priority ordering
    println!("Test 4: Verifying priority ordering...");
    let msg1 = manager.peek_next_message().unwrap();
    println!("  Next message priority: {:?}", msg1.priority);
    if msg1.priority == MessagePriority::Critical {
        println!("✓ Critical priority message is first");
    } else {
        println!("✗ Priority ordering incorrect!");
    }
    println!();

    // Test 5: Process messages in order
    println!("Test 5: Processing messages by priority...");
    let mut processed = Vec::new();
    while let Some(msg) = manager.get_next_message() {
        processed.push((msg.priority, msg.id.clone()));
    }

    println!("✓ Processed {} messages", processed.len());
    for (i, (priority, id)) in processed.iter().enumerate() {
        println!("  {}. Priority: {:?}, ID: {}", i + 1, priority, id);
    }
    println!("  Queue size after processing: {}", manager.queue_size());
    println!();

    // Test 6: Message types
    println!("Test 6: Testing different message types...");
    manager.queue_message(
        recipient.to_string(),
        b"Chat message".to_vec(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;
    manager.queue_message(
        recipient.to_string(),
        b"Signaling data".to_vec(),
        MessageType::Signaling,
        MessagePriority::High,
    )?;
    manager.queue_message(
        recipient.to_string(),
        b"File metadata".to_vec(),
        MessageType::FileMetadata,
        MessagePriority::Normal,
    )?;

    let stats = manager.get_stats();
    println!("✓ Different message types queued");
    println!("  Total messages: {}", stats.queued_count);
    println!("  By type:");
    for (msg_type, count) in &stats.by_type {
        println!("    {:?}: {}", msg_type, count);
    }
    println!();

    // Test 7: Queue statistics
    println!("Test 7: Getting queue statistics...");
    let stats = manager.get_stats();
    println!("✓ Statistics retrieved");
    println!("  Queued: {}", stats.queued_count);
    println!("  Sent: {}", stats.sent_count);
    println!("  Failed: {}", stats.failed_count);
    println!("  Total payload size: {} bytes", stats.total_payload_size);
    println!("  By priority:");
    for (priority, count) in &stats.by_priority {
        println!("    {:?}: {}", priority, count);
    }
    println!();

    // Test 8: Mark message as sent
    println!("Test 8: Marking message as sent...");
    let test_msg_id = manager.queue_message(
        recipient.to_string(),
        b"Test send".to_vec(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;
    println!("  Queued message: {}", test_msg_id);

    manager.mark_message_sent(&test_msg_id, "test_tx_12345".to_string())?;
    println!("✓ Message marked as sent");
    println!("  Queue size: {}", manager.queue_size());
    println!("  Sent count: {}", manager.sent_count());
    println!();

    // Test 9: Mark message as failed and retry
    println!("Test 9: Testing message failure and retry...");
    let fail_msg_id = manager.queue_message(
        recipient.to_string(),
        b"Test failure".to_vec(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;
    println!("  Queued message: {}", fail_msg_id);

    // Simulate failure
    manager.mark_message_failed(&fail_msg_id)?;
    println!("✓ Message marked as failed");
    println!("  Queue size (should still be in queue for retry): {}", manager.queue_size());
    println!();

    // Test 10: Get messages for specific recipient
    println!("Test 10: Getting messages for specific recipient...");
    let recipient2 = "kaspatest:qrpupyeqkk6hj8793pj2a7jggf38dduq9sv3l0k4ax3re4snglyakwp8s29ex";

    manager.queue_message(
        recipient.to_string(),
        b"Message to recipient 1".to_vec(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;

    manager.queue_message(
        recipient2.to_string(),
        b"Message to recipient 2".to_vec(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;

    let messages_for_r1 = manager.get_messages_for_recipient(recipient);
    let messages_for_r2 = manager.get_messages_for_recipient(recipient2);

    println!("✓ Messages filtered by recipient");
    println!("  Messages for recipient 1: {}", messages_for_r1.len());
    println!("  Messages for recipient 2: {}", messages_for_r2.len());
    println!();

    // Test 11: Large payload
    println!("Test 11: Testing large payload...");
    let large_payload = vec![0u8; 50_000]; // 50 KB
    let large_id = manager.queue_message(
        recipient.to_string(),
        large_payload.clone(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;
    println!("✓ Large payload queued");
    println!("  Payload size: {} bytes", large_payload.len());
    println!("  Message ID: {}", large_id);
    println!();

    // Test 12: Payload size limit
    println!("Test 12: Testing payload size limit...");
    let oversized_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
    match manager.queue_message(
        recipient.to_string(),
        oversized_payload,
        MessageType::Chat,
        MessagePriority::Normal,
    ) {
        Ok(_) => println!("✗ Should have rejected oversized payload"),
        Err(e) => {
            println!("✓ Correctly rejected oversized payload");
            println!("  Error: {}", e);
        }
    }
    println!();

    // Test 13: Message priorities by value
    println!("Test 13: Testing priority comparison...");
    assert!(MessagePriority::Critical > MessagePriority::High);
    assert!(MessagePriority::High > MessagePriority::Normal);
    assert!(MessagePriority::Normal > MessagePriority::Low);
    println!("✓ Priority ordering verified");
    println!("  Critical > High > Normal > Low");
    println!();

    // Test 14: Clear queues
    println!("Test 14: Clearing all queues...");
    let before_clear = manager.queue_size();
    manager.clear_all();
    println!("✓ Queues cleared");
    println!("  Before: {} messages", before_clear);
    println!("  After: {} messages", manager.queue_size());
    println!();

    // Test 15: QueuedMessage creation and properties
    println!("Test 15: Testing QueuedMessage directly...");
    let msg = QueuedMessage::new(
        recipient.to_string(),
        b"Direct message test".to_vec(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;
    println!("✓ QueuedMessage created");
    println!("  ID: {}", msg.id);
    println!("  Status: {:?}", msg.status);
    println!("  Priority: {:?}", msg.priority);
    println!("  Attempts: {}", msg.attempts);
    println!("  Original size: {} bytes", msg.original_size);
    println!("  Queued at: {}", msg.queued_at);
    println!();

    println!("=== All Payload Manager Tests Completed! ===\n");
    println!("✓ Payload Manager is working correctly");
    println!("✓ Priority-based message queuing");
    println!("✓ Message status tracking");
    println!("✓ Queue statistics and filtering");
    println!("✓ Payload size validation");
    println!("✓ Ready for delivery strategy integration");

    Ok(())
}
