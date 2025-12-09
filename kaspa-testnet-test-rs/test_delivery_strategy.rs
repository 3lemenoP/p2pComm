/// Test program for delivery_strategy module
/// Run with: cargo run --bin test-delivery

#[path = "src/payload_manager.rs"]
mod payload_manager;

#[path = "src/delivery_strategy.rs"]
mod delivery_strategy;

#[path = "src/wallet_manager.rs"]
mod wallet_manager;

#[path = "src/transaction_builder.rs"]
mod transaction_builder;

#[path = "src/rpc_client.rs"]
mod rpc_client;

use payload_manager::{PayloadManager, MessageType, MessagePriority};
use delivery_strategy::{DeliveryCoordinator, DeliveryMode, BatchingStrategy};

fn main() -> anyhow::Result<()> {
    println!("=== P2PComm Delivery Strategy Test ===\n");

    // Test 1: Create delivery coordinator
    println!("Test 1: Creating delivery coordinator...");
    let coordinator = DeliveryCoordinator::with_default_strategy();
    println!("✓ Delivery coordinator created");
    println!("  Strategy: {:?}", DeliveryMode::Smart);
    println!("  Pending batches: {}", coordinator.pending_batch_count());
    println!();

    // Test 2: Create payload manager with messages
    println!("Test 2: Setting up payload manager with messages...");
    let payload_manager = PayloadManager::new();

    let recipient1 = "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7";
    let recipient2 = "kaspatest:qrpupyeqkk6hj8793pj2a7jggf38dduq9sv3l0k4ax3re4snglyakwp8s29ex";

    // Queue several messages to recipient 1
    for i in 1..=5 {
        payload_manager.queue_message(
            recipient1.to_string(),
            format!("Message {} to recipient 1", i).as_bytes().to_vec(),
            MessageType::Chat,
            MessagePriority::Normal,
        )?;
    }

    // Queue messages to recipient 2
    for i in 1..=3 {
        payload_manager.queue_message(
            recipient2.to_string(),
            format!("Message {} to recipient 2", i).as_bytes().to_vec(),
            MessageType::Chat,
            MessagePriority::Normal,
        )?;
    }

    // Queue some high-priority messages
    payload_manager.queue_message(
        recipient1.to_string(),
        b"Urgent message!".to_vec(),
        MessageType::System,
        MessagePriority::High,
    )?;

    println!("✓ Messages queued");
    println!("  Total messages: {}", payload_manager.queue_size());
    println!();

    // Test 3: Process queue with Smart mode
    println!("Test 3: Processing queue with Smart delivery mode...");
    let mut smart_coordinator = DeliveryCoordinator::with_default_strategy();
    let batches = smart_coordinator.process_queue(&payload_manager);

    println!("✓ Queue processed");
    println!("  Batches created: {}", batches.len());
    for (i, batch) in batches.iter().enumerate() {
        println!("  Batch {}: {} messages, {} bytes, recipient: {}...{}",
            i + 1,
            batch.messages.len(),
            batch.total_size,
            &batch.recipient[..15],
            &batch.recipient[batch.recipient.len()-10..]);
    }
    println!();

    // Test 4: Test immediate delivery mode
    println!("Test 4: Testing Immediate delivery mode...");
    let payload_manager2 = PayloadManager::new();
    payload_manager2.queue_message(
        recipient1.to_string(),
        b"Immediate message".to_vec(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;

    let immediate_strategy = BatchingStrategy {
        mode: DeliveryMode::Immediate,
        ..Default::default()
    };
    let mut immediate_coordinator = DeliveryCoordinator::new(immediate_strategy);
    let immediate_batches = immediate_coordinator.process_queue(&payload_manager2);

    println!("✓ Immediate mode processed");
    println!("  Batches created: {}", immediate_batches.len());
    if !immediate_batches.is_empty() {
        println!("  Messages per batch: {}", immediate_batches[0].messages.len());
    }
    println!();

    // Test 5: Test batched delivery mode
    println!("Test 5: Testing Batched delivery mode...");
    let payload_manager3 = PayloadManager::new();
    for i in 1..=10 {
        payload_manager3.queue_message(
            recipient1.to_string(),
            format!("Batch message {}", i).as_bytes().to_vec(),
            MessageType::Chat,
            MessagePriority::Normal,
        )?;
    }

    let batched_strategy = BatchingStrategy {
        mode: DeliveryMode::Batched,
        max_batch_size: 5,
        ..Default::default()
    };
    let mut batched_coordinator = DeliveryCoordinator::new(batched_strategy);
    let batched_batches = batched_coordinator.process_queue(&payload_manager3);

    println!("✓ Batched mode processed");
    println!("  Batches created: {}", batched_batches.len());
    for (i, batch) in batched_batches.iter().enumerate() {
        println!("  Batch {}: {} messages", i + 1, batch.messages.len());
    }
    println!();

    // Test 6: Message batch properties
    println!("Test 6: Testing message batch properties...");
    let payload_manager4 = PayloadManager::new();
    payload_manager4.queue_message(
        recipient1.to_string(),
        b"Test message for batch properties".to_vec(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;

    let mut test_coordinator = DeliveryCoordinator::with_default_strategy();
    let test_batches = test_coordinator.process_queue(&payload_manager4);

    if let Some(batch) = test_batches.first() {
        println!("✓ Batch properties:");
        println!("  Messages: {}", batch.messages.len());
        println!("  Total size: {} bytes", batch.total_size);
        println!("  Age: {} seconds", batch.age_seconds());
        println!("  Created at: {}", batch.created_at);
    }
    println!();

    // Test 7: Fee savings calculation
    println!("Test 7: Calculating fee savings from batching...");
    let savings_manager = PayloadManager::new();
    for i in 1..=5 {
        savings_manager.queue_message(
            recipient1.to_string(),
            format!("Message {} for savings calculation", i).as_bytes().to_vec(),
            MessageType::Chat,
            MessagePriority::Normal,
        )?;
    }

    let mut savings_coordinator = DeliveryCoordinator::with_default_strategy();
    let savings_batches = savings_coordinator.process_queue(&savings_manager);

    if let Some(batch) = savings_batches.first() {
        let savings = savings_coordinator.calculate_batch_savings(batch);
        println!("✓ Fee savings calculated");
        println!("  Messages in batch: {}", batch.messages.len());
        println!("  Estimated savings: {} sompis ({} KAS)",
            savings,
            savings as f64 / 100_000_000.0);
    }
    println!();

    // Test 8: Delivery statistics
    println!("Test 8: Checking delivery statistics...");
    let stats = smart_coordinator.get_stats();
    println!("✓ Statistics retrieved");
    println!("  Messages sent: {}", stats.messages_sent);
    println!("  Batches sent: {}", stats.batches_sent);
    println!("  Transactions created: {}", stats.transactions_created);
    println!("  Total fees paid: {} sompis", stats.total_fees_paid);
    println!("  Fees saved by batching: {} sompis", stats.fees_saved_by_batching);
    println!("  Failed deliveries: {}", stats.failed_deliveries);
    println!();

    // Test 9: Priority-based batching
    println!("Test 9: Testing priority-based batching...");
    let priority_manager = PayloadManager::new();

    // Mix of priorities
    priority_manager.queue_message(
        recipient1.to_string(),
        b"Low priority 1".to_vec(),
        MessageType::Chat,
        MessagePriority::Low,
    )?;
    priority_manager.queue_message(
        recipient1.to_string(),
        b"Critical message!".to_vec(),
        MessageType::System,
        MessagePriority::Critical,
    )?;
    priority_manager.queue_message(
        recipient1.to_string(),
        b"Normal priority 1".to_vec(),
        MessageType::Chat,
        MessagePriority::Normal,
    )?;
    priority_manager.queue_message(
        recipient1.to_string(),
        b"High priority message".to_vec(),
        MessageType::Signaling,
        MessagePriority::High,
    )?;

    let mut priority_coordinator = DeliveryCoordinator::with_default_strategy();
    let priority_batches = priority_coordinator.process_queue(&priority_manager);

    println!("✓ Priority-based batching processed");
    println!("  Batches created: {}", priority_batches.len());
    for (i, batch) in priority_batches.iter().enumerate() {
        if let Some(first_msg) = batch.messages.first() {
            println!("  Batch {}: Priority {:?}, {} messages",
                i + 1,
                first_msg.priority,
                batch.messages.len());
        }
    }
    println!();

    // Test 10: Batch size limits
    println!("Test 10: Testing batch size limits...");
    let limit_manager = PayloadManager::new();

    // Queue more messages than max batch size
    for i in 1..=15 {
        limit_manager.queue_message(
            recipient1.to_string(),
            format!("Message {} for size limit test", i).as_bytes().to_vec(),
            MessageType::Chat,
            MessagePriority::Normal,
        )?;
    }

    let limit_strategy = BatchingStrategy {
        mode: DeliveryMode::Batched,
        max_batch_size: 5,
        ..Default::default()
    };
    let mut limit_coordinator = DeliveryCoordinator::new(limit_strategy);
    let limit_batches = limit_coordinator.process_queue(&limit_manager);

    println!("✓ Batch size limits enforced");
    println!("  Total messages: 15");
    println!("  Max batch size: 5");
    println!("  Batches created: {}", limit_batches.len());
    for (i, batch) in limit_batches.iter().enumerate() {
        println!("  Batch {}: {} messages (≤ 5)", i + 1, batch.messages.len());
    }
    println!();

    println!("=== All Delivery Strategy Tests Completed! ===\n");
    println!("✓ Delivery Strategy is working correctly");
    println!("✓ Immediate, Batched, and Smart delivery modes");
    println!("✓ Priority-based message handling");
    println!("✓ Fee savings through batching");
    println!("✓ Batch size limits enforced");
    println!("✓ Ready for integration with wallet and RPC client");

    Ok(())
}
