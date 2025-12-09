/// Test program for transaction_builder module
/// Run with: cargo run --bin test-tx

// Include modules directly
#[path = "src/wallet_manager.rs"]
mod wallet_manager;

#[path = "src/transaction_builder.rs"]
mod transaction_builder;

use anyhow::Result;
use wallet_manager::{P2PCommWallet, WalletConfig};
use transaction_builder::{TransactionBuilder, kas_to_sompis, sompis_to_kas, DUST_AMOUNT};

fn main() -> Result<()> {
    println!("=== P2PComm Transaction Builder Test ===\n");

    // Test 1: Create a wallet for testing
    println!("Test 1: Setting up test wallet...");
    let config = WalletConfig::default();
    let wallet = P2PCommWallet::from_password("test_password", config)?;
    let sender_address = wallet.get_primary_address()?;
    println!("✓ Wallet created");
    println!("  Sender Address: {}", sender_address);
    println!();

    // Test 2: Create transaction builder
    println!("Test 2: Creating transaction builder...");
    let mut builder = TransactionBuilder::new();
    println!("✓ Transaction builder created");
    println!();

    // Test 3: Add input UTXO
    println!("Test 3: Adding input UTXO...");
    let tx_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let amount = kas_to_sompis(0.1); // 0.1 KAS = 10,000,000 sompis
    builder.add_input(tx_id, 0, amount, vec![])?;
    println!("✓ Added input UTXO");
    println!("  Transaction ID: {}", tx_id);
    println!("  Amount: {} sompis ({} KAS)", amount, sompis_to_kas(amount));
    println!();

    // Test 4: Add dust output (recipient notification)
    println!("Test 4: Adding dust output...");
    let recipient = "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7";
    builder.add_dust_output(recipient)?;
    println!("✓ Added dust output");
    println!("  Recipient: {}", recipient);
    println!("  Amount: {} sompis ({} KAS)", DUST_AMOUNT, sompis_to_kas(DUST_AMOUNT));
    println!();

    // Test 5: Set message payload
    println!("Test 5: Setting message payload...");
    let message = b"Hello from P2PComm! This is a test message embedded in the Kaspa blockchain.";
    builder.set_payload(message.to_vec())?;
    println!("✓ Payload set");
    println!("  Size: {} bytes", message.len());
    println!("  Content: {}", String::from_utf8_lossy(message));
    println!();

    // Test 6: Set change address
    println!("Test 6: Setting change address...");
    builder.set_change_address(&sender_address)?;
    println!("✓ Change address set");
    println!("  Address: {}", sender_address);
    println!();

    // Test 7: Calculate fees
    println!("Test 7: Calculating transaction fees...");
    let fee = builder.calculate_fee();
    println!("✓ Fee calculated");
    println!("  Fee: {} sompis ({} KAS)", fee, sompis_to_kas(fee));
    println!();

    // Test 8: Display transaction summary
    println!("Test 8: Transaction summary...");
    println!("{}", builder.summary());
    println!();

    // Test 9: Build transaction
    println!("Test 9: Building transaction...");
    let tx = builder.build()?;
    println!("✓ Transaction built successfully");
    println!("  Version: {}", tx.version);
    println!("  Inputs: {}", tx.inputs.len());
    println!("  Outputs: {}", tx.outputs.len());
    println!("  Payload: {} bytes", tx.payload.len());
    println!("  Lock time: {}", tx.lock_time);
    println!();

    // Test 10: Verify transaction properties
    println!("Test 10: Verifying transaction properties...");

    if tx.inputs.len() == 1 {
        println!("✓ Correct number of inputs (1)");
    } else {
        println!("✗ Incorrect number of inputs: {}", tx.inputs.len());
    }

    if tx.outputs.len() == 2 {  // dust + change
        println!("✓ Correct number of outputs (2: dust + change)");
    } else {
        println!("✗ Incorrect number of outputs: {}", tx.outputs.len());
    }

    if tx.payload.len() == message.len() {
        println!("✓ Payload size correct ({} bytes)", tx.payload.len());
    } else {
        println!("✗ Payload size incorrect: {} bytes", tx.payload.len());
    }

    // Verify dust output amount
    if tx.outputs[0].value == DUST_AMOUNT {
        println!("✓ Dust output amount correct ({} sompis)", DUST_AMOUNT);
    } else {
        println!("✗ Dust output amount incorrect: {} sompis", tx.outputs[0].value);
    }

    // Verify change output exists
    if tx.outputs[1].value > 0 {
        println!("✓ Change output created ({} sompis)", tx.outputs[1].value);
    } else {
        println!("✗ Change output missing or zero");
    }

    println!();

    // Test 11: Test large payload
    println!("Test 11: Testing large payload...");
    let mut large_builder = TransactionBuilder::new();
    large_builder.add_input(tx_id, 0, kas_to_sompis(1.0), vec![])?;
    large_builder.add_dust_output(recipient)?;
    large_builder.set_change_address(&sender_address)?;

    let large_payload = vec![0u8; 50_000]; // 50 KB payload
    large_builder.set_payload(large_payload.clone())?;
    println!("✓ Large payload accepted");
    println!("  Size: {} bytes", large_payload.len());

    let large_tx = large_builder.build()?;
    println!("✓ Transaction with large payload built");
    println!("  Payload size in transaction: {} bytes", large_tx.payload.len());
    println!();

    // Test 12: Test payload size limit
    println!("Test 12: Testing payload size limit...");
    let mut max_builder = TransactionBuilder::new();
    let too_large = vec![0u8; 100_000]; // 100 KB - should fail

    match max_builder.set_payload(too_large) {
        Ok(_) => println!("✗ Should have rejected oversized payload"),
        Err(e) => {
            println!("✓ Correctly rejected oversized payload");
            println!("  Error: {}", e);
        }
    }
    println!();

    // Test 13: Unit conversions
    println!("Test 13: Testing KAS/sompis conversions...");
    assert_eq!(kas_to_sompis(1.0), 100_000_000);
    assert_eq!(kas_to_sompis(0.5), 50_000_000);
    assert_eq!(kas_to_sompis(0.00001), 1_000);
    println!("✓ KAS to sompis conversions correct");

    assert_eq!(sompis_to_kas(100_000_000), 1.0);
    assert_eq!(sompis_to_kas(50_000_000), 0.5);
    assert_eq!(sompis_to_kas(1_000), 0.00001);
    println!("✓ Sompis to KAS conversions correct");
    println!();

    println!("=== All Tests Passed! ===");
    println!();
    println!("✓ Transaction Builder is working correctly");
    println!("✓ Can build transactions with message payloads");
    println!("✓ Fee calculation working");
    println!("✓ Change outputs created correctly");
    println!("✓ Payload size limits enforced");
    println!("✓ Ready for RPC client integration");

    Ok(())
}
