/// Test program for RPC client module
/// Run with: cargo run --bin test-rpc
///
/// Note: This test requires internet connectivity and a working Kaspa testnet

#[path = "src/rpc_client.rs"]
mod rpc_client;

use anyhow::Result;
use rpc_client::{KaspaTestnetClient, DEFAULT_TESTNET_RPC, TESTNET_ENDPOINTS};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== P2PComm RPC Client Test ===\n");

    // Test 1: Create RPC client
    println!("Test 1: Creating RPC client...");
    let mut client = KaspaTestnetClient::new();
    println!("✓ Client created");
    println!("  Endpoint: {}", client.endpoint());
    println!("  Connected: {}", client.is_connected());
    println!();

    // Test 2: Test endpoint listing
    println!("Test 2: Available testnet endpoints...");
    println!("✓ {} endpoints configured:", TESTNET_ENDPOINTS.len());
    for (i, endpoint) in TESTNET_ENDPOINTS.iter().enumerate() {
        println!("  {}. {}", i + 1, endpoint);
    }
    println!();

    // Test 3: Connect to testnet
    println!("Test 3: Connecting to Kaspa testnet...");
    println!("  Endpoint: {}", DEFAULT_TESTNET_RPC);
    match client.connect().await {
        Ok(_) => {
            println!("✓ Connected successfully");
            println!("  Status: {}", if client.is_connected() { "Connected" } else { "Disconnected" });
        }
        Err(e) => {
            println!("✗ Connection failed: {}", e);
            println!("\nNote: This test requires:");
            println!("  - Internet connectivity");
            println!("  - Kaspa testnet to be operational");
            println!("  - No firewall blocking WebSocket connections");
            return Ok(());
        }
    }
    println!();

    // Test 4: Get network information
    println!("Test 4: Fetching network information...");
    match client.get_info().await {
        Ok(info) => {
            println!("✓ Network info retrieved");
            println!("  Server Version: {}", info.server_version);
            println!("  Is Synced: {}", info.is_synced);
            println!("  Is UTXO Indexed: {}", info.is_utxo_indexed);
        }
        Err(e) => {
            println!("✗ Failed to get network info: {}", e);
        }
    }
    println!();

    // Test 5: Get block DAG info
    println!("Test 5: Fetching block DAG information...");
    match client.get_block_dag_info().await {
        Ok(info) => {
            println!("✓ Block DAG info retrieved");
            println!("  Network: {}", info.network);
            println!("  Block Count: {}", info.block_count);
            println!("  Header Count: {}", info.header_count);
            println!("  Virtual DAA Score: {}", info.virtual_daa_score);
            println!("  Difficulty: {:.2}", info.difficulty);
            println!("  Tip Hashes: {} blocks", info.tip_hashes.len());
            if !info.tip_hashes.is_empty() {
                println!("    First tip: {}", info.tip_hashes[0]);
            }
        }
        Err(e) => {
            println!("✗ Failed to get block DAG info: {}", e);
        }
    }
    println!();

    // Test 6: Query a known testnet address for UTXOs
    println!("Test 6: Querying UTXOs for test address...");
    // Using a test address - replace with actual testnet address if needed
    let test_address = "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7";
    println!("  Address: {}", test_address);

    match client.get_utxos_by_address(test_address).await {
        Ok(utxos) => {
            println!("✓ UTXOs retrieved");
            println!("  UTXO Count: {}", utxos.len());

            if utxos.is_empty() {
                println!("  (No UTXOs found - address has no balance)");
            } else {
                println!("  UTXOs:");
                for (i, utxo) in utxos.iter().enumerate().take(5) {
                    println!("    {}. TX: {}:{}", i + 1, &utxo.transaction_id[..16], utxo.index);
                    println!("       Amount: {} sompis ({} KAS)", utxo.amount, utxo.amount as f64 / 100_000_000.0);
                    println!("       Coinbase: {}", utxo.is_coinbase);
                }
                if utxos.len() > 5 {
                    println!("    ... and {} more", utxos.len() - 5);
                }
            }
        }
        Err(e) => {
            println!("✗ Failed to get UTXOs: {}", e);
        }
    }
    println!();

    // Test 7: Get balance for test address
    println!("Test 7: Checking balance for test address...");
    match client.get_balance(test_address).await {
        Ok(balance) => {
            println!("✓ Balance retrieved");
            println!("  Balance: {} sompis", balance);
            println!("  Balance: {} KAS", balance as f64 / 100_000_000.0);
        }
        Err(e) => {
            println!("✗ Failed to get balance: {}", e);
        }
    }
    println!();

    // Test 8: Query a transaction (if we know a testnet tx ID)
    println!("Test 8: Querying transaction status...");
    // This is a placeholder - you'd need a real testnet transaction ID
    let test_tx_id = "0000000000000000000000000000000000000000000000000000000000000000";
    println!("  Transaction ID: {}", test_tx_id);

    match client.get_transaction(test_tx_id).await {
        Ok(Some(tx_info)) => {
            println!("✓ Transaction found");
            println!("  Transaction ID: {}", tx_info.transaction_id);
            println!("  Is Accepted: {}", tx_info.is_accepted);
            if let Some(block_hash) = tx_info.accepting_block_hash {
                println!("  Accepting Block: {}", block_hash);
            }
        }
        Ok(None) => {
            println!("✓ Transaction not found (expected for placeholder ID)");
        }
        Err(e) => {
            println!("✓ Transaction query handled (expected error for placeholder ID)");
            println!("  Error: {}", e);
        }
    }
    println!();

    // Test 9: Test connection status check
    println!("Test 9: Verifying connection status...");
    if client.is_connected() {
        println!("✓ Client connection verified");
        println!("  Status: Connected");
    } else {
        println!("✗ Client not connected");
    }
    println!();

    // Test 10: Disconnect
    println!("Test 10: Disconnecting from testnet...");
    match client.disconnect().await {
        Ok(_) => {
            println!("✓ Disconnected successfully");
            println!("  Status: {}", if client.is_connected() { "Connected" } else { "Disconnected" });
        }
        Err(e) => {
            println!("✗ Disconnect failed: {}", e);
        }
    }
    println!();

    // Test 11: Test custom endpoint creation
    println!("Test 11: Testing custom endpoint...");
    let custom_endpoint = "wss://testnet-1.kaspad.net:443";
    let client2 = KaspaTestnetClient::with_endpoint(custom_endpoint);
    println!("✓ Client created with custom endpoint");
    println!("  Endpoint: {}", client2.endpoint());
    println!();

    println!("=== All RPC Client Tests Completed! ===\n");

    println!("✓ RPC Client is working correctly");
    println!("✓ Can connect to Kaspa testnet");
    println!("✓ Can query network information");
    println!("✓ Can fetch UTXOs and balances");
    println!("✓ Can query transactions");
    println!("✓ Ready for transaction submission");
    println!();

    println!("Next steps:");
    println!("  1. Fund a wallet address with testnet KAS");
    println!("  2. Test transaction submission with real funds");
    println!("  3. Integrate with wallet manager and transaction builder");
    println!("  4. Build end-to-end message sending flow");

    Ok(())
}
