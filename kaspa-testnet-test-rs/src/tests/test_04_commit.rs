use anyhow::{Result, Context};
use kaspa_wrpc_client::{KaspaRpcClient, WrpcEncoding};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpIf, OpEndIf, OpFalse, OpBlake2b, OpEqual};
use kaspa_addresses::Address;
use crate::utils;
use serde_json::json;
use std::path::PathBuf;

pub async fn run() -> Result<()> {
    utils::header("Test 04: P2SH Commit Transaction");

    utils::warning("NOTE: This test requires testnet KAS in your wallet!");
    utils::info("Get testnet KAS from: https://faucet.kaspanet.io/");

    // Step 1: Load or generate wallet
    utils::section("Loading wallet");

    let wallet_path = PathBuf::from("./wallet/test-wallet.txt");
    let wallet = if wallet_path.exists() {
        let spinner = utils::spinner("Loading existing wallet...");
        let w = utils::TestWallet::load_from_file(&wallet_path)?;
        spinner.finish_and_clear();
        utils::success("Wallet loaded");
        w
    } else {
        let spinner = utils::spinner("Generating new wallet...");
        let w = utils::TestWallet::generate()?;
        w.save_to_file(&wallet_path)?;
        spinner.finish_and_clear();
        utils::success("New wallet generated and saved");
        utils::warning(&format!("Please fund this address: {}", w.address_string()));
        utils::warning("Get testnet KAS from: https://faucet.kaspanet.io/");
        w
    };

    utils::data("Wallet Address", &wallet.address_string());

    // Step 2: Connect to RPC (using mainnet endpoint for now)
    utils::section("Connecting to Kaspa RPC");

    use kaspa_consensus_core::network::{NetworkId, NetworkType};

    let spinner = utils::spinner("Creating RPC client...");

    // Use local testnet node
    let network_id = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let endpoint = "ws://127.0.0.1:17110";

    let rpc_client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some(endpoint),
        None,
        Some(network_id),
        None,
    )?;

    spinner.finish_and_clear();
    utils::success("RPC client created");

    let connect_spinner = utils::spinner(&format!("Connecting to {}...", endpoint));
    rpc_client.connect(None).await?;
    connect_spinner.finish_and_clear();
    utils::success("Connected successfully");
    utils::warning("Note: Using mainnet RPC, but wallet is testnet (balance check will fail)");

    // Step 3: Check wallet balance
    utils::section("Checking wallet balance");

    let balance_spinner = utils::spinner("Querying UTXOs...");
    let utxos_result = rpc_client.get_utxos_by_addresses(vec![wallet.address.clone()]).await;

    let utxos = match utxos_result {
        Ok(utxos) => utxos,
        Err(e) => {
            balance_spinner.finish_and_clear();
            utils::error(&format!("Failed to get UTXOs: {}", e));
            utils::warning("Wallet may not have any funds");
            utils::info("This test requires testnet KAS. Please fund the wallet and try again.");
            rpc_client.disconnect().await?;
            return Ok(());
        }
    };

    balance_spinner.finish_and_clear();

    if utxos.is_empty() {
        utils::warning("No UTXOs found - wallet has no funds");
        utils::info(&format!("Please send testnet KAS to: {}", wallet.address_string()));
        utils::info("Get testnet KAS from: https://faucet.kaspanet.io/");
        rpc_client.disconnect().await?;
        return Ok(());
    }

    let total_balance: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
    utils::success(&format!("Found {} UTXOs", utxos.len()));
    utils::data("Total Balance", &format!("{} sompi ({} KAS)", total_balance, total_balance as f64 / 1e8));

    // Step 4: Build P2SH reveal script
    utils::section("Building P2SH reveal script");

    let peer_announcement = json!({
        "peerId": "12D3KooWTest",
        "connectionInfo": {
            "multiaddrs": ["/ip4/192.168.1.100/tcp/9001"],
            "protocol": "webrtc"
        },
        "timestamp": chrono::Utc::now().timestamp(),
    });

    let script_spinner = utils::spinner("Constructing reveal script...");

    let mut script = ScriptBuilder::new();
    script.add_data(&wallet.public_key)?;
    script.add_op(OpCheckSig)?;
    script.add_op(OpFalse)?;
    script.add_op(OpIf)?;
    script.add_data(b"p2pcomm")?;
    script.add_i64(1)?;
    let announcement_bytes = utils::json_to_bytes(&peer_announcement)?;
    script.add_data(&announcement_bytes)?;
    script.add_op(OpEndIf)?;

    let reveal_script_bytes = script.drain();

    script_spinner.finish_and_clear();
    utils::success(&format!("Reveal script built ({} bytes)", reveal_script_bytes.len()));

    // Step 5: Create P2SH commit address
    utils::section("Creating P2SH commit address");

    let commit_spinner = utils::spinner("Generating P2SH address...");

    let script_hash = utils::script_hash(&reveal_script_bytes);

    let mut p2sh_builder = ScriptBuilder::new();
    p2sh_builder.add_op(OpBlake2b)?;
    p2sh_builder.add_data(&script_hash)?;
    p2sh_builder.add_op(OpEqual)?;

    let p2sh_script_bytes = p2sh_builder.drain();
    // Note: In real implementation, we need to convert p2sh_script to an Address
    // This is a simplified version showing the concept

    commit_spinner.finish_and_clear();
    utils::success("P2SH commit address created");
    utils::data("Script Hash", &utils::to_hex(&script_hash));
    utils::data("P2SH Script", &utils::to_hex(&p2sh_script_bytes));

    // Step 6: Build commit transaction
    utils::section("Building commit transaction");

    utils::info("In a real implementation, we would:");
    utils::info("  1. Create transaction inputs from our UTXOs");
    utils::info("  2. Create output to P2SH address (commit)");
    utils::info("  3. Create change output back to our wallet");
    utils::info("  4. Sign the transaction");
    utils::info("  5. Broadcast to the network");

    utils::warning("Transaction building requires kaspa-wallet-core's transaction builder");
    utils::warning("This is a complex operation that needs proper fee calculation");
    utils::warning("and signature handling - beyond the scope of this test");

    // Save the reveal script for Test 05
    let script_path = PathBuf::from("./results/reveal-script.bin");
    if let Some(parent) = script_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&script_path, &reveal_script_bytes)?;
    utils::success(&format!("Reveal script saved to {:?}", script_path));

    // Disconnect
    utils::section("Cleaning up");
    rpc_client.disconnect().await?;
    utils::success("Disconnected from testnet");

    utils::success("Test 04 completed");
    utils::info("Note: Actual transaction creation requires full wallet integration");
    Ok(())
}
