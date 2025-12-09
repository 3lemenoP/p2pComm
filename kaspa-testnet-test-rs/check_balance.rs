// Quick balance checker for test wallet
use kaspa_wrpc_client::{KaspaRpcClient, WrpcEncoding};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_addresses::Address;
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("\n=== Kaspa Testnet Wallet Balance Checker ===\n");

    // Read wallet address
    let wallet_file = std::fs::read_to_string("./wallet/test-wallet.txt")?;
    let mnemonic = wallet_file.trim();

    println!("Wallet Mnemonic: {}...", &mnemonic[..50]);

    // For this quick check, we'll use a hard-coded address
    // In production, you'd derive it from the mnemonic
    let address_str = "kaspatest:qz78vhsnsncpkfrvwneyc5tymqw5fat4lx866al7jg000nzgwtme2s397v6d2";
    println!("Checking address: {}\n", address_str);

    // Connect to testnet RPC
    println!("Connecting to Kaspa testnet...");
    let rpc_client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some("wss://testnet-1.kas.pa"),
        None,
        None,
        None,
    )?;

    rpc_client.connect(None).await?;
    println!("✓ Connected to testnet\n");

    // Parse address
    let address = Address::from_str(address_str)?;

    // Get UTXOs
    println!("Fetching UTXOs...");
    match rpc_client.get_utxos_by_addresses(vec![address.clone()]).await {
        Ok(utxos_response) => {
            let utxo_entries = utxos_response.entries;

            if utxo_entries.is_empty() {
                println!("❌ No UTXOs found - wallet has no funds");
                println!("\nPlease fund this wallet at: https://faucet.kaspanet.io/");
                println!("Address: {}", address_str);
            } else {
                let total_sompi: u64 = utxo_entries.iter()
                    .map(|e| e.utxo_entry.amount)
                    .sum();

                let total_kas = total_sompi as f64 / 100_000_000.0;

                println!("✓ Wallet Balance:");
                println!("  {} KAS", total_kas);
                println!("  {} SOMPI", total_sompi);
                println!("  {} UTXOs", utxo_entries.len());

                println!("\n✓ Wallet is funded and ready for testing!");
            }
        }
        Err(e) => {
            println!("❌ Error fetching UTXOs: {}", e);
        }
    }

    rpc_client.disconnect().await?;
    println!("\n✓ Disconnected from testnet");

    Ok(())
}
