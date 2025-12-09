use anyhow::Result;
use kaspa_wrpc_client::{KaspaRpcClient, WrpcEncoding, Resolver};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use crate::utils;

pub async fn run() -> Result<()> {
    utils::header("Test 01: Kaspa Testnet RPC Connection");

    // Test with mainnet public endpoints (testnet endpoints seem unavailable)
    // Using mainnet for connection test only - wallet operations use testnet addresses
    // Test with local node endpoints
    let test_configs = vec![
        ("ws://127.0.0.1:17110", WrpcEncoding::Borsh, "Borsh"),
        ("ws://127.0.0.1:18110", WrpcEncoding::SerdeJson, "JSON"),
    ];

    for (endpoint, encoding, encoding_name) in test_configs {
        utils::section(&format!("Testing {} encoding: {}", encoding_name, endpoint));

        let spinner = utils::spinner("Creating RPC client...");

        // Use testnet-10
        let network_id = NetworkId::with_suffix(NetworkType::Testnet, 10);

        let rpc_client = match KaspaRpcClient::new(
            encoding,
            Some(endpoint),
            None,
            Some(network_id),
            None,
        ) {
            Ok(client) => client,
            Err(e) => {
                spinner.finish_and_clear();
                utils::error(&format!("Failed to create RPC client: {}", e));
                continue;
            }
        };

        spinner.finish_and_clear();
        utils::success(&format!("RPC client created with {} encoding", encoding_name));

        // Connect to the server with timeout
        use std::time::Duration;
        use tokio::time::timeout;

        let connect_spinner = utils::spinner("Connecting to testnet (via Resolver)...");
        let connect_result = timeout(Duration::from_secs(15), rpc_client.connect(None)).await;

        match connect_result {
            Ok(Ok(_receiver_opt)) => {
                connect_spinner.finish_and_clear();
                utils::success(&format!("Connected successfully with {} encoding", encoding_name));
            },
            Ok(Err(e)) => {
                connect_spinner.finish_and_clear();
                utils::error(&format!("Failed to connect: {}", e));
                continue;
            },
            Err(_) => {
                connect_spinner.finish_and_clear();
                utils::error("Connection timed out after 15 seconds");
                continue;
            }
        }

        // Get server info
        let info_spinner = utils::spinner("Fetching server info...");
        match rpc_client.get_server_info().await {
            Ok(info) => {
                info_spinner.finish_and_clear();
                utils::success("Server info retrieved");
                utils::data("Server Version", &info.server_version);
                utils::data("Network ID", &info.network_id.to_string());
                utils::data("Has UTXOIndex", &info.has_utxo_index.to_string());
                utils::data("Is Synced", &info.is_synced.to_string());
            }
            Err(e) => {
                info_spinner.finish_and_clear();
                utils::error(&format!("Failed to get server info: {}", e));
            }
        }

        // Get block DAG info
        let dag_spinner = utils::spinner("Fetching block DAG info...");
        match rpc_client.get_block_dag_info().await {
            Ok(dag_info) => {
                dag_spinner.finish_and_clear();
                utils::success("Block DAG info retrieved");
                utils::data("Virtual Parent Hashes", &format!("{} blocks", dag_info.virtual_parent_hashes.len()));
                utils::data("Virtual DAA Score", &dag_info.virtual_daa_score.to_string());
                utils::data("Block Count", &dag_info.block_count.to_string());
                utils::data("Header Count", &dag_info.header_count.to_string());
            }
            Err(e) => {
                dag_spinner.finish_and_clear();
                utils::error(&format!("Failed to get DAG info: {}", e));
            }
        }

        // Get current network
        match rpc_client.get_current_network().await {
            Ok(network) => {
                utils::data("Network", &format!("{:?}", network));
            }
            Err(e) => {
                utils::warning(&format!("Failed to get network info: {}", e));
            }
        }

        // Disconnect
        let disconnect_spinner = utils::spinner("Disconnecting...");
        if let Err(e) = rpc_client.disconnect().await {
            disconnect_spinner.finish_and_clear();
            utils::warning(&format!("Failed to disconnect cleanly: {}", e));
        } else {
            disconnect_spinner.finish_and_clear();
            utils::success("Disconnected successfully");
        }

        println!();
    }

    utils::success("Test 01 completed");
    Ok(())
}
