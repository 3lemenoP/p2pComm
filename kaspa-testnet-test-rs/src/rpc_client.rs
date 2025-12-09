/// RPC Client for Kaspa Testnet
///
/// This module provides RPC client functionality for:
/// - Connecting to Kaspa testnet nodes
/// - Submitting transactions to the network
/// - Querying transaction status and confirmations
/// - Fetching UTXOs for addresses
/// - Monitoring network connectivity

use anyhow::{Result, Context, bail};
use kaspa_wrpc_client::{KaspaRpcClient, WrpcEncoding};
use kaspa_wrpc_client::prelude::RpcApi;
use kaspa_rpc_core::{
    RpcTransaction, RpcTransactionInput, RpcTransactionOutput,
    RpcScriptPublicKey, RpcTransactionId,
};
use kaspa_consensus_core::tx::Transaction;
use std::sync::Arc;

/// Default Kaspa testnet RPC endpoint (local node)
pub const DEFAULT_TESTNET_RPC: &str = "ws://127.0.0.1:17110";

/// Alternative testnet endpoints
pub const TESTNET_ENDPOINTS: &[&str] = &[
    "wss://photon-10.kaspa.red/kaspa/testnet-10/wrpc/borsh",  // Public testnet (Borsh)
    "wss://photon-10.kaspa.red/kaspa/testnet-10/wrpc/json",   // Public testnet (JSON)
    "ws://127.0.0.1:17110",      // Local kaspad (Borsh)
    "ws://127.0.0.1:18110",      // Local kaspad (JSON)
];

/// RPC client for Kaspa testnet operations
pub struct KaspaTestnetClient {
    /// Internal wRPC client
    client: Arc<KaspaRpcClient>,
    /// RPC endpoint URL
    endpoint: String,
    /// Whether the client is connected
    connected: bool,
}

impl KaspaTestnetClient {
    /// Create a new RPC client with default endpoint
    pub fn new() -> Self {
        Self {
            client: Arc::new(KaspaRpcClient::new(
                WrpcEncoding::Borsh,
                Some(DEFAULT_TESTNET_RPC),
                None,
                None,
                None,
            ).expect("Failed to create RPC client")),
            endpoint: DEFAULT_TESTNET_RPC.to_string(),
            connected: false,
        }
    }

    /// Create a new RPC client with custom endpoint
    pub fn with_endpoint(endpoint: &str) -> Self {
        Self {
            client: Arc::new(KaspaRpcClient::new(
                WrpcEncoding::Borsh,
                Some(endpoint),
                None,
                None,
                None,
            ).expect("Failed to create RPC client")),
            endpoint: endpoint.to_string(),
            connected: false,
        }
    }

    /// Connect to the Kaspa testnet
    pub async fn connect(&mut self) -> Result<()> {
        self.client.connect(None).await
            .context("Failed to connect to Kaspa testnet")?;

        self.connected = true;
        Ok(())
    }

    /// Disconnect from the Kaspa testnet
    pub async fn disconnect(&mut self) -> Result<()> {
        if self.connected {
            self.client.disconnect().await
                .context("Failed to disconnect from Kaspa testnet")?;
            self.connected = false;
        }
        Ok(())
    }

    /// Check if the client is connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get the current endpoint
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Get network information
    pub async fn get_info(&self) -> Result<NetworkInfo> {
        if !self.connected {
            bail!("Client not connected. Call connect() first.");
        }

        let info = self.client.get_info().await
            .context("Failed to get network info")?;

        Ok(NetworkInfo {
            server_version: info.server_version.clone(),
            is_synced: info.is_synced,
            is_utxo_indexed: info.is_utxo_indexed,
        })
    }

    /// Submit a transaction to the network
    pub async fn submit_transaction(&self, tx: &Transaction) -> Result<String> {
        if !self.connected {
            bail!("Client not connected. Call connect() first.");
        }

        // Convert Transaction to RpcTransaction
        let rpc_tx = self.convert_to_rpc_transaction(tx)?;

        // Submit transaction
        let _response = self.client.submit_transaction(rpc_tx.into(), false).await
            .context("Failed to submit transaction")?;

        // Calculate transaction ID from the transaction itself
        let tx_id = tx.id().to_string();
        Ok(tx_id)
    }

    /// Get transaction by ID
    /// Note: This is a placeholder implementation as the RPC API doesn't provide
    /// a direct get_transaction method. You would need to implement a custom
    /// indexer or use block scanning to retrieve transaction details.
    pub async fn get_transaction(&self, _tx_id: &str) -> Result<Option<TransactionInfo>> {
        if !self.connected {
            bail!("Client not connected. Call connect() first.");
        }

        // Placeholder: Transaction queries not directly supported in current API
        // Would need to implement custom indexer or block scanning
        Ok(None)
    }

    /// Get UTXOs for an address
    pub async fn get_utxos_by_address(&self, address: &str) -> Result<Vec<UtxoEntry>> {
        if !self.connected {
            bail!("Client not connected. Call connect() first.");
        }

        use kaspa_addresses::Address;
        let addr = Address::try_from(address)
            .context("Failed to parse address")?;

        let addresses = vec![addr];

        let response = self.client.get_utxos_by_addresses(addresses).await
            .context("Failed to get UTXOs")?;

        let mut utxos = Vec::new();
        for entry in response {
            utxos.push(UtxoEntry {
                transaction_id: entry.outpoint.transaction_id.to_string(),
                index: entry.outpoint.index,
                amount: entry.utxo_entry.amount,
                script_public_key: entry.utxo_entry.script_public_key.script().to_vec(),
                block_daa_score: entry.utxo_entry.block_daa_score,
                is_coinbase: entry.utxo_entry.is_coinbase,
            });
        }

        Ok(utxos)
    }

    /// Get balance for an address
    pub async fn get_balance(&self, address: &str) -> Result<u64> {
        let utxos = self.get_utxos_by_address(address).await?;
        Ok(utxos.iter().map(|u| u.amount).sum())
    }

    /// Get current block DAA score (for tracking confirmations)
    pub async fn get_block_dag_info(&self) -> Result<BlockDagInfo> {
        if !self.connected {
            bail!("Client not connected. Call connect() first.");
        }

        let info = self.client.get_block_dag_info().await
            .context("Failed to get block DAG info")?;

        Ok(BlockDagInfo {
            network: info.network.to_string(),
            block_count: info.block_count,
            header_count: info.header_count,
            tip_hashes: info.tip_hashes.iter().map(|h| h.to_string()).collect(),
            difficulty: info.difficulty,
            past_median_time: info.past_median_time as i64,
            virtual_parent_hashes: info.virtual_parent_hashes.iter().map(|h| h.to_string()).collect(),
            pruning_point_hash: info.pruning_point_hash.to_string(),
            virtual_daa_score: info.virtual_daa_score,
        })
    }

    /// Wait for transaction to be accepted
    pub async fn wait_for_transaction(&self, tx_id: &str, max_attempts: u32) -> Result<bool> {
        for attempt in 1..=max_attempts {
            if let Some(tx_info) = self.get_transaction(tx_id).await? {
                if tx_info.is_accepted {
                    return Ok(true);
                }
            }

            if attempt < max_attempts {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }

        Ok(false)
    }

    /// Convert internal Transaction to RpcTransaction
    fn convert_to_rpc_transaction(&self, tx: &Transaction) -> Result<RpcTransaction> {
        let inputs: Vec<RpcTransactionInput> = tx.inputs.iter().map(|input| {
            RpcTransactionInput {
                previous_outpoint: input.previous_outpoint.into(),
                signature_script: input.signature_script.clone(),
                sequence: input.sequence,
                sig_op_count: input.sig_op_count,
                verbose_data: None,
            }
        }).collect();

        let outputs: Vec<RpcTransactionOutput> = tx.outputs.iter().map(|output| {
            RpcTransactionOutput {
                value: output.value,
                script_public_key: RpcScriptPublicKey::new(
                    output.script_public_key.version(),
                    output.script_public_key.script().to_vec().into(),
                ),
                verbose_data: None,
            }
        }).collect();

        Ok(RpcTransaction {
            version: tx.version,
            inputs,
            outputs,
            lock_time: tx.lock_time,
            subnetwork_id: tx.subnetwork_id.clone().into(),
            gas: tx.gas,
            payload: tx.payload.clone(),
            mass: 0, // Will be calculated by the node
            verbose_data: None,
        })
    }
}

impl Default for KaspaTestnetClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Network information
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub server_version: String,
    pub is_synced: bool,
    pub is_utxo_indexed: bool,
}

/// Transaction information
#[derive(Debug, Clone)]
pub struct TransactionInfo {
    pub transaction_id: String,
    pub is_accepted: bool,
    pub accepting_block_hash: Option<String>,
}

/// UTXO entry information
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub transaction_id: String,
    pub index: u32,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

/// Block DAG information
#[derive(Debug, Clone)]
pub struct BlockDagInfo {
    pub network: String,
    pub block_count: u64,
    pub header_count: u64,
    pub tip_hashes: Vec<String>,
    pub difficulty: f64,
    pub past_median_time: i64,
    pub virtual_parent_hashes: Vec<String>,
    pub pruning_point_hash: String,
    pub virtual_daa_score: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = KaspaTestnetClient::new();
        assert_eq!(client.endpoint(), DEFAULT_TESTNET_RPC);
        assert!(!client.is_connected());
    }

    #[test]
    fn test_client_with_custom_endpoint() {
        let endpoint = "wss://testnet-1.kaspad.net:443";
        let client = KaspaTestnetClient::with_endpoint(endpoint);
        assert_eq!(client.endpoint(), endpoint);
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn test_client_connection() {
        let mut client = KaspaTestnetClient::new();

        // Try to connect (may fail if no internet/testnet down)
        if client.connect().await.is_ok() {
            assert!(client.is_connected());

            // Try to get info
            if let Ok(info) = client.get_info().await {
                println!("Network info: {:?}", info);
            }

            // Disconnect
            assert!(client.disconnect().await.is_ok());
            assert!(!client.is_connected());
        }
    }
}
