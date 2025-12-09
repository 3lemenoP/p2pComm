//! Kaspa RPC Bridge for WASM
//!
//! Provides WebSocket RPC connectivity to Kaspa testnet nodes
//! using the kaspa-wrpc-client crate compiled to WASM.

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use serde_json;
use std::sync::Arc;
use std::cell::RefCell;

use kaspa_wrpc_client::{KaspaRpcClient, WrpcEncoding};
use kaspa_wrpc_client::prelude::RpcApi;
use kaspa_rpc_core::{
    RpcTransaction, RpcTransactionInput, RpcTransactionOutput,
    RpcScriptPublicKey, RpcBlock,
};
use kaspa_consensus_core::tx::Transaction;
use kaspa_addresses::Address;
use kaspa_hashes::Hash;

/// Default Kaspa testnet RPC endpoint
pub const DEFAULT_TESTNET_RPC: &str = "wss://photon-10.kaspa.red/kaspa/testnet-10/wrpc/borsh";

/// Alternative testnet endpoints
pub const TESTNET_ENDPOINTS: &[&str] = &[
    "wss://photon-10.kaspa.red/kaspa/testnet-10/wrpc/borsh",  // Public testnet-10 (Borsh)
    "wss://photon-10.kaspa.red/kaspa/testnet-10/wrpc/json",   // Public testnet-10 (JSON)
    "ws://127.0.0.1:17110",      // Local kaspad (Borsh)
    "ws://127.0.0.1:18110",      // Local kaspad (JSON)
];

thread_local! {
    /// Global RPC client instance (for WASM single-threaded environment)
    static RPC_CLIENT: RefCell<Option<Arc<KaspaRpcClient>>> = RefCell::new(None);
    static CONNECTION_STATE: RefCell<ConnectionState> = RefCell::new(ConnectionState::default());
    static RPC_STATS: RefCell<RpcStatistics> = RefCell::new(RpcStatistics::default());
}

/// Connection state tracking
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    pub connected: bool,
    pub endpoint: String,
    pub connected_at: u64, // timestamp in ms
    pub retry_count: u32,
    pub last_error: Option<String>,
}

/// RPC Statistics
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct RpcStatistics {
    pub successful_connections: usize,
    pub failed_connections: usize,
    pub total_requests: usize,
    pub failed_requests: usize,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub current_endpoint: String,
}

/// Network information returned from get_info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub server_version: String,
    pub is_synced: bool,
    pub is_utxo_indexed: bool,
}

/// UTXO entry information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub transaction_id: String,
    pub index: u32,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub script_public_key_version: u16,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

/// Block DAG information
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Connect to a Kaspa testnet node
#[wasm_bindgen]
pub async fn kaspa_connect(endpoint: Option<String>) -> Result<(), JsValue> {
    let endpoint = endpoint.unwrap_or_else(|| DEFAULT_TESTNET_RPC.to_string());

    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some(&endpoint),
        None,
        None,
        None,
    ).map_err(|e| JsValue::from_str(&format!("Failed to create RPC client: {}", e)))?;

    let client = Arc::new(client);

    // Connect to the node
    client.connect(None).await
        .map_err(|e| JsValue::from_str(&format!("Failed to connect to {}: {}", endpoint, e)))?;

    // Store the client globally
    RPC_CLIENT.with(|c| {
        *c.borrow_mut() = Some(client);
    });

    CONNECTION_STATE.with(|s| {
        let mut state = s.borrow_mut();
        state.connected = true;
        state.endpoint = endpoint;
    });

    Ok(())
}

/// Disconnect from the Kaspa node
#[wasm_bindgen]
pub async fn kaspa_disconnect() -> Result<(), JsValue> {
    let client = RPC_CLIENT.with(|c| c.borrow().clone());

    if let Some(client) = client {
        client.disconnect().await
            .map_err(|e| JsValue::from_str(&format!("Failed to disconnect: {}", e)))?;
    }

    RPC_CLIENT.with(|c| {
        *c.borrow_mut() = None;
    });

    CONNECTION_STATE.with(|s| {
        s.borrow_mut().connected = false;
    });

    Ok(())
}

/// Check if connected to a Kaspa node
#[wasm_bindgen]
pub fn kaspa_is_connected() -> bool {
    CONNECTION_STATE.with(|s| s.borrow().connected)
}

/// Get network information
#[wasm_bindgen]
pub async fn kaspa_get_info() -> Result<JsValue, JsValue> {
    let client = get_client()?;

    let info = client.get_info().await
        .map_err(|e| JsValue::from_str(&format!("Failed to get info: {}", e)))?;

    let network_info = NetworkInfo {
        server_version: info.server_version.clone(),
        is_synced: info.is_synced,
        is_utxo_indexed: info.is_utxo_indexed,
    };

    serde_wasm_bindgen::to_value(&network_info)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Get UTXOs for an address
#[wasm_bindgen]
pub async fn kaspa_get_utxos(address: String) -> Result<JsValue, JsValue> {
    let client = get_client()?;

    let addr = Address::try_from(address.as_str())
        .map_err(|e| JsValue::from_str(&format!("Invalid address: {}", e)))?;

    let addresses = vec![addr];

    let response = client.get_utxos_by_addresses(addresses).await
        .map_err(|e| JsValue::from_str(&format!("Failed to get UTXOs: {}", e)))?;

    let utxos: Vec<UtxoEntry> = response.iter().map(|entry| {
        let version = entry.utxo_entry.script_public_key.version();
        web_sys::console::log_1(&format!(
            "UTXO from RPC: txid={}, index={}, script_version={}, script={}",
            entry.outpoint.transaction_id,
            entry.outpoint.index,
            version,
            hex::encode(entry.utxo_entry.script_public_key.script())
        ).into());
        UtxoEntry {
            transaction_id: entry.outpoint.transaction_id.to_string(),
            index: entry.outpoint.index,
            amount: entry.utxo_entry.amount,
            script_public_key: entry.utxo_entry.script_public_key.script().to_vec(),
            script_public_key_version: version,
            block_daa_score: entry.utxo_entry.block_daa_score,
            is_coinbase: entry.utxo_entry.is_coinbase,
        }
    }).collect();

    serde_wasm_bindgen::to_value(&utxos)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Get balance for an address (sum of UTXOs)
#[wasm_bindgen]
pub async fn kaspa_get_balance(address: String) -> Result<u64, JsValue> {
    let client = get_client()?;

    let addr = Address::try_from(address.as_str())
        .map_err(|e| JsValue::from_str(&format!("Invalid address: {}", e)))?;

    let addresses = vec![addr];

    let response = client.get_utxos_by_addresses(addresses).await
        .map_err(|e| JsValue::from_str(&format!("Failed to get UTXOs: {}", e)))?;

    let balance: u64 = response.iter().map(|entry| entry.utxo_entry.amount).sum();

    Ok(balance)
}

/// Get block DAG information
#[wasm_bindgen]
pub async fn kaspa_get_block_dag_info() -> Result<JsValue, JsValue> {
    let client = get_client()?;

    let info = client.get_block_dag_info().await
        .map_err(|e| JsValue::from_str(&format!("Failed to get block DAG info: {}", e)))?;

    let dag_info = BlockDagInfo {
        network: info.network.to_string(),
        block_count: info.block_count,
        header_count: info.header_count,
        tip_hashes: info.tip_hashes.iter().map(|h| h.to_string()).collect(),
        difficulty: info.difficulty,
        past_median_time: info.past_median_time as i64,
        virtual_parent_hashes: info.virtual_parent_hashes.iter().map(|h| h.to_string()).collect(),
        pruning_point_hash: info.pruning_point_hash.to_string(),
        virtual_daa_score: info.virtual_daa_score,
    };

    serde_wasm_bindgen::to_value(&dag_info)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Submit a transaction to the network
/// Takes a JSON-serialized transaction
#[wasm_bindgen]
pub async fn kaspa_submit_transaction(tx_json: String) -> Result<String, JsValue> {
    let client = get_client()?;

    // Parse the transaction from JSON
    let tx: Transaction = serde_json::from_str(&tx_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid transaction JSON: {}", e)))?;

    // Debug: Log parsed transaction details
    web_sys::console::log_1(&format!("=== Transaction Being Submitted ===").into());
    web_sys::console::log_1(&format!("TX ID: {}", tx.id()).into());
    web_sys::console::log_1(&format!("TX version: {}", tx.version).into());
    web_sys::console::log_1(&format!("TX lock_time: {}", tx.lock_time).into());
    web_sys::console::log_1(&format!("TX subnetwork_id: {}", hex::encode(tx.subnetwork_id.as_ref() as &[u8])).into());
    web_sys::console::log_1(&format!("TX gas: {}", tx.gas).into());
    web_sys::console::log_1(&format!("TX payload len: {}", tx.payload.len()).into());

    for (i, input) in tx.inputs.iter().enumerate() {
        web_sys::console::log_1(&format!(
            "Submit Input {}: outpoint={}:{}, sequence={}, sig_op_count={}, sig_script={}",
            i,
            input.previous_outpoint.transaction_id,
            input.previous_outpoint.index,
            input.sequence,
            input.sig_op_count,
            hex::encode(&input.signature_script)
        ).into());
    }

    for (i, output) in tx.outputs.iter().enumerate() {
        web_sys::console::log_1(&format!(
            "Submit Output {}: value={}, script_version={}, script={}",
            i,
            output.value,
            output.script_public_key.version(),
            hex::encode(output.script_public_key.script())
        ).into());
    }

    // Convert to RPC transaction format
    let rpc_tx = convert_to_rpc_transaction(&tx)?;

    // Submit the transaction
    let _response = client.submit_transaction(rpc_tx.into(), false).await
        .map_err(|e| JsValue::from_str(&format!("Failed to submit transaction: {}", e)))?;

    // Return the transaction ID
    let tx_id = tx.id().to_string();
    Ok(tx_id)
}

/// Get a block by hash
///
/// Returns block data including all transactions with their payloads.
/// This is the primary method for retrieving transaction payloads for incoming messages.
#[wasm_bindgen]
pub async fn kaspa_get_block(block_hash: String, include_transactions: bool) -> Result<JsValue, JsValue> {
    let client = get_client()?;

    // Parse block hash
    let hash_bytes = hex::decode(&block_hash)
        .map_err(|e| JsValue::from_str(&format!("Invalid block hash: {}", e)))?;

    if hash_bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "Block hash must be 32 bytes, got {}",
            hash_bytes.len()
        )));
    }

    let hash = Hash::from_slice(&hash_bytes);

    // Fetch the block
    let block = client.get_block(hash.into(), include_transactions).await
        .map_err(|e| JsValue::from_str(&format!("Failed to get block: {}", e)))?;

    // Serialize and return
    serde_wasm_bindgen::to_value(&block)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Find transaction payload by scanning recent blocks
///
/// Searches through the most recent blocks to find a transaction by ID and return its payload.
/// This is used to retrieve message payloads for incoming dust UTXO notifications.
/// Uses recursive DAG traversal to search through parent blocks.
#[wasm_bindgen]
pub async fn kaspa_find_transaction_payload(tx_id: String, max_blocks_to_scan: Option<u32>) -> Result<JsValue, JsValue> {
    let client = get_client()?;
    let max_depth = max_blocks_to_scan.unwrap_or(50) as usize; // Max recursion depth

    // Parse transaction ID
    let tx_id_bytes = hex::decode(&tx_id)
        .map_err(|e| JsValue::from_str(&format!("Invalid transaction ID: {}", e)))?;

    if tx_id_bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "Transaction ID must be 32 bytes, got {}",
            tx_id_bytes.len()
        )));
    }

    // Get current DAG info to find recent blocks
    let dag_info = client.get_block_dag_info().await
        .map_err(|e| JsValue::from_str(&format!("Failed to get DAG info: {}", e)))?;

    // Track visited blocks to avoid duplicates
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut blocks_to_search: Vec<Hash> = Vec::new();
    let mut blocks_searched = 0;

    // Start with tips and virtual parents
    for tip_hash in &dag_info.tip_hashes {
        blocks_to_search.push(*tip_hash);
    }
    for parent_hash in &dag_info.virtual_parent_hashes {
        blocks_to_search.push(*parent_hash);
    }

    // BFS through the DAG
    while !blocks_to_search.is_empty() && blocks_searched < max_depth {
        let block_hash = blocks_to_search.remove(0);
        let hash_str = block_hash.to_string();

        // Skip if already visited
        if visited.contains(&hash_str) {
            continue;
        }
        visited.insert(hash_str.clone());
        blocks_searched += 1;

        // Get the block with transactions
        match client.get_block(block_hash.into(), true).await {
            Ok(block) => {
                // Search for the transaction in this block
                for tx in &block.transactions {
                    if let Some(verbose_data) = &tx.verbose_data {
                        let found_tx_id = verbose_data.transaction_id.to_string();
                        if found_tx_id == tx_id {
                            // Found it! Log payload details for debugging
                            web_sys::console::log_1(&format!(
                                "[KaspaRPC] Found transaction {} in block {} after searching {} blocks",
                                tx_id, hash_str, blocks_searched
                            ).into());
                            web_sys::console::log_1(&format!(
                                "[KaspaRPC] Transaction payload length: {} bytes, hex: {}",
                                tx.payload.len(),
                                hex::encode(&tx.payload)
                            ).into());
                            web_sys::console::log_1(&format!(
                                "[KaspaRPC] Transaction has {} inputs and {} outputs",
                                tx.inputs.len(),
                                tx.outputs.len()
                            ).into());
                            
                            // Return the payload as hex string for easy JS parsing
                            let payload_hex = hex::encode(&tx.payload);
                            let payload_info = serde_json::json!({
                                "transaction_id": tx_id,
                                "payload": payload_hex,
                                "payload_length": tx.payload.len(),
                                "block_hash": block.header.hash.to_string(),
                            });
                            return serde_wasm_bindgen::to_value(&payload_info)
                                .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)));
                        }
                    }
                }

                // Add parent blocks to search queue
                for parent_hash in &block.header.parents_by_level {
                    for parent in parent_hash {
                        if !visited.contains(&parent.to_string()) {
                            blocks_to_search.push(*parent);
                        }
                    }
                }
            }
            Err(e) => {
                web_sys::console::warn_1(&format!("Failed to get block {}: {}", hash_str, e).into());
                continue;
            }
        }
    }

    // If not found after searching, return error
    Err(JsValue::from_str(&format!(
        "Transaction {} not found (searched {} blocks)",
        tx_id,
        blocks_searched
    )))
}

/// Helper function to get the RPC client
fn get_client() -> Result<Arc<KaspaRpcClient>, JsValue> {
    RPC_CLIENT.with(|c| {
        c.borrow().clone().ok_or_else(|| {
            JsValue::from_str("Not connected. Call kaspa_connect() first.")
        })
    })
}

/// Convert internal Transaction to RpcTransaction
fn convert_to_rpc_transaction(tx: &Transaction) -> Result<RpcTransaction, JsValue> {
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

/// Get list of available testnet endpoints
#[wasm_bindgen]
pub fn kaspa_get_testnet_endpoints() -> JsValue {
    let endpoints: Vec<&str> = TESTNET_ENDPOINTS.to_vec();
    serde_wasm_bindgen::to_value(&endpoints).unwrap_or(JsValue::NULL)
}

// ============================================================================
// Enhanced RPC Features: Failover, Statistics, State Management
// ============================================================================

/// Connect with automatic endpoint failover
///
/// Tries each endpoint in TESTNET_ENDPOINTS with a timeout.
/// Returns the successfully connected endpoint or an error if all fail.
#[wasm_bindgen]
pub async fn kaspa_connect_with_failover(timeout_ms: Option<u32>) -> Result<String, JsValue> {
    let timeout = timeout_ms.unwrap_or(10000); // Default 10 second timeout

    for endpoint in TESTNET_ENDPOINTS {
        web_sys::console::log_1(&format!("Attempting to connect to: {}", endpoint).into());

        // Try to connect with timeout
        match connect_with_timeout(endpoint, timeout).await {
            Ok(_) => {
                web_sys::console::log_1(&format!("Successfully connected to: {}", endpoint).into());

                // Update statistics
                RPC_STATS.with(|stats| {
                    let mut stats = stats.borrow_mut();
                    stats.successful_connections += 1;
                    stats.current_endpoint = endpoint.to_string();
                });

                // Update connection state
                CONNECTION_STATE.with(|s| {
                    let mut state = s.borrow_mut();
                    state.connected = true;
                    state.endpoint = endpoint.to_string();
                    state.connected_at = js_sys::Date::now() as u64;
                    state.retry_count = 0;
                    state.last_error = None;
                });

                return Ok(endpoint.to_string());
            }
            Err(e) => {
                let error_msg = format!("{:?}", e);
                web_sys::console::log_1(&format!("Failed to connect to {}: {}", endpoint, error_msg).into());

                // Update statistics
                RPC_STATS.with(|stats| {
                    stats.borrow_mut().failed_connections += 1;
                });

                // Update connection state
                CONNECTION_STATE.with(|s| {
                    let mut state = s.borrow_mut();
                    state.retry_count += 1;
                    state.last_error = Some(error_msg);
                });

                continue;
            }
        }
    }

    Err(JsValue::from_str("Failed to connect to any endpoint"))
}

/// Connect to a specific endpoint with timeout
async fn connect_with_timeout(endpoint: &str, _timeout_ms: u32) -> Result<(), JsValue> {
    // Note: Actual timeout implementation would require more complex async machinery
    // For now, we rely on the underlying connection timeout
    kaspa_connect(Some(endpoint.to_string())).await
}

/// Get connection state
#[wasm_bindgen]
pub fn kaspa_get_connection_state() -> Result<JsValue, JsValue> {
    CONNECTION_STATE.with(|s| {
        let state = s.borrow().clone();
        serde_wasm_bindgen::to_value(&state)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get RPC statistics
#[wasm_bindgen]
pub fn kaspa_get_rpc_stats() -> Result<JsValue, JsValue> {
    RPC_STATS.with(|stats| {
        let stats = stats.borrow().clone();
        serde_wasm_bindgen::to_value(&stats)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Reset RPC statistics
#[wasm_bindgen]
pub fn kaspa_reset_rpc_stats() {
    RPC_STATS.with(|stats| {
        *stats.borrow_mut() = RpcStatistics::default();
    });
}

/// Record a successful request (for statistics)
#[wasm_bindgen]
pub fn kaspa_record_request_success() {
    RPC_STATS.with(|stats| {
        stats.borrow_mut().total_requests += 1;
    });
}

/// Record a failed request (for statistics)
#[wasm_bindgen]
pub fn kaspa_record_request_failure() {
    RPC_STATS.with(|stats| {
        let mut stats = stats.borrow_mut();
        stats.total_requests += 1;
        stats.failed_requests += 1;
    });
}

/// Get current endpoint
#[wasm_bindgen]
pub fn kaspa_get_current_endpoint() -> String {
    CONNECTION_STATE.with(|s| s.borrow().endpoint.clone())
}

/// Check connection health
///
/// Returns true if connected and can communicate with the node
#[wasm_bindgen]
pub async fn kaspa_check_health() -> bool {
    if !kaspa_is_connected() {
        return false;
    }

    // Try to get info as a health check
    match kaspa_get_info().await {
        Ok(_) => {
            kaspa_record_request_success();
            true
        }
        Err(_) => {
            kaspa_record_request_failure();
            false
        }
    }
}

/// Reconnect to the last successful endpoint
#[wasm_bindgen]
pub async fn kaspa_reconnect() -> Result<(), JsValue> {
    let endpoint = CONNECTION_STATE.with(|s| s.borrow().endpoint.clone());

    if endpoint.is_empty() {
        return Err(JsValue::from_str("No previous endpoint to reconnect to"));
    }

    kaspa_connect(Some(endpoint)).await
}

/// Get connection uptime in milliseconds
#[wasm_bindgen]
pub fn kaspa_get_uptime() -> u64 {
    CONNECTION_STATE.with(|s| {
        let state = s.borrow();
        if state.connected && state.connected_at > 0 {
            let now = js_sys::Date::now() as u64;
            now.saturating_sub(state.connected_at)
        } else {
            0
        }
    })
}
