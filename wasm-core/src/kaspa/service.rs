//! P2PComm Service Layer
//!
//! Unified service that coordinates all modules:
//! - Wallet management
//! - RPC connectivity
//! - UTXO monitoring
//! - Message reception
//! - Delivery coordination
//! - WebRTC connections
//! - Peer discovery

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::cell::RefCell;

thread_local! {
    /// Global service state
    static SERVICE: RefCell<Option<P2PCommService>> = RefCell::new(None);
}

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// User's peer ID
    pub peer_id: String,
    /// User's password (for wallet derivation)
    pub password: String,
    /// Network (testnet/mainnet)
    pub is_testnet: bool,
    /// Auto-connect to RPC on initialization
    pub auto_connect_rpc: bool,
    /// Auto-start UTXO monitor
    pub auto_start_utxo_monitor: bool,
    /// UTXO monitor poll interval (ms)
    pub utxo_poll_interval_ms: u64,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            peer_id: String::new(),
            password: String::new(),
            is_testnet: true,
            auto_connect_rpc: true,
            auto_start_utxo_monitor: true,
            utxo_poll_interval_ms: 30_000, // 30 seconds
        }
    }
}

/// Service state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Uninitialized,
    Initializing,
    Ready,
    Running,
    Error,
    Stopped,
}

/// Service statistics (aggregate from all modules)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceStats {
    pub wallet_balance: u64,
    pub utxos_monitored: usize,
    pub messages_received: usize,
    pub messages_sent: usize,
    pub webrtc_connections: usize,
    pub peers_discovered: usize,
    pub rpc_connected: bool,
    pub rpc_endpoint: String,
}

/// Internal service state
struct P2PCommService {
    config: ServiceConfig,
    state: ServiceState,
    initialized_modules: Vec<String>,
}

impl P2PCommService {
    fn new(config: ServiceConfig) -> Self {
        Self {
            config,
            state: ServiceState::Uninitialized,
            initialized_modules: Vec::new(),
        }
    }
}

/// Initialize the P2PComm service
///
/// This is the main entry point that sets up all modules.
#[wasm_bindgen]
pub async fn p2pcomm_init(config_json: JsValue) -> Result<(), JsValue> {
    let config: ServiceConfig = serde_wasm_bindgen::from_value(config_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid config: {}", e)))?;

    SERVICE.with(|svc| {
        let mut svc = svc.borrow_mut();
        *svc = Some(P2PCommService::new(config.clone()));

        if let Some(service) = svc.as_mut() {
            service.state = ServiceState::Initializing;
        }
    });

    web_sys::console::log_1(&"P2PComm: Initializing service...".into());

    // Initialize wallet
    web_sys::console::log_1(&"P2PComm: Creating wallet...".into());
    super::wallet_bridge::kaspa_create_wallet(config.password.clone(), config.is_testnet)?;

    SERVICE.with(|svc| {
        if let Some(service) = svc.borrow_mut().as_mut() {
            service.initialized_modules.push("wallet".to_string());
        }
    });

    // Initialize WebRTC manager
    web_sys::console::log_1(&"P2PComm: Initializing WebRTC manager...".into());
    super::webrtc_manager::webrtc_manager_init(config.peer_id.clone())?;

    SERVICE.with(|svc| {
        if let Some(service) = svc.borrow_mut().as_mut() {
            service.initialized_modules.push("webrtc".to_string());
        }
    });

    // Initialize UTXO monitor
    web_sys::console::log_1(&"P2PComm: Initializing UTXO monitor...".into());
    super::utxo_monitor::utxo_monitor_init()?;

    SERVICE.with(|svc| {
        if let Some(service) = svc.borrow_mut().as_mut() {
            service.initialized_modules.push("utxo_monitor".to_string());
        }
    });

    // Add wallet addresses to UTXO monitor
    let addresses = super::wallet_bridge::kaspa_get_all_addresses()?;
    super::utxo_monitor::utxo_monitor_add_addresses(addresses)?;

    // Initialize message reception handler
    web_sys::console::log_1(&"P2PComm: Initializing message handler...".into());
    super::message_reception::message_handler_init(config.peer_id.clone())?;

    SERVICE.with(|svc| {
        if let Some(service) = svc.borrow_mut().as_mut() {
            service.initialized_modules.push("message_handler".to_string());
        }
    });

    // Initialize delivery coordinator
    web_sys::console::log_1(&"P2PComm: Initializing delivery coordinator...".into());
    super::delivery_coordinator::delivery_coordinator_init(JsValue::NULL)?;

    SERVICE.with(|svc| {
        if let Some(service) = svc.borrow_mut().as_mut() {
            service.initialized_modules.push("delivery_coordinator".to_string());
        }
    });

    // Initialize peer discovery and signaling
    web_sys::console::log_1(&"P2PComm: Initializing peer discovery...".into());
    super::discovery::kaspa_discovery_init(config.peer_id.clone())?;
    super::signaling::kaspa_signaling_init()?;

    SERVICE.with(|svc| {
        if let Some(service) = svc.borrow_mut().as_mut() {
            service.initialized_modules.push("peer_discovery".to_string());
            service.initialized_modules.push("signaling".to_string());
        }
    });

    // Connect to RPC if auto-connect is enabled
    if config.auto_connect_rpc {
        web_sys::console::log_1(&"P2PComm: Connecting to RPC with failover...".into());
        match super::rpc_bridge::kaspa_connect_with_failover(Some(10000)).await {
            Ok(endpoint) => {
                web_sys::console::log_1(&format!("P2PComm: Connected to RPC at {}", endpoint).into());

                SERVICE.with(|svc| {
                    if let Some(service) = svc.borrow_mut().as_mut() {
                        service.initialized_modules.push("rpc".to_string());
                    }
                });
            }
            Err(e) => {
                web_sys::console::log_1(&format!("P2PComm: Failed to connect to RPC: {:?}", e).into());
            }
        }
    }

    // Start UTXO monitor if auto-start is enabled
    if config.auto_start_utxo_monitor {
        web_sys::console::log_1(&"P2PComm: Starting UTXO monitor...".into());
        super::utxo_monitor::utxo_monitor_start()?;
    }

    SERVICE.with(|svc| {
        if let Some(service) = svc.borrow_mut().as_mut() {
            service.state = ServiceState::Ready;
        }
    });

    web_sys::console::log_1(&"P2PComm: Service initialization complete!".into());

    Ok(())
}

/// Start the service (begin processing)
#[wasm_bindgen]
pub fn p2pcomm_start() -> Result<(), JsValue> {
    SERVICE.with(|svc| {
        let mut svc = svc.borrow_mut();
        let service = svc.as_mut()
            .ok_or_else(|| JsValue::from_str("Service not initialized. Call p2pcomm_init() first."))?;

        service.state = ServiceState::Running;
        Ok(())
    })
}

/// Stop the service
#[wasm_bindgen]
pub fn p2pcomm_stop() -> Result<(), JsValue> {
    SERVICE.with(|svc| {
        let mut svc = svc.borrow_mut();
        let service = svc.as_mut()
            .ok_or_else(|| JsValue::from_str("Service not initialized"))?;

        // Stop UTXO monitor
        super::utxo_monitor::utxo_monitor_stop()?;

        service.state = ServiceState::Stopped;
        Ok(())
    })
}

/// Get service state
#[wasm_bindgen]
pub fn p2pcomm_get_state() -> Result<JsValue, JsValue> {
    SERVICE.with(|svc| {
        let svc = svc.borrow();
        let service = svc.as_ref()
            .ok_or_else(|| JsValue::from_str("Service not initialized"))?;

        serde_wasm_bindgen::to_value(&service.state)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get aggregate service statistics
#[wasm_bindgen]
pub async fn p2pcomm_get_stats() -> Result<JsValue, JsValue> {
    let mut stats = ServiceStats::default();

    // Get wallet balance
    stats.wallet_balance = super::wallet_bridge::kaspa_wallet_get_balance();

    // Get UTXO monitor stats
    if let Ok(monitor_stats) = super::utxo_monitor::utxo_monitor_get_stats() {
        let monitor_stats: super::utxo_monitor::MonitorStats = serde_wasm_bindgen::from_value(monitor_stats)
            .unwrap_or_default();
        stats.utxos_monitored = monitor_stats.utxos_detected;
    }

    // Get message handler stats
    if let Ok(msg_stats) = super::message_reception::message_handler_get_stats() {
        let msg_stats: super::message_reception::ReceptionStats = serde_wasm_bindgen::from_value(msg_stats)
            .unwrap_or_default();
        stats.messages_received = msg_stats.messages_received;
    }

    // Get delivery coordinator stats
    if let Ok(delivery_stats) = super::delivery_coordinator::delivery_coordinator_get_stats() {
        let delivery_stats: super::delivery_coordinator::DeliveryStats = serde_wasm_bindgen::from_value(delivery_stats)
            .unwrap_or_default();
        stats.messages_sent = delivery_stats.messages_sent;
    }

    // Get WebRTC connection count
    if let Ok(count) = super::webrtc_manager::webrtc_manager_connection_count() {
        stats.webrtc_connections = count;
    }

    // Get peer discovery stats
    stats.peers_discovered = super::discovery::kaspa_discovery_get_peers()
        .map(|peers| {
            let peers: Vec<super::discovery::DiscoveredPeer> = serde_wasm_bindgen::from_value(peers)
                .unwrap_or_default();
            peers.len()
        })
        .unwrap_or(0);

    // Get RPC state
    stats.rpc_connected = super::rpc_bridge::kaspa_is_connected();
    stats.rpc_endpoint = super::rpc_bridge::kaspa_get_current_endpoint();

    serde_wasm_bindgen::to_value(&stats)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Get list of initialized modules
#[wasm_bindgen]
pub fn p2pcomm_get_initialized_modules() -> Result<JsValue, JsValue> {
    SERVICE.with(|svc| {
        let svc = svc.borrow();
        let service = svc.as_ref()
            .ok_or_else(|| JsValue::from_str("Service not initialized"))?;

        serde_wasm_bindgen::to_value(&service.initialized_modules)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Process one cycle of all active tasks
///
/// This should be called periodically (e.g., via setInterval) to:
/// - Check for new UTXOs
/// - Process received messages
/// - Send pending messages
/// - Update peer connections
#[wasm_bindgen]
pub async fn p2pcomm_process_cycle() -> Result<JsValue, JsValue> {
    let mut cycle_result = serde_json::json!({
        "utxo_events": 0,
        "received_messages": 0,
        "sent_batches": 0,
        "errors": []
    });

    // Poll UTXO monitor for new events
    if let Ok(events) = super::utxo_monitor::utxo_monitor_poll_events() {
        let events: Vec<super::utxo_monitor::NewUtxoEvent> = serde_wasm_bindgen::from_value(events)
            .unwrap_or_default();

        cycle_result["utxo_events"] = serde_json::json!(events.len());

        // Process each UTXO event through message handler
        for event in events {
            // Add UTXO to wallet
            let _ = super::wallet_bridge::kaspa_wallet_add_utxo(
                event.address.clone(),
                event.transaction_id.clone(),
                event.output_index,
                event.amount,
                event.script_public_key.clone(),
                0, // Default version 0 for P2PK
                event.is_coinbase,
            );
        }
    }

    // Poll message handler for received messages
    if let Ok(messages) = super::message_reception::message_handler_pop_received() {
        let messages: Vec<super::message_reception::ReceivedMessage> = serde_wasm_bindgen::from_value(messages)
            .unwrap_or_default();
        cycle_result["received_messages"] = serde_json::json!(messages.len());
    }

    // Process waiting batches in delivery coordinator
    let _ = super::delivery_coordinator::delivery_coordinator_process_waiting_batches();

    // Get ready batches
    if let Ok(batches) = super::delivery_coordinator::delivery_coordinator_get_ready_batches() {
        let batches: Vec<super::delivery_coordinator::DeliveryBatch> = serde_wasm_bindgen::from_value(batches)
            .unwrap_or_default();
        cycle_result["sent_batches"] = serde_json::json!(batches.len());
    }

    serde_wasm_bindgen::to_value(&cycle_result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Quick initialization with defaults
#[wasm_bindgen]
pub async fn p2pcomm_quick_init(peer_id: String, password: String) -> Result<(), JsValue> {
    let config = ServiceConfig {
        peer_id,
        password,
        is_testnet: true,
        auto_connect_rpc: true,
        auto_start_utxo_monitor: true,
        utxo_poll_interval_ms: 30_000,
    };

    let config_json = serde_wasm_bindgen::to_value(&config)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    p2pcomm_init(config_json).await
}
