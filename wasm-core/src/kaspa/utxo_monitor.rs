//! UTXO Monitor for WASM
//!
//! Monitors user addresses for incoming transactions:
//! - Detects incoming UTXOs
//! - Filters dust outputs (message notifications)
//! - Provides deduplication via known UTXO tracking
//! - Event-based notification system

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

/// Dust amount threshold for message notifications (0.25 KAS = 25,000,000 sompis)
/// Must be >= DUST_AMOUNT in tx_builder.rs (20,000,000) to detect incoming messages
pub const DUST_THRESHOLD: u64 = 25_000_000;

thread_local! {
    /// Global UTXO monitor instance
    static UTXO_MONITOR: RefCell<Option<UtxoMonitorState>> = RefCell::new(None);
}

/// Monitored address state
#[derive(Debug, Clone)]
struct MonitoredAddress {
    address: String,
    known_utxos: HashSet<String>,
    failure_count: u32,
}

impl MonitoredAddress {
    fn new(address: String) -> Self {
        Self {
            address,
            known_utxos: HashSet::new(),
            failure_count: 0,
        }
    }

    /// Generate UTXO key for deduplication
    fn utxo_key(tx_id: &str, index: u32) -> String {
        format!("{}:{}", tx_id, index)
    }
}

/// New UTXO event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUtxoEvent {
    pub transaction_id: String,
    pub output_index: u32,
    pub amount: u64,
    pub address: String,
    pub script_public_key: Vec<u8>,
    pub is_dust: bool,
    pub is_coinbase: bool,
}

/// Monitor state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitorState {
    Stopped,
    Running,
    Error,
}

/// UTXO Monitor statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MonitorStats {
    pub utxos_detected: usize,
    pub dust_utxos_detected: usize,
    pub poll_cycles: usize,
    pub errors_encountered: usize,
    pub addresses_monitored: usize,
}

/// Internal monitor state
struct UtxoMonitorState {
    addresses: HashMap<String, MonitoredAddress>,
    state: MonitorState,
    stats: MonitorStats,
    pending_events: Vec<NewUtxoEvent>,
}

impl UtxoMonitorState {
    fn new() -> Self {
        Self {
            addresses: HashMap::new(),
            state: MonitorState::Stopped,
            stats: MonitorStats::default(),
            pending_events: Vec::new(),
        }
    }
}

/// Initialize the UTXO monitor
#[wasm_bindgen]
pub fn utxo_monitor_init() -> Result<(), JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        if monitor.is_some() {
            return Err(JsValue::from_str("UTXO monitor already initialized"));
        }
        *monitor = Some(UtxoMonitorState::new());
        Ok(())
    })
}

/// Add an address to monitor
#[wasm_bindgen]
pub fn utxo_monitor_add_address(address: String) -> Result<(), JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized. Call utxo_monitor_init() first."))?;

        if monitor.addresses.contains_key(&address) {
            return Ok(()); // Already monitoring
        }

        monitor.addresses.insert(address.clone(), MonitoredAddress::new(address));
        monitor.stats.addresses_monitored = monitor.addresses.len();

        Ok(())
    })
}

/// Add multiple addresses to monitor
#[wasm_bindgen]
pub fn utxo_monitor_add_addresses(addresses: JsValue) -> Result<(), JsValue> {
    let addresses: Vec<String> = serde_wasm_bindgen::from_value(addresses)
        .map_err(|e| JsValue::from_str(&format!("Invalid addresses array: {}", e)))?;

    for address in addresses {
        utxo_monitor_add_address(address)?;
    }

    Ok(())
}

/// Remove an address from monitoring
#[wasm_bindgen]
pub fn utxo_monitor_remove_address(address: String) -> Result<(), JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        monitor.addresses.remove(&address);
        monitor.stats.addresses_monitored = monitor.addresses.len();

        Ok(())
    })
}

/// Process a new UTXO from RPC response
///
/// JavaScript calls this when it receives UTXO data from the RPC client.
/// The monitor will check if this is a new UTXO and emit an event if so.
#[wasm_bindgen]
pub fn utxo_monitor_process_utxo(
    address: String,
    transaction_id: String,
    output_index: u32,
    amount: u64,
    script_public_key: Vec<u8>,
    is_coinbase: bool,
) -> Result<bool, JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        // Check if we're monitoring this address
        if !monitor.addresses.contains_key(&address) {
            return Ok(false); // Not monitoring, ignore
        }

        // Generate UTXO key for deduplication
        let key = MonitoredAddress::utxo_key(&transaction_id, output_index);

        // Check if this is a known UTXO
        let is_new = {
            let monitored = monitor.addresses.get(&address).unwrap();
            !monitored.known_utxos.contains(&key)
        };

        if !is_new {
            return Ok(false); // Already seen this UTXO
        }

        // This is a new UTXO - add to known set
        if let Some(monitored) = monitor.addresses.get_mut(&address) {
            monitored.known_utxos.insert(key);
        }

        // Create event
        let is_dust = amount <= DUST_THRESHOLD;
        let event = NewUtxoEvent {
            transaction_id,
            output_index,
            amount,
            address,
            script_public_key,
            is_dust,
            is_coinbase,
        };

        // Update stats
        monitor.stats.utxos_detected += 1;
        if is_dust {
            monitor.stats.dust_utxos_detected += 1;
        }

        // Add to pending events
        monitor.pending_events.push(event);

        Ok(true) // New UTXO detected
    })
}

/// Get pending UTXO events and clear them
#[wasm_bindgen]
pub fn utxo_monitor_poll_events() -> Result<JsValue, JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        let events = std::mem::take(&mut monitor.pending_events);

        serde_wasm_bindgen::to_value(&events)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get pending dust events only (likely messages) and clear them
#[wasm_bindgen]
pub fn utxo_monitor_poll_dust_events() -> Result<JsValue, JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        let dust_events: Vec<NewUtxoEvent> = monitor.pending_events
            .iter()
            .filter(|e| e.is_dust)
            .cloned()
            .collect();

        // Remove dust events from pending
        monitor.pending_events.retain(|e| !e.is_dust);

        serde_wasm_bindgen::to_value(&dust_events)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get monitor statistics
#[wasm_bindgen]
pub fn utxo_monitor_get_stats() -> Result<JsValue, JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let monitor = monitor.borrow();
        let monitor = monitor.as_ref()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        serde_wasm_bindgen::to_value(&monitor.stats)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get current monitor state
#[wasm_bindgen]
pub fn utxo_monitor_get_state() -> Result<JsValue, JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let monitor = monitor.borrow();
        let monitor = monitor.as_ref()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        serde_wasm_bindgen::to_value(&monitor.state)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Start the monitor
#[wasm_bindgen]
pub fn utxo_monitor_start() -> Result<(), JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        monitor.state = MonitorState::Running;
        Ok(())
    })
}

/// Stop the monitor
#[wasm_bindgen]
pub fn utxo_monitor_stop() -> Result<(), JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        monitor.state = MonitorState::Stopped;
        Ok(())
    })
}

/// Clear all known UTXOs (force rescan)
#[wasm_bindgen]
pub fn utxo_monitor_clear_known_utxos() -> Result<(), JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        for monitored in monitor.addresses.values_mut() {
            monitored.known_utxos.clear();
        }

        Ok(())
    })
}

/// Clear pending events
#[wasm_bindgen]
pub fn utxo_monitor_clear_pending_events() -> Result<(), JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        monitor.pending_events.clear();
        Ok(())
    })
}

/// Get number of monitored addresses
#[wasm_bindgen]
pub fn utxo_monitor_address_count() -> Result<usize, JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let monitor = monitor.borrow();
        let monitor = monitor.as_ref()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        Ok(monitor.addresses.len())
    })
}

/// Get all monitored addresses
#[wasm_bindgen]
pub fn utxo_monitor_get_addresses() -> Result<JsValue, JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let monitor = monitor.borrow();
        let monitor = monitor.as_ref()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        let addresses: Vec<String> = monitor.addresses.keys().cloned().collect();

        serde_wasm_bindgen::to_value(&addresses)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Check if an address is being monitored
#[wasm_bindgen]
pub fn utxo_monitor_is_monitoring(address: String) -> Result<bool, JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let monitor = monitor.borrow();
        let monitor = monitor.as_ref()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        Ok(monitor.addresses.contains_key(&address))
    })
}

/// Increment poll cycle count (for statistics)
#[wasm_bindgen]
pub fn utxo_monitor_increment_poll_cycle() -> Result<(), JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        monitor.stats.poll_cycles += 1;
        Ok(())
    })
}

/// Record an error (for statistics)
#[wasm_bindgen]
pub fn utxo_monitor_record_error() -> Result<(), JsValue> {
    UTXO_MONITOR.with(|monitor| {
        let mut monitor = monitor.borrow_mut();
        let monitor = monitor.as_mut()
            .ok_or_else(|| JsValue::from_str("UTXO monitor not initialized"))?;

        monitor.stats.errors_encountered += 1;
        Ok(())
    })
}
