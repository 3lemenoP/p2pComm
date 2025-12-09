/// UTXO Monitor for P2PComm
///
/// This module monitors user addresses for incoming transactions:
/// - Subscribes to address pool changes
/// - Detects incoming dust outputs (message notifications)
/// - Fetches transaction payloads
/// - Supports background polling fallback
/// - Handles connection failures gracefully

use anyhow::{Result, Context, bail};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::rpc_client::{KaspaTestnetClient, UtxoEntry};

/// Dust amount threshold for message notifications (0.00001 KAS = 1,000 sompis)
pub const DUST_THRESHOLD: u64 = 1_000;

/// Default polling interval in seconds
pub const DEFAULT_POLL_INTERVAL: u64 = 30;

/// Maximum polling interval (exponential backoff cap)
pub const MAX_POLL_INTERVAL: u64 = 300;

/// Monitored address state
#[derive(Debug, Clone)]
pub struct MonitoredAddress {
    /// The Kaspa address string
    pub address: String,
    /// Known UTXOs for this address
    pub known_utxos: HashSet<String>,
    /// Last time this address was checked
    pub last_checked: DateTime<Utc>,
    /// Number of consecutive failures
    pub failure_count: u32,
}

impl MonitoredAddress {
    pub fn new(address: String) -> Self {
        Self {
            address,
            known_utxos: HashSet::new(),
            last_checked: Utc::now(),
            failure_count: 0,
        }
    }

    /// Generate UTXO key for deduplication
    pub fn utxo_key(tx_id: &str, index: u32) -> String {
        format!("{}:{}", tx_id, index)
    }
}

/// New UTXO event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUtxoEvent {
    /// Transaction ID containing this UTXO
    pub transaction_id: String,
    /// Output index in the transaction
    pub output_index: u32,
    /// Amount in sompis
    pub amount: u64,
    /// Recipient address
    pub address: String,
    /// Block DAA score when detected
    pub block_daa_score: u64,
    /// Whether this is a dust output (likely message notification)
    pub is_dust: bool,
    /// Timestamp when detected
    pub detected_at: DateTime<Utc>,
}

impl NewUtxoEvent {
    pub fn from_utxo_entry(entry: &UtxoEntry, address: &str) -> Self {
        Self {
            transaction_id: entry.transaction_id.clone(),
            output_index: entry.index,
            amount: entry.amount,
            address: address.to_string(),
            block_daa_score: entry.block_daa_score,
            is_dust: entry.amount <= DUST_THRESHOLD,
            detected_at: Utc::now(),
        }
    }
}

/// Monitor state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorState {
    /// Monitor is stopped
    Stopped,
    /// Monitor is running (WebSocket connected)
    Running,
    /// Monitor is polling (fallback mode)
    Polling,
    /// Monitor encountered an error
    Error,
}

/// Callback type for new UTXO events
pub type UtxoCallback = Box<dyn Fn(NewUtxoEvent) + Send + Sync>;

/// UTXO Monitor statistics
#[derive(Debug, Clone, Default)]
pub struct MonitorStats {
    /// Total UTXOs detected
    pub utxos_detected: usize,
    /// Dust UTXOs detected (message notifications)
    pub dust_utxos_detected: usize,
    /// Total poll cycles completed
    pub poll_cycles: usize,
    /// Total errors encountered
    pub errors_encountered: usize,
    /// Addresses being monitored
    pub addresses_monitored: usize,
}

/// UTXO Monitor for watching incoming transactions
pub struct UtxoMonitor {
    /// Monitored addresses
    addresses: Arc<Mutex<HashMap<String, MonitoredAddress>>>,
    /// Monitor state
    state: Arc<Mutex<MonitorState>>,
    /// Current polling interval (seconds)
    poll_interval: Arc<Mutex<u64>>,
    /// Statistics
    stats: Arc<Mutex<MonitorStats>>,
    /// New UTXO events (for retrieval)
    pending_events: Arc<Mutex<Vec<NewUtxoEvent>>>,
}

impl UtxoMonitor {
    /// Create a new UTXO monitor
    pub fn new() -> Self {
        Self {
            addresses: Arc::new(Mutex::new(HashMap::new())),
            state: Arc::new(Mutex::new(MonitorState::Stopped)),
            poll_interval: Arc::new(Mutex::new(DEFAULT_POLL_INTERVAL)),
            stats: Arc::new(Mutex::new(MonitorStats::default())),
            pending_events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add an address to monitor
    pub fn add_address(&self, address: &str) -> Result<()> {
        let mut addresses = self.addresses.lock().unwrap();

        if addresses.contains_key(address) {
            return Ok(()); // Already monitoring
        }

        addresses.insert(address.to_string(), MonitoredAddress::new(address.to_string()));

        let mut stats = self.stats.lock().unwrap();
        stats.addresses_monitored = addresses.len();

        Ok(())
    }

    /// Add multiple addresses to monitor
    pub fn add_addresses(&self, addrs: &[String]) -> Result<()> {
        for addr in addrs {
            self.add_address(addr)?;
        }
        Ok(())
    }

    /// Remove an address from monitoring
    pub fn remove_address(&self, address: &str) -> Result<()> {
        let mut addresses = self.addresses.lock().unwrap();
        addresses.remove(address);

        let mut stats = self.stats.lock().unwrap();
        stats.addresses_monitored = addresses.len();

        Ok(())
    }

    /// Get current monitor state
    pub fn get_state(&self) -> MonitorState {
        *self.state.lock().unwrap()
    }

    /// Get monitor statistics
    pub fn get_stats(&self) -> MonitorStats {
        self.stats.lock().unwrap().clone()
    }

    /// Get pending UTXO events
    pub fn get_pending_events(&self) -> Vec<NewUtxoEvent> {
        let mut events = self.pending_events.lock().unwrap();
        std::mem::take(&mut *events)
    }

    /// Get pending dust events only (likely messages)
    pub fn get_pending_dust_events(&self) -> Vec<NewUtxoEvent> {
        let mut events = self.pending_events.lock().unwrap();
        let dust_events: Vec<NewUtxoEvent> = events
            .iter()
            .filter(|e| e.is_dust)
            .cloned()
            .collect();

        // Remove dust events from pending
        events.retain(|e| !e.is_dust);

        dust_events
    }

    /// Poll all monitored addresses (single cycle)
    pub async fn poll_once(&self, rpc_client: &KaspaTestnetClient) -> Result<Vec<NewUtxoEvent>> {
        let addresses: Vec<String> = {
            let addrs = self.addresses.lock().unwrap();
            addrs.keys().cloned().collect()
        };

        if addresses.is_empty() {
            return Ok(Vec::new());
        }

        let mut new_events = Vec::new();

        for address in addresses {
            match self.check_address(rpc_client, &address).await {
                Ok(events) => {
                    new_events.extend(events);
                    self.reset_failure_count(&address);
                }
                Err(e) => {
                    self.increment_failure_count(&address);
                    let mut stats = self.stats.lock().unwrap();
                    stats.errors_encountered += 1;
                    log::warn!("Failed to check address {}: {}", address, e);
                }
            }
        }

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.poll_cycles += 1;
            stats.utxos_detected += new_events.len();
            stats.dust_utxos_detected += new_events.iter().filter(|e| e.is_dust).count();
        }

        // Store pending events
        {
            let mut pending = self.pending_events.lock().unwrap();
            pending.extend(new_events.clone());
        }

        Ok(new_events)
    }

    /// Check a single address for new UTXOs
    async fn check_address(
        &self,
        rpc_client: &KaspaTestnetClient,
        address: &str,
    ) -> Result<Vec<NewUtxoEvent>> {
        // Get current UTXOs from network
        let utxos = rpc_client.get_utxos_by_address(address).await
            .context("Failed to fetch UTXOs")?;

        // Get known UTXOs
        let known_utxos: HashSet<String> = {
            let addresses = self.addresses.lock().unwrap();
            if let Some(monitored) = addresses.get(address) {
                monitored.known_utxos.clone()
            } else {
                HashSet::new()
            }
        };

        // Find new UTXOs
        let mut new_events = Vec::new();
        let mut new_utxo_keys = Vec::new();

        for utxo in &utxos {
            let key = MonitoredAddress::utxo_key(&utxo.transaction_id, utxo.index);

            if !known_utxos.contains(&key) {
                let event = NewUtxoEvent::from_utxo_entry(utxo, address);
                new_events.push(event);
                new_utxo_keys.push(key);
            }
        }

        // Update known UTXOs
        {
            let mut addresses = self.addresses.lock().unwrap();
            if let Some(monitored) = addresses.get_mut(address) {
                for key in new_utxo_keys {
                    monitored.known_utxos.insert(key);
                }
                monitored.last_checked = Utc::now();
            }
        }

        Ok(new_events)
    }

    /// Reset failure count for an address
    fn reset_failure_count(&self, address: &str) {
        let mut addresses = self.addresses.lock().unwrap();
        if let Some(monitored) = addresses.get_mut(address) {
            monitored.failure_count = 0;
        }
    }

    /// Increment failure count for an address
    fn increment_failure_count(&self, address: &str) {
        let mut addresses = self.addresses.lock().unwrap();
        if let Some(monitored) = addresses.get_mut(address) {
            monitored.failure_count += 1;
        }
    }

    /// Start polling in background mode
    pub fn start_polling(&self) {
        let mut state = self.state.lock().unwrap();
        *state = MonitorState::Polling;
    }

    /// Stop monitoring
    pub fn stop(&self) {
        let mut state = self.state.lock().unwrap();
        *state = MonitorState::Stopped;
    }

    /// Calculate backoff interval based on failures
    pub fn calculate_backoff(&self, failures: u32) -> u64 {
        let base = DEFAULT_POLL_INTERVAL;
        let backoff = base * 2u64.pow(failures.min(5));
        backoff.min(MAX_POLL_INTERVAL)
    }

    /// Get number of monitored addresses
    pub fn address_count(&self) -> usize {
        self.addresses.lock().unwrap().len()
    }

    /// Get all monitored addresses
    pub fn get_addresses(&self) -> Vec<String> {
        self.addresses.lock().unwrap().keys().cloned().collect()
    }

    /// Check if an address is being monitored
    pub fn is_monitoring(&self, address: &str) -> bool {
        self.addresses.lock().unwrap().contains_key(address)
    }

    /// Clear all known UTXOs (force rescan)
    pub fn clear_known_utxos(&self) {
        let mut addresses = self.addresses.lock().unwrap();
        for monitored in addresses.values_mut() {
            monitored.known_utxos.clear();
        }
    }

    /// Clear pending events
    pub fn clear_pending_events(&self) {
        self.pending_events.lock().unwrap().clear();
    }
}

impl Default for UtxoMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_creation() {
        let monitor = UtxoMonitor::new();
        assert_eq!(monitor.get_state(), MonitorState::Stopped);
        assert_eq!(monitor.address_count(), 0);
    }

    #[test]
    fn test_add_address() {
        let monitor = UtxoMonitor::new();
        let address = "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7";

        monitor.add_address(address).unwrap();
        assert_eq!(monitor.address_count(), 1);
        assert!(monitor.is_monitoring(address));
    }

    #[test]
    fn test_remove_address() {
        let monitor = UtxoMonitor::new();
        let address = "kaspatest:qp8z334xvtsx3fynqwancncu8srvpw3ru9szf3l0zp9wfne2awetyu7v7a4c7";

        monitor.add_address(address).unwrap();
        assert_eq!(monitor.address_count(), 1);

        monitor.remove_address(address).unwrap();
        assert_eq!(monitor.address_count(), 0);
        assert!(!monitor.is_monitoring(address));
    }

    #[test]
    fn test_backoff_calculation() {
        let monitor = UtxoMonitor::new();

        // No failures: base interval
        assert_eq!(monitor.calculate_backoff(0), DEFAULT_POLL_INTERVAL);

        // 1 failure: double
        assert_eq!(monitor.calculate_backoff(1), DEFAULT_POLL_INTERVAL * 2);

        // 2 failures: quadruple
        assert_eq!(monitor.calculate_backoff(2), DEFAULT_POLL_INTERVAL * 4);

        // Max backoff cap
        assert!(monitor.calculate_backoff(10) <= MAX_POLL_INTERVAL);
    }

    #[test]
    fn test_new_utxo_event() {
        let entry = UtxoEntry {
            transaction_id: "abc123".to_string(),
            index: 0,
            amount: 1_000, // Dust amount
            script_public_key: vec![],
            block_daa_score: 12345,
            is_coinbase: false,
        };

        let event = NewUtxoEvent::from_utxo_entry(&entry, "test_address");

        assert_eq!(event.transaction_id, "abc123");
        assert_eq!(event.amount, 1_000);
        assert!(event.is_dust);
    }

    #[test]
    fn test_utxo_key_generation() {
        let key = MonitoredAddress::utxo_key("tx123", 0);
        assert_eq!(key, "tx123:0");

        let key2 = MonitoredAddress::utxo_key("tx123", 1);
        assert_eq!(key2, "tx123:1");
        assert_ne!(key, key2);
    }

    #[test]
    fn test_state_transitions() {
        let monitor = UtxoMonitor::new();

        assert_eq!(monitor.get_state(), MonitorState::Stopped);

        monitor.start_polling();
        assert_eq!(monitor.get_state(), MonitorState::Polling);

        monitor.stop();
        assert_eq!(monitor.get_state(), MonitorState::Stopped);
    }
}
