
//! Kaspa Blockchain Integration for P2PComm
//!
//! This module provides blockchain-based messaging capabilities:
//! - Message envelope format for embedding in transactions
//! - WebRTC signaling via blockchain
//! - Peer discovery through transaction monitoring
//! - Offline message delivery
//! - Real RPC connectivity to Kaspa testnet nodes

pub mod envelope;
pub mod signaling;
pub mod discovery;
pub mod payload;
pub mod types;
pub mod rpc_bridge;
pub mod wallet_bridge;
pub mod tx_builder;
pub mod tx_signer;
pub mod utxo_monitor;
pub mod message_reception;
pub mod delivery_coordinator;
pub mod webrtc_manager;
pub mod service;

// Re-exports
pub use envelope::{KaspaEnvelope, EnvelopeType};
pub use signaling::{SignalingMessage, SignalingState, SdpData, IceCandidate};
pub use discovery::{PeerAnnouncement, DiscoveredPeer, PeerStatus};
pub use payload::{MessageQueue, QueuedMessage, MessagePriority};
pub use types::*;
pub use rpc_bridge::*;
pub use wallet_bridge::*;
pub use tx_builder::*;
pub use utxo_monitor::*;
pub use message_reception::*;
pub use delivery_coordinator::*;
pub use webrtc_manager::*;
pub use service::*;


use wasm_bindgen::prelude::*;

/// JavaScript interface for Kaspa RPC operations
/// These methods are implemented in JavaScript and called from Rust
#[wasm_bindgen]
extern "C" {
    /// Kaspa RPC handler provided by JavaScript
    pub type KaspaRpcHandler;

    #[wasm_bindgen(method)]
    pub fn submit_transaction(this: &KaspaRpcHandler, payload: &[u8]) -> js_sys::Promise;

    #[wasm_bindgen(method)]
    pub fn get_utxos(this: &KaspaRpcHandler, address: &str) -> js_sys::Promise;

    #[wasm_bindgen(method)]
    pub fn monitor_address(this: &KaspaRpcHandler, address: &str) -> js_sys::Promise;
}
