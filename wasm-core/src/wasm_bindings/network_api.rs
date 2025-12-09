// Network API for JavaScript
// Provides network protocol and connection functions

use wasm_bindgen::prelude::*;
use crate::network::protocol::{
    ProtocolMessage, MessagePayload, HandshakeMessage, PingMessage, PongMessage,
    UserMessagePayload,
};
use crate::network::manager::NetworkManager;
use crate::network::ConnectionState;
use crate::identity::PeerId;
use std::cell::RefCell;

// WebAssembly is single-threaded, so we use thread_local storage
thread_local! {
    /// Global network manager instance
    static NETWORK_MANAGER: RefCell<Option<NetworkManager>> = RefCell::new(None);

    /// Message callback for incoming messages
    static MESSAGE_CALLBACK: RefCell<Option<js_sys::Function>> = RefCell::new(None);
}

/// Create a handshake message
#[wasm_bindgen]
pub fn create_handshake(
    signing_public_key_hex: String,
    encryption_public_key_hex: String,
) -> Result<String, String> {
    let signing_pk = hex::decode(&signing_public_key_hex)
        .map_err(|e| format!("Invalid signing public key: {}", e))?;

    let encryption_pk = hex::decode(&encryption_public_key_hex)
        .map_err(|e| format!("Invalid encryption public key: {}", e))?;

    let handshake = HandshakeMessage::new(signing_pk, encryption_pk);

    serde_json::to_string(&handshake)
        .map_err(|e| format!("Failed to serialize handshake: {}", e))
}

/// Create a ping message
#[wasm_bindgen]
pub fn create_ping() -> Result<String, String> {
    let ping = PingMessage::new();

    serde_json::to_string(&ping)
        .map_err(|e| format!("Failed to serialize ping: {}", e))
}

/// Create a pong response from a ping
#[wasm_bindgen]
pub fn create_pong(ping_json: String) -> Result<String, String> {
    let ping: PingMessage = serde_json::from_str(&ping_json)
        .map_err(|e| format!("Failed to deserialize ping: {}", e))?;

    let pong = PongMessage::from_ping(&ping);

    serde_json::to_string(&pong)
        .map_err(|e| format!("Failed to serialize pong: {}", e))
}

/// Calculate RTT from a pong message
#[wasm_bindgen]
pub fn calculate_rtt(pong_json: String) -> Result<f64, String> {
    let pong: PongMessage = serde_json::from_str(&pong_json)
        .map_err(|e| format!("Failed to deserialize pong: {}", e))?;

    Ok(pong.calculate_rtt() as f64)
}

/// Create a protocol message envelope
#[wasm_bindgen]
pub fn create_protocol_message(
    from_peer_id: String,
    to_peer_id: String,
    payload_json: String,
    payload_type: String,
) -> Result<Vec<u8>, String> {
    let from = PeerId::from_hex(&from_peer_id)
        .map_err(|e| format!("Invalid from peer ID: {:?}", e))?;

    let to = PeerId::from_hex(&to_peer_id)
        .map_err(|e| format!("Invalid to peer ID: {:?}", e))?;

    // Parse payload based on type
    let payload = match payload_type.as_str() {
        "handshake" => {
            let handshake: HandshakeMessage = serde_json::from_str(&payload_json)
                .map_err(|e| format!("Failed to parse handshake: {}", e))?;
            MessagePayload::Handshake(handshake)
        }
        "user_message" => {
            let message: crate::message::Message = serde_json::from_str(&payload_json)
                .map_err(|e| format!("Failed to parse message: {}", e))?;
            MessagePayload::UserMessage(UserMessagePayload { message })
        }
        "ping" => {
            let ping: PingMessage = serde_json::from_str(&payload_json)
                .map_err(|e| format!("Failed to parse ping: {}", e))?;
            MessagePayload::Ping(ping)
        }
        "pong" => {
            let pong: PongMessage = serde_json::from_str(&payload_json)
                .map_err(|e| format!("Failed to parse pong: {}", e))?;
            MessagePayload::Pong(pong)
        }
        _ => return Err(format!("Unsupported payload type: {}", payload_type)),
    };

    let msg = ProtocolMessage::new(from, to, payload);

    msg.to_bytes()
}

/// Parse a protocol message from bytes
#[wasm_bindgen]
pub fn parse_protocol_message(bytes: Vec<u8>) -> Result<String, String> {
    let msg = ProtocolMessage::from_bytes(&bytes)?;

    serde_json::to_string(&msg)
        .map_err(|e| format!("Failed to serialize protocol message: {}", e))
}

/// Check if a protocol message is expired
#[wasm_bindgen]
pub fn is_protocol_message_expired(message_json: String, max_age_ms: u64) -> Result<bool, String> {
    let msg: ProtocolMessage = serde_json::from_str(&message_json)
        .map_err(|e| format!("Failed to deserialize protocol message: {}", e))?;

    Ok(msg.is_expired(max_age_ms))
}

/// Get protocol version
#[wasm_bindgen]
pub fn get_protocol_version() -> u8 {
    crate::network::protocol::PROTOCOL_VERSION
}

// ========================================
// Network Manager API
// ========================================

/// Initialize the network manager with a local peer ID
#[wasm_bindgen]
pub fn network_init(local_peer_id: String) -> Result<(), String> {
    let peer_id = PeerId::from_hex(&local_peer_id)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    let mut manager = NetworkManager::new();
    manager.set_local_peer_id(peer_id);

    NETWORK_MANAGER.with(|nm| {
        *nm.borrow_mut() = Some(manager);
    });

    web_sys::console::log_1(&"Network manager initialized".into());
    Ok(())
}

/// Connect to a peer
#[wasm_bindgen]
pub fn network_connect_peer(peer_id: String) -> Result<(), String> {
    let peer = PeerId::from_hex(&peer_id)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        manager.connect_to_peer(peer)
            .map_err(|e| format!("Failed to connect: {:?}", e))
    })
}

/// Disconnect from a peer
#[wasm_bindgen]
pub fn network_disconnect_peer(peer_id: String, reason: String) -> Result<(), String> {
    let peer = PeerId::from_hex(&peer_id)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        manager.disconnect_peer(&peer, &reason)
            .map_err(|e| format!("Failed to disconnect: {:?}", e))
    })
}

/// Send a protocol message to a peer
#[wasm_bindgen]
pub fn network_send_message(peer_id: String, message_bytes: Vec<u8>) -> Result<(), String> {
    let peer = PeerId::from_hex(&peer_id)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    let message = ProtocolMessage::from_bytes(&message_bytes)?;

    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        manager.send_to_peer(&peer, message)
            .map_err(|e| format!("Failed to send message: {:?}", e))?;

        Ok(())
    })
}

/// Handle incoming message bytes from a peer
#[wasm_bindgen]
pub fn network_handle_incoming(peer_id: String, bytes: Vec<u8>) -> Result<(), String> {
    let peer = PeerId::from_hex(&peer_id)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    let message = NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        manager.handle_incoming_message(&peer, &bytes)
            .map_err(|e| format!("Failed to handle message: {:?}", e))
    })?;

    // Call the message callback if set
    MESSAGE_CALLBACK.with(|cb| {
        if let Some(callback) = cb.borrow().as_ref() {
            let this = JsValue::null();
            let peer_id_js = JsValue::from_str(&peer.to_hex());
            let message_json = serde_json::to_string(&message)
                .map_err(|e| format!("Failed to serialize message: {}", e))?;
            let message_js = JsValue::from_str(&message_json);

            let _ = callback.call2(&this, &peer_id_js, &message_js);
        }
        Ok::<(), String>(())
    })?;

    Ok(())
}

/// Mark a connection as established
#[wasm_bindgen]
pub fn network_mark_connected(peer_id: String) -> Result<(), String> {
    let peer = PeerId::from_hex(&peer_id)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        manager.mark_connected(&peer);
        Ok(())
    })
}

/// Mark a connection as failed
#[wasm_bindgen]
pub fn network_mark_failed(peer_id: String, reason: String) -> Result<(), String> {
    let peer = PeerId::from_hex(&peer_id)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        manager.mark_failed(&peer, reason);
        Ok(())
    })
}

/// Set WebRTC connection ID for a peer
#[wasm_bindgen]
pub fn network_set_connection_id(peer_id: String, connection_id: String) -> Result<(), String> {
    let peer = PeerId::from_hex(&peer_id)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        manager.set_connection_id(&peer, connection_id);
        Ok(())
    })
}

/// Get connection state for a peer
#[wasm_bindgen]
pub fn network_get_connection_state(peer_id: String) -> Result<String, String> {
    let peer = PeerId::from_hex(&peer_id)
        .map_err(|e| format!("Invalid peer ID: {:?}", e))?;

    NETWORK_MANAGER.with(|nm| {
        let manager_opt = nm.borrow();
        let manager = manager_opt.as_ref()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        let state = manager.get_connection_state(&peer)
            .ok_or_else(|| "Peer not found".to_string())?;

        Ok(connection_state_to_string(state))
    })
}

/// Get network statistics
#[wasm_bindgen]
pub fn network_get_stats() -> Result<String, String> {
    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        let stats = manager.get_aggregate_stats();

        serde_json::to_string(&stats)
            .map_err(|e| format!("Failed to serialize stats: {}", e))
    })
}

/// Clean up closed connections
#[wasm_bindgen]
pub fn network_cleanup_connections() -> Result<usize, String> {
    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        Ok(manager.cleanup_connections())
    })
}

/// Check connection health and mark unhealthy ones as failed
#[wasm_bindgen]
pub fn network_check_health() -> Result<Vec<JsValue>, String> {
    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        let unhealthy = manager.check_connection_health();

        Ok(unhealthy.iter()
            .map(|peer_id| JsValue::from_str(&peer_id.to_hex()))
            .collect())
    })
}

/// Send keepalive pings to all connected peers
#[wasm_bindgen]
pub fn network_send_keepalive_pings() -> Result<usize, String> {
    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        let pings = manager.send_keepalive_pings()
            .map_err(|e| format!("Failed to send pings: {:?}", e))?;

        Ok(pings.len())
    })
}

/// Get list of all peer IDs
#[wasm_bindgen]
pub fn network_get_peer_ids() -> Result<Vec<JsValue>, String> {
    NETWORK_MANAGER.with(|nm| {
        let manager_opt = nm.borrow();
        let manager = manager_opt.as_ref()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        let peer_ids = manager.get_peer_ids();

        Ok(peer_ids.iter()
            .map(|peer_id| JsValue::from_str(&peer_id.to_hex()))
            .collect())
    })
}

/// Disconnect all peers
#[wasm_bindgen]
pub fn network_disconnect_all(reason: String) -> Result<(), String> {
    NETWORK_MANAGER.with(|nm| {
        let mut manager_opt = nm.borrow_mut();
        let manager = manager_opt.as_mut()
            .ok_or_else(|| "Network manager not initialized".to_string())?;

        manager.disconnect_all(&reason);
        Ok(())
    })
}

/// Set callback for incoming messages
#[wasm_bindgen]
pub fn network_set_message_callback(callback: js_sys::Function) -> Result<(), String> {
    MESSAGE_CALLBACK.with(|cb| {
        *cb.borrow_mut() = Some(callback);
    });

    web_sys::console::log_1(&"Message callback set".into());
    Ok(())
}

/// Helper function to convert ConnectionState to string
fn connection_state_to_string(state: ConnectionState) -> String {
    match state {
        ConnectionState::Disconnected => "disconnected".to_string(),
        ConnectionState::Connecting => "connecting".to_string(),
        ConnectionState::Connected => "connected".to_string(),
        ConnectionState::Failed => "failed".to_string(),
        ConnectionState::Closed => "closed".to_string(),
    }
}
