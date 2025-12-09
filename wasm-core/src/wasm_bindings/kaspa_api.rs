//! WASM Bindings for Kaspa Blockchain Integration
//!
//! Exposes the Kaspa messaging functionality to JavaScript/TypeScript.

use wasm_bindgen::prelude::*;
use crate::kaspa::{
    envelope::{KaspaEnvelope, EnvelopeType, extract_envelopes, is_p2pcomm_payload},
    signaling::{SignalingManager, SignalingMessage, SdpData, IceCandidate, SdpType, SignalingState},
    discovery::{PeerDiscoveryManager, PeerAnnouncement, DiscoveredPeer, PeerStatus},
    payload::{MessageQueue, QueuedMessage, MessagePriority, MessageStatus},
    types::KaspaStats,
};

// ============================================================================
// Envelope API
// ============================================================================

/// Create a direct message envelope
#[wasm_bindgen]
pub fn create_direct_message_envelope(
    sender_peer_id: String,
    recipient_peer_id: String,
    payload: String,
) -> KaspaEnvelope {
    KaspaEnvelope::direct_message(sender_peer_id, recipient_peer_id, payload)
}

/// Create a peer announcement envelope
#[wasm_bindgen]
pub fn create_announcement_envelope(
    sender_peer_id: String,
    payload: String,
) -> KaspaEnvelope {
    KaspaEnvelope::peer_announcement(sender_peer_id, payload)
}

/// Create a signaling envelope
#[wasm_bindgen]
pub fn create_signaling_envelope(
    sender_peer_id: String,
    recipient_peer_id: String,
    signaling_type: EnvelopeType,
    payload: String,
) -> KaspaEnvelope {
    KaspaEnvelope::signaling(sender_peer_id, recipient_peer_id, signaling_type, payload)
}

/// Serialize envelope to JSON bytes
#[wasm_bindgen]
pub fn serialize_envelope(envelope: &KaspaEnvelope) -> Result<Vec<u8>, JsValue> {
    envelope.to_bytes().map_err(|e| JsValue::from(e))
}

/// Deserialize envelope from JSON bytes
#[wasm_bindgen]
pub fn deserialize_envelope(bytes: &[u8]) -> Result<KaspaEnvelope, JsValue> {
    KaspaEnvelope::from_bytes(bytes).map_err(|e| JsValue::from(e))
}

/// Check if payload is from P2PComm
#[wasm_bindgen]
pub fn check_p2pcomm_payload(payload: &[u8]) -> bool {
    is_p2pcomm_payload(payload)
}

/// Extract envelopes from transaction payload
#[wasm_bindgen]
pub fn extract_envelopes_from_payload(payload: &[u8]) -> Vec<JsValue> {
    extract_envelopes(payload)
        .into_iter()
        .map(|e| serde_wasm_bindgen::to_value(&e).unwrap_or(JsValue::NULL))
        .collect()
}

// ============================================================================
// Signaling API
// ============================================================================

/// Create a new signaling manager
#[wasm_bindgen]
pub fn create_signaling_manager(local_peer_id: String) -> SignalingManager {
    SignalingManager::new(local_peer_id)
}

/// Create SDP offer data
#[wasm_bindgen]
pub fn create_sdp_offer(sdp: String, session_id: String) -> SdpData {
    SdpData::offer(sdp, session_id)
}

/// Create SDP answer data
#[wasm_bindgen]
pub fn create_sdp_answer(sdp: String, session_id: String) -> SdpData {
    SdpData::answer(sdp, session_id)
}

/// Create ICE candidate
#[wasm_bindgen]
pub fn create_ice_candidate(candidate: String, session_id: String) -> IceCandidate {
    IceCandidate::new(candidate, session_id)
}

/// Create signaling message
#[wasm_bindgen]
pub fn create_signaling_message(
    sender_peer_id: String,
    signaling_type: EnvelopeType,
    data: String,
) -> SignalingMessage {
    SignalingMessage::new(sender_peer_id, signaling_type, data)
}

// ============================================================================
// Discovery API
// ============================================================================

/// Create a new peer discovery manager
#[wasm_bindgen]
pub fn create_discovery_manager(local_peer_id: String) -> PeerDiscoveryManager {
    PeerDiscoveryManager::new(local_peer_id)
}

/// Create a peer announcement
#[wasm_bindgen]
pub fn create_peer_announcement(
    peer_id: String,
    kaspa_address: String,
    public_key: String,
) -> PeerAnnouncement {
    PeerAnnouncement::new(peer_id, kaspa_address, public_key)
}

/// Serialize peer announcement to JSON
#[wasm_bindgen]
pub fn serialize_announcement(announcement: &PeerAnnouncement) -> Result<String, JsValue> {
    serde_json::to_string(announcement)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Deserialize peer announcement from JSON
#[wasm_bindgen]
pub fn deserialize_announcement(json: &str) -> Result<PeerAnnouncement, JsValue> {
    serde_json::from_str(json)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ============================================================================
// Message Queue API
// ============================================================================

/// Create a new message queue
#[wasm_bindgen]
pub fn create_message_queue(local_peer_id: String) -> MessageQueue {
    MessageQueue::new(local_peer_id)
}

// ============================================================================
// Stats API
// ============================================================================

/// Create empty Kaspa stats
#[wasm_bindgen]
pub fn create_kaspa_stats() -> KaspaStats {
    KaspaStats::new()
}

// ============================================================================
// Utility Types - Export to JS
// ============================================================================

/// Get available envelope types for JavaScript
#[wasm_bindgen]
pub fn get_envelope_types() -> JsValue {
    let types = vec![
        ("DirectMessage", 0),
        ("GroupMessage", 1),
        ("PeerAnnouncement", 2),
        ("SignalingOffer", 3),
        ("SignalingAnswer", 4),
        ("SignalingIce", 5),
        ("Acknowledgment", 6),
        ("Encrypted", 7),
        ("KeyExchange", 8),
        ("StatusUpdate", 9),
    ];
    serde_wasm_bindgen::to_value(&types).unwrap_or(JsValue::NULL)
}

/// Get available peer statuses for JavaScript
#[wasm_bindgen]
pub fn get_peer_statuses() -> JsValue {
    let statuses = vec![
        ("Discovered", "discovered"),
        ("Connecting", "connecting"),
        ("Connected", "connected"),
        ("Failed", "failed"),
        ("Offline", "offline"),
        ("Banned", "banned"),
    ];
    serde_wasm_bindgen::to_value(&statuses).unwrap_or(JsValue::NULL)
}

/// Get available signaling states for JavaScript
#[wasm_bindgen]
pub fn get_signaling_states() -> JsValue {
    let states = vec![
        ("Idle", "idle"),
        ("CreatingOffer", "creating_offer"),
        ("OfferSent", "offer_sent"),
        ("OfferReceived", "offer_received"),
        ("AnswerSent", "answer_sent"),
        ("IceExchange", "ice_exchange"),
        ("Connected", "connected"),
        ("Closed", "closed"),
        ("Failed", "failed"),
    ];
    serde_wasm_bindgen::to_value(&states).unwrap_or(JsValue::NULL)
}

/// Get available message priorities for JavaScript
#[wasm_bindgen]
pub fn get_message_priorities() -> JsValue {
    let priorities = vec![
        ("Low", 0),
        ("Normal", 1),
        ("High", 2),
        ("Critical", 3),
    ];
    serde_wasm_bindgen::to_value(&priorities).unwrap_or(JsValue::NULL)
}
