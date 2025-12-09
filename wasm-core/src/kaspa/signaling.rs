//! WebRTC Signaling via Kaspa Blockchain
//!
//! Handles SDP offer/answer exchange and ICE candidate trickling
//! through blockchain transactions for NAT traversal.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use std::collections::{HashMap, VecDeque};
use crate::kaspa::envelope::{KaspaEnvelope, EnvelopeType};
use crate::kaspa::types::{KaspaError, KaspaResult, KaspaErrorKind, current_timestamp_ms};

/// Signaling session timeout in milliseconds
pub const SIGNALING_TIMEOUT_MS: u64 = 60_000;

/// Maximum ICE candidates to batch together
pub const MAX_ICE_BATCH_SIZE: usize = 10;

/// Signaling connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[wasm_bindgen]
pub enum SignalingState {
    /// Initial state, no connection attempt
    Idle,
    /// Creating local offer
    CreatingOffer,
    /// Offer sent, waiting for answer
    OfferSent,
    /// Received offer, need to create answer
    OfferReceived,
    /// Answer sent, waiting for ICE
    AnswerSent,
    /// Exchanging ICE candidates
    IceExchange,
    /// Connection established
    Connected,
    /// Connection closed
    Closed,
    /// Connection failed
    Failed,
}

impl std::fmt::Display for SignalingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::CreatingOffer => write!(f, "creating_offer"),
            Self::OfferSent => write!(f, "offer_sent"),
            Self::OfferReceived => write!(f, "offer_received"),
            Self::AnswerSent => write!(f, "answer_sent"),
            Self::IceExchange => write!(f, "ice_exchange"),
            Self::Connected => write!(f, "connected"),
            Self::Closed => write!(f, "closed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// SDP type (offer or answer)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[wasm_bindgen]
pub enum SdpType {
    Offer,
    Answer,
}

impl std::fmt::Display for SdpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offer => write!(f, "offer"),
            Self::Answer => write!(f, "answer"),
        }
    }
}

/// SDP data for WebRTC negotiation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct SdpData {
    /// SDP type
    pub sdp_type: SdpType,
    /// SDP string
    pub sdp: String,
    /// Session identifier
    pub session_id: String,
}

#[wasm_bindgen]
impl SdpData {
    #[wasm_bindgen(constructor)]
    pub fn new(sdp_type: SdpType, sdp: String, session_id: String) -> Self {
        Self { sdp_type, sdp, session_id }
    }

    /// Create offer SDP
    pub fn offer(sdp: String, session_id: String) -> Self {
        Self::new(SdpType::Offer, sdp, session_id)
    }

    /// Create answer SDP
    pub fn answer(sdp: String, session_id: String) -> Self {
        Self::new(SdpType::Answer, sdp, session_id)
    }
}

/// ICE candidate for WebRTC
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct IceCandidate {
    /// ICE candidate string
    pub candidate: String,
    /// SDP mid
    pub sdp_mid: Option<String>,
    /// SDP m-line index
    pub sdp_m_line_index: Option<u16>,
    /// Username fragment
    pub username_fragment: Option<String>,
    /// Session ID
    pub session_id: String,
}

#[wasm_bindgen]
impl IceCandidate {
    #[wasm_bindgen(constructor)]
    pub fn new(candidate: String, session_id: String) -> Self {
        Self {
            candidate,
            sdp_mid: None,
            sdp_m_line_index: None,
            username_fragment: None,
            session_id,
        }
    }

    /// Set SDP mid
    pub fn with_sdp_mid(mut self, mid: String) -> Self {
        self.sdp_mid = Some(mid);
        self
    }

    /// Set m-line index
    pub fn with_m_line_index(mut self, index: u16) -> Self {
        self.sdp_m_line_index = Some(index);
        self
    }
}

/// Signaling message received from blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct SignalingMessage {
    /// Sender's peer ID
    pub sender_peer_id: String,
    /// Type of signaling message
    pub signaling_type: EnvelopeType,
    /// JSON payload (SdpData or IceCandidate)
    pub data: String,
    /// Timestamp when received
    pub timestamp: u64,
}

#[wasm_bindgen]
impl SignalingMessage {
    #[wasm_bindgen(constructor)]
    pub fn new(
        sender_peer_id: String,
        signaling_type: EnvelopeType,
        data: String,
    ) -> Self {
        Self {
            sender_peer_id,
            signaling_type,
            data,
            timestamp: current_timestamp_ms(),
        }
    }
}

/// Signaling session with a remote peer
#[derive(Debug, Clone)]
pub struct SignalingSession {
    /// Remote peer ID
    pub remote_peer_id: String,
    /// Session ID
    pub session_id: String,
    /// Current state
    pub state: SignalingState,
    /// Whether we initiated the connection
    pub is_initiator: bool,
    /// Local SDP
    pub local_sdp: Option<SdpData>,
    /// Remote SDP
    pub remote_sdp: Option<SdpData>,
    /// Local ICE candidates pending send
    pub local_ice_candidates: Vec<IceCandidate>,
    /// Remote ICE candidates received
    pub remote_ice_candidates: Vec<IceCandidate>,
    /// Session creation time
    pub created_at: u64,
    /// Last activity time
    pub last_activity: u64,
    /// ICE gathering complete
    pub ice_gathering_complete: bool,
}

impl SignalingSession {
    /// Create new session as initiator (sending offer)
    pub fn new_as_initiator(remote_peer_id: String) -> Self {
        let now = current_timestamp_ms();
        Self {
            remote_peer_id,
            session_id: format!("session_{}", crate::kaspa::types::generate_message_id()),
            state: SignalingState::CreatingOffer,
            is_initiator: true,
            local_sdp: None,
            remote_sdp: None,
            local_ice_candidates: Vec::new(),
            remote_ice_candidates: Vec::new(),
            created_at: now,
            last_activity: now,
            ice_gathering_complete: false,
        }
    }

    /// Create new session as responder (received offer)
    pub fn new_as_responder(remote_peer_id: String, session_id: String) -> Self {
        let now = current_timestamp_ms();
        Self {
            remote_peer_id,
            session_id,
            state: SignalingState::OfferReceived,
            is_initiator: false,
            local_sdp: None,
            remote_sdp: None,
            local_ice_candidates: Vec::new(),
            remote_ice_candidates: Vec::new(),
            created_at: now,
            last_activity: now,
            ice_gathering_complete: false,
        }
    }

    /// Update last activity time
    pub fn touch(&mut self) {
        self.last_activity = current_timestamp_ms();
    }

    /// Check if session has timed out
    pub fn is_timed_out(&self, timeout_ms: u64) -> bool {
        let now = current_timestamp_ms();
        now.saturating_sub(self.last_activity) > timeout_ms
    }

    /// Check if session can accept ICE candidates
    pub fn can_accept_ice(&self) -> bool {
        matches!(
            self.state,
            SignalingState::OfferSent
                | SignalingState::OfferReceived
                | SignalingState::AnswerSent
                | SignalingState::IceExchange
        )
    }
}

/// Outgoing signal to be sent via blockchain
#[derive(Debug, Clone)]
pub struct OutgoingSignal {
    /// Target peer ID
    pub peer_id: String,
    /// Signal type
    pub signal_type: SignalType,
    /// JSON data
    pub data: String,
    /// Session ID
    pub session_id: String,
    /// Creation timestamp
    pub created_at: u64,
}

/// Type of outgoing signal
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalType {
    Offer,
    Answer,
    IceCandidate,
    IceBatch,
}

/// Signaling statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct SignalingStats {
    pub offers_sent: u32,
    pub offers_received: u32,
    pub answers_sent: u32,
    pub answers_received: u32,
    pub ice_candidates_sent: u32,
    pub ice_candidates_received: u32,
    pub connections_established: u32,
    pub connections_failed: u32,
    pub sessions_timed_out: u32,
}

/// Manager for WebRTC signaling via Kaspa blockchain
#[wasm_bindgen]
pub struct SignalingManager {
    /// Our peer ID
    local_peer_id: String,
    /// Active sessions by remote peer ID
    sessions: HashMap<String, SignalingSession>,
    /// Queue of signals to send
    outgoing_queue: VecDeque<OutgoingSignal>,
    /// Statistics
    stats: SignalingStats,
}

#[wasm_bindgen]
impl SignalingManager {
    /// Create a new signaling manager
    #[wasm_bindgen(constructor)]
    pub fn new(local_peer_id: String) -> Self {
        Self {
            local_peer_id,
            sessions: HashMap::new(),
            outgoing_queue: VecDeque::new(),
            stats: SignalingStats::default(),
        }
    }

    /// Get our peer ID
    pub fn local_peer_id(&self) -> String {
        self.local_peer_id.clone()
    }

    /// Get session state for a peer
    pub fn get_session_state(&self, peer_id: &str) -> Option<SignalingState> {
        self.sessions.get(peer_id).map(|s| s.state)
    }

    /// Get statistics
    pub fn get_stats(&self) -> SignalingStats {
        self.stats.clone()
    }

    /// Get number of active sessions
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| !matches!(s.state, SignalingState::Closed | SignalingState::Failed))
            .count()
    }
}

impl SignalingManager {
    /// Initiate connection to a peer
    pub fn initiate_connection(&mut self, peer_id: &str) -> KaspaResult<String> {
        // Check for existing session
        if let Some(session) = self.sessions.get(peer_id) {
            if !matches!(session.state, SignalingState::Closed | SignalingState::Failed) {
                return Err(KaspaError::new(
                    KaspaErrorKind::SessionError,
                    format!("Session already exists for peer {}", peer_id),
                ));
            }
        }

        let session = SignalingSession::new_as_initiator(peer_id.to_string());
        let session_id = session.session_id.clone();
        self.sessions.insert(peer_id.to_string(), session);

        Ok(session_id)
    }

    /// Set local offer (after creating RTCPeerConnection offer)
    pub fn set_local_offer(&mut self, peer_id: &str, sdp: &str) -> KaspaResult<()> {
        let session = self.sessions.get_mut(peer_id).ok_or_else(|| {
            KaspaError::new(KaspaErrorKind::SessionError, "Session not found")
        })?;

        let sdp_data = SdpData::offer(sdp.to_string(), session.session_id.clone());

        // Queue outgoing offer
        self.outgoing_queue.push_back(OutgoingSignal {
            peer_id: peer_id.to_string(),
            signal_type: SignalType::Offer,
            data: serde_json::to_string(&sdp_data).unwrap(),
            session_id: session.session_id.clone(),
            created_at: current_timestamp_ms(),
        });

        session.local_sdp = Some(sdp_data);
        session.state = SignalingState::OfferSent;
        session.touch();
        self.stats.offers_sent += 1;

        Ok(())
    }

    /// Set local answer (after creating RTCPeerConnection answer)
    pub fn set_local_answer(&mut self, peer_id: &str, sdp: &str) -> KaspaResult<()> {
        let session = self.sessions.get_mut(peer_id).ok_or_else(|| {
            KaspaError::new(KaspaErrorKind::SessionError, "Session not found")
        })?;

        let sdp_data = SdpData::answer(sdp.to_string(), session.session_id.clone());

        // Queue outgoing answer
        self.outgoing_queue.push_back(OutgoingSignal {
            peer_id: peer_id.to_string(),
            signal_type: SignalType::Answer,
            data: serde_json::to_string(&sdp_data).unwrap(),
            session_id: session.session_id.clone(),
            created_at: current_timestamp_ms(),
        });

        session.local_sdp = Some(sdp_data);
        session.state = SignalingState::AnswerSent;
        session.touch();
        self.stats.answers_sent += 1;

        Ok(())
    }

    /// Add local ICE candidate
    pub fn add_local_ice_candidate(&mut self, peer_id: &str, candidate: IceCandidate) -> KaspaResult<()> {
        let session = self.sessions.get_mut(peer_id).ok_or_else(|| {
            KaspaError::new(KaspaErrorKind::SessionError, "Session not found")
        })?;

        session.local_ice_candidates.push(candidate);
        session.touch();

        Ok(())
    }

    /// Mark ICE gathering complete and flush candidates
    pub fn set_ice_gathering_complete(&mut self, peer_id: &str) -> KaspaResult<()> {
        let session = self.sessions.get_mut(peer_id).ok_or_else(|| {
            KaspaError::new(KaspaErrorKind::SessionError, "Session not found")
        })?;

        session.ice_gathering_complete = true;

        // Batch send all ICE candidates
        let candidates: Vec<IceCandidate> = session.local_ice_candidates.drain(..).collect();
        let count = candidates.len();

        if !candidates.is_empty() {
            let signal_type = if candidates.len() > 1 {
                SignalType::IceBatch
            } else {
                SignalType::IceCandidate
            };

            let data = if candidates.len() > 1 {
                serde_json::to_string(&candidates).unwrap()
            } else {
                serde_json::to_string(&candidates[0]).unwrap()
            };

            self.outgoing_queue.push_back(OutgoingSignal {
                peer_id: peer_id.to_string(),
                signal_type,
                data,
                session_id: session.session_id.clone(),
                created_at: current_timestamp_ms(),
            });
        }

        self.stats.ice_candidates_sent += count as u32;
        session.touch();

        Ok(())
    }

    /// Process incoming signaling message
    pub fn process_incoming(&mut self, message: &SignalingMessage) -> KaspaResult<()> {
        // Ignore our own messages
        if message.sender_peer_id == self.local_peer_id {
            return Ok(());
        }

        match message.signaling_type {
            EnvelopeType::SignalingOffer => {
                let sdp_data: SdpData = serde_json::from_str(&message.data)
                    .map_err(|e| KaspaError::serialization(e.to_string()))?;

                // Create responder session
                let session = SignalingSession::new_as_responder(
                    message.sender_peer_id.clone(),
                    sdp_data.session_id.clone(),
                );
                self.sessions.insert(message.sender_peer_id.clone(), session);

                let session = self.sessions.get_mut(&message.sender_peer_id).unwrap();
                session.remote_sdp = Some(sdp_data);
                session.touch();

                self.stats.offers_received += 1;
            }

            EnvelopeType::SignalingAnswer => {
                let sdp_data: SdpData = serde_json::from_str(&message.data)
                    .map_err(|e| KaspaError::serialization(e.to_string()))?;

                if let Some(session) = self.sessions.get_mut(&message.sender_peer_id) {
                    session.remote_sdp = Some(sdp_data);
                    session.state = SignalingState::IceExchange;
                    session.touch();
                    self.stats.answers_received += 1;
                }
            }

            EnvelopeType::SignalingIce => {
                // Try parsing as single candidate or batch
                if let Ok(candidate) = serde_json::from_str::<IceCandidate>(&message.data) {
                    if let Some(session) = self.sessions.get_mut(&message.sender_peer_id) {
                        if session.can_accept_ice() {
                            session.remote_ice_candidates.push(candidate);
                            session.touch();
                            self.stats.ice_candidates_received += 1;
                        }
                    }
                } else if let Ok(candidates) = serde_json::from_str::<Vec<IceCandidate>>(&message.data) {
                    if let Some(session) = self.sessions.get_mut(&message.sender_peer_id) {
                        if session.can_accept_ice() {
                            let count = candidates.len();
                            session.remote_ice_candidates.extend(candidates);
                            session.touch();
                            self.stats.ice_candidates_received += count as u32;
                        }
                    }
                }
            }

            _ => {}
        }

        Ok(())
    }

    /// Mark connection as established
    pub fn connection_established(&mut self, peer_id: &str) -> KaspaResult<()> {
        if let Some(session) = self.sessions.get_mut(peer_id) {
            session.state = SignalingState::Connected;
            session.touch();
            self.stats.connections_established += 1;
        }
        Ok(())
    }

    /// Mark connection as failed
    pub fn connection_failed(&mut self, peer_id: &str, _reason: &str) -> KaspaResult<()> {
        if let Some(session) = self.sessions.get_mut(peer_id) {
            session.state = SignalingState::Failed;
            session.touch();
            self.stats.connections_failed += 1;
        }
        Ok(())
    }

    /// Close a connection
    pub fn close_connection(&mut self, peer_id: &str) -> KaspaResult<()> {
        if let Some(session) = self.sessions.get_mut(peer_id) {
            session.state = SignalingState::Closed;
            session.touch();
        }
        Ok(())
    }

    /// Take outgoing signals to send
    pub fn take_outgoing_signals(&mut self) -> Vec<OutgoingSignal> {
        self.outgoing_queue.drain(..).collect()
    }

    /// Get session for peer
    pub fn get_session(&self, peer_id: &str) -> Option<&SignalingSession> {
        self.sessions.get(peer_id)
    }

    /// Get remote ICE candidates for a peer
    pub fn take_remote_ice_candidates(&mut self, peer_id: &str) -> Vec<IceCandidate> {
        if let Some(session) = self.sessions.get_mut(peer_id) {
            session.remote_ice_candidates.drain(..).collect()
        } else {
            Vec::new()
        }
    }

    /// Cleanup timed out sessions
    pub fn cleanup_timed_out(&mut self, timeout_ms: u64) {
        for session in self.sessions.values_mut() {
            if session.is_timed_out(timeout_ms) && session.state != SignalingState::Connected {
                session.state = SignalingState::Failed;
                self.stats.sessions_timed_out += 1;
            }
        }
    }

    /// Get list of active session peer IDs
    pub fn get_active_sessions(&self) -> Vec<String> {
        self.sessions
            .iter()
            .filter(|(_, s)| !matches!(s.state, SignalingState::Closed | SignalingState::Failed))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Build envelope for outgoing signal
    pub fn build_envelope(&self, signal: &OutgoingSignal) -> KaspaEnvelope {
        let envelope_type = match signal.signal_type {
            SignalType::Offer => EnvelopeType::SignalingOffer,
            SignalType::Answer => EnvelopeType::SignalingAnswer,
            SignalType::IceCandidate | SignalType::IceBatch => EnvelopeType::SignalingIce,
        };

        KaspaEnvelope::signaling(
            self.local_peer_id.clone(),
            signal.peer_id.clone(),
            envelope_type,
            signal.data.clone(),
        )
    }
}

// ============================================================================
// WASM Bindings for Global Signaling Manager
// ============================================================================

use std::cell::RefCell;

thread_local! {
    static SIGNALING_MANAGER: RefCell<Option<SignalingManager>> = RefCell::new(None);
}

/// Initialize the global signaling manager
#[wasm_bindgen]
pub fn kaspa_signaling_init() -> Result<(), JsValue> {
    // Signaling manager needs a peer_id, but we don't have it here
    // For now, create a placeholder - it should be set properly when needed
    SIGNALING_MANAGER.with(|manager| {
        *manager.borrow_mut() = Some(SignalingManager::new(String::new()));
        Ok(())
    })
}
