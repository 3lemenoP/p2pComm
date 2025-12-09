/// WebRTC Signaling via Kaspa Blockchain
///
/// This module implements WebRTC signaling over Kaspa transactions:
/// - Create and send SDP offers/answers
/// - Handle ICE candidate exchange (trickle ICE)
/// - Manage connection state machine
/// - Queue and batch signaling messages
/// - Timeout and retry logic

use anyhow::{Result, Context, bail};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::message_extractor::{KaspaEnvelope, EnvelopeType};
use crate::message_reception::SignalingMessage;
use crate::payload_manager::{PayloadManager, MessagePriority, MessageType};

/// Signaling timeout in seconds
pub const SIGNALING_TIMEOUT: u64 = 60;

/// Maximum ICE candidates to batch together
pub const MAX_ICE_BATCH_SIZE: usize = 10;

/// ICE candidate gathering timeout in milliseconds
pub const ICE_GATHERING_TIMEOUT: u64 = 5000;

/// Connection states for WebRTC signaling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalingState {
    /// No connection attempted
    Idle,
    /// Waiting to send offer
    CreatingOffer,
    /// Offer sent, waiting for answer
    OfferSent,
    /// Received offer, creating answer
    OfferReceived,
    /// Answer sent, waiting for ICE completion
    AnswerSent,
    /// ICE candidates being exchanged
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

/// SDP (Session Description Protocol) data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpData {
    /// SDP type (offer or answer)
    pub sdp_type: SdpType,
    /// The actual SDP string
    pub sdp: String,
    /// Session ID for correlation
    pub session_id: String,
}

/// SDP types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// ICE (Interactive Connectivity Establishment) candidate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Candidate string
    pub candidate: String,
    /// SDP mid (media stream identification)
    pub sdp_mid: Option<String>,
    /// SDP m-line index
    pub sdp_m_line_index: Option<u16>,
    /// Username fragment
    pub username_fragment: Option<String>,
    /// Session ID for correlation
    pub session_id: String,
}

/// Signaling session state
#[derive(Debug, Clone)]
pub struct SignalingSession {
    /// Session ID (unique per connection attempt)
    pub session_id: String,
    /// Remote peer ID
    pub remote_peer_id: String,
    /// Current state
    pub state: SignalingState,
    /// Whether we initiated the connection
    pub is_initiator: bool,
    /// Local SDP (our offer or answer)
    pub local_sdp: Option<SdpData>,
    /// Remote SDP (their offer or answer)
    pub remote_sdp: Option<SdpData>,
    /// Local ICE candidates
    pub local_ice_candidates: Vec<IceCandidate>,
    /// Remote ICE candidates
    pub remote_ice_candidates: Vec<IceCandidate>,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Retry count
    pub retry_count: u32,
    /// ICE gathering complete flag
    pub ice_gathering_complete: bool,
}

impl SignalingSession {
    /// Create a new session as initiator
    pub fn new_as_initiator(remote_peer_id: String) -> Self {
        let session_id = Self::generate_session_id();
        let now = Utc::now();

        Self {
            session_id,
            remote_peer_id,
            state: SignalingState::CreatingOffer,
            is_initiator: true,
            local_sdp: None,
            remote_sdp: None,
            local_ice_candidates: Vec::new(),
            remote_ice_candidates: Vec::new(),
            created_at: now,
            last_activity: now,
            retry_count: 0,
            ice_gathering_complete: false,
        }
    }

    /// Create a new session as responder (received offer)
    pub fn new_as_responder(remote_peer_id: String, session_id: String) -> Self {
        let now = Utc::now();

        Self {
            session_id,
            remote_peer_id,
            state: SignalingState::OfferReceived,
            is_initiator: false,
            local_sdp: None,
            remote_sdp: None,
            local_ice_candidates: Vec::new(),
            remote_ice_candidates: Vec::new(),
            created_at: now,
            last_activity: now,
            retry_count: 0,
            ice_gathering_complete: false,
        }
    }

    /// Generate a unique session ID
    fn generate_session_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("session_{:x}", timestamp)
    }

    /// Check if session is timed out
    pub fn is_timed_out(&self, timeout_seconds: u64) -> bool {
        let elapsed = Utc::now().signed_duration_since(self.last_activity);
        elapsed.num_seconds() > timeout_seconds as i64
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Check if session can accept more ICE candidates
    pub fn can_accept_ice(&self) -> bool {
        matches!(
            self.state,
            SignalingState::OfferSent
                | SignalingState::OfferReceived
                | SignalingState::AnswerSent
                | SignalingState::IceExchange
        )
    }

    /// Get session duration in seconds
    pub fn duration_seconds(&self) -> i64 {
        Utc::now().signed_duration_since(self.created_at).num_seconds()
    }
}

/// Signaling statistics
#[derive(Debug, Clone, Default)]
pub struct SignalingStats {
    /// Total offers sent
    pub offers_sent: usize,
    /// Total offers received
    pub offers_received: usize,
    /// Total answers sent
    pub answers_sent: usize,
    /// Total answers received
    pub answers_received: usize,
    /// Total ICE candidates sent
    pub ice_candidates_sent: usize,
    /// Total ICE candidates received
    pub ice_candidates_received: usize,
    /// Connections established
    pub connections_established: usize,
    /// Connections failed
    pub connections_failed: usize,
    /// Sessions timed out
    pub sessions_timed_out: usize,
}

/// WebRTC Signaling Manager
pub struct SignalingManager {
    /// Our peer ID
    local_peer_id: String,
    /// Active sessions by remote peer ID
    sessions: Arc<Mutex<HashMap<String, SignalingSession>>>,
    /// Pending outgoing signaling messages
    outgoing_queue: Arc<Mutex<VecDeque<OutgoingSignal>>>,
    /// Statistics
    stats: Arc<Mutex<SignalingStats>>,
    /// Callback for when connection is established
    on_connected: Arc<Mutex<Option<Box<dyn Fn(&str, &str) + Send + Sync>>>>,
    /// Callback for when we need to create an offer (triggers WebRTC API)
    on_create_offer: Arc<Mutex<Option<Box<dyn Fn(&str) + Send + Sync>>>>,
    /// Callback for when we need to create an answer (triggers WebRTC API)
    on_create_answer: Arc<Mutex<Option<Box<dyn Fn(&str, &str) + Send + Sync>>>>,
    /// Callback for remote ICE candidates
    on_remote_ice: Arc<Mutex<Option<Box<dyn Fn(&str, &IceCandidate) + Send + Sync>>>>,
}

/// Outgoing signaling message
#[derive(Debug, Clone)]
pub struct OutgoingSignal {
    /// Target peer ID
    pub peer_id: String,
    /// Signal type
    pub signal_type: SignalType,
    /// Signal data (JSON)
    pub data: String,
    /// Session ID
    pub session_id: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Signal types for outgoing messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalType {
    Offer,
    Answer,
    IceCandidate,
    IceBatch,
}

impl SignalingManager {
    /// Create a new signaling manager
    pub fn new(local_peer_id: String) -> Self {
        Self {
            local_peer_id,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            outgoing_queue: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(Mutex::new(SignalingStats::default())),
            on_connected: Arc::new(Mutex::new(None)),
            on_create_offer: Arc::new(Mutex::new(None)),
            on_create_answer: Arc::new(Mutex::new(None)),
            on_remote_ice: Arc::new(Mutex::new(None)),
        }
    }

    /// Set callback for connection established
    pub fn set_on_connected<F>(&self, callback: F)
    where
        F: Fn(&str, &str) + Send + Sync + 'static,
    {
        let mut on_connected = self.on_connected.lock().unwrap();
        *on_connected = Some(Box::new(callback));
    }

    /// Set callback for create offer request
    pub fn set_on_create_offer<F>(&self, callback: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        let mut on_create_offer = self.on_create_offer.lock().unwrap();
        *on_create_offer = Some(Box::new(callback));
    }

    /// Set callback for create answer request
    pub fn set_on_create_answer<F>(&self, callback: F)
    where
        F: Fn(&str, &str) + Send + Sync + 'static,
    {
        let mut on_create_answer = self.on_create_answer.lock().unwrap();
        *on_create_answer = Some(Box::new(callback));
    }

    /// Set callback for remote ICE candidate
    pub fn set_on_remote_ice<F>(&self, callback: F)
    where
        F: Fn(&str, &IceCandidate) + Send + Sync + 'static,
    {
        let mut on_remote_ice = self.on_remote_ice.lock().unwrap();
        *on_remote_ice = Some(Box::new(callback));
    }

    /// Initiate a connection to a remote peer
    pub fn initiate_connection(&self, remote_peer_id: &str) -> Result<String> {
        let mut sessions = self.sessions.lock().unwrap();

        // Check if we already have an active session
        if let Some(existing) = sessions.get(remote_peer_id) {
            if !matches!(existing.state, SignalingState::Failed | SignalingState::Closed) {
                bail!("Active session already exists for peer {}", remote_peer_id);
            }
        }

        // Create new session
        let session = SignalingSession::new_as_initiator(remote_peer_id.to_string());
        let session_id = session.session_id.clone();

        sessions.insert(remote_peer_id.to_string(), session);

        // Trigger offer creation callback
        if let Some(ref callback) = *self.on_create_offer.lock().unwrap() {
            callback(&session_id);
        }

        log::info!("Initiated connection to peer {} with session {}", remote_peer_id, session_id);

        Ok(session_id)
    }

    /// Set the local SDP offer (called after WebRTC creates offer)
    pub fn set_local_offer(&self, remote_peer_id: &str, sdp: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions.get_mut(remote_peer_id)
            .ok_or_else(|| anyhow::anyhow!("No session for peer {}", remote_peer_id))?;

        if session.state != SignalingState::CreatingOffer {
            bail!("Invalid state for setting offer: {}", session.state);
        }

        let sdp_data = SdpData {
            sdp_type: SdpType::Offer,
            sdp: sdp.to_string(),
            session_id: session.session_id.clone(),
        };

        session.local_sdp = Some(sdp_data.clone());
        session.state = SignalingState::OfferSent;
        session.touch();

        // Queue outgoing offer
        let signal = OutgoingSignal {
            peer_id: remote_peer_id.to_string(),
            signal_type: SignalType::Offer,
            data: serde_json::to_string(&sdp_data)?,
            session_id: session.session_id.clone(),
            created_at: Utc::now(),
        };

        self.outgoing_queue.lock().unwrap().push_back(signal);

        let mut stats = self.stats.lock().unwrap();
        stats.offers_sent += 1;

        log::info!("Local offer set for peer {}", remote_peer_id);

        Ok(())
    }

    /// Set the local SDP answer (called after WebRTC creates answer)
    pub fn set_local_answer(&self, remote_peer_id: &str, sdp: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions.get_mut(remote_peer_id)
            .ok_or_else(|| anyhow::anyhow!("No session for peer {}", remote_peer_id))?;

        if session.state != SignalingState::OfferReceived {
            bail!("Invalid state for setting answer: {}", session.state);
        }

        let sdp_data = SdpData {
            sdp_type: SdpType::Answer,
            sdp: sdp.to_string(),
            session_id: session.session_id.clone(),
        };

        session.local_sdp = Some(sdp_data.clone());
        session.state = SignalingState::AnswerSent;
        session.touch();

        // Queue outgoing answer
        let signal = OutgoingSignal {
            peer_id: remote_peer_id.to_string(),
            signal_type: SignalType::Answer,
            data: serde_json::to_string(&sdp_data)?,
            session_id: session.session_id.clone(),
            created_at: Utc::now(),
        };

        self.outgoing_queue.lock().unwrap().push_back(signal);

        let mut stats = self.stats.lock().unwrap();
        stats.answers_sent += 1;

        log::info!("Local answer set for peer {}", remote_peer_id);

        Ok(())
    }

    /// Add a local ICE candidate
    pub fn add_local_ice_candidate(&self, remote_peer_id: &str, candidate: IceCandidate) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions.get_mut(remote_peer_id)
            .ok_or_else(|| anyhow::anyhow!("No session for peer {}", remote_peer_id))?;

        if !session.can_accept_ice() {
            bail!("Session not ready for ICE candidates: {}", session.state);
        }

        session.local_ice_candidates.push(candidate.clone());
        session.touch();

        // Check if we should batch or send immediately
        let should_send = session.ice_gathering_complete
            || session.local_ice_candidates.len() >= MAX_ICE_BATCH_SIZE;

        if should_send {
            self.flush_ice_candidates(session)?;
        }

        Ok(())
    }

    /// Mark ICE gathering as complete
    pub fn set_ice_gathering_complete(&self, remote_peer_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions.get_mut(remote_peer_id)
            .ok_or_else(|| anyhow::anyhow!("No session for peer {}", remote_peer_id))?;

        session.ice_gathering_complete = true;
        session.touch();

        // Flush any remaining candidates
        self.flush_ice_candidates(session)?;

        log::info!("ICE gathering complete for peer {}", remote_peer_id);

        Ok(())
    }

    /// Flush pending ICE candidates to outgoing queue
    fn flush_ice_candidates(&self, session: &mut SignalingSession) -> Result<()> {
        if session.local_ice_candidates.is_empty() {
            return Ok(());
        }

        let candidates: Vec<IceCandidate> = session.local_ice_candidates.drain(..).collect();
        let count = candidates.len();

        // Send as batch if multiple candidates
        let signal = if candidates.len() > 1 {
            OutgoingSignal {
                peer_id: session.remote_peer_id.clone(),
                signal_type: SignalType::IceBatch,
                data: serde_json::to_string(&candidates)?,
                session_id: session.session_id.clone(),
                created_at: Utc::now(),
            }
        } else {
            OutgoingSignal {
                peer_id: session.remote_peer_id.clone(),
                signal_type: SignalType::IceCandidate,
                data: serde_json::to_string(&candidates[0])?,
                session_id: session.session_id.clone(),
                created_at: Utc::now(),
            }
        };

        self.outgoing_queue.lock().unwrap().push_back(signal);

        let mut stats = self.stats.lock().unwrap();
        stats.ice_candidates_sent += count;

        Ok(())
    }

    /// Process incoming signaling message
    pub fn process_incoming(&self, message: &SignalingMessage) -> Result<()> {
        match message.signaling_type {
            EnvelopeType::SignalingOffer => {
                self.handle_remote_offer(message)?;
            }
            EnvelopeType::SignalingAnswer => {
                self.handle_remote_answer(message)?;
            }
            EnvelopeType::SignalingIce => {
                self.handle_remote_ice(message)?;
            }
            _ => {
                log::warn!("Unexpected signaling type: {:?}", message.signaling_type);
            }
        }

        Ok(())
    }

    /// Handle incoming offer
    fn handle_remote_offer(&self, message: &SignalingMessage) -> Result<()> {
        let sdp_data: SdpData = serde_json::from_str(&message.data)
            .context("Failed to parse offer SDP")?;

        let mut sessions = self.sessions.lock().unwrap();

        // Create or update session
        let session = sessions
            .entry(message.sender_peer_id.clone())
            .or_insert_with(|| {
                SignalingSession::new_as_responder(
                    message.sender_peer_id.clone(),
                    sdp_data.session_id.clone(),
                )
            });

        session.remote_sdp = Some(sdp_data.clone());
        session.state = SignalingState::OfferReceived;
        session.touch();

        let mut stats = self.stats.lock().unwrap();
        stats.offers_received += 1;

        log::info!("Received offer from peer {}", message.sender_peer_id);

        // Trigger answer creation callback
        drop(sessions); // Release lock before callback
        if let Some(ref callback) = *self.on_create_answer.lock().unwrap() {
            callback(&message.sender_peer_id, &sdp_data.sdp);
        }

        Ok(())
    }

    /// Handle incoming answer
    fn handle_remote_answer(&self, message: &SignalingMessage) -> Result<()> {
        let sdp_data: SdpData = serde_json::from_str(&message.data)
            .context("Failed to parse answer SDP")?;

        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions.get_mut(&message.sender_peer_id)
            .ok_or_else(|| anyhow::anyhow!("No session for peer {}", message.sender_peer_id))?;

        if session.state != SignalingState::OfferSent {
            bail!("Unexpected answer in state: {}", session.state);
        }

        session.remote_sdp = Some(sdp_data);
        session.state = SignalingState::IceExchange;
        session.touch();

        let mut stats = self.stats.lock().unwrap();
        stats.answers_received += 1;

        log::info!("Received answer from peer {}", message.sender_peer_id);

        Ok(())
    }

    /// Handle incoming ICE candidate(s)
    fn handle_remote_ice(&self, message: &SignalingMessage) -> Result<()> {
        // Try parsing as batch first
        let candidates: Vec<IceCandidate> = if message.data.starts_with('[') {
            serde_json::from_str(&message.data)
                .context("Failed to parse ICE candidate batch")?
        } else {
            let candidate: IceCandidate = serde_json::from_str(&message.data)
                .context("Failed to parse ICE candidate")?;
            vec![candidate]
        };

        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions.get_mut(&message.sender_peer_id)
            .ok_or_else(|| anyhow::anyhow!("No session for peer {}", message.sender_peer_id))?;

        if !session.can_accept_ice() {
            // Buffer candidates for later
            session.remote_ice_candidates.extend(candidates.clone());
        } else {
            session.remote_ice_candidates.extend(candidates.clone());
        }

        session.touch();

        let mut stats = self.stats.lock().unwrap();
        stats.ice_candidates_received += candidates.len();

        // Notify via callback
        drop(sessions); // Release lock before callbacks
        if let Some(ref callback) = *self.on_remote_ice.lock().unwrap() {
            for candidate in &candidates {
                callback(&message.sender_peer_id, candidate);
            }
        }

        log::debug!("Received {} ICE candidate(s) from peer {}",
            candidates.len(), message.sender_peer_id);

        Ok(())
    }

    /// Mark connection as established
    pub fn connection_established(&self, remote_peer_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions.get_mut(remote_peer_id)
            .ok_or_else(|| anyhow::anyhow!("No session for peer {}", remote_peer_id))?;

        session.state = SignalingState::Connected;
        session.touch();

        let session_id = session.session_id.clone();

        let mut stats = self.stats.lock().unwrap();
        stats.connections_established += 1;

        log::info!("Connection established with peer {}", remote_peer_id);

        // Notify via callback
        drop(sessions); // Release lock before callback
        if let Some(ref callback) = *self.on_connected.lock().unwrap() {
            callback(remote_peer_id, &session_id);
        }

        Ok(())
    }

    /// Mark connection as failed
    pub fn connection_failed(&self, remote_peer_id: &str, reason: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions.get_mut(remote_peer_id)
            .ok_or_else(|| anyhow::anyhow!("No session for peer {}", remote_peer_id))?;

        session.state = SignalingState::Failed;
        session.touch();

        let mut stats = self.stats.lock().unwrap();
        stats.connections_failed += 1;

        log::warn!("Connection failed with peer {}: {}", remote_peer_id, reason);

        Ok(())
    }

    /// Close a connection
    pub fn close_connection(&self, remote_peer_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();

        if let Some(session) = sessions.get_mut(remote_peer_id) {
            session.state = SignalingState::Closed;
            session.touch();
            log::info!("Connection closed with peer {}", remote_peer_id);
        }

        Ok(())
    }

    /// Get session state for a peer
    pub fn get_session_state(&self, remote_peer_id: &str) -> Option<SignalingState> {
        self.sessions.lock().unwrap()
            .get(remote_peer_id)
            .map(|s| s.state)
    }

    /// Get session info for a peer
    pub fn get_session(&self, remote_peer_id: &str) -> Option<SignalingSession> {
        self.sessions.lock().unwrap()
            .get(remote_peer_id)
            .cloned()
    }

    /// Get all active sessions
    pub fn get_active_sessions(&self) -> Vec<SignalingSession> {
        self.sessions.lock().unwrap()
            .values()
            .filter(|s| !matches!(s.state, SignalingState::Closed | SignalingState::Failed))
            .cloned()
            .collect()
    }

    /// Take pending outgoing signals
    pub fn take_outgoing_signals(&self) -> Vec<OutgoingSignal> {
        let mut queue = self.outgoing_queue.lock().unwrap();
        queue.drain(..).collect()
    }

    /// Get count of pending outgoing signals
    pub fn pending_signal_count(&self) -> usize {
        self.outgoing_queue.lock().unwrap().len()
    }

    /// Clean up timed out sessions
    pub fn cleanup_timed_out(&self, timeout_seconds: u64) {
        let mut sessions = self.sessions.lock().unwrap();
        let mut timed_out = Vec::new();

        for (peer_id, session) in sessions.iter_mut() {
            if session.is_timed_out(timeout_seconds) {
                match session.state {
                    SignalingState::Closed | SignalingState::Failed | SignalingState::Connected => {},
                    _ => {
                        session.state = SignalingState::Failed;
                        timed_out.push(peer_id.clone());
                    }
                }
            }
        }

        if !timed_out.is_empty() {
            let mut stats = self.stats.lock().unwrap();
            stats.sessions_timed_out += timed_out.len();

            log::warn!("Timed out {} signaling sessions", timed_out.len());
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> SignalingStats {
        self.stats.lock().unwrap().clone()
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> &str {
        &self.local_peer_id
    }

    /// Modify session state (for testing purposes)
    pub fn set_session_state(&self, peer_id: &str, state: SignalingState) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(peer_id) {
            session.state = state;
            session.touch();
            Ok(())
        } else {
            bail!("No session for peer {}", peer_id)
        }
    }

    /// Modify session last activity for timeout testing
    pub fn set_session_last_activity(&self, peer_id: &str, offset_seconds: i64) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(peer_id) {
            session.last_activity = Utc::now() - chrono::Duration::seconds(offset_seconds);
            Ok(())
        } else {
            bail!("No session for peer {}", peer_id)
        }
    }
}

/// Signaling message builder for Kaspa transactions
pub struct SignalingMessageBuilder {
    local_peer_id: String,
}

impl SignalingMessageBuilder {
    /// Create a new builder
    pub fn new(local_peer_id: String) -> Self {
        Self { local_peer_id }
    }

    /// Build a KaspaEnvelope for an outgoing signal
    pub fn build_envelope(&self, signal: &OutgoingSignal) -> KaspaEnvelope {
        let envelope_type = match signal.signal_type {
            SignalType::Offer => EnvelopeType::SignalingOffer,
            SignalType::Answer => EnvelopeType::SignalingAnswer,
            SignalType::IceCandidate | SignalType::IceBatch => EnvelopeType::SignalingIce,
        };

        let mut envelope = KaspaEnvelope::new(
            envelope_type,
            self.local_peer_id.clone(),
            signal.peer_id.clone(),
            signal.data.as_bytes().to_vec(),
        );

        envelope.message_id = Some(format!("{}:{}", signal.session_id, signal.created_at.timestamp_millis()));

        envelope
    }

    /// Queue signaling message via payload manager
    pub fn queue_via_payload_manager(
        &self,
        signal: &OutgoingSignal,
        payload_manager: &PayloadManager,
    ) -> Result<String> {
        // Signaling messages get high priority
        let priority = match signal.signal_type {
            SignalType::Offer | SignalType::Answer => MessagePriority::Critical,
            SignalType::IceCandidate | SignalType::IceBatch => MessagePriority::High,
        };

        let message_id = payload_manager.queue_message(
            signal.peer_id.clone(),
            signal.data.clone().into_bytes(),
            MessageType::Signaling,
            priority,
        )?;

        Ok(message_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signaling_state_display() {
        assert_eq!(format!("{}", SignalingState::Idle), "idle");
        assert_eq!(format!("{}", SignalingState::OfferSent), "offer_sent");
        assert_eq!(format!("{}", SignalingState::Connected), "connected");
    }

    #[test]
    fn test_session_creation_initiator() {
        let session = SignalingSession::new_as_initiator("remote_peer".to_string());

        assert!(session.is_initiator);
        assert_eq!(session.state, SignalingState::CreatingOffer);
        assert!(session.session_id.starts_with("session_"));
        assert!(session.local_ice_candidates.is_empty());
    }

    #[test]
    fn test_session_creation_responder() {
        let session = SignalingSession::new_as_responder(
            "remote_peer".to_string(),
            "session_abc123".to_string(),
        );

        assert!(!session.is_initiator);
        assert_eq!(session.state, SignalingState::OfferReceived);
        assert_eq!(session.session_id, "session_abc123");
    }

    #[test]
    fn test_signaling_manager_creation() {
        let manager = SignalingManager::new("local_peer_123".to_string());

        assert_eq!(manager.local_peer_id(), "local_peer_123");
        assert_eq!(manager.pending_signal_count(), 0);
    }

    #[test]
    fn test_initiate_connection() {
        let manager = SignalingManager::new("local_peer".to_string());

        let session_id = manager.initiate_connection("remote_peer").unwrap();

        assert!(session_id.starts_with("session_"));

        let state = manager.get_session_state("remote_peer");
        assert_eq!(state, Some(SignalingState::CreatingOffer));
    }

    #[test]
    fn test_set_local_offer() {
        let manager = SignalingManager::new("local_peer".to_string());

        manager.initiate_connection("remote_peer").unwrap();
        manager.set_local_offer("remote_peer", "v=0\r\no=...").unwrap();

        let state = manager.get_session_state("remote_peer");
        assert_eq!(state, Some(SignalingState::OfferSent));

        // Check outgoing signal was queued
        let signals = manager.take_outgoing_signals();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].signal_type, SignalType::Offer);
    }

    #[test]
    fn test_duplicate_initiation_rejected() {
        let manager = SignalingManager::new("local_peer".to_string());

        manager.initiate_connection("remote_peer").unwrap();

        // Second initiation should fail
        let result = manager.initiate_connection("remote_peer");
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_remote_offer() {
        let manager = SignalingManager::new("local_peer".to_string());

        let sdp_data = SdpData {
            sdp_type: SdpType::Offer,
            sdp: "v=0\r\no=...".to_string(),
            session_id: "session_remote".to_string(),
        };

        let message = SignalingMessage {
            sender_peer_id: "remote_peer".to_string(),
            signaling_type: EnvelopeType::SignalingOffer,
            data: serde_json::to_string(&sdp_data).unwrap(),
            timestamp: Utc::now().timestamp_millis() as u64,
        };

        manager.process_incoming(&message).unwrap();

        let state = manager.get_session_state("remote_peer");
        assert_eq!(state, Some(SignalingState::OfferReceived));

        let stats = manager.get_stats();
        assert_eq!(stats.offers_received, 1);
    }

    #[test]
    fn test_ice_candidate_flow() {
        let manager = SignalingManager::new("local_peer".to_string());

        // Set up session
        manager.initiate_connection("remote_peer").unwrap();
        manager.set_local_offer("remote_peer", "v=0\r\no=...").unwrap();

        // Clear the offer signal
        manager.take_outgoing_signals();

        // Add ICE candidates
        for i in 0..5 {
            let candidate = IceCandidate {
                candidate: format!("candidate:{}", i),
                sdp_mid: Some("0".to_string()),
                sdp_m_line_index: Some(0),
                username_fragment: None,
                session_id: "session_1".to_string(),
            };
            manager.add_local_ice_candidate("remote_peer", candidate).unwrap();
        }

        // Mark gathering complete
        manager.set_ice_gathering_complete("remote_peer").unwrap();

        // Check candidates were flushed
        let signals = manager.take_outgoing_signals();
        assert!(!signals.is_empty());

        let stats = manager.get_stats();
        assert_eq!(stats.ice_candidates_sent, 5);
    }

    #[test]
    fn test_connection_lifecycle() {
        let manager = SignalingManager::new("local_peer".to_string());

        manager.initiate_connection("remote_peer").unwrap();
        assert_eq!(manager.get_session_state("remote_peer"), Some(SignalingState::CreatingOffer));

        manager.set_local_offer("remote_peer", "v=0...").unwrap();
        assert_eq!(manager.get_session_state("remote_peer"), Some(SignalingState::OfferSent));

        manager.connection_established("remote_peer").unwrap();
        assert_eq!(manager.get_session_state("remote_peer"), Some(SignalingState::Connected));

        let stats = manager.get_stats();
        assert_eq!(stats.connections_established, 1);

        manager.close_connection("remote_peer").unwrap();
        assert_eq!(manager.get_session_state("remote_peer"), Some(SignalingState::Closed));
    }

    #[test]
    fn test_session_timeout() {
        let manager = SignalingManager::new("local_peer".to_string());

        manager.initiate_connection("remote_peer").unwrap();

        // Manually set last_activity to past (simulating timeout)
        {
            let mut sessions = manager.sessions.lock().unwrap();
            if let Some(session) = sessions.get_mut("remote_peer") {
                session.last_activity = Utc::now() - chrono::Duration::seconds(120);
            }
        }

        // Cleanup timed out sessions
        manager.cleanup_timed_out(60);

        assert_eq!(manager.get_session_state("remote_peer"), Some(SignalingState::Failed));

        let stats = manager.get_stats();
        assert_eq!(stats.sessions_timed_out, 1);
    }

    #[test]
    fn test_signaling_message_builder() {
        let builder = SignalingMessageBuilder::new("local_peer".to_string());

        let signal = OutgoingSignal {
            peer_id: "remote_peer".to_string(),
            signal_type: SignalType::Offer,
            data: r#"{"sdp":"v=0..."}"#.to_string(),
            session_id: "session_123".to_string(),
            created_at: Utc::now(),
        };

        let envelope = builder.build_envelope(&signal);

        assert_eq!(envelope.envelope_type, EnvelopeType::SignalingOffer);
        assert_eq!(envelope.sender_peer_id, "local_peer");
        assert_eq!(envelope.recipient_peer_id, "remote_peer");
        assert!(envelope.message_id.is_some());
    }

    #[test]
    fn test_sdp_data_serialization() {
        let sdp = SdpData {
            sdp_type: SdpType::Offer,
            sdp: "v=0\r\no=- 123 1 IN IP4 0.0.0.0\r\n".to_string(),
            session_id: "session_xyz".to_string(),
        };

        let json = serde_json::to_string(&sdp).unwrap();
        let restored: SdpData = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.sdp_type, SdpType::Offer);
        assert_eq!(restored.session_id, "session_xyz");
    }

    #[test]
    fn test_ice_candidate_serialization() {
        let candidate = IceCandidate {
            candidate: "candidate:1 1 UDP 2122252543 192.168.1.1 12345 typ host".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_m_line_index: Some(0),
            username_fragment: Some("abc123".to_string()),
            session_id: "session_xyz".to_string(),
        };

        let json = serde_json::to_string(&candidate).unwrap();
        let restored: IceCandidate = serde_json::from_str(&json).unwrap();

        assert!(restored.candidate.contains("UDP"));
        assert_eq!(restored.sdp_mid, Some("0".to_string()));
    }

    #[test]
    fn test_active_sessions_filter() {
        let manager = SignalingManager::new("local_peer".to_string());

        manager.initiate_connection("peer1").unwrap();
        manager.initiate_connection("peer2").unwrap();
        manager.initiate_connection("peer3").unwrap();

        // Close one connection
        manager.close_connection("peer2").unwrap();

        let active = manager.get_active_sessions();
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_can_accept_ice_states() {
        let session = SignalingSession::new_as_initiator("peer".to_string());

        // CreatingOffer cannot accept ICE
        assert!(!session.can_accept_ice());

        let mut session = SignalingSession::new_as_initiator("peer".to_string());
        session.state = SignalingState::OfferSent;
        assert!(session.can_accept_ice());

        session.state = SignalingState::IceExchange;
        assert!(session.can_accept_ice());

        session.state = SignalingState::Connected;
        assert!(!session.can_accept_ice());
    }
}
