// Message Router
// Routes messages between peers based on PeerId

use crate::identity::{PeerId, Contact};
use crate::message::Message;
use super::protocol::{
    ProtocolMessage, MessagePayload, HandshakeMessage, HandshakeAckMessage,
    UserMessagePayload, MessageAckPayload, PingMessage, PongMessage,
    DiscoveryRequestMessage, DiscoveryResponseMessage, CloseMessage, ErrorMessage,
    PROTOCOL_VERSION, error_codes
};
use super::{NetworkResult, NetworkError};
use std::collections::HashMap;

/// Maximum message age in milliseconds (5 minutes)
const MAX_MESSAGE_AGE_MS: u64 = 300000;

/// Rate limit: max messages per peer per second
const MAX_MESSAGES_PER_SECOND: u32 = 100;

/// Message handler callbacks
pub trait MessageHandler: Send + Sync {
    /// Handle a user message (chat message)
    fn on_user_message(&mut self, from: &PeerId, message: Message);

    /// Handle peer connected event
    fn on_peer_connected(&mut self, peer_id: &PeerId, contact: Contact);

    /// Handle peer disconnected event
    fn on_peer_disconnected(&mut self, peer_id: &PeerId);

    /// Handle discovery response
    fn on_discovery_response(&mut self, peer_ids: Vec<PeerId>);
}

/// Message router for P2P network
pub struct MessageRouter {
    /// Local peer ID
    local_peer_id: PeerId,

    /// Message rate limiter (peer_id -> (count, last_reset))
    rate_limiter: HashMap<PeerId, (u32, u64)>,

    /// Known peers for discovery
    known_peers: Vec<PeerId>,
}

impl MessageRouter {
    /// Create a new message router
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            local_peer_id,
            rate_limiter: HashMap::new(),
            known_peers: Vec::new(),
        }
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Route an incoming message
    pub fn route_message(
        &mut self,
        message: ProtocolMessage,
        handler: &mut dyn MessageHandler,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        // Validate message
        self.validate_message(&message)?;

        // Check rate limit
        if !self.check_rate_limit(&message.from) {
            return Err(NetworkError::ProtocolError(
                "Rate limit exceeded".to_string()
            ));
        }

        // Route based on payload type
        match message.payload {
            MessagePayload::Handshake(handshake) => {
                self.handle_handshake(&message.from, handshake, handler)
            }
            MessagePayload::HandshakeAck(ack) => {
                self.handle_handshake_ack(&message.from, ack, handler)
            }
            MessagePayload::UserMessage(user_msg) => {
                self.handle_user_message(&message.from, user_msg, handler)
            }
            MessagePayload::MessageAck(ack) => {
                self.handle_message_ack(&message.from, ack)
            }
            MessagePayload::Ping(ping) => {
                self.handle_ping(&message.from, ping)
            }
            MessagePayload::Pong(pong) => {
                self.handle_pong(&message.from, pong)
            }
            MessagePayload::DiscoveryRequest(req) => {
                self.handle_discovery_request(&message.from, req)
            }
            MessagePayload::DiscoveryResponse(resp) => {
                self.handle_discovery_response(resp, handler)
            }
            MessagePayload::Close(close) => {
                self.handle_close(&message.from, close, handler)
            }
            MessagePayload::Error(error) => {
                self.handle_error(&message.from, error)
            }
        }
    }

    /// Validate a protocol message
    fn validate_message(&self, message: &ProtocolMessage) -> NetworkResult<()> {
        // Check protocol version
        if message.version > PROTOCOL_VERSION {
            return Err(NetworkError::ProtocolError(format!(
                "Unsupported protocol version: {}",
                message.version
            )));
        }

        // Check if message is too old
        if message.is_expired(MAX_MESSAGE_AGE_MS) {
            return Err(NetworkError::InvalidMessage(
                "Message expired".to_string()
            ));
        }

        // Check if message is for us
        if message.to != self.local_peer_id {
            return Err(NetworkError::InvalidMessage(format!(
                "Message not addressed to us (to: {}, us: {})",
                message.to.to_hex(),
                self.local_peer_id.to_hex()
            )));
        }

        Ok(())
    }

    /// Check rate limit for a peer
    fn check_rate_limit(&mut self, peer_id: &PeerId) -> bool {
        let now = js_sys::Date::now() as u64;
        let entry = self.rate_limiter.entry(peer_id.clone())
            .or_insert((0, now));

        let (count, last_reset) = entry;

        // Reset counter every second
        if now - *last_reset > 1000 {
            *count = 1;
            *last_reset = now;
            return true;
        }

        // Check limit
        if *count >= MAX_MESSAGES_PER_SECOND {
            return false;
        }

        *count += 1;
        true
    }

    /// Handle handshake message
    fn handle_handshake(
        &mut self,
        from: &PeerId,
        handshake: HandshakeMessage,
        handler: &mut dyn MessageHandler,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        // Check protocol version
        if handshake.protocol_version > PROTOCOL_VERSION {
            let error = ErrorMessage {
                code: error_codes::PROTOCOL_VERSION_MISMATCH,
                message: format!("Unsupported protocol version: {}", handshake.protocol_version),
            };

            let response = ProtocolMessage::new(
                self.local_peer_id.clone(),
                from.clone(),
                MessagePayload::Error(error)
            );

            return Ok(Some(response));
        }

        // Create contact from handshake
        let contact = Contact {
            peer_id: from.clone(),
            display_name: "Unknown".to_string(), // Will be updated later
            signing_public_key: handshake.signing_public_key,
            encryption_public_key: handshake.encryption_public_key,
            verified: false,
            added_at: js_sys::Date::now() as u64,
            last_seen: Some(js_sys::Date::now() as u64),
            notes: None,
        };

        // Notify handler
        handler.on_peer_connected(from, contact);

        // Send handshake acknowledgment
        let ack = HandshakeAckMessage {
            accepted: true,
            reason: None,
        };

        let response = ProtocolMessage::new(
            self.local_peer_id.clone(),
            from.clone(),
            MessagePayload::HandshakeAck(ack)
        );

        Ok(Some(response))
    }

    /// Handle handshake acknowledgment
    fn handle_handshake_ack(
        &mut self,
        from: &PeerId,
        ack: HandshakeAckMessage,
        _handler: &mut dyn MessageHandler,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        if ack.accepted {
            web_sys::console::log_1(&format!(
                "Handshake accepted by {}",
                from.to_hex()
            ).into());
        } else {
            web_sys::console::warn_1(&format!(
                "Handshake rejected by {}: {:?}",
                from.to_hex(),
                ack.reason
            ).into());
        }

        Ok(None)
    }

    /// Handle user message (chat message)
    fn handle_user_message(
        &mut self,
        from: &PeerId,
        user_msg: UserMessagePayload,
        handler: &mut dyn MessageHandler,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        // Notify handler
        handler.on_user_message(from, user_msg.message.clone());

        // Send acknowledgment
        let ack = MessageAckPayload {
            message_id: user_msg.message.id,
            success: true,
            error: None,
        };

        let response = ProtocolMessage::new(
            self.local_peer_id.clone(),
            from.clone(),
            MessagePayload::MessageAck(ack)
        );

        Ok(Some(response))
    }

    /// Handle message acknowledgment
    fn handle_message_ack(
        &mut self,
        from: &PeerId,
        ack: MessageAckPayload,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        if ack.success {
            web_sys::console::log_1(&format!(
                "Message {} acknowledged by {}",
                ack.message_id.to_hex(),
                from.to_hex()
            ).into());
        } else {
            web_sys::console::warn_1(&format!(
                "Message {} failed for {}: {:?}",
                ack.message_id.to_hex(),
                from.to_hex(),
                ack.error
            ).into());
        }

        Ok(None)
    }

    /// Handle ping message
    fn handle_ping(
        &mut self,
        from: &PeerId,
        ping: PingMessage,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        // Create pong response
        let pong = PongMessage::from_ping(&ping);

        let response = ProtocolMessage::new(
            self.local_peer_id.clone(),
            from.clone(),
            MessagePayload::Pong(pong)
        );

        Ok(Some(response))
    }

    /// Handle pong message
    fn handle_pong(
        &mut self,
        _from: &PeerId,
        _pong: PongMessage,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        // Pong is handled by NetworkManager directly for RTT calculation
        Ok(None)
    }

    /// Handle discovery request
    fn handle_discovery_request(
        &mut self,
        from: &PeerId,
        req: DiscoveryRequestMessage,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        // Return known peers (up to requested count)
        let count = req.count.min(50) as usize; // Cap at 50
        let peers: Vec<PeerId> = self.known_peers
            .iter()
            .filter(|p| *p != from) // Don't include requestor
            .take(count)
            .cloned()
            .collect();

        let response_payload = DiscoveryResponseMessage { peers };

        let response = ProtocolMessage::new(
            self.local_peer_id.clone(),
            from.clone(),
            MessagePayload::DiscoveryResponse(response_payload)
        );

        Ok(Some(response))
    }

    /// Handle discovery response
    fn handle_discovery_response(
        &mut self,
        resp: DiscoveryResponseMessage,
        handler: &mut dyn MessageHandler,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        // Add newly discovered peers
        for peer_id in &resp.peers {
            if !self.known_peers.contains(peer_id) {
                self.known_peers.push(peer_id.clone());
            }
        }

        // Notify handler
        handler.on_discovery_response(resp.peers);

        Ok(None)
    }

    /// Handle close message
    fn handle_close(
        &mut self,
        from: &PeerId,
        close: CloseMessage,
        handler: &mut dyn MessageHandler,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        web_sys::console::log_1(&format!(
            "Peer {} closed connection: {} (graceful: {})",
            from.to_hex(),
            close.reason,
            close.graceful
        ).into());

        // Notify handler
        handler.on_peer_disconnected(from);

        Ok(None)
    }

    /// Handle error message
    fn handle_error(
        &mut self,
        from: &PeerId,
        error: ErrorMessage,
    ) -> NetworkResult<Option<ProtocolMessage>> {
        web_sys::console::error_1(&format!(
            "Error from {}: [{}] {}",
            from.to_hex(),
            error.code,
            error.message
        ).into());

        Ok(None)
    }

    /// Add a known peer for discovery
    pub fn add_known_peer(&mut self, peer_id: PeerId) {
        if !self.known_peers.contains(&peer_id) {
            self.known_peers.push(peer_id);
        }
    }

    /// Get known peers
    pub fn known_peers(&self) -> &[PeerId] {
        &self.known_peers
    }

    /// Clear rate limiter (for testing or periodic cleanup)
    pub fn clear_rate_limiter(&mut self) {
        self.rate_limiter.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeyPair;
    use crate::message::MessageContent;

    fn create_test_peer_id() -> PeerId {
        let keypair = IdentityKeyPair::generate().unwrap();
        PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes())
    }

    struct TestHandler {
        messages: Vec<Message>,
        connected_peers: Vec<PeerId>,
        disconnected_peers: Vec<PeerId>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                messages: Vec::new(),
                connected_peers: Vec::new(),
                disconnected_peers: Vec::new(),
            }
        }
    }

    impl MessageHandler for TestHandler {
        fn on_user_message(&mut self, _from: &PeerId, message: Message) {
            self.messages.push(message);
        }

        fn on_peer_connected(&mut self, peer_id: &PeerId, _contact: Contact) {
            self.connected_peers.push(peer_id.clone());
        }

        fn on_peer_disconnected(&mut self, peer_id: &PeerId) {
            self.disconnected_peers.push(peer_id.clone());
        }

        fn on_discovery_response(&mut self, _peer_ids: Vec<PeerId>) {
            // Not tested in these basic tests
        }
    }

    #[test]
    fn test_router_creation() {
        let local_peer_id = create_test_peer_id();
        let router = MessageRouter::new(local_peer_id.clone());
        assert_eq!(*router.local_peer_id(), local_peer_id);
    }

    #[test]
    fn test_ping_pong() {
        let local_peer_id = create_test_peer_id();
        let remote_peer_id = create_test_peer_id();
        let mut router = MessageRouter::new(local_peer_id.clone());
        let mut handler = TestHandler::new();

        let ping = PingMessage::new();
        let ping_msg = ProtocolMessage::new(
            remote_peer_id.clone(),
            local_peer_id.clone(),
            MessagePayload::Ping(ping)
        );

        let response = router.route_message(ping_msg, &mut handler).unwrap();
        assert!(response.is_some());

        let resp_msg = response.unwrap();
        assert!(matches!(resp_msg.payload, MessagePayload::Pong(_)));
    }

    #[test]
    fn test_handshake() {
        let local_peer_id = create_test_peer_id();
        let remote_peer_id = create_test_peer_id();
        let mut router = MessageRouter::new(local_peer_id.clone());
        let mut handler = TestHandler::new();

        let keypair = IdentityKeyPair::generate().unwrap();
        let handshake = HandshakeMessage::new(
            keypair.signing_keypair.verifying_key.to_bytes().to_vec(),
            keypair.encryption_keypair.public_key.as_bytes().to_vec()
        );

        let msg = ProtocolMessage::new(
            remote_peer_id.clone(),
            local_peer_id.clone(),
            MessagePayload::Handshake(handshake)
        );

        let response = router.route_message(msg, &mut handler).unwrap();
        assert!(response.is_some());
        assert_eq!(handler.connected_peers.len(), 1);
    }

    #[test]
    fn test_rate_limiting() {
        let local_peer_id = create_test_peer_id();
        let remote_peer_id = create_test_peer_id();
        let mut router = MessageRouter::new(local_peer_id.clone());

        // Check rate limit works
        for _ in 0..MAX_MESSAGES_PER_SECOND {
            assert!(router.check_rate_limit(&remote_peer_id));
        }

        // Next one should fail
        assert!(!router.check_rate_limit(&remote_peer_id));
    }

    #[test]
    fn test_discovery() {
        let local_peer_id = create_test_peer_id();
        let remote_peer_id = create_test_peer_id();
        let mut router = MessageRouter::new(local_peer_id.clone());
        let mut handler = TestHandler::new();

        // Add some known peers
        router.add_known_peer(create_test_peer_id());
        router.add_known_peer(create_test_peer_id());

        let discovery_req = DiscoveryRequestMessage { count: 10 };
        let msg = ProtocolMessage::new(
            remote_peer_id.clone(),
            local_peer_id.clone(),
            MessagePayload::DiscoveryRequest(discovery_req)
        );

        let response = router.route_message(msg, &mut handler).unwrap();
        assert!(response.is_some());

        if let Some(resp_msg) = response {
            if let MessagePayload::DiscoveryResponse(resp) = resp_msg.payload {
                assert_eq!(resp.peers.len(), 2);
            } else {
                panic!("Expected discovery response");
            }
        }
    }
}
