// Reconnection Logic
// Handles automatic reconnection with exponential backoff
// Includes per-peer state tracking and jitter to prevent thundering herd

use crate::identity::PeerId;
use std::collections::HashMap;

/// Reconnection strategy with exponential backoff
pub struct ReconnectionManager {
    max_retries: u32,
    base_delay_ms: u64,
}

impl ReconnectionManager {
    pub fn new(max_retries: u32, base_delay_ms: u64) -> Self {
        Self {
            max_retries,
            base_delay_ms,
        }
    }

    /// Calculate delay for next reconnection attempt
    pub fn calculate_delay(&self, attempt: u32) -> u64 {
        if attempt >= self.max_retries {
            return 0;
        }

        // Exponential backoff: base_delay * 2^attempt
        let multiplier = 2_u64.pow(attempt);
        self.base_delay_ms * multiplier
    }

    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }
}

impl Default for ReconnectionManager {
    fn default() -> Self {
        // Default: 5 retries, starting with 1 second delay
        Self::new(5, 1000)
    }
}

/// Per-peer reconnection state
#[derive(Debug, Clone)]
pub(crate) struct PeerReconnectionState {
    /// Number of reconnection attempts
    pub(crate) attempts: u32,

    /// Last attempt timestamp (milliseconds)
    pub(crate) last_attempt: u64,

    /// Next scheduled attempt timestamp (milliseconds)
    pub(crate) next_attempt: u64,

    /// Last failure reason
    pub(crate) last_failure: Option<String>,

    /// Total failures for this peer
    pub(crate) total_failures: u32,
}

impl PeerReconnectionState {
    fn new() -> Self {
        Self {
            attempts: 0,
            last_attempt: 0,
            next_attempt: 0,
            last_failure: None,
            total_failures: 0,
        }
    }
}

/// Enhanced reconnection manager with per-peer state tracking and jitter
pub struct EnhancedReconnectionManager {
    /// Base reconnection manager
    base: ReconnectionManager,

    /// Per-peer reconnection states (pub for testing)
    pub(crate) peer_states: HashMap<PeerId, PeerReconnectionState>,

    /// Maximum age for state entries (milliseconds) - 1 hour
    max_state_age_ms: u64,
}

impl EnhancedReconnectionManager {
    /// Create a new enhanced reconnection manager
    pub fn new(max_retries: u32, base_delay_ms: u64) -> Self {
        Self {
            base: ReconnectionManager::new(max_retries, base_delay_ms),
            peer_states: HashMap::new(),
            max_state_age_ms: 3600000, // 1 hour
        }
    }

    /// Schedule a reconnection for a peer
    pub fn schedule_reconnect(&mut self, peer_id: &PeerId, reason: String) {
        let now = js_sys::Date::now() as u64;
        let state = self.peer_states.entry(peer_id.clone()).or_insert_with(PeerReconnectionState::new);

        // Calculate base delay with exponential backoff
        let base_delay = self.base.calculate_delay(state.attempts);

        if base_delay == 0 {
            // Max retries reached
            web_sys::console::warn_1(&format!(
                "Max reconnection attempts reached for {}",
                peer_id.to_hex()
            ).into());
            return;
        }

        // Add jitter: delay * (0.5 + random(0.5))
        // This spreads reconnection attempts between 50% and 100% of base delay
        let jitter_factor = 0.5 + (js_sys::Math::random() * 0.5);
        let jittered_delay = (base_delay as f64 * jitter_factor) as u64;

        state.last_attempt = now;
        state.next_attempt = now + jittered_delay;
        state.last_failure = Some(reason);
        state.attempts += 1;
        state.total_failures += 1;

        web_sys::console::log_1(&format!(
            "Scheduled reconnection for {} in {}ms (attempt {})",
            peer_id.to_hex(),
            jittered_delay,
            state.attempts
        ).into());
    }

    /// Check if we should attempt reconnection now
    pub fn should_attempt_now(&self, peer_id: &PeerId) -> bool {
        if let Some(state) = self.peer_states.get(peer_id) {
            let now = js_sys::Date::now() as u64;

            // Check if enough time has passed
            if now >= state.next_attempt {
                return true;
            }
        }

        false
    }

    /// Record successful reconnection
    pub fn record_success(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.peer_states.get_mut(peer_id) {
            web_sys::console::log_1(&format!(
                "Reconnection successful for {} after {} attempts",
                peer_id.to_hex(),
                state.attempts
            ).into());

            // Reset attempts but keep total_failures for statistics
            state.attempts = 0;
            state.last_failure = None;
        }
    }

    /// Record failed reconnection attempt
    pub fn record_failure(&mut self, peer_id: &PeerId, reason: String) {
        self.schedule_reconnect(peer_id, reason);
    }

    /// Get next attempt time for a peer
    pub fn get_next_attempt_time(&self, peer_id: &PeerId) -> Option<u64> {
        self.peer_states.get(peer_id).map(|s| s.next_attempt)
    }

    /// Get number of attempts for a peer
    pub fn get_attempts(&self, peer_id: &PeerId) -> u32 {
        self.peer_states.get(peer_id).map(|s| s.attempts).unwrap_or(0)
    }

    /// Get total failures for a peer
    pub fn get_total_failures(&self, peer_id: &PeerId) -> u32 {
        self.peer_states.get(peer_id).map(|s| s.total_failures).unwrap_or(0)
    }

    /// Clear state for a specific peer
    pub fn clear_peer(&mut self, peer_id: &PeerId) {
        self.peer_states.remove(peer_id);
    }

    /// Clean up old state entries
    pub fn cleanup_old_states(&mut self) -> usize {
        let now = js_sys::Date::now() as u64;
        let max_age = self.max_state_age_ms;

        let mut to_remove = Vec::new();

        for (peer_id, state) in self.peer_states.iter() {
            // Remove states older than max_state_age_ms
            if now - state.last_attempt > max_age {
                to_remove.push(peer_id.clone());
            }
        }

        let count = to_remove.len();
        for peer_id in to_remove {
            self.peer_states.remove(&peer_id);
        }

        if count > 0 {
            web_sys::console::log_1(&format!(
                "Cleaned up {} old reconnection states",
                count
            ).into());
        }

        count
    }

    /// Get statistics about reconnection states
    pub fn get_stats(&self) -> ReconnectionStats {
        let mut stats = ReconnectionStats {
            total_peers: self.peer_states.len(),
            active_reconnections: 0,
            total_attempts: 0,
            total_failures: 0,
        };

        let now = js_sys::Date::now() as u64;

        for state in self.peer_states.values() {
            if state.next_attempt > now {
                stats.active_reconnections += 1;
            }
            stats.total_attempts += state.attempts as usize;
            stats.total_failures += state.total_failures as usize;
        }

        stats
    }
}

impl Default for EnhancedReconnectionManager {
    fn default() -> Self {
        Self::new(5, 1000)
    }
}

/// Reconnection statistics
#[derive(Debug, Clone)]
pub struct ReconnectionStats {
    pub total_peers: usize,
    pub active_reconnections: usize,
    pub total_attempts: usize,
    pub total_failures: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconnection_delay_calculation() {
        let manager = ReconnectionManager::new(5, 1000);

        assert_eq!(manager.calculate_delay(0), 1000);   // 1s
        assert_eq!(manager.calculate_delay(1), 2000);   // 2s
        assert_eq!(manager.calculate_delay(2), 4000);   // 4s
        assert_eq!(manager.calculate_delay(3), 8000);   // 8s
        assert_eq!(manager.calculate_delay(4), 16000);  // 16s
        assert_eq!(manager.calculate_delay(5), 0);      // Max retries exceeded
    }

    #[test]
    fn test_reconnection_manager_defaults() {
        let manager = ReconnectionManager::default();

        assert_eq!(manager.max_retries(), 5);
        assert_eq!(manager.calculate_delay(0), 1000);
    }

    fn create_test_peer_id() -> PeerId {
        use crate::crypto::IdentityKeyPair;
        let keypair = IdentityKeyPair::generate().unwrap();
        PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes())
    }

    #[test]
    fn test_enhanced_reconnection_with_jitter() {
        let mut manager = EnhancedReconnectionManager::new(5, 1000);
        let peer_id = create_test_peer_id();

        // Schedule first reconnection
        manager.schedule_reconnect(&peer_id, "Test failure".to_string());

        // Check that state was created
        assert_eq!(manager.get_attempts(&peer_id), 1);
        assert_eq!(manager.get_total_failures(&peer_id), 1);

        // Get next attempt time
        let next_attempt = manager.get_next_attempt_time(&peer_id).unwrap();
        let now = js_sys::Date::now() as u64;

        // Jitter should make delay between 50% and 100% of base delay (1000ms)
        // So next_attempt should be between now+500 and now+1000
        assert!(next_attempt >= now + 500, "Next attempt too soon");
        assert!(next_attempt <= now + 1000, "Next attempt too late");

        // Schedule multiple reconnections to test jitter distribution
        let peer2 = create_test_peer_id();
        let peer3 = create_test_peer_id();

        manager.schedule_reconnect(&peer2, "Test".to_string());
        manager.schedule_reconnect(&peer3, "Test".to_string());

        let time2 = manager.get_next_attempt_time(&peer2).unwrap();
        let time3 = manager.get_next_attempt_time(&peer3).unwrap();

        // Due to jitter, these should likely be different
        // (though they could theoretically be the same)
        // At minimum, they should both be in valid range
        assert!(time2 >= now + 500);
        assert!(time3 >= now + 500);
    }

    #[test]
    fn test_per_peer_state_tracking() {
        let mut manager = EnhancedReconnectionManager::new(5, 1000);
        let peer1 = create_test_peer_id();
        let peer2 = create_test_peer_id();

        // Schedule reconnections for both peers
        manager.schedule_reconnect(&peer1, "Failure 1".to_string());
        manager.schedule_reconnect(&peer1, "Failure 2".to_string());
        manager.schedule_reconnect(&peer2, "Failure A".to_string());

        // Check individual peer states
        assert_eq!(manager.get_attempts(&peer1), 2);
        assert_eq!(manager.get_total_failures(&peer1), 2);
        assert_eq!(manager.get_attempts(&peer2), 1);
        assert_eq!(manager.get_total_failures(&peer2), 1);

        // Record success for peer1
        manager.record_success(&peer1);
        assert_eq!(manager.get_attempts(&peer1), 0);
        assert_eq!(manager.get_total_failures(&peer1), 2); // Total failures preserved

        // Peer2 should be unaffected
        assert_eq!(manager.get_attempts(&peer2), 1);

        // Clear peer2
        manager.clear_peer(&peer2);
        assert_eq!(manager.get_attempts(&peer2), 0);

        // Get statistics
        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 1); // Only peer1 remains
    }

    #[test]
    fn test_cleanup_old_states() {
        let mut manager = EnhancedReconnectionManager::new(5, 1000);
        manager.max_state_age_ms = 100; // Set very short max age for testing

        let peer1 = create_test_peer_id();
        let peer2 = create_test_peer_id();

        // Schedule reconnections
        manager.schedule_reconnect(&peer1, "Old failure".to_string());

        // Wait a bit (in real tests this would be longer)
        // For unit tests, we'll manually set the last_attempt to an old time
        if let Some(state) = manager.peer_states.get_mut(&peer1) {
            state.last_attempt = 0; // Very old
        }

        // Add a new peer
        manager.schedule_reconnect(&peer2, "Recent failure".to_string());

        // Cleanup should remove peer1 but not peer2
        let removed = manager.cleanup_old_states();
        assert_eq!(removed, 1);

        // Check that peer1 is gone but peer2 remains
        assert_eq!(manager.get_attempts(&peer1), 0);
        assert_eq!(manager.get_attempts(&peer2), 1);

        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 1);
    }

    #[test]
    fn test_should_attempt_now() {
        let mut manager = EnhancedReconnectionManager::new(5, 1000);
        let peer_id = create_test_peer_id();

        // No state yet
        assert!(!manager.should_attempt_now(&peer_id));

        // Schedule reconnection
        manager.schedule_reconnect(&peer_id, "Test".to_string());

        // Should not be ready immediately (jitter adds at least 500ms)
        assert!(!manager.should_attempt_now(&peer_id));

        // Manually set next_attempt to past
        if let Some(state) = manager.peer_states.get_mut(&peer_id) {
            state.next_attempt = 0; // In the past
        }

        // Now it should be ready
        assert!(manager.should_attempt_now(&peer_id));
    }

    #[test]
    fn test_exponential_backoff_with_max_retries() {
        let mut manager = EnhancedReconnectionManager::new(3, 1000); // Only 3 retries
        let peer_id = create_test_peer_id();

        // First 3 attempts should work
        for i in 0..3 {
            manager.schedule_reconnect(&peer_id, format!("Failure {}", i + 1));
            assert_eq!(manager.get_attempts(&peer_id), i + 1);
        }

        // 4th attempt should hit max retries
        let initial_attempts = manager.get_attempts(&peer_id);
        manager.schedule_reconnect(&peer_id, "Failure 4".to_string());

        // Attempts should not increase beyond max
        assert_eq!(manager.get_attempts(&peer_id), initial_attempts);
    }
}
