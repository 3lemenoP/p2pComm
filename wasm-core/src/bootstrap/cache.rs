// Address Cache Integration
// Integrates bootstrap with the storage layer's peer address cache

use crate::identity::PeerId;
use crate::storage::StorageManager;
use super::{PeerInfo, BootstrapMethod};

/// Bootstrap cache manager
///
/// Manages cached peer addresses from previous connections
/// Integrates with the storage layer's TTL-based peer address cache
pub struct BootstrapCache {
    storage: StorageManager,
}

impl BootstrapCache {
    /// Create a new bootstrap cache
    pub fn new(storage: StorageManager) -> Self {
        Self { storage }
    }

    /// Cache a peer's connection information after successful bootstrap
    pub async fn cache_peer(&self, peer_info: &PeerInfo) -> Result<(), String> {
        let now = js_sys::Date::now() as u64;

        // Extract addresses from connection info
        let addresses = peer_info.connection_info.direct_addresses.clone();

        // Cache with default TTL (24 hours)
        self.storage
            .cache()
            .peer_addresses()
            .cache_addresses(&peer_info.peer_id, addresses, now)
            .await
            .map_err(|e| format!("Failed to cache peer addresses: {:?}", e))?;

        Ok(())
    }

    /// Cache a peer with custom TTL
    pub async fn cache_peer_with_ttl(
        &self,
        peer_info: &PeerInfo,
        ttl_ms: u64,
    ) -> Result<(), String> {
        let now = js_sys::Date::now() as u64;
        let addresses = peer_info.connection_info.direct_addresses.clone();

        self.storage
            .cache()
            .peer_addresses()
            .cache_addresses_with_ttl(&peer_info.peer_id, addresses, now, ttl_ms)
            .await
            .map_err(|e| format!("Failed to cache peer addresses: {:?}", e))?;

        Ok(())
    }

    /// Get cached addresses for a peer
    pub async fn get_cached_addresses(&self, peer_id: &PeerId) -> Result<Option<Vec<String>>, String> {
        let now = js_sys::Date::now() as u64;

        self.storage
            .cache()
            .peer_addresses()
            .get_addresses(peer_id, now)
            .await
            .map_err(|e| format!("Failed to get cached addresses: {:?}", e))
    }

    /// Update last seen timestamp when successfully connecting to a peer
    pub async fn mark_peer_seen(&self, peer_id: &PeerId) -> Result<(), String> {
        let now = js_sys::Date::now() as u64;

        self.storage
            .cache()
            .peer_addresses()
            .update_last_seen(peer_id, now)
            .await
            .map_err(|e| format!("Failed to update last seen: {:?}", e))?;

        Ok(())
    }

    /// Get all cached peers (for reconnection attempts)
    pub async fn get_all_cached_peers(&self) -> Result<Vec<PeerId>, String> {
        let now = js_sys::Date::now() as u64;

        let cached = self.storage
            .cache()
            .peer_addresses()
            .get_fresh_addresses(now)
            .await
            .map_err(|e| format!("Failed to get cached peers: {:?}", e))?;

        // Convert to PeerIds
        let mut peer_ids = Vec::new();
        for cached_addr in cached {
            let peer_id = cached_addr.get_peer_id()
                .map_err(|e| format!("Invalid peer ID in cache: {:?}", e))?;
            peer_ids.push(peer_id);
        }

        Ok(peer_ids)
    }

    /// Get recently seen peers (within the last N milliseconds)
    pub async fn get_recently_seen_peers(&self, within_ms: u64) -> Result<Vec<PeerId>, String> {
        let now = js_sys::Date::now() as u64;
        let since = now.saturating_sub(within_ms);

        let recent = self.storage
            .cache()
            .peer_addresses()
            .get_recently_seen(since)
            .await
            .map_err(|e| format!("Failed to get recently seen peers: {:?}", e))?;

        let mut peer_ids = Vec::new();
        for cached_addr in recent {
            let peer_id = cached_addr.get_peer_id()
                .map_err(|e| format!("Invalid peer ID in cache: {:?}", e))?;
            peer_ids.push(peer_id);
        }

        Ok(peer_ids)
    }

    /// Check if a peer is in the cache
    pub async fn has_cached_peer(&self, peer_id: &PeerId) -> Result<bool, String> {
        self.storage
            .cache()
            .peer_addresses()
            .has_cached(peer_id)
            .await
            .map_err(|e| format!("Failed to check cache: {:?}", e))
    }

    /// Remove expired entries from cache
    pub async fn cleanup_expired(&self) -> Result<u32, String> {
        let now = js_sys::Date::now() as u64;

        self.storage
            .cache()
            .peer_addresses()
            .remove_expired(now)
            .await
            .map_err(|e| format!("Failed to cleanup expired entries: {:?}", e))
    }

    /// Clear all cached peer addresses
    pub async fn clear_cache(&self) -> Result<(), String> {
        self.storage
            .cache()
            .peer_addresses()
            .clear()
            .await
            .map_err(|e| format!("Failed to clear cache: {:?}", e))?;

        Ok(())
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> Result<CacheStats, String> {
        let now = js_sys::Date::now() as u64;

        let total = self.storage
            .cache()
            .peer_addresses()
            .count()
            .await
            .map_err(|e| format!("Failed to get total count: {:?}", e))?;

        let fresh = self.storage
            .cache()
            .peer_addresses()
            .count_fresh(now)
            .await
            .map_err(|e| format!("Failed to get fresh count: {:?}", e))?;

        Ok(CacheStats {
            total_entries: total,
            fresh_entries: fresh,
            expired_entries: total - fresh,
        })
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of cached entries (including expired)
    pub total_entries: u32,
    /// Number of fresh (non-expired) entries
    pub fresh_entries: u32,
    /// Number of expired entries
    pub expired_entries: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeyPair;
    use crate::bootstrap::ConnectionInfo;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    async fn create_test_storage() -> StorageManager {
        StorageManager::new("test_bootstrap_cache", "test_password".to_string())
            .await
            .unwrap()
    }

    fn create_test_peer_info() -> PeerInfo {
        let keypair = IdentityKeyPair::generate().unwrap();
        let peer_id = PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes());
        let signing_pk = keypair.signing_keypair.verifying_key.to_bytes().to_vec();
        let encryption_pk = keypair.encryption_keypair.public_key.as_bytes().to_vec();

        let mut conn_info = ConnectionInfo::new();
        conn_info.add_address("192.168.1.100:5000".to_string());
        conn_info.add_address("10.0.0.1:5001".to_string());

        PeerInfo::new(peer_id, signing_pk, encryption_pk, conn_info)
    }

    #[wasm_bindgen_test]
    async fn test_cache_peer() {
        let storage = create_test_storage().await;
        let cache = BootstrapCache::new(storage);

        let peer_info = create_test_peer_info();

        // Cache the peer
        cache.cache_peer(&peer_info).await.unwrap();

        // Verify cached
        assert!(cache.has_cached_peer(&peer_info.peer_id).await.unwrap());

        // Get cached addresses
        let addresses = cache.get_cached_addresses(&peer_info.peer_id).await.unwrap();
        assert_eq!(addresses.as_ref().unwrap().len(), 2);
        assert!(addresses.unwrap().contains(&"192.168.1.100:5000".to_string()));

        // Cleanup
        cache.clear_cache().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_mark_peer_seen() {
        let storage = create_test_storage().await;
        let cache = BootstrapCache::new(storage);

        let peer_info = create_test_peer_info();

        // Cache the peer
        cache.cache_peer(&peer_info).await.unwrap();

        // Mark as seen
        cache.mark_peer_seen(&peer_info.peer_id).await.unwrap();

        // Verify it appears in recently seen
        let recent = cache.get_recently_seen_peers(10000).await.unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0], peer_info.peer_id);

        // Cleanup
        cache.clear_cache().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_cache_stats() {
        let storage = create_test_storage().await;
        let cache = BootstrapCache::new(storage);

        let peer_info1 = create_test_peer_info();
        let peer_info2 = create_test_peer_info();

        // Cache two peers
        cache.cache_peer(&peer_info1).await.unwrap();
        cache.cache_peer(&peer_info2).await.unwrap();

        // Check stats
        let stats = cache.get_cache_stats().await.unwrap();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.fresh_entries, 2);
        assert_eq!(stats.expired_entries, 0);

        // Cleanup
        cache.clear_cache().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_get_all_cached_peers() {
        let storage = create_test_storage().await;
        let cache = BootstrapCache::new(storage);

        let peer_info1 = create_test_peer_info();
        let peer_info2 = create_test_peer_info();

        cache.cache_peer(&peer_info1).await.unwrap();
        cache.cache_peer(&peer_info2).await.unwrap();

        let cached_peers = cache.get_all_cached_peers().await.unwrap();
        assert_eq!(cached_peers.len(), 2);

        // Cleanup
        cache.clear_cache().await.unwrap();
    }
}
