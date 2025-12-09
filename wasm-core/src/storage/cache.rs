// Cache Management
// Centralized cache cleanup and management

use crate::storage::{
    indexed_db::IndexedDB,
    stores::PeerAddressesStore,
    StorageResult,
};

/// Cache manager for handling TTL-based cleanup
pub struct CacheManager {
    peer_addresses: PeerAddressesStore,
}

impl CacheManager {
    /// Create a new cache manager
    pub fn new(db: IndexedDB) -> Self {
        Self {
            peer_addresses: PeerAddressesStore::new(db),
        }
    }

    /// Clean up all expired cache entries
    /// Returns the total number of entries removed
    pub async fn cleanup_expired(&self, now: u64) -> StorageResult<CacheCleanupStats> {
        let peer_addresses_removed = self.peer_addresses.remove_expired(now).await?;

        Ok(CacheCleanupStats {
            peer_addresses_removed,
            total_removed: peer_addresses_removed,
        })
    }

    /// Get cache statistics
    pub async fn get_stats(&self, now: u64) -> StorageResult<CacheStats> {
        let peer_addresses_total = self.peer_addresses.count().await?;
        let peer_addresses_fresh = self.peer_addresses.count_fresh(now).await?;
        let peer_addresses_expired = peer_addresses_total - peer_addresses_fresh;

        Ok(CacheStats {
            peer_addresses_total,
            peer_addresses_fresh,
            peer_addresses_expired,
        })
    }

    /// Clear all caches (use with caution!)
    pub async fn clear_all(&self) -> StorageResult<()> {
        self.peer_addresses.clear().await?;
        Ok(())
    }

    /// Get a reference to the peer addresses store
    pub fn peer_addresses(&self) -> &PeerAddressesStore {
        &self.peer_addresses
    }
}

/// Statistics from cache cleanup operation
#[derive(Debug, Clone)]
pub struct CacheCleanupStats {
    /// Number of peer address entries removed
    pub peer_addresses_removed: u32,
    /// Total number of entries removed across all caches
    pub total_removed: u32,
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of peer address entries
    pub peer_addresses_total: u32,
    /// Number of fresh (non-expired) peer address entries
    pub peer_addresses_fresh: u32,
    /// Number of expired peer address entries
    pub peer_addresses_expired: u32,
}

impl CacheStats {
    /// Get the total number of cached entries across all caches
    pub fn total_entries(&self) -> u32 {
        self.peer_addresses_total
    }

    /// Get the total number of fresh entries across all caches
    pub fn total_fresh(&self) -> u32 {
        self.peer_addresses_fresh
    }

    /// Get the total number of expired entries across all caches
    pub fn total_expired(&self) -> u32 {
        self.peer_addresses_expired
    }

    /// Calculate the cache hit rate (percentage of fresh entries)
    pub fn hit_rate(&self) -> f64 {
        let total = self.total_entries();
        if total == 0 {
            return 0.0;
        }
        (self.total_fresh() as f64 / total as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PeerId;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_cache_manager_cleanup() {
        let db = IndexedDB::open("test_cache_manager_cleanup", 1).await.unwrap();
        let manager = CacheManager::new(db);

        let peer1 = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let peer2 = PeerId::from_hex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = 1000000;

        // Cache with different TTLs
        manager.peer_addresses()
            .cache_addresses_with_ttl(&peer1, addresses.clone(), now, 1000)
            .await
            .unwrap();

        manager.peer_addresses()
            .cache_addresses_with_ttl(&peer2, addresses.clone(), now, 100000)
            .await
            .unwrap();

        // Cleanup when peer1 is expired
        let stats = manager.cleanup_expired(now + 2000).await.unwrap();
        assert_eq!(stats.peer_addresses_removed, 1);
        assert_eq!(stats.total_removed, 1);

        // Cleanup
        manager.clear_all().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_cache_manager_stats() {
        let db = IndexedDB::open("test_cache_manager_stats", 1).await.unwrap();
        let manager = CacheManager::new(db);

        let peer1 = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let peer2 = PeerId::from_hex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").unwrap();
        let peer3 = PeerId::from_hex("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = 1000000;

        // Cache entries with different TTLs
        manager.peer_addresses()
            .cache_addresses_with_ttl(&peer1, addresses.clone(), now, 1000)
            .await
            .unwrap();

        manager.peer_addresses()
            .cache_addresses_with_ttl(&peer2, addresses.clone(), now, 2000)
            .await
            .unwrap();

        manager.peer_addresses()
            .cache_addresses_with_ttl(&peer3, addresses.clone(), now, 100000)
            .await
            .unwrap();

        // Get stats at different times
        let stats1 = manager.get_stats(now).await.unwrap();
        assert_eq!(stats1.peer_addresses_total, 3);
        assert_eq!(stats1.peer_addresses_fresh, 3);
        assert_eq!(stats1.peer_addresses_expired, 0);
        assert_eq!(stats1.hit_rate(), 100.0);

        // After peer1 expires
        let stats2 = manager.get_stats(now + 1500).await.unwrap();
        assert_eq!(stats2.peer_addresses_total, 3);
        assert_eq!(stats2.peer_addresses_fresh, 2);
        assert_eq!(stats2.peer_addresses_expired, 1);

        // After peer1 and peer2 expire
        let stats3 = manager.get_stats(now + 3000).await.unwrap();
        assert_eq!(stats3.peer_addresses_total, 3);
        assert_eq!(stats3.peer_addresses_fresh, 1);
        assert_eq!(stats3.peer_addresses_expired, 2);

        // Cleanup
        manager.clear_all().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_cache_stats_hit_rate() {
        let stats = CacheStats {
            peer_addresses_total: 10,
            peer_addresses_fresh: 7,
            peer_addresses_expired: 3,
        };

        assert_eq!(stats.hit_rate(), 70.0);

        let empty_stats = CacheStats {
            peer_addresses_total: 0,
            peer_addresses_fresh: 0,
            peer_addresses_expired: 0,
        };

        assert_eq!(empty_stats.hit_rate(), 0.0);
    }

    #[wasm_bindgen_test]
    async fn test_cache_manager_clear_all() {
        let db = IndexedDB::open("test_cache_manager_clear", 1).await.unwrap();
        let manager = CacheManager::new(db);

        let peer1 = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = 1000000;

        manager.peer_addresses()
            .cache_addresses(&peer1, addresses, now)
            .await
            .unwrap();

        assert_eq!(manager.peer_addresses().count().await.unwrap(), 1);

        manager.clear_all().await.unwrap();

        assert_eq!(manager.peer_addresses().count().await.unwrap(), 0);
    }
}
