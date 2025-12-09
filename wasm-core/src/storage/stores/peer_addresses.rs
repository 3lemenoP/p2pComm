// Peer Addresses Store
// TTL-based cache for peer connection addresses

use wasm_bindgen::JsValue;
use wasm_bindgen::JsCast;
use crate::identity::PeerId;
use crate::storage::{
    indexed_db::IndexedDB,
    types::CachedPeerAddress,
    StorageResult, StorageError,
};

/// Store for managing cached peer addresses with TTL
pub struct PeerAddressesStore {
    db: IndexedDB,
}

impl PeerAddressesStore {
    /// Create a new peer addresses store
    pub fn new(db: IndexedDB) -> Self {
        Self { db }
    }

    /// Cache addresses for a peer with default TTL (24 hours)
    pub async fn cache_addresses(
        &self,
        peer_id: &PeerId,
        addresses: Vec<String>,
        now: u64,
    ) -> StorageResult<()> {
        let cached = CachedPeerAddress::new(peer_id, addresses, now);
        self.save_cached_address(cached).await
    }

    /// Cache addresses with custom TTL (in milliseconds)
    pub async fn cache_addresses_with_ttl(
        &self,
        peer_id: &PeerId,
        addresses: Vec<String>,
        now: u64,
        ttl_ms: u64,
    ) -> StorageResult<()> {
        let cached = CachedPeerAddress::with_ttl(peer_id, addresses, now, ttl_ms);
        self.save_cached_address(cached).await
    }

    /// Internal method to save cached address
    async fn save_cached_address(&self, cached: CachedPeerAddress) -> StorageResult<()> {
        let key: JsValue = cached.peer_id.clone().into();
        let value = serde_wasm_bindgen::to_value(&cached)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        self.db.put("peer_addresses", &value, Some(&key)).await?;
        Ok(())
    }

    /// Get cached addresses for a peer (if not expired)
    pub async fn get_addresses(
        &self,
        peer_id: &PeerId,
        now: u64,
    ) -> StorageResult<Option<Vec<String>>> {
        let key: JsValue = peer_id.to_hex().into();

        match self.db.get("peer_addresses", &key).await? {
            Some(value) => {
                let cached: CachedPeerAddress = serde_wasm_bindgen::from_value(value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;

                // Check if expired
                if cached.is_expired(now) {
                    // Remove expired entry
                    self.delete_address(peer_id).await?;
                    return Ok(None);
                }

                Ok(Some(cached.addresses))
            }
            None => Ok(None),
        }
    }

    /// Get cached address object (including metadata)
    pub async fn get_cached_address(
        &self,
        peer_id: &PeerId,
    ) -> StorageResult<Option<CachedPeerAddress>> {
        let key: JsValue = peer_id.to_hex().into();

        match self.db.get("peer_addresses", &key).await? {
            Some(value) => {
                let cached: CachedPeerAddress = serde_wasm_bindgen::from_value(value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(cached))
            }
            None => Ok(None),
        }
    }

    /// Update last seen timestamp for a peer
    pub async fn update_last_seen(&self, peer_id: &PeerId, now: u64) -> StorageResult<()> {
        let mut cached = self.get_cached_address(peer_id).await?
            .ok_or(StorageError::NotFound)?;

        cached.mark_seen(now);
        self.save_cached_address(cached).await
    }

    /// Check if a cached entry is expired
    pub async fn is_expired(&self, peer_id: &PeerId, now: u64) -> StorageResult<bool> {
        match self.get_cached_address(peer_id).await? {
            Some(cached) => Ok(cached.is_expired(now)),
            None => Ok(true), // Not found = expired
        }
    }

    /// Delete cached addresses for a peer
    pub async fn delete_address(&self, peer_id: &PeerId) -> StorageResult<()> {
        let key: JsValue = peer_id.to_hex().into();
        self.db.delete("peer_addresses", &key).await?;
        Ok(())
    }

    /// Get all cached addresses (including expired ones)
    pub async fn get_all_cached(&self) -> StorageResult<Vec<CachedPeerAddress>> {
        let all = self.db.get_all("peer_addresses", None).await?;
        let mut cached_addresses = Vec::new();

        if let Ok(array) = all.dyn_into::<js_sys::Array>() {
            for i in 0..array.length() {
                let item = array.get(i);
                if let Ok(cached) = serde_wasm_bindgen::from_value::<CachedPeerAddress>(item) {
                    cached_addresses.push(cached);
                }
            }
        }

        Ok(cached_addresses)
    }

    /// Get all fresh (non-expired) cached addresses
    pub async fn get_fresh_addresses(&self, now: u64) -> StorageResult<Vec<CachedPeerAddress>> {
        let all = self.get_all_cached().await?;
        let fresh: Vec<CachedPeerAddress> = all
            .into_iter()
            .filter(|cached| !cached.is_expired(now))
            .collect();

        Ok(fresh)
    }

    /// Remove all expired entries
    pub async fn remove_expired(&self, now: u64) -> StorageResult<u32> {
        let all = self.get_all_cached().await?;
        let mut removed_count = 0;

        for cached in all {
            if cached.is_expired(now) {
                let peer_id = cached.get_peer_id()
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                self.delete_address(&peer_id).await?;
                removed_count += 1;
            }
        }

        Ok(removed_count)
    }

    /// Get recently seen peers (seen within the last N milliseconds)
    pub async fn get_recently_seen(&self, since: u64) -> StorageResult<Vec<CachedPeerAddress>> {
        let all = self.get_all_cached().await?;
        let recent: Vec<CachedPeerAddress> = all
            .into_iter()
            .filter(|cached| {
                if let Some(last_seen) = cached.last_seen {
                    last_seen >= since
                } else {
                    false
                }
            })
            .collect();

        Ok(recent)
    }

    /// Count total cached entries
    pub async fn count(&self) -> StorageResult<u32> {
        self.db.count("peer_addresses", None).await
    }

    /// Count fresh (non-expired) entries
    pub async fn count_fresh(&self, now: u64) -> StorageResult<u32> {
        let fresh = self.get_fresh_addresses(now).await?;
        Ok(fresh.len() as u32)
    }

    /// Clear all cached addresses
    pub async fn clear(&self) -> StorageResult<()> {
        self.db.clear("peer_addresses").await?;
        Ok(())
    }

    /// Extend TTL for a cached entry (add more time)
    pub async fn extend_ttl(&self, peer_id: &PeerId, additional_ms: u64) -> StorageResult<()> {
        let mut cached = self.get_cached_address(peer_id).await?
            .ok_or(StorageError::NotFound)?;

        cached.expires_at += additional_ms;
        self.save_cached_address(cached).await
    }

    /// Check if addresses are cached for a peer (regardless of expiration)
    pub async fn has_cached(&self, peer_id: &PeerId) -> StorageResult<bool> {
        Ok(self.get_cached_address(peer_id).await?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_peer_addresses_store_basic() {
        let db = IndexedDB::open("test_peer_addresses_basic", 1).await.unwrap();
        let store = PeerAddressesStore::new(db);

        let peer_id = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string(), "192.168.1.1:9090".to_string()];
        let now = 1000000;

        // Cache addresses
        store.cache_addresses(&peer_id, addresses.clone(), now).await.unwrap();

        // Get addresses (should not be expired)
        let retrieved = store.get_addresses(&peer_id, now).await.unwrap();
        assert_eq!(retrieved, Some(addresses));

        // Delete
        store.delete_address(&peer_id).await.unwrap();
        assert!(store.get_addresses(&peer_id, now).await.unwrap().is_none());

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_peer_addresses_store_ttl() {
        let db = IndexedDB::open("test_peer_addresses_ttl", 1).await.unwrap();
        let store = PeerAddressesStore::new(db);

        let peer_id = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = 1000000;
        let ttl = 5000; // 5 seconds

        // Cache with custom TTL
        store.cache_addresses_with_ttl(&peer_id, addresses.clone(), now, ttl).await.unwrap();

        // Not expired yet
        assert!(!store.is_expired(&peer_id, now + 4000).await.unwrap());

        // Expired
        assert!(store.is_expired(&peer_id, now + 6000).await.unwrap());

        // Get addresses after expiration should return None and remove entry
        let result = store.get_addresses(&peer_id, now + 6000).await.unwrap();
        assert!(result.is_none());

        // Entry should be removed
        assert!(!store.has_cached(&peer_id).await.unwrap());

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_peer_addresses_store_last_seen() {
        let db = IndexedDB::open("test_peer_addresses_last_seen", 1).await.unwrap();
        let store = PeerAddressesStore::new(db);

        let peer_id = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = 1000000;

        store.cache_addresses(&peer_id, addresses, now).await.unwrap();

        // Initially no last_seen
        let cached = store.get_cached_address(&peer_id).await.unwrap();
        assert!(cached.unwrap().last_seen.is_none());

        // Update last seen
        store.update_last_seen(&peer_id, now + 5000).await.unwrap();

        let cached2 = store.get_cached_address(&peer_id).await.unwrap();
        assert_eq!(cached2.unwrap().last_seen, Some(now + 5000));

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_peer_addresses_store_remove_expired() {
        let db = IndexedDB::open("test_peer_addresses_remove_expired", 1).await.unwrap();
        let store = PeerAddressesStore::new(db);

        let peer1 = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let peer2 = PeerId::from_hex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = 1000000;

        // Cache peer1 with short TTL
        store.cache_addresses_with_ttl(&peer1, addresses.clone(), now, 1000).await.unwrap();

        // Cache peer2 with long TTL
        store.cache_addresses_with_ttl(&peer2, addresses.clone(), now, 100000).await.unwrap();

        assert_eq!(store.count().await.unwrap(), 2);

        // Remove expired at time when peer1 is expired but peer2 is not
        let removed = store.remove_expired(now + 2000).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.count().await.unwrap(), 1);

        // Only peer2 should remain
        assert!(!store.has_cached(&peer1).await.unwrap());
        assert!(store.has_cached(&peer2).await.unwrap());

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_peer_addresses_store_fresh_count() {
        let db = IndexedDB::open("test_peer_addresses_fresh", 1).await.unwrap();
        let store = PeerAddressesStore::new(db);

        let peer1 = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let peer2 = PeerId::from_hex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = 1000000;

        // Cache both
        store.cache_addresses_with_ttl(&peer1, addresses.clone(), now, 1000).await.unwrap();
        store.cache_addresses_with_ttl(&peer2, addresses.clone(), now, 100000).await.unwrap();

        // At now, both are fresh
        assert_eq!(store.count_fresh(now).await.unwrap(), 2);

        // After peer1 expires, only 1 is fresh
        assert_eq!(store.count_fresh(now + 2000).await.unwrap(), 1);

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_peer_addresses_store_extend_ttl() {
        let db = IndexedDB::open("test_peer_addresses_extend", 1).await.unwrap();
        let store = PeerAddressesStore::new(db);

        let peer_id = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = 1000000;
        let ttl = 5000;

        store.cache_addresses_with_ttl(&peer_id, addresses, now, ttl).await.unwrap();

        // Would normally expire at now + 5000
        assert!(store.is_expired(&peer_id, now + 6000).await.unwrap());

        // Extend TTL by 10000ms
        store.extend_ttl(&peer_id, 10000).await.unwrap();

        // Now it shouldn't be expired at now + 6000
        assert!(!store.is_expired(&peer_id, now + 6000).await.unwrap());

        // But should be expired at now + 16000
        assert!(store.is_expired(&peer_id, now + 16000).await.unwrap());

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_peer_addresses_store_recently_seen() {
        let db = IndexedDB::open("test_peer_addresses_recent", 1).await.unwrap();
        let store = PeerAddressesStore::new(db);

        let peer1 = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let peer2 = PeerId::from_hex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = 1000000;

        store.cache_addresses(&peer1, addresses.clone(), now).await.unwrap();
        store.cache_addresses(&peer2, addresses.clone(), now).await.unwrap();

        // Update last seen for peer1
        store.update_last_seen(&peer1, now + 1000).await.unwrap();

        // Get recently seen (within last 2000ms from now + 1000)
        let recent = store.get_recently_seen(now - 1000).await.unwrap();
        assert_eq!(recent.len(), 1); // Only peer1

        // Cleanup
        store.clear().await.unwrap();
    }
}
