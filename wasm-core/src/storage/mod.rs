// Storage Module
// Handles local data persistence with IndexedDB

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

pub mod indexed_db;
pub mod encryption;
pub mod types;
pub mod stores;
pub mod cache;

/// Storage error types
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database not initialized")]
    NotInitialized,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Item not found")]
    NotFound,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Schema migration failed: {0}")]
    MigrationError(String),

    #[error("Invalid data format: {0}")]
    InvalidData(String),
}

pub type StorageResult<T> = Result<T, StorageError>;

use indexed_db::IndexedDB;
use stores::*;
use cache::CacheManager;

/// Unified storage manager providing access to all stores
pub struct StorageManager {
    db: IndexedDB,
    settings: SettingsStore,
    contacts: ContactsStore,
    identity: IdentityStore,
    messages: MessagesStore,
    conversations: ConversationsStore,
    cache: CacheManager,
}

impl StorageManager {
    /// Initialize the storage manager
    ///
    /// # Arguments
    /// * `db_name` - Name of the IndexedDB database
    /// * `message_password` - Password for encrypting messages
    pub async fn new(db_name: &str, message_password: String) -> StorageResult<Self> {
        let db = IndexedDB::open(db_name, 1).await?;

        Ok(Self {
            settings: SettingsStore::new(db.clone()),
            contacts: ContactsStore::new(db.clone()),
            identity: IdentityStore::new(db.clone()),
            messages: MessagesStore::new(db.clone(), message_password),
            conversations: ConversationsStore::new(db.clone()),
            cache: CacheManager::new(db.clone()),
            db,
        })
    }

    /// Get the settings store
    pub fn settings(&self) -> &SettingsStore {
        &self.settings
    }

    /// Get the contacts store
    pub fn contacts(&self) -> &ContactsStore {
        &self.contacts
    }

    /// Get the identity store
    pub fn identity(&self) -> &IdentityStore {
        &self.identity
    }

    /// Get the messages store
    pub fn messages(&self) -> &MessagesStore {
        &self.messages
    }

    /// Get the conversations store
    pub fn conversations(&self) -> &ConversationsStore {
        &self.conversations
    }

    /// Get the cache manager
    pub fn cache(&self) -> &CacheManager {
        &self.cache
    }

    /// Get the underlying database
    pub fn db(&self) -> &IndexedDB {
        &self.db
    }

    /// Clean up expired cache entries
    /// Should be called periodically (e.g., on app startup or at intervals)
    pub async fn cleanup_expired_caches(&self) -> StorageResult<cache::CacheCleanupStats> {
        let now = js_sys::Date::now() as u64;
        self.cache.cleanup_expired(now).await
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> StorageResult<cache::CacheStats> {
        let now = js_sys::Date::now() as u64;
        self.cache.get_stats(now).await
    }

    /// Clear all data (use with extreme caution!)
    /// This will delete all user data including identity, messages, and contacts
    pub async fn clear_all_data(&self) -> StorageResult<()> {
        self.settings.clear().await?;
        self.contacts.clear().await?;
        self.identity.clear().await?;
        self.messages.clear().await?;
        self.conversations.clear().await?;
        self.cache.clear_all().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_storage_manager_initialization() {
        let manager = StorageManager::new("test_storage_manager", "test_password".to_string())
            .await
            .unwrap();

        // Verify all stores are accessible
        assert_eq!(manager.settings().count().await.unwrap(), 0);
        assert_eq!(manager.contacts().count().await.unwrap(), 0);
        assert!(!manager.identity().has_identity().await.unwrap());
        assert_eq!(manager.messages().count_messages().await.unwrap(), 0);
        assert_eq!(manager.conversations().count().await.unwrap(), 0);

        // Cleanup
        manager.clear_all_data().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_storage_manager_settings() {
        let manager = StorageManager::new("test_storage_settings", "test_password".to_string())
            .await
            .unwrap();

        // Test settings operations
        manager.settings()
            .set_string("theme", "dark".to_string())
            .await
            .unwrap();

        let theme = manager.settings()
            .get_string("theme", "light")
            .await
            .unwrap();

        assert_eq!(theme, "dark");

        // Cleanup
        manager.clear_all_data().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_storage_manager_cache_cleanup() {
        let manager = StorageManager::new("test_storage_cache", "test_password".to_string())
            .await
            .unwrap();

        use crate::identity::PeerId;

        let peer_id = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let addresses = vec!["127.0.0.1:8080".to_string()];
        let now = js_sys::Date::now() as u64;

        // Cache with short TTL
        manager.cache()
            .peer_addresses()
            .cache_addresses_with_ttl(&peer_id, addresses, now, 1)
            .await
            .unwrap();

        // Wait a bit for expiration (in real scenario)
        // For test purposes, we'll use manual time advancement
        // In production, this would be called periodically

        // Get stats before cleanup
        let stats_before = manager.get_cache_stats().await.unwrap();
        assert!(stats_before.peer_addresses_total > 0);

        // Cleanup with future timestamp
        let future_time = now + 1000;
        let cleanup_stats = manager.cache().cleanup_expired(future_time).await.unwrap();
        assert!(cleanup_stats.total_removed > 0);

        // Cleanup
        manager.clear_all_data().await.unwrap();
    }
}
