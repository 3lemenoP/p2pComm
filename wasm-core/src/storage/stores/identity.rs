// Identity Store
// Manages the user's encrypted identity (private keys)

use wasm_bindgen::JsValue;
use wasm_bindgen::JsCast;
use crate::identity::{Identity, PeerId};
use crate::storage::{
    indexed_db::IndexedDB,
    encryption::{encrypt_for_storage, decrypt_from_storage, verify_password as verify_pwd},
    types::StoredIdentity,
    StorageResult, StorageError,
};

/// Store for managing the user's identity
/// Identity contains private keys and is always encrypted at rest
pub struct IdentityStore {
    db: IndexedDB,
}

impl IdentityStore {
    /// Create a new identity store
    pub fn new(db: IndexedDB) -> Self {
        Self { db }
    }

    /// Save a new identity (encrypted with password)
    /// This will fail if an identity already exists
    pub async fn create_identity(&self, identity: Identity, password: &str) -> StorageResult<()> {
        // Check if identity already exists
        if self.has_identity().await? {
            return Err(StorageError::InvalidData(
                "Identity already exists. Delete existing identity first.".to_string()
            ));
        }

        self.save_identity(identity, password).await
    }

    /// Update an existing identity (requires correct password)
    pub async fn update_identity(&self, identity: Identity, password: &str) -> StorageResult<()> {
        // Verify password first by trying to decrypt existing identity
        if !self.verify_password(password).await? {
            return Err(StorageError::InvalidPassword);
        }

        self.save_identity(identity, password).await
    }

    /// Internal method to save identity with encryption
    async fn save_identity(&self, identity: Identity, password: &str) -> StorageResult<()> {
        let peer_id = identity.peer_id.clone();
        let created_at = identity.created_at;

        // Encrypt the identity
        let encrypted_data = encrypt_for_storage(&identity, password)?;

        // Create stored wrapper
        let stored = StoredIdentity::new(&peer_id, encrypted_data, created_at);

        let key: JsValue = stored.peer_id.clone().into();
        let value = serde_wasm_bindgen::to_value(&stored)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        self.db.put("identity", &value, Some(&key)).await?;
        Ok(())
    }

    /// Get the user's identity (decrypted with password)
    pub async fn get_identity(&self, password: &str) -> StorageResult<Option<Identity>> {
        // Get all identities (should only be one)
        let all = self.db.get_all("identity", None).await?;

        if let Ok(array) = all.dyn_into::<js_sys::Array>() {
            if array.length() == 0 {
                return Ok(None);
            }

            // Get the first (and should be only) identity
            let item = array.get(0);
            let stored: StoredIdentity = serde_wasm_bindgen::from_value(item)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;

            // Decrypt the identity
            let identity = decrypt_from_storage::<Identity>(&stored.encrypted_data, password)?;
            return Ok(Some(identity));
        }

        Ok(None)
    }

    /// Get identity by peer ID (requires password)
    pub async fn get_identity_by_id(&self, peer_id: &PeerId, password: &str) -> StorageResult<Option<Identity>> {
        let key: JsValue = peer_id.to_hex().into();

        match self.db.get("identity", &key).await? {
            Some(value) => {
                let stored: StoredIdentity = serde_wasm_bindgen::from_value(value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;

                // Decrypt the identity
                let identity = decrypt_from_storage::<Identity>(&stored.encrypted_data, password)?;
                Ok(Some(identity))
            }
            None => Ok(None),
        }
    }

    /// Delete the user's identity
    pub async fn delete_identity(&self, peer_id: &PeerId, password: &str) -> StorageResult<()> {
        // Verify password first
        if !self.verify_password(password).await? {
            return Err(StorageError::InvalidPassword);
        }

        let key: JsValue = peer_id.to_hex().into();
        self.db.delete("identity", &key).await?;
        Ok(())
    }

    /// Check if an identity exists
    pub async fn has_identity(&self) -> StorageResult<bool> {
        let count = self.db.count("identity", None).await?;
        Ok(count > 0)
    }

    /// Verify that a password is correct for the stored identity
    pub async fn verify_password(&self, password: &str) -> StorageResult<bool> {
        // Get all identities (should only be one)
        let all = self.db.get_all("identity", None).await?;

        if let Ok(array) = all.dyn_into::<js_sys::Array>() {
            if array.length() == 0 {
                return Ok(false);
            }

            // Get the first identity
            let item = array.get(0);
            let stored: StoredIdentity = serde_wasm_bindgen::from_value(item)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;

            // Try to verify password using encryption module's verify function
            return Ok(verify_pwd(&stored.encrypted_data, password));
        }

        Ok(false)
    }

    /// Change the password for an identity
    pub async fn change_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> StorageResult<()> {
        // Get the identity with old password
        let identity = self.get_identity(old_password).await?
            .ok_or(StorageError::NotFound)?;

        // Re-encrypt with new password
        self.save_identity(identity, new_password).await
    }

    /// Get the peer ID of the stored identity without decrypting
    pub async fn get_peer_id(&self) -> StorageResult<Option<PeerId>> {
        let all = self.db.get_all("identity", None).await?;

        if let Ok(array) = all.dyn_into::<js_sys::Array>() {
            if array.length() == 0 {
                return Ok(None);
            }

            let item = array.get(0);
            let stored: StoredIdentity = serde_wasm_bindgen::from_value(item)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;

            let peer_id = stored.get_peer_id()
                .map_err(|e| StorageError::InvalidData(e.to_string()))?;

            return Ok(Some(peer_id));
        }

        Ok(None)
    }

    /// Clear all identities (use with caution!)
    pub async fn clear(&self) -> StorageResult<()> {
        self.db.clear("identity").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeyPair;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn create_test_identity() -> Identity {
        let keypair = IdentityKeyPair::generate().unwrap();
        Identity {
            peer_id: PeerId::from_public_key(&keypair.signing_keypair.verifying_key.to_bytes()),
            display_name: "Test User".to_string(),
            keypair,
            created_at: 123456789,
        }
    }

    #[wasm_bindgen_test]
    async fn test_identity_store_basic() {
        let db = IndexedDB::open("test_identity_basic", 1).await.unwrap();
        let store = IdentityStore::new(db);

        let identity = create_test_identity();
        let password = "secure_password_123";
        let peer_id = identity.peer_id.clone();

        // Initially no identity
        assert!(!store.has_identity().await.unwrap());

        // Create identity
        store.create_identity(identity.clone(), password).await.unwrap();
        assert!(store.has_identity().await.unwrap());

        // Get identity with correct password
        let retrieved = store.get_identity(password).await.unwrap();
        assert_eq!(retrieved.as_ref().unwrap().peer_id, identity.peer_id);
        assert_eq!(retrieved.as_ref().unwrap().display_name, identity.display_name);

        // Try with wrong password
        let wrong_result = store.get_identity("wrong_password").await;
        assert!(wrong_result.is_err());

        // Cleanup
        store.delete_identity(&peer_id, password).await.unwrap();
        assert!(!store.has_identity().await.unwrap());
    }

    #[wasm_bindgen_test]
    async fn test_identity_store_password_verification() {
        let db = IndexedDB::open("test_identity_verify", 1).await.unwrap();
        let store = IdentityStore::new(db);

        let identity = create_test_identity();
        let password = "correct_password";
        let peer_id = identity.peer_id.clone();

        store.create_identity(identity, password).await.unwrap();

        // Verify correct password
        assert!(store.verify_password(password).await.unwrap());

        // Verify wrong password
        assert!(!store.verify_password("wrong_password").await.unwrap());

        // Cleanup
        store.delete_identity(&peer_id, password).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_identity_store_change_password() {
        let db = IndexedDB::open("test_identity_change_pwd", 1).await.unwrap();
        let store = IdentityStore::new(db);

        let identity = create_test_identity();
        let old_password = "old_password";
        let new_password = "new_password";
        let peer_id = identity.peer_id.clone();

        store.create_identity(identity.clone(), old_password).await.unwrap();

        // Change password
        store.change_password(old_password, new_password).await.unwrap();

        // Old password should not work
        assert!(!store.verify_password(old_password).await.unwrap());

        // New password should work
        assert!(store.verify_password(new_password).await.unwrap());

        // Should be able to get identity with new password
        let retrieved = store.get_identity(new_password).await.unwrap();
        assert_eq!(retrieved.unwrap().peer_id, identity.peer_id);

        // Cleanup
        store.delete_identity(&peer_id, new_password).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_identity_store_duplicate_creation() {
        let db = IndexedDB::open("test_identity_duplicate", 1).await.unwrap();
        let store = IdentityStore::new(db);

        let identity1 = create_test_identity();
        let identity2 = create_test_identity();
        let password = "password";

        // Create first identity
        store.create_identity(identity1.clone(), password).await.unwrap();

        // Try to create second identity - should fail
        let result = store.create_identity(identity2, password).await;
        assert!(result.is_err());

        // Cleanup
        store.delete_identity(&identity1.peer_id, password).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_identity_store_update() {
        let db = IndexedDB::open("test_identity_update", 1).await.unwrap();
        let store = IdentityStore::new(db);

        let mut identity = create_test_identity();
        let password = "password";
        let peer_id = identity.peer_id.clone();

        // Create identity
        store.create_identity(identity.clone(), password).await.unwrap();

        // Update display name
        identity.display_name = "Updated Name".to_string();
        store.update_identity(identity.clone(), password).await.unwrap();

        // Retrieve and verify update
        let retrieved = store.get_identity(password).await.unwrap();
        assert_eq!(retrieved.unwrap().display_name, "Updated Name");

        // Try to update with wrong password
        identity.display_name = "Another Update".to_string();
        let result = store.update_identity(identity, "wrong_password").await;
        assert!(result.is_err());

        // Cleanup
        store.delete_identity(&peer_id, password).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_identity_store_get_peer_id() {
        let db = IndexedDB::open("test_identity_peer_id", 1).await.unwrap();
        let store = IdentityStore::new(db);

        let identity = create_test_identity();
        let password = "password";
        let peer_id = identity.peer_id.clone();

        // No identity yet
        assert!(store.get_peer_id().await.unwrap().is_none());

        // Create identity
        store.create_identity(identity, password).await.unwrap();

        // Get peer ID without decrypting
        let retrieved_id = store.get_peer_id().await.unwrap();
        assert_eq!(retrieved_id, Some(peer_id.clone()));

        // Cleanup
        store.delete_identity(&peer_id, password).await.unwrap();
    }
}
