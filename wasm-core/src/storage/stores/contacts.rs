// Contacts Store
// Manages contact information

use wasm_bindgen::JsValue;
use wasm_bindgen::JsCast;
use crate::identity::{Contact, PeerId};
use crate::storage::{
    indexed_db::IndexedDB,
    types::StoredContact,
    StorageResult, StorageError,
};

/// Store for managing contacts
pub struct ContactsStore {
    db: IndexedDB,
}

impl ContactsStore {
    /// Create a new contacts store
    pub fn new(db: IndexedDB) -> Self {
        Self { db }
    }

    /// Add or update a contact
    pub async fn add_contact(&self, contact: Contact) -> StorageResult<()> {
        let stored = StoredContact::from_contact(contact);
        let key: JsValue = stored.peer_id.clone().into();
        let value = serde_wasm_bindgen::to_value(&stored)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        self.db.put("contacts", &value, Some(&key)).await?;
        Ok(())
    }

    /// Get a contact by peer ID
    pub async fn get_contact(&self, peer_id: &PeerId) -> StorageResult<Option<Contact>> {
        let key: JsValue = peer_id.to_hex().into();

        match self.db.get("contacts", &key).await? {
            Some(value) => {
                let stored: StoredContact = serde_wasm_bindgen::from_value(value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(stored.contact))
            }
            None => Ok(None),
        }
    }

    /// Update an existing contact
    pub async fn update_contact(&self, contact: Contact) -> StorageResult<()> {
        // Check if contact exists
        if self.get_contact(&contact.peer_id).await?.is_none() {
            return Err(StorageError::NotFound);
        }

        self.add_contact(contact).await
    }

    /// Delete a contact
    pub async fn delete_contact(&self, peer_id: &PeerId) -> StorageResult<()> {
        let key: JsValue = peer_id.to_hex().into();
        self.db.delete("contacts", &key).await?;
        Ok(())
    }

    /// Get all contacts
    pub async fn get_all_contacts(&self) -> StorageResult<Vec<Contact>> {
        let all = self.db.get_all("contacts", None).await?;
        let mut contacts = Vec::new();

        if let Ok(array) = all.dyn_into::<js_sys::Array>() {
            for i in 0..array.length() {
                let item = array.get(i);
                if let Ok(stored) = serde_wasm_bindgen::from_value::<StoredContact>(item) {
                    contacts.push(stored.contact);
                }
            }
        }

        Ok(contacts)
    }

    /// Search contacts by display name (case-insensitive partial match)
    pub async fn search_by_name(&self, query: &str) -> StorageResult<Vec<Contact>> {
        // Get all contacts and filter in Rust
        // (IndexedDB doesn't support case-insensitive or partial string matching natively)
        let all_contacts = self.get_all_contacts().await?;
        let query_lower = query.to_lowercase();

        let filtered: Vec<Contact> = all_contacts
            .into_iter()
            .filter(|c| c.display_name.to_lowercase().contains(&query_lower))
            .collect();

        Ok(filtered)
    }

    /// Get all verified contacts
    pub async fn get_verified_contacts(&self) -> StorageResult<Vec<Contact>> {
        let all_contacts = self.get_all_contacts().await?;
        let verified: Vec<Contact> = all_contacts
            .into_iter()
            .filter(|c| c.verified)
            .collect();

        Ok(verified)
    }

    /// Get contact count
    pub async fn count(&self) -> StorageResult<u32> {
        self.db.count("contacts", None).await
    }

    /// Check if a contact exists
    pub async fn exists(&self, peer_id: &PeerId) -> StorageResult<bool> {
        Ok(self.get_contact(peer_id).await?.is_some())
    }

    /// Mark a contact as verified
    pub async fn mark_verified(&self, peer_id: &PeerId, verified: bool) -> StorageResult<()> {
        let mut contact = self.get_contact(peer_id).await?
            .ok_or(StorageError::NotFound)?;

        contact.verified = verified;
        self.add_contact(contact).await
    }

    /// Update last seen timestamp for a contact
    pub async fn update_last_seen(&self, peer_id: &PeerId, timestamp: u64) -> StorageResult<()> {
        let mut contact = self.get_contact(peer_id).await?
            .ok_or(StorageError::NotFound)?;

        contact.last_seen = Some(timestamp);
        self.add_contact(contact).await
    }

    /// Get recently active contacts (those seen in the last N milliseconds)
    pub async fn get_recently_active(&self, since: u64) -> StorageResult<Vec<Contact>> {
        let all_contacts = self.get_all_contacts().await?;
        let recent: Vec<Contact> = all_contacts
            .into_iter()
            .filter(|c| {
                if let Some(last_seen) = c.last_seen {
                    last_seen >= since
                } else {
                    false
                }
            })
            .collect();

        Ok(recent)
    }

    /// Clear all contacts
    pub async fn clear(&self) -> StorageResult<()> {
        self.db.clear("contacts").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn create_test_contact(name: &str, verified: bool) -> Contact {
        let peer_id = PeerId::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        Contact {
            peer_id,
            display_name: name.to_string(),
            signing_public_key: vec![1, 2, 3],
            encryption_public_key: vec![4, 5, 6],
            verified,
            added_at: 123456,
            last_seen: None,
            notes: None,
        }
    }

    #[wasm_bindgen_test]
    async fn test_contacts_store_basic() {
        let db = IndexedDB::open("test_contacts_basic", 1).await.unwrap();
        let store = ContactsStore::new(db);

        let contact = create_test_contact("Alice", false);
        let peer_id = contact.peer_id.clone();

        // Add contact
        store.add_contact(contact.clone()).await.unwrap();

        // Get contact
        let retrieved = store.get_contact(&peer_id).await.unwrap();
        assert_eq!(retrieved.as_ref().unwrap().display_name, "Alice");
        assert_eq!(retrieved.as_ref().unwrap().verified, false);

        // Update contact
        let mut updated = retrieved.clone();
        updated.as_mut().unwrap().display_name = "Alice Updated".to_string();
        store.update_contact(updated.unwrap()).await.unwrap();

        let retrieved2 = store.get_contact(&peer_id).await.unwrap();
        assert_eq!(retrieved2.unwrap().display_name, "Alice Updated");

        // Delete contact
        store.delete_contact(&peer_id).await.unwrap();
        assert!(store.get_contact(&peer_id).await.unwrap().is_none());

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_contacts_store_search() {
        let db = IndexedDB::open("test_contacts_search", 1).await.unwrap();
        let store = ContactsStore::new(db);

        let alice = create_test_contact("Alice Smith", false);
        let bob = create_test_contact("Bob Johnson", true);

        store.add_contact(alice).await.unwrap();
        store.add_contact(bob).await.unwrap();

        // Search by partial name
        let results = store.search_by_name("alice").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].display_name, "Alice Smith");

        // Search case-insensitive
        let results2 = store.search_by_name("SMITH").await.unwrap();
        assert_eq!(results2.len(), 1);
        assert_eq!(results2[0].display_name, "Alice Smith");

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_contacts_store_verified() {
        let db = IndexedDB::open("test_contacts_verified", 1).await.unwrap();
        let store = ContactsStore::new(db);

        let alice = create_test_contact("Alice", false);
        let bob = create_test_contact("Bob", true);

        store.add_contact(alice.clone()).await.unwrap();
        store.add_contact(bob).await.unwrap();

        // Get verified contacts
        let verified = store.get_verified_contacts().await.unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].display_name, "Bob");

        // Mark Alice as verified
        store.mark_verified(&alice.peer_id, true).await.unwrap();
        let verified2 = store.get_verified_contacts().await.unwrap();
        assert_eq!(verified2.len(), 2);

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_contacts_store_count() {
        let db = IndexedDB::open("test_contacts_count", 1).await.unwrap();
        let store = ContactsStore::new(db);

        assert_eq!(store.count().await.unwrap(), 0);

        let alice = create_test_contact("Alice", false);
        let bob = create_test_contact("Bob", true);

        store.add_contact(alice).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 1);

        store.add_contact(bob).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 2);

        // Cleanup
        store.clear().await.unwrap();
    }
}
