// Conversations Store
// Manages conversation metadata for efficient UI rendering

use wasm_bindgen::JsValue;
use wasm_bindgen::JsCast;
use crate::identity::PeerId;
use crate::message::{Message, MessageContent};
use crate::storage::{
    indexed_db::IndexedDB,
    types::ConversationMeta,
    StorageResult, StorageError,
};

/// Store for managing conversation metadata
pub struct ConversationsStore {
    db: IndexedDB,
}

impl ConversationsStore {
    /// Create a new conversations store
    pub fn new(db: IndexedDB) -> Self {
        Self { db }
    }

    /// Update conversation metadata with a new message
    pub async fn update_with_message(&self, peer_id: &PeerId, message: &Message) -> StorageResult<()> {
        // Get preview text (first 100 characters)
        let preview = match &message.content {
            MessageContent::Text { text, .. } => {
                if text.len() > 100 {
                    format!("{}...", &text[..100])
                } else {
                    text.clone()
                }
            }
        };

        // Check if conversation already exists
        if let Some(mut meta) = self.get_conversation(peer_id).await? {
            // Update existing conversation
            meta.update_with_message(message, preview);
            self.save_conversation(meta).await?;
        } else {
            // Create new conversation
            let meta = ConversationMeta::from_message(peer_id, message, preview);
            self.save_conversation(meta).await?;
        }

        Ok(())
    }

    /// Save conversation metadata
    async fn save_conversation(&self, meta: ConversationMeta) -> StorageResult<()> {
        let key: JsValue = meta.peer_id.clone().into();
        let value = serde_wasm_bindgen::to_value(&meta)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        self.db.put("conversations", &value, Some(&key)).await?;
        Ok(())
    }

    /// Get conversation metadata for a peer
    pub async fn get_conversation(&self, peer_id: &PeerId) -> StorageResult<Option<ConversationMeta>> {
        let key: JsValue = peer_id.to_hex().into();

        match self.db.get("conversations", &key).await? {
            Some(value) => {
                let meta: ConversationMeta = serde_wasm_bindgen::from_value(value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    /// Get all conversations, sorted by last message timestamp (newest first)
    pub async fn get_all_conversations(&self) -> StorageResult<Vec<ConversationMeta>> {
        let all = self.db.get_all("conversations", None).await?;
        let mut conversations = Vec::new();

        if let Ok(array) = all.dyn_into::<js_sys::Array>() {
            for i in 0..array.length() {
                let item = array.get(i);
                if let Ok(meta) = serde_wasm_bindgen::from_value::<ConversationMeta>(item) {
                    conversations.push(meta);
                }
            }
        }

        // Sort by timestamp (newest first)
        conversations.sort_by(|a, b| b.last_message_timestamp.cmp(&a.last_message_timestamp));

        Ok(conversations)
    }

    /// Get active conversations (not archived), sorted by last message
    pub async fn get_active_conversations(&self) -> StorageResult<Vec<ConversationMeta>> {
        let all = self.get_all_conversations().await?;
        let active: Vec<ConversationMeta> = all
            .into_iter()
            .filter(|c| !c.archived)
            .collect();

        Ok(active)
    }

    /// Get pinned conversations
    pub async fn get_pinned_conversations(&self) -> StorageResult<Vec<ConversationMeta>> {
        let all = self.get_all_conversations().await?;
        let pinned: Vec<ConversationMeta> = all
            .into_iter()
            .filter(|c| c.pinned)
            .collect();

        Ok(pinned)
    }

    /// Get archived conversations
    pub async fn get_archived_conversations(&self) -> StorageResult<Vec<ConversationMeta>> {
        let all = self.get_all_conversations().await?;
        let archived: Vec<ConversationMeta> = all
            .into_iter()
            .filter(|c| c.archived)
            .collect();

        Ok(archived)
    }

    /// Mark a conversation as read (reset unread count to 0)
    pub async fn mark_as_read(&self, peer_id: &PeerId) -> StorageResult<()> {
        let mut meta = self.get_conversation(peer_id).await?
            .ok_or(StorageError::NotFound)?;

        meta.unread_count = 0;
        self.save_conversation(meta).await
    }

    /// Increment unread count for a conversation
    pub async fn increment_unread(&self, peer_id: &PeerId) -> StorageResult<()> {
        let mut meta = self.get_conversation(peer_id).await?
            .ok_or(StorageError::NotFound)?;

        meta.unread_count += 1;
        self.save_conversation(meta).await
    }

    /// Get total unread message count across all conversations
    pub async fn get_total_unread_count(&self) -> StorageResult<u32> {
        let all = self.get_all_conversations().await?;
        let total: u32 = all.iter().map(|c| c.unread_count).sum();
        Ok(total)
    }

    /// Pin a conversation
    pub async fn pin_conversation(&self, peer_id: &PeerId, pinned: bool) -> StorageResult<()> {
        let mut meta = self.get_conversation(peer_id).await?
            .ok_or(StorageError::NotFound)?;

        meta.pinned = pinned;
        self.save_conversation(meta).await
    }

    /// Mute a conversation
    pub async fn mute_conversation(&self, peer_id: &PeerId, muted: bool) -> StorageResult<()> {
        let mut meta = self.get_conversation(peer_id).await?
            .ok_or(StorageError::NotFound)?;

        meta.muted = muted;
        self.save_conversation(meta).await
    }

    /// Archive a conversation
    pub async fn archive_conversation(&self, peer_id: &PeerId, archived: bool) -> StorageResult<()> {
        let mut meta = self.get_conversation(peer_id).await?
            .ok_or(StorageError::NotFound)?;

        meta.archived = archived;
        self.save_conversation(meta).await
    }

    /// Delete a conversation's metadata
    pub async fn delete_conversation(&self, peer_id: &PeerId) -> StorageResult<()> {
        let key: JsValue = peer_id.to_hex().into();
        self.db.delete("conversations", &key).await?;
        Ok(())
    }

    /// Check if a conversation exists
    pub async fn exists(&self, peer_id: &PeerId) -> StorageResult<bool> {
        Ok(self.get_conversation(peer_id).await?.is_some())
    }

    /// Get conversation count
    pub async fn count(&self) -> StorageResult<u32> {
        self.db.count("conversations", None).await
    }

    /// Clear all conversations
    pub async fn clear(&self) -> StorageResult<()> {
        self.db.clear("conversations").await?;
        Ok(())
    }

    /// Get conversations with unread messages
    pub async fn get_conversations_with_unread(&self) -> StorageResult<Vec<ConversationMeta>> {
        let all = self.get_all_conversations().await?;
        let with_unread: Vec<ConversationMeta> = all
            .into_iter()
            .filter(|c| c.unread_count > 0)
            .collect();

        Ok(with_unread)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MessageId;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn create_test_message(from: &str, to: &str, text: &str, _timestamp: u64) -> Message {
        let from_peer = PeerId::from_hex(from).unwrap();
        let to_peer = PeerId::from_hex(to).unwrap();

        // Create a test identity
        let keypair = crate::crypto::IdentityKeyPair::generate().unwrap();
        let identity = crate::identity::Identity {
            peer_id: from_peer.clone(),
            display_name: "Test User".to_string(),
            keypair,
            created_at: js_sys::Date::now() as u64,
        };

        Message::new(
            from_peer,
            to_peer,
            MessageContent::Text {
                text: text.to_string(),
                reply_to: None,
            },
            &identity,
        ).unwrap()
    }

    #[wasm_bindgen_test]
    async fn test_conversations_store_basic() {
        let db = IndexedDB::open("test_conversations_basic", 1).await.unwrap();
        let store = ConversationsStore::new(db);

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let bob_peer = PeerId::from_hex(bob).unwrap();

        let message = create_test_message(alice, bob, "Hello Bob!", 1000);

        // Update with message
        store.update_with_message(&bob_peer, &message).await.unwrap();

        // Get conversation
        let conv = store.get_conversation(&bob_peer).await.unwrap().unwrap();
        assert_eq!(conv.last_message_preview, "Hello Bob!");
        assert_eq!(conv.last_message_timestamp, 1000);
        assert_eq!(conv.unread_count, 0);

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_conversations_store_unread() {
        let db = IndexedDB::open("test_conversations_unread", 1).await.unwrap();
        let store = ConversationsStore::new(db);

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let bob_peer = PeerId::from_hex(bob).unwrap();

        let message = create_test_message(alice, bob, "Test", 1000);
        store.update_with_message(&bob_peer, &message).await.unwrap();

        // Increment unread
        store.increment_unread(&bob_peer).await.unwrap();
        store.increment_unread(&bob_peer).await.unwrap();

        let conv = store.get_conversation(&bob_peer).await.unwrap().unwrap();
        assert_eq!(conv.unread_count, 2);

        // Mark as read
        store.mark_as_read(&bob_peer).await.unwrap();

        let conv2 = store.get_conversation(&bob_peer).await.unwrap().unwrap();
        assert_eq!(conv2.unread_count, 0);

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_conversations_store_pin_mute_archive() {
        let db = IndexedDB::open("test_conversations_flags", 1).await.unwrap();
        let store = ConversationsStore::new(db);

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let bob_peer = PeerId::from_hex(bob).unwrap();

        let message = create_test_message(alice, bob, "Test", 1000);
        store.update_with_message(&bob_peer, &message).await.unwrap();

        // Pin conversation
        store.pin_conversation(&bob_peer, true).await.unwrap();
        let conv = store.get_conversation(&bob_peer).await.unwrap().unwrap();
        assert!(conv.pinned);

        // Mute conversation
        store.mute_conversation(&bob_peer, true).await.unwrap();
        let conv = store.get_conversation(&bob_peer).await.unwrap().unwrap();
        assert!(conv.muted);

        // Archive conversation
        store.archive_conversation(&bob_peer, true).await.unwrap();
        let conv = store.get_conversation(&bob_peer).await.unwrap().unwrap();
        assert!(conv.archived);

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_conversations_store_sorting() {
        let db = IndexedDB::open("test_conversations_sorting", 1).await.unwrap();
        let store = ConversationsStore::new(db);

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let charlie = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let bob_peer = PeerId::from_hex(bob).unwrap();
        let charlie_peer = PeerId::from_hex(charlie).unwrap();

        // Create conversations with different timestamps
        let msg1 = create_test_message(alice, bob, "Message to Bob", 1000);
        let msg2 = create_test_message(alice, charlie, "Message to Charlie", 3000);

        store.update_with_message(&bob_peer, &msg1).await.unwrap();
        store.update_with_message(&charlie_peer, &msg2).await.unwrap();

        // Get all conversations - should be sorted by timestamp (newest first)
        let all = store.get_all_conversations().await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].last_message_timestamp, 3000); // Charlie (newest)
        assert_eq!(all[1].last_message_timestamp, 1000); // Bob

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_conversations_store_total_unread() {
        let db = IndexedDB::open("test_conversations_total_unread", 1).await.unwrap();
        let store = ConversationsStore::new(db);

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let charlie = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let bob_peer = PeerId::from_hex(bob).unwrap();
        let charlie_peer = PeerId::from_hex(charlie).unwrap();

        let msg1 = create_test_message(alice, bob, "Message 1", 1000);
        let msg2 = create_test_message(alice, charlie, "Message 2", 2000);

        store.update_with_message(&bob_peer, &msg1).await.unwrap();
        store.update_with_message(&charlie_peer, &msg2).await.unwrap();

        store.increment_unread(&bob_peer).await.unwrap();
        store.increment_unread(&bob_peer).await.unwrap();
        store.increment_unread(&charlie_peer).await.unwrap();

        // Total should be 3
        let total = store.get_total_unread_count().await.unwrap();
        assert_eq!(total, 3);

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_conversations_store_active_filter() {
        let db = IndexedDB::open("test_conversations_active", 1).await.unwrap();
        let store = ConversationsStore::new(db);

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let charlie = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let bob_peer = PeerId::from_hex(bob).unwrap();
        let charlie_peer = PeerId::from_hex(charlie).unwrap();

        let msg1 = create_test_message(alice, bob, "Message 1", 1000);
        let msg2 = create_test_message(alice, charlie, "Message 2", 2000);

        store.update_with_message(&bob_peer, &msg1).await.unwrap();
        store.update_with_message(&charlie_peer, &msg2).await.unwrap();

        // Archive Bob's conversation
        store.archive_conversation(&bob_peer, true).await.unwrap();

        // Get active conversations - should only have Charlie
        let active = store.get_active_conversations().await.unwrap();
        assert_eq!(active.len(), 1);

        // Get archived - should only have Bob
        let archived = store.get_archived_conversations().await.unwrap();
        assert_eq!(archived.len(), 1);

        // Cleanup
        store.clear().await.unwrap();
    }
}
