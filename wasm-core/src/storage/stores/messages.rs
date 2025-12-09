// Messages Store
// Manages encrypted message storage with efficient querying

use wasm_bindgen::JsValue;
use wasm_bindgen::JsCast;
use crate::identity::PeerId;
use crate::message::{Message, MessageId};
use crate::storage::{
    indexed_db::IndexedDB,
    encryption::{encrypt_for_storage, decrypt_from_storage},
    types::StoredMessage,
    StorageResult, StorageError,
};

/// Store for managing messages
pub struct MessagesStore {
    db: IndexedDB,
    /// Password for message encryption
    password: String,
}

impl MessagesStore {
    /// Create a new messages store with encryption password
    pub fn new(db: IndexedDB, password: String) -> Self {
        Self { db, password }
    }

    /// Save a message (encrypted)
    pub async fn save_message(&self, message: Message) -> StorageResult<()> {
        // Encrypt the message
        let encrypted_data = encrypt_for_storage(&message, &self.password)?;

        // Create stored wrapper with index fields
        let stored = StoredMessage::new(&message, encrypted_data);

        let key: JsValue = stored.id.clone().into();
        let value = serde_wasm_bindgen::to_value(&stored)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        self.db.put("messages", &value, Some(&key)).await?;
        Ok(())
    }

    /// Get a message by ID (decrypted)
    pub async fn get_message(&self, message_id: &MessageId) -> StorageResult<Option<Message>> {
        let key: JsValue = message_id.to_hex().into();

        match self.db.get("messages", &key).await? {
            Some(value) => {
                let stored: StoredMessage = serde_wasm_bindgen::from_value(value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;

                // Decrypt the message
                let message = decrypt_from_storage::<Message>(&stored.encrypted_data, &self.password)?;
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    /// Get all messages in a conversation with a peer (bi-directional)
    /// Returns messages sorted by timestamp (newest first) with optional limit
    pub async fn get_conversation_messages(
        &self,
        peer_id: &PeerId,
        limit: Option<usize>,
    ) -> StorageResult<Vec<Message>> {
        // Get all messages and filter in Rust
        // (More efficient than two IndexedDB queries for small datasets)
        let all_messages = self.get_all_messages().await?;

        let peer_id_hex = peer_id.to_hex();
        let mut conversation_messages: Vec<Message> = all_messages
            .into_iter()
            .filter(|msg| {
                msg.from.to_hex() == peer_id_hex || msg.to.to_hex() == peer_id_hex
            })
            .collect();

        // Sort by timestamp (newest first)
        conversation_messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply limit if specified
        if let Some(limit) = limit {
            conversation_messages.truncate(limit);
        }

        Ok(conversation_messages)
    }

    /// Get messages sent to a specific peer
    pub async fn get_messages_to_peer(
        &self,
        peer_id: &PeerId,
        limit: Option<usize>,
    ) -> StorageResult<Vec<Message>> {
        let all_messages = self.get_all_messages().await?;

        let peer_id_hex = peer_id.to_hex();
        let mut to_messages: Vec<Message> = all_messages
            .into_iter()
            .filter(|msg| msg.to.to_hex() == peer_id_hex)
            .collect();

        // Sort by timestamp (newest first)
        to_messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(limit) = limit {
            to_messages.truncate(limit);
        }

        Ok(to_messages)
    }

    /// Get messages from a specific peer
    pub async fn get_messages_from_peer(
        &self,
        peer_id: &PeerId,
        limit: Option<usize>,
    ) -> StorageResult<Vec<Message>> {
        let all_messages = self.get_all_messages().await?;

        let peer_id_hex = peer_id.to_hex();
        let mut from_messages: Vec<Message> = all_messages
            .into_iter()
            .filter(|msg| msg.from.to_hex() == peer_id_hex)
            .collect();

        // Sort by timestamp (newest first)
        from_messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(limit) = limit {
            from_messages.truncate(limit);
        }

        Ok(from_messages)
    }

    /// Get all messages (decrypted)
    async fn get_all_messages(&self) -> StorageResult<Vec<Message>> {
        let all = self.db.get_all("messages", None).await?;
        let mut messages = Vec::new();

        if let Ok(array) = all.dyn_into::<js_sys::Array>() {
            for i in 0..array.length() {
                let item = array.get(i);
                if let Ok(stored) = serde_wasm_bindgen::from_value::<StoredMessage>(item) {
                    // Decrypt each message
                    if let Ok(message) = decrypt_from_storage::<Message>(&stored.encrypted_data, &self.password) {
                        messages.push(message);
                    }
                }
            }
        }

        Ok(messages)
    }

    /// Get messages within a timestamp range
    pub async fn get_messages_by_timestamp_range(
        &self,
        start_time: u64,
        end_time: u64,
    ) -> StorageResult<Vec<Message>> {
        let all_messages = self.get_all_messages().await?;

        let filtered: Vec<Message> = all_messages
            .into_iter()
            .filter(|msg| msg.timestamp >= start_time && msg.timestamp <= end_time)
            .collect();

        Ok(filtered)
    }

    /// Delete a message
    pub async fn delete_message(&self, message_id: &MessageId) -> StorageResult<()> {
        let key: JsValue = message_id.to_hex().into();
        self.db.delete("messages", &key).await?;
        Ok(())
    }

    /// Delete all messages in a conversation with a peer
    pub async fn delete_conversation(&self, peer_id: &PeerId) -> StorageResult<()> {
        let conversation_messages = self.get_conversation_messages(peer_id, None).await?;

        for message in conversation_messages {
            self.delete_message(&message.id).await?;
        }

        Ok(())
    }

    /// Count total messages
    pub async fn count_messages(&self) -> StorageResult<u32> {
        self.db.count("messages", None).await
    }

    /// Count messages in a conversation
    pub async fn count_conversation_messages(&self, peer_id: &PeerId) -> StorageResult<u32> {
        let messages = self.get_conversation_messages(peer_id, None).await?;
        Ok(messages.len() as u32)
    }

    /// Get the most recent message in a conversation
    pub async fn get_last_message(&self, peer_id: &PeerId) -> StorageResult<Option<Message>> {
        let messages = self.get_conversation_messages(peer_id, Some(1)).await?;
        Ok(messages.into_iter().next())
    }

    /// Check if a message exists
    pub async fn message_exists(&self, message_id: &MessageId) -> StorageResult<bool> {
        Ok(self.get_message(message_id).await?.is_some())
    }

    /// Clear all messages
    pub async fn clear(&self) -> StorageResult<()> {
        self.db.clear("messages").await?;
        Ok(())
    }

    /// Get recent messages (across all conversations)
    pub async fn get_recent_messages(&self, limit: usize) -> StorageResult<Vec<Message>> {
        let mut all_messages = self.get_all_messages().await?;

        // Sort by timestamp (newest first)
        all_messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply limit
        all_messages.truncate(limit);

        Ok(all_messages)
    }

    /// Search messages by text content (decrypts and searches in Rust)
    pub async fn search_messages(&self, query: &str) -> StorageResult<Vec<Message>> {
        let all_messages = self.get_all_messages().await?;
        let query_lower = query.to_lowercase();

        let matching: Vec<Message> = all_messages
            .into_iter()
            .filter(|msg| {
                // Search in message content
                match &msg.content {
                    crate::message::MessageContent::Text { text, .. } => {
                        text.to_lowercase().contains(&query_lower)
                    }
                }
            })
            .collect();

        Ok(matching)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MessageContent;
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
    async fn test_messages_store_basic() {
        let db = IndexedDB::open("test_messages_basic", 1).await.unwrap();
        let store = MessagesStore::new(db, "test_password".to_string());

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";

        let message = create_test_message(alice, bob, "Hello Bob!", 1000);
        let message_id = message.id.clone();

        // Save message
        store.save_message(message.clone()).await.unwrap();

        // Get message
        let retrieved = store.get_message(&message_id).await.unwrap();
        assert_eq!(retrieved.as_ref().unwrap().id, message.id);

        match retrieved.unwrap().content {
            MessageContent::Text { text, .. } => assert_eq!(text, "Hello Bob!"),
        }

        // Delete message
        store.delete_message(&message_id).await.unwrap();
        assert!(store.get_message(&message_id).await.unwrap().is_none());

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_messages_store_conversation() {
        let db = IndexedDB::open("test_messages_conversation", 1).await.unwrap();
        let store = MessagesStore::new(db, "test_password".to_string());

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let alice_peer = PeerId::from_hex(alice).unwrap();
        let bob_peer = PeerId::from_hex(bob).unwrap();

        // Create conversation
        let msg1 = create_test_message(alice, bob, "Hi Bob", 1000);
        let msg2 = create_test_message(bob, alice, "Hi Alice", 2000);
        let msg3 = create_test_message(alice, bob, "How are you?", 3000);

        store.save_message(msg1).await.unwrap();
        store.save_message(msg2).await.unwrap();
        store.save_message(msg3).await.unwrap();

        // Get conversation from Alice's perspective
        let conversation = store.get_conversation_messages(&bob_peer, None).await.unwrap();
        assert_eq!(conversation.len(), 3);

        // Should be sorted newest first
        assert_eq!(conversation[0].timestamp, 3000);
        assert_eq!(conversation[1].timestamp, 2000);
        assert_eq!(conversation[2].timestamp, 1000);

        // Get with limit
        let limited = store.get_conversation_messages(&bob_peer, Some(2)).await.unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].timestamp, 3000);

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_messages_store_search() {
        let db = IndexedDB::open("test_messages_search", 1).await.unwrap();
        let store = MessagesStore::new(db, "test_password".to_string());

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";

        let msg1 = create_test_message(alice, bob, "Hello world", 1000);
        let msg2 = create_test_message(bob, alice, "Goodbye world", 2000);
        let msg3 = create_test_message(alice, bob, "Random text", 3000);

        store.save_message(msg1).await.unwrap();
        store.save_message(msg2).await.unwrap();
        store.save_message(msg3).await.unwrap();

        // Search for "world"
        let results = store.search_messages("world").await.unwrap();
        assert_eq!(results.len(), 2);

        // Search case-insensitive
        let results2 = store.search_messages("HELLO").await.unwrap();
        assert_eq!(results2.len(), 1);

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_messages_store_last_message() {
        let db = IndexedDB::open("test_messages_last", 1).await.unwrap();
        let store = MessagesStore::new(db, "test_password".to_string());

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let bob_peer = PeerId::from_hex(bob).unwrap();

        let msg1 = create_test_message(alice, bob, "First", 1000);
        let msg2 = create_test_message(alice, bob, "Second", 2000);
        let msg3 = create_test_message(alice, bob, "Third", 3000);

        store.save_message(msg1).await.unwrap();
        store.save_message(msg2).await.unwrap();
        store.save_message(msg3).await.unwrap();

        // Get last message
        let last = store.get_last_message(&bob_peer).await.unwrap();
        assert_eq!(last.as_ref().unwrap().timestamp, 3000);
        match last.unwrap().content {
            MessageContent::Text { text, .. } => assert_eq!(text, "Third"),
        }

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_messages_store_delete_conversation() {
        let db = IndexedDB::open("test_messages_delete_conv", 1).await.unwrap();
        let store = MessagesStore::new(db, "test_password".to_string());

        let alice = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bob = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let bob_peer = PeerId::from_hex(bob).unwrap();

        let msg1 = create_test_message(alice, bob, "Message 1", 1000);
        let msg2 = create_test_message(bob, alice, "Message 2", 2000);

        store.save_message(msg1).await.unwrap();
        store.save_message(msg2).await.unwrap();

        assert_eq!(store.count_messages().await.unwrap(), 2);

        // Delete conversation
        store.delete_conversation(&bob_peer).await.unwrap();

        assert_eq!(store.count_messages().await.unwrap(), 0);

        // Cleanup
        store.clear().await.unwrap();
    }
}
