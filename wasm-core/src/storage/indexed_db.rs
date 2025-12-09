// Low-level IndexedDB wrapper for Wasm
// Provides abstraction over web-sys IndexedDB APIs

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    IdbDatabase, IdbFactory, IdbObjectStore, IdbOpenDbRequest, IdbTransaction, IdbRequest,
    IdbKeyRange, IdbIndex, IdbCursor, IdbCursorWithValue, IdbTransactionMode,
    IdbObjectStoreParameters, IdbIndexParameters, DomException, DomStringList,
};
use js_sys::{Object, Array, Reflect, Promise};
use std::sync::Arc;

use super::{StorageError, StorageResult};

/// Database name constant
pub const DB_NAME: &str = "DecentralizedMessenger";

/// Current schema version
pub const DB_VERSION: u32 = 1;

/// Object store names
pub mod stores {
    pub const IDENTITY: &str = "identity";
    pub const CONTACTS: &str = "contacts";
    pub const MESSAGES: &str = "messages";
    pub const CONVERSATIONS: &str = "conversations";
    pub const SETTINGS: &str = "settings";
    pub const PEER_ADDRESSES: &str = "peer_addresses";
}

/// IndexedDB connection wrapper
#[derive(Clone)]
pub struct IndexedDBConnection {
    db: Arc<IdbDatabase>,
}

/// Type alias for easier usage
pub type IndexedDB = IndexedDBConnection;

impl IndexedDBConnection {
    /// Open or create the database
    pub async fn open(db_name: &str, version: u32) -> StorageResult<Self> {
        let window = web_sys::window()
            .ok_or_else(|| StorageError::DatabaseError("No window object".to_string()))?;

        let idb_factory = window
            .indexed_db()
            .map_err(|e| StorageError::DatabaseError(format!("IndexedDB not available: {:?}", e)))?
            .ok_or_else(|| StorageError::DatabaseError("IndexedDB not supported".to_string()))?;

        let open_request = idb_factory
            .open_with_u32(db_name, version)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to open database: {:?}", e)))?;

        // Set up upgrade handler
        {
            let open_req_clone = open_request.clone();
            let upgrade_handler = Closure::wrap(Box::new(move |event: web_sys::IdbVersionChangeEvent| {
                web_sys::console::log_1(&"Database upgrade triggered".into());

                if let Some(target) = event.target() {
                    if let Ok(request) = target.dyn_into::<IdbOpenDbRequest>() {
                        if let Ok(result) = request.result() {
                            if let Ok(db) = result.dyn_into::<IdbDatabase>() {
                                if let Err(e) = Self::create_schema_sync(&db) {
                                    web_sys::console::error_1(&format!("Schema creation failed: {:?}", e).into());
                                }
                            }
                        }
                    }
                }
            }) as Box<dyn FnMut(_)>);

            open_request.set_onupgradeneeded(Some(upgrade_handler.as_ref().unchecked_ref()));
            upgrade_handler.forget(); // Keep handler alive
        }

        // Wait for the database to open
        // Cast IdbOpenDbRequest to Promise
        let promise = open_request.clone().unchecked_into::<Promise>();
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| {
                // Extract error message from DomException if available
                let error_msg = e.dyn_into::<DomException>()
                    .map(|exc| format!("Database error: {}", exc.message()))
                    .unwrap_or_else(|_| "Unknown database error".to_string());
                StorageError::DatabaseError(error_msg)
            })?;

        let db = result
            .dyn_into::<IdbDatabase>()
            .map_err(|_| StorageError::DatabaseError("Failed to cast to IdbDatabase".to_string()))?;

        Ok(IndexedDBConnection { db: Arc::new(db) })
    }

    /// Create database schema synchronously (called during upgrade)
    fn create_schema_sync(db: &IdbDatabase) -> StorageResult<()> {
        let store_names = db.object_store_names();

        // Create identity store
        if !Self::contains_store(&store_names, stores::IDENTITY) {
            let params = IdbObjectStoreParameters::new();
            let key_path: JsValue = "peer_id".into();
            params.set_key_path(&key_path);

            db.create_object_store_with_optional_parameters(stores::IDENTITY, &params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create identity store: {:?}", e)))?;
        }

        // Create contacts store
        if !Self::contains_store(&store_names, stores::CONTACTS) {
            let params = IdbObjectStoreParameters::new();
            let key_path: JsValue = "peer_id".into();
            params.set_key_path(&key_path);

            let contacts_store = db
                .create_object_store_with_optional_parameters(stores::CONTACTS, &params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create contacts store: {:?}", e)))?;

            // Create index on display_name
            let idx_params = IdbIndexParameters::new();
            contacts_store
                .create_index_with_str_and_optional_parameters("display_name", "display_name", &idx_params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create display_name index: {:?}", e)))?;
        }

        // Create messages store
        if !Self::contains_store(&store_names, stores::MESSAGES) {
            let params = IdbObjectStoreParameters::new();
            let key_path: JsValue = "id".into();
            params.set_key_path(&key_path);

            let messages_store = db
                .create_object_store_with_optional_parameters(stores::MESSAGES, &params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create messages store: {:?}", e)))?;

            // Create indexes
            let idx_params = IdbIndexParameters::new();

            messages_store
                .create_index_with_str_and_optional_parameters("from_peer_id", "from_peer_id", &idx_params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create from_peer_id index: {:?}", e)))?;

            messages_store
                .create_index_with_str_and_optional_parameters("to_peer_id", "to_peer_id", &idx_params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create to_peer_id index: {:?}", e)))?;

            messages_store
                .create_index_with_str_and_optional_parameters("timestamp", "timestamp", &idx_params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create timestamp index: {:?}", e)))?;

            // Compound indexes
            let compound_from = Array::new();
            compound_from.push(&"from_peer_id".into());
            compound_from.push(&"timestamp".into());
            messages_store
                .create_index_with_str_sequence_and_optional_parameters("from_peer_timestamp", &compound_from, &idx_params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create compound index: {:?}", e)))?;

            let compound_to = Array::new();
            compound_to.push(&"to_peer_id".into());
            compound_to.push(&"timestamp".into());
            messages_store
                .create_index_with_str_sequence_and_optional_parameters("to_peer_timestamp", &compound_to, &idx_params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create compound index: {:?}", e)))?;
        }

        // Create conversations store
        if !Self::contains_store(&store_names, stores::CONVERSATIONS) {
            let params = IdbObjectStoreParameters::new();
            let key_path: JsValue = "peer_id".into();
            params.set_key_path(&key_path);

            db.create_object_store_with_optional_parameters(stores::CONVERSATIONS, &params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create conversations store: {:?}", e)))?;
        }

        // Create settings store
        if !Self::contains_store(&store_names, stores::SETTINGS) {
            let params = IdbObjectStoreParameters::new();
            let key_path: JsValue = "key".into();
            params.set_key_path(&key_path);

            db.create_object_store_with_optional_parameters(stores::SETTINGS, &params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create settings store: {:?}", e)))?;
        }

        // Create peer_addresses store
        if !Self::contains_store(&store_names, stores::PEER_ADDRESSES) {
            let params = IdbObjectStoreParameters::new();
            let key_path: JsValue = "peer_id".into();
            params.set_key_path(&key_path);

            db.create_object_store_with_optional_parameters(stores::PEER_ADDRESSES, &params)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to create peer_addresses store: {:?}", e)))?;
        }

        Ok(())
    }

    /// Helper to check if store exists in DomStringList
    fn contains_store(list: &DomStringList, name: &str) -> bool {
        for i in 0..list.length() {
            if let Some(store_name) = list.item(i) {
                if store_name == name {
                    return true;
                }
            }
        }
        false
    }

    /// Get a transaction for a store
    fn get_transaction(&self, store_name: &str, mode: IdbTransactionMode) -> StorageResult<IdbTransaction> {
        self.db
            .transaction_with_str_and_mode(store_name, mode)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to create transaction: {:?}", e)))
    }

    /// Get a value from an object store
    pub async fn get(&self, store_name: &str, key: &JsValue) -> StorageResult<Option<JsValue>> {
        let transaction = self.get_transaction(store_name, IdbTransactionMode::Readonly)?;

        let store = transaction
            .object_store(store_name)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get object store: {:?}", e)))?;

        let request = store
            .get(key)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get value: {:?}", e)))?;

        // Cast IdbRequest to Promise
        let promise = request.unchecked_into::<Promise>();
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| StorageError::DatabaseError(format!("Get operation failed: {:?}", e)))?;

        if result.is_undefined() || result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Put a value into an object store
    pub async fn put(&self, store_name: &str, value: &JsValue, key: Option<&JsValue>) -> StorageResult<()> {
        let transaction = self.get_transaction(store_name, IdbTransactionMode::Readwrite)?;

        let store = transaction
            .object_store(store_name)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get object store: {:?}", e)))?;

        let request = if let Some(k) = key {
            store
                .put_with_key(value, k)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to put value with key: {:?}", e)))?
        } else {
            store
                .put(value)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to put value: {:?}", e)))?
        };

        // Cast IdbRequest to Promise
        let promise = request.unchecked_into::<Promise>();
        JsFuture::from(promise)
            .await
            .map_err(|e| StorageError::DatabaseError(format!("Put operation failed: {:?}", e)))?;

        Ok(())
    }

    /// Delete a value from an object store
    pub async fn delete(&self, store_name: &str, key: &JsValue) -> StorageResult<()> {
        let transaction = self.get_transaction(store_name, IdbTransactionMode::Readwrite)?;

        let store = transaction
            .object_store(store_name)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get object store: {:?}", e)))?;

        let request = store
            .delete(key)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to delete value: {:?}", e)))?;

        // Cast IdbRequest to Promise
        let promise = request.unchecked_into::<Promise>();
        JsFuture::from(promise)
            .await
            .map_err(|e| StorageError::DatabaseError(format!("Delete operation failed: {:?}", e)))?;

        Ok(())
    }

    /// Get all values from an object store (returns as JsValue Array)
    pub async fn get_all(&self, store_name: &str, _index: Option<&str>) -> StorageResult<JsValue> {
        let transaction = self.get_transaction(store_name, IdbTransactionMode::Readonly)?;

        let store = transaction
            .object_store(store_name)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get object store: {:?}", e)))?;

        let request = store
            .get_all()
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get all values: {:?}", e)))?;

        // Cast IdbRequest to Promise
        let promise = request.unchecked_into::<Promise>();
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| StorageError::DatabaseError(format!("Get all operation failed: {:?}", e)))?;

        // Return the result as JsValue (which is an Array)
        Ok(result)
    }

    /// Get a range of values from an index
    pub async fn get_range(
        &self,
        store_name: &str,
        index_name: Option<&str>,
        lower_bound: Option<&JsValue>,
        upper_bound: Option<&JsValue>,
        limit: Option<u32>,
    ) -> StorageResult<Vec<JsValue>> {
        let transaction = self.get_transaction(store_name, IdbTransactionMode::Readonly)?;

        let store = transaction
            .object_store(store_name)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get object store: {:?}", e)))?;

        // Create key range if bounds are provided
        let key_range = if lower_bound.is_some() || upper_bound.is_some() {
            match (lower_bound, upper_bound) {
                (Some(lower), Some(upper)) => Some(
                    IdbKeyRange::bound(lower, upper)
                        .map_err(|e| StorageError::DatabaseError(format!("Failed to create key range: {:?}", e)))?,
                ),
                (Some(lower), None) => Some(
                    IdbKeyRange::lower_bound(lower)
                        .map_err(|e| StorageError::DatabaseError(format!("Failed to create key range: {:?}", e)))?,
                ),
                (None, Some(upper)) => Some(
                    IdbKeyRange::upper_bound(upper)
                        .map_err(|e| StorageError::DatabaseError(format!("Failed to create key range: {:?}", e)))?,
                ),
                (None, None) => None,
            }
        } else {
            None
        };

        // Get cursor on index or store
        let cursor_request = if let Some(idx_name) = index_name {
            let index = store
                .index(idx_name)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get index: {:?}", e)))?;

            if let Some(ref range) = key_range {
                index
                    .open_cursor_with_range(range)
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to open cursor: {:?}", e)))?
            } else {
                index
                    .open_cursor()
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to open cursor: {:?}", e)))?
            }
        } else {
            if let Some(ref range) = key_range {
                store
                    .open_cursor_with_range(range)
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to open cursor: {:?}", e)))?
            } else {
                store
                    .open_cursor()
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to open cursor: {:?}", e)))?
            }
        };

        // For now, use a simpler approach: just get all and filter in Rust
        // TODO: Implement proper async cursor iteration with event handlers
        // The cursor API requires setting up onsuccess handlers which is complex in async Rust

        // Use get_all on the index or store
        let all_results = if let Some(idx_name) = index_name {
            let index = store
                .index(idx_name)
                .map_err(|e| StorageError::DatabaseError(format!("Failed to get index: {:?}", e)))?;

            let request = if let Some(ref range) = key_range {
                index.get_all_with_key(range)
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to get all from index: {:?}", e)))?
            } else {
                index.get_all()
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to get all from index: {:?}", e)))?
            };

            let promise = request.unchecked_into::<Promise>();
            JsFuture::from(promise).await
                .map_err(|e| StorageError::DatabaseError(format!("Get all operation failed: {:?}", e)))?
        } else {
            let request = if let Some(ref range) = key_range {
                store.get_all_with_key(range)
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to get all: {:?}", e)))?
            } else {
                store.get_all()
                    .map_err(|e| StorageError::DatabaseError(format!("Failed to get all: {:?}", e)))?
            };

            let promise = request.unchecked_into::<Promise>();
            JsFuture::from(promise).await
                .map_err(|e| StorageError::DatabaseError(format!("Get all operation failed: {:?}", e)))?
        };

        let array = all_results
            .dyn_into::<Array>()
            .map_err(|_| StorageError::DatabaseError("Failed to cast result to array".to_string()))?;

        // Apply limit if specified
        let max_count = limit.unwrap_or(u32::MAX) as usize;
        let result_count = std::cmp::min(array.length() as usize, max_count);

        let mut results = Vec::new();
        for i in 0..result_count {
            results.push(array.get(i as u32));
        }

        Ok(results)
    }

    /// Count entries in an object store
    pub async fn count(&self, store_name: &str, _index: Option<&str>) -> StorageResult<u32> {
        let transaction = self.get_transaction(store_name, IdbTransactionMode::Readonly)?;

        let store = transaction
            .object_store(store_name)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get object store: {:?}", e)))?;

        let request = store
            .count()
            .map_err(|e| StorageError::DatabaseError(format!("Failed to count entries: {:?}", e)))?;

        // Cast IdbRequest to Promise
        let promise = request.unchecked_into::<Promise>();
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| StorageError::DatabaseError(format!("Count operation failed: {:?}", e)))?;

        result
            .as_f64()
            .map(|f| f as u32)
            .ok_or_else(|| StorageError::DatabaseError("Failed to get count as number".to_string()))
    }

    /// Clear all entries from an object store
    pub async fn clear(&self, store_name: &str) -> StorageResult<()> {
        let transaction = self.get_transaction(store_name, IdbTransactionMode::Readwrite)?;

        let store = transaction
            .object_store(store_name)
            .map_err(|e| StorageError::DatabaseError(format!("Failed to get object store: {:?}", e)))?;

        let request = store
            .clear()
            .map_err(|e| StorageError::DatabaseError(format!("Failed to clear store: {:?}", e)))?;

        // Cast IdbRequest to Promise
        let promise = request.unchecked_into::<Promise>();
        JsFuture::from(promise)
            .await
            .map_err(|e| StorageError::DatabaseError(format!("Clear operation failed: {:?}", e)))?;

        Ok(())
    }

    /// Close the database connection
    pub fn close(&self) {
        self.db.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_open_database() {
        let conn = IndexedDBConnection::open("test_db_open", 1).await;
        assert!(conn.is_ok());
    }

    #[wasm_bindgen_test]
    async fn test_put_and_get() {
        let conn = IndexedDBConnection::open("test_db_put_get", 1).await.unwrap();

        let test_value = JsValue::from_str("test_value");
        let test_key = JsValue::from_str("test_key");

        // Create test object
        let obj = Object::new();
        Reflect::set(&obj, &"key".into(), &test_key).unwrap();
        Reflect::set(&obj, &"value".into(), &test_value).unwrap();

        // Test put and get
        conn.put(stores::SETTINGS, &obj.into(), None).await.unwrap();
        let result = conn.get(stores::SETTINGS, &test_key).await.unwrap();

        assert!(result.is_some());
        conn.close();
    }

    #[wasm_bindgen_test]
    async fn test_delete() {
        let conn = IndexedDBConnection::open("test_db_delete", 1).await.unwrap();

        let test_key = JsValue::from_str("delete_test_key");

        // Create and put test object
        let obj = Object::new();
        Reflect::set(&obj, &"key".into(), &test_key).unwrap();
        conn.put(stores::SETTINGS, &obj.into(), None).await.unwrap();

        // Delete and verify
        conn.delete(stores::SETTINGS, &test_key).await.unwrap();
        let result = conn.get(stores::SETTINGS, &test_key).await.unwrap();

        assert!(result.is_none());
        conn.close();
    }
}
