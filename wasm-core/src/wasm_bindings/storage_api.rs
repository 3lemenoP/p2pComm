// Storage API for JavaScript
// Provides storage operations through IndexedDB

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Initialize storage (opens IndexedDB)
/// Returns true on success
#[wasm_bindgen]
pub async fn init_storage(db_name: String, password: String) -> Result<JsValue, JsValue> {
    use crate::storage::StorageManager;

    let storage = StorageManager::new(&db_name, password)
        .await
        .map_err(|e| JsValue::from_str(&format!("Storage init failed: {:?}", e)))?;

    // Store reference (simplified - in production would use a global state manager)
    Ok(JsValue::from_str("Storage initialized"))
}

/// Save a setting
#[wasm_bindgen]
pub async fn save_setting(key: String, value: String) -> Result<(), JsValue> {
    // TODO: Implement with global storage instance
    Ok(())
}

/// Get a setting
#[wasm_bindgen]
pub async fn get_setting(key: String) -> Result<String, JsValue> {
    // TODO: Implement with global storage instance
    Ok(String::new())
}

/// Check if storage is initialized
#[wasm_bindgen]
pub fn is_storage_initialized() -> bool {
    // TODO: Check global storage instance
    false
}
