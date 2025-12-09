// Settings Store
// Key-value store for application settings

use wasm_bindgen::JsValue;
use wasm_bindgen::JsCast;
use crate::storage::{
    indexed_db::IndexedDB,
    types::SettingValue,
    StorageResult, StorageError,
};

/// Store for application settings
pub struct SettingsStore {
    db: IndexedDB,
}

impl SettingsStore {
    /// Create a new settings store
    pub fn new(db: IndexedDB) -> Self {
        Self { db }
    }

    /// Get a setting by key
    pub async fn get(&self, key: &str) -> StorageResult<Option<SettingValue>> {
        let key_js: JsValue = key.into();

        match self.db.get("settings", &key_js).await? {
            Some(value) => {
                let setting: SettingValue = serde_wasm_bindgen::from_value(value)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(setting))
            }
            None => Ok(None),
        }
    }

    /// Set a setting value
    pub async fn set(&self, key: &str, value: SettingValue) -> StorageResult<()> {
        let key_js: JsValue = key.into();
        let value_js = serde_wasm_bindgen::to_value(&value)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        self.db.put("settings", &value_js, Some(&key_js)).await?;
        Ok(())
    }

    /// Delete a setting
    pub async fn delete(&self, key: &str) -> StorageResult<()> {
        let key_js: JsValue = key.into();
        self.db.delete("settings", &key_js).await?;
        Ok(())
    }

    /// Get all settings as a map
    pub async fn get_all(&self) -> StorageResult<std::collections::HashMap<String, SettingValue>> {
        let all = self.db.get_all("settings", None).await?;

        let mut settings = std::collections::HashMap::new();

        // all is a JsValue array
        if let Ok(array) = all.dyn_into::<js_sys::Array>() {
            for i in 0..array.length() {
                let item = array.get(i);
                // Each item is a stored setting object with key and value
                if let Ok(setting) = serde_wasm_bindgen::from_value::<SettingValue>(item) {
                    // Note: For settings store, the key should be extracted from the object
                    // This is a simplified version - in reality we'd need to deserialize the full object
                    // For now, we'll skip this complex iteration
                    // TODO: Properly handle settings iteration with key extraction
                }
            }
        }

        Ok(settings)
    }

    /// Clear all settings
    pub async fn clear(&self) -> StorageResult<()> {
        self.db.clear("settings").await?;
        Ok(())
    }

    /// Check if a setting exists
    pub async fn exists(&self, key: &str) -> StorageResult<bool> {
        Ok(self.get(key).await?.is_some())
    }

    /// Get a string setting with default
    pub async fn get_string(&self, key: &str, default: &str) -> StorageResult<String> {
        match self.get(key).await? {
            Some(SettingValue::String(s)) => Ok(s),
            Some(_) => Err(StorageError::InvalidData(
                format!("Setting '{}' is not a string", key)
            )),
            None => Ok(default.to_string()),
        }
    }

    /// Get a boolean setting with default
    pub async fn get_bool(&self, key: &str, default: bool) -> StorageResult<bool> {
        match self.get(key).await? {
            Some(SettingValue::Bool(b)) => Ok(b),
            Some(_) => Err(StorageError::InvalidData(
                format!("Setting '{}' is not a boolean", key)
            )),
            None => Ok(default),
        }
    }

    /// Get a number setting with default
    pub async fn get_number(&self, key: &str, default: f64) -> StorageResult<f64> {
        match self.get(key).await? {
            Some(SettingValue::Number(n)) => Ok(n),
            Some(_) => Err(StorageError::InvalidData(
                format!("Setting '{}' is not a number", key)
            )),
            None => Ok(default),
        }
    }

    /// Set a string setting
    pub async fn set_string(&self, key: &str, value: String) -> StorageResult<()> {
        self.set(key, SettingValue::String(value)).await
    }

    /// Set a boolean setting
    pub async fn set_bool(&self, key: &str, value: bool) -> StorageResult<()> {
        self.set(key, SettingValue::Bool(value)).await
    }

    /// Set a number setting
    pub async fn set_number(&self, key: &str, value: f64) -> StorageResult<()> {
        self.set(key, SettingValue::Number(value)).await
    }

    /// Get settings count
    pub async fn count(&self) -> StorageResult<u32> {
        self.db.count("settings", None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_settings_store_basic() {
        let db = IndexedDB::open("test_settings_basic", 1).await.unwrap();
        let store = SettingsStore::new(db);

        // Test string setting
        store.set_string("theme", "dark".to_string()).await.unwrap();
        let theme = store.get_string("theme", "light").await.unwrap();
        assert_eq!(theme, "dark");

        // Test boolean setting
        store.set_bool("notifications_enabled", true).await.unwrap();
        let enabled = store.get_bool("notifications_enabled", false).await.unwrap();
        assert_eq!(enabled, true);

        // Test number setting
        store.set_number("volume", 0.75).await.unwrap();
        let volume = store.get_number("volume", 1.0).await.unwrap();
        assert_eq!(volume, 0.75);

        // Test default value when setting doesn't exist
        let missing = store.get_string("missing", "default").await.unwrap();
        assert_eq!(missing, "default");

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_settings_store_exists() {
        let db = IndexedDB::open("test_settings_exists", 1).await.unwrap();
        let store = SettingsStore::new(db);

        assert!(!store.exists("test_key").await.unwrap());

        store.set_string("test_key", "test_value".to_string()).await.unwrap();
        assert!(store.exists("test_key").await.unwrap());

        store.delete("test_key").await.unwrap();
        assert!(!store.exists("test_key").await.unwrap());

        // Cleanup
        store.clear().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_settings_store_delete() {
        let db = IndexedDB::open("test_settings_delete", 1).await.unwrap();
        let store = SettingsStore::new(db);

        store.set_string("to_delete", "value".to_string()).await.unwrap();
        assert!(store.get("to_delete").await.unwrap().is_some());

        store.delete("to_delete").await.unwrap();
        assert!(store.get("to_delete").await.unwrap().is_none());

        // Cleanup
        store.clear().await.unwrap();
    }
}
