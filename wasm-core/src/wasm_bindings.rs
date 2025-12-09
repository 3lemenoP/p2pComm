// Wasm Bindings Module
// JavaScript API for the P2P messaging system

use wasm_bindgen::prelude::*;

pub mod identity_api;
pub mod storage_api;
pub mod bootstrap_api;
pub mod message_api;
pub mod network_api;
pub mod kaspa_api;

// Re-export for JavaScript
pub use identity_api::*;
pub use storage_api::*;
pub use bootstrap_api::*;
pub use message_api::*;
pub use network_api::*;
pub use kaspa_api::*;

/// Get the library version
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Check if WebAssembly is working correctly
#[wasm_bindgen]
pub fn health_check() -> bool {
    true
}
