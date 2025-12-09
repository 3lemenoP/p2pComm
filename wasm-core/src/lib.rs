use wasm_bindgen::prelude::*;

pub mod crypto;
pub mod message;
pub mod identity;
pub mod storage;
pub mod network;
pub mod bootstrap;
pub mod wasm_bindings;

// Kaspa blockchain integration for decentralized peer discovery and messaging
pub mod kaspa;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator for smaller Wasm binary size
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Log to browser console
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

/// Macro for console logging
#[macro_export]
macro_rules! console_log {
    ($($t:tt)*) => {
        $crate::log(&format_args!($($t)*).to_string())
    };
}
