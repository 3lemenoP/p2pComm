//! Kaspa Wallet Bridge for WASM
//!
//! Provides HD wallet functionality for P2PComm:
//! - Deterministic wallet creation from password
//! - Address derivation
//! - Transaction signing

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::cell::RefCell;

use kaspa_addresses::{Address, Prefix as AddressPrefix};
use kaspa_wallet_keys::derivation::gen1::WalletDerivationManager;
use kaspa_wallet_keys::derivation::traits::WalletDerivationManagerTrait;
use kaspa_bip32::{Mnemonic, Language, ExtendedPrivateKey, SecretKey, Prefix};
use kaspa_consensus_core::tx::Transaction;

use std::collections::HashMap;

thread_local! {
    /// Global wallet instance (for WASM single-threaded environment)
    pub(crate) static WALLET: RefCell<Option<WalletState>> = RefCell::new(None);
    /// UTXO storage (address -> list of UTXOs)
    pub(crate) static WALLET_UTXOS: RefCell<HashMap<String, Vec<Utxo>>> = RefCell::new(HashMap::new());
    /// Balance cache (in sompis)
    static WALLET_BALANCE: RefCell<u64> = RefCell::new(0);
}

/// UTXO (Unspent Transaction Output) representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub transaction_id: String,
    pub index: u32,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub script_public_key_version: u16,
    pub address: String,
    pub is_coinbase: bool,
}

/// Internal wallet state
pub(crate) struct WalletState {
    pub(crate) derivation_manager: WalletDerivationManager,
    pub(crate) mnemonic: String,
    pub(crate) is_testnet: bool,
    pub(crate) receive_addresses: Vec<AddressInfo>,
    pub(crate) change_addresses: Vec<AddressInfo>,
}

/// Address information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    pub address: String,
    pub index: u32,
    pub is_change: bool,
    pub used: bool,
}

/// Wallet info returned to JavaScript
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub primary_address: String,
    pub receive_addresses: Vec<String>,
    pub change_addresses: Vec<String>,
    pub is_testnet: bool,
}

/// Create a deterministic wallet from a password
///
/// The password is hashed with a domain-specific salt to derive
/// a BIP39 mnemonic, which is then used to create an HD wallet.
#[wasm_bindgen]
pub fn kaspa_create_wallet(password: String, is_testnet: bool) -> Result<JsValue, JsValue> {
    use sha2::{Sha256, Digest};

    // Derive deterministic seed from password
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(b"p2pcomm-kaspa-wallet-v1"); // Salt for domain separation
    let hash = hasher.finalize();

    // Generate mnemonic from hash (deterministic)
    let mnemonic = Mnemonic::from_entropy(hash.to_vec(), Language::English)
        .map_err(|e| JsValue::from_str(&format!("Failed to create mnemonic: {}", e)))?;

    create_wallet_from_mnemonic(mnemonic.phrase(), is_testnet)
}

/// Create a wallet from an existing BIP39 mnemonic
#[wasm_bindgen]
pub fn kaspa_create_wallet_from_mnemonic(mnemonic: String, is_testnet: bool) -> Result<JsValue, JsValue> {
    create_wallet_from_mnemonic(&mnemonic, is_testnet)
}

/// Internal function to create wallet from mnemonic
fn create_wallet_from_mnemonic(mnemonic: &str, is_testnet: bool) -> Result<JsValue, JsValue> {
    // Parse mnemonic
    let mnemonic_obj = Mnemonic::new(mnemonic, Language::English)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse mnemonic: {}", e)))?;

    // Create extended private key from mnemonic
    let xprv = ExtendedPrivateKey::<SecretKey>::new(mnemonic_obj.to_seed(""))
        .map_err(|e| JsValue::from_str(&format!("Failed to create extended key: {}", e)))?;

    // Convert to string format (KTRV for testnet, KPRV for mainnet)
    let prefix = if is_testnet { Prefix::KTRV } else { Prefix::KPRV };
    let xprv_str = xprv.to_string(prefix).to_string();

    // Create wallet derivation manager
    let derivation_manager = WalletDerivationManager::from_master_xprv(
        &xprv_str,
        false,  // is_multisig = false
        0,      // account_index = 0
        None    // cosigner_index = None
    ).map_err(|e| JsValue::from_str(&format!("Failed to create derivation manager: {}", e)))?;

    // Generate addresses
    let addr_prefix = if is_testnet {
        AddressPrefix::Testnet
    } else {
        AddressPrefix::Mainnet
    };

    // Generate receive addresses (gap limit = 5 for WASM to save memory)
    let mut receive_addresses = Vec::new();
    for i in 0..5u32 {
        let pubkey = derivation_manager.receive_pubkey_manager()
            .derive_pubkey(i)
            .map_err(|e| JsValue::from_str(&format!("Failed to derive receive pubkey: {}", e)))?;

        // Convert secp256k1 pubkey to x-only format (32 bytes)
        // serialize() returns 33 bytes (compressed), we need just the x-coordinate
        let pubkey_compressed = pubkey.serialize();
        let pubkey_xonly = &pubkey_compressed[1..33]; // Skip the prefix byte
        let address = Address::new(addr_prefix.clone(), kaspa_addresses::Version::PubKey, pubkey_xonly);

        receive_addresses.push(AddressInfo {
            address: address.to_string(),
            index: i,
            is_change: false,
            used: false,
        });
    }

    // Generate change addresses
    let mut change_addresses = Vec::new();
    for i in 0..3u32 {
        let pubkey = derivation_manager.change_pubkey_manager()
            .derive_pubkey(i)
            .map_err(|e| JsValue::from_str(&format!("Failed to derive change pubkey: {}", e)))?;

        // Convert secp256k1 pubkey to x-only format (32 bytes)
        let pubkey_compressed = pubkey.serialize();
        let pubkey_xonly = &pubkey_compressed[1..33]; // Skip the prefix byte
        let address = Address::new(addr_prefix.clone(), kaspa_addresses::Version::PubKey, pubkey_xonly);

        change_addresses.push(AddressInfo {
            address: address.to_string(),
            index: i,
            is_change: true,
            used: false,
        });
    }

    // Create wallet info for return
    let wallet_info = WalletInfo {
        primary_address: receive_addresses.first()
            .map(|a| a.address.clone())
            .unwrap_or_default(),
        receive_addresses: receive_addresses.iter().map(|a| a.address.clone()).collect(),
        change_addresses: change_addresses.iter().map(|a| a.address.clone()).collect(),
        is_testnet,
    };

    // Store wallet state globally
    WALLET.with(|w| {
        *w.borrow_mut() = Some(WalletState {
            derivation_manager,
            mnemonic: mnemonic.to_string(),
            is_testnet,
            receive_addresses,
            change_addresses,
        });
    });

    serde_wasm_bindgen::to_value(&wallet_info)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Get the primary receive address
#[wasm_bindgen]
pub fn kaspa_get_receive_address() -> Result<String, JsValue> {
    WALLET.with(|w| {
        let wallet = w.borrow();
        let wallet = wallet.as_ref()
            .ok_or_else(|| JsValue::from_str("Wallet not initialized. Call kaspa_create_wallet() first."))?;

        wallet.receive_addresses.first()
            .map(|a| a.address.clone())
            .ok_or_else(|| JsValue::from_str("No receive address available"))
    })
}

/// Get all receive addresses for monitoring
#[wasm_bindgen]
pub fn kaspa_get_all_addresses() -> Result<JsValue, JsValue> {
    WALLET.with(|w| {
        let wallet = w.borrow();
        let wallet = wallet.as_ref()
            .ok_or_else(|| JsValue::from_str("Wallet not initialized. Call kaspa_create_wallet() first."))?;

        let all_addresses: Vec<String> = wallet.receive_addresses.iter()
            .chain(wallet.change_addresses.iter())
            .map(|a| a.address.clone())
            .collect();

        serde_wasm_bindgen::to_value(&all_addresses)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get a change address for transaction outputs
#[wasm_bindgen]
pub fn kaspa_get_change_address() -> Result<String, JsValue> {
    WALLET.with(|w| {
        let wallet = w.borrow();
        let wallet = wallet.as_ref()
            .ok_or_else(|| JsValue::from_str("Wallet not initialized. Call kaspa_create_wallet() first."))?;

        wallet.change_addresses.first()
            .map(|a| a.address.clone())
            .ok_or_else(|| JsValue::from_str("No change address available"))
    })
}

/// Check if wallet is initialized
#[wasm_bindgen]
pub fn kaspa_wallet_initialized() -> bool {
    WALLET.with(|w| w.borrow().is_some())
}

/// Get wallet mnemonic (for backup purposes - should be protected in production!)
#[wasm_bindgen]
pub fn kaspa_get_mnemonic() -> Result<String, JsValue> {
    WALLET.with(|w| {
        let wallet = w.borrow();
        let wallet = wallet.as_ref()
            .ok_or_else(|| JsValue::from_str("Wallet not initialized"))?;

        Ok(wallet.mnemonic.clone())
    })
}

/// Check if wallet is testnet
#[wasm_bindgen]
pub fn kaspa_is_testnet() -> Result<bool, JsValue> {
    WALLET.with(|w| {
        let wallet = w.borrow();
        let wallet = wallet.as_ref()
            .ok_or_else(|| JsValue::from_str("Wallet not initialized"))?;

        Ok(wallet.is_testnet)
    })
}

// ============================================================================
// UTXO Management Functions
// ============================================================================

/// Add a UTXO to the wallet
#[wasm_bindgen]
pub fn kaspa_wallet_add_utxo(
    address: String,
    transaction_id: String,
    index: u32,
    amount: u64,
    script_public_key: Vec<u8>,
    script_public_key_version: u16,
    is_coinbase: bool,
) -> Result<(), JsValue> {
    let utxo = Utxo {
        transaction_id,
        index,
        amount,
        script_public_key,
        script_public_key_version,
        address: address.clone(),
        is_coinbase,
    };

    WALLET_UTXOS.with(|utxos| {
        let mut utxos = utxos.borrow_mut();
        utxos.entry(address)
            .or_insert_with(Vec::new)
            .push(utxo.clone());
    });

    // Update balance
    WALLET_BALANCE.with(|balance| {
        let mut balance = balance.borrow_mut();
        *balance += amount;
    });

    Ok(())
}

/// Add multiple UTXOs to the wallet in a single call (batch operation)
///
/// This is more efficient than calling kaspa_wallet_add_utxo() multiple times
/// from JavaScript, as it crosses the WASM boundary only once.
#[wasm_bindgen]
pub fn kaspa_wallet_add_utxos_batch(utxos_json: String) -> Result<u32, JsValue> {
    // Define a struct for deserializing UTXOs from JSON
    #[derive(Deserialize)]
    struct UtxoJson {
        address: Option<String>,
        transaction_id: String,
        index: u32,
        amount: u64,
        script_public_key: Vec<u8>,
        script_public_key_version: Option<u16>,
        is_coinbase: bool,
    }

    // Parse JSON array
    let utxo_array: Vec<UtxoJson> = serde_json::from_str(&utxos_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse UTXOs JSON: {}", e)))?;

    if utxo_array.is_empty() {
        return Ok(0);
    }

    let mut added_count = 0u32;
    let mut total_amount = 0u64;

    // Get primary wallet address as fallback
    let default_address = WALLET.with(|w| {
        w.borrow()
            .as_ref()
            .and_then(|wallet| wallet.receive_addresses.first())
            .map(|addr| addr.address.clone())
    });

    // Add each UTXO to storage
    WALLET_UTXOS.with(|utxos| {
        let mut utxos = utxos.borrow_mut();

        for utxo_json in utxo_array {
            // Use address from UTXO or fallback to primary address
            let address = utxo_json.address
                .or_else(|| default_address.clone())
                .ok_or_else(|| JsValue::from_str("No address available for UTXO"))?;

            let utxo = Utxo {
                transaction_id: utxo_json.transaction_id,
                index: utxo_json.index,
                amount: utxo_json.amount,
                script_public_key: utxo_json.script_public_key,
                script_public_key_version: utxo_json.script_public_key_version.unwrap_or(0),
                address: address.clone(),
                is_coinbase: utxo_json.is_coinbase,
            };

            total_amount += utxo.amount;

            utxos.entry(address)
                .or_insert_with(Vec::new)
                .push(utxo);

            added_count += 1;
        }

        Ok::<(), JsValue>(())
    })?;

    // Update balance cache
    WALLET_BALANCE.with(|balance| {
        let mut balance = balance.borrow_mut();
        *balance += total_amount;
    });

    Ok(added_count)
}

/// Remove a spent UTXO
#[wasm_bindgen]
pub fn kaspa_wallet_remove_utxo(transaction_id: String, index: u32) -> Result<(), JsValue> {
    let mut removed_amount = 0u64;

    WALLET_UTXOS.with(|utxos| {
        let mut utxos = utxos.borrow_mut();

        for utxo_list in utxos.values_mut() {
            utxo_list.retain(|utxo| {
                if utxo.transaction_id == transaction_id && utxo.index == index {
                    removed_amount = utxo.amount;
                    false // Remove this UTXO
                } else {
                    true // Keep this UTXO
                }
            });
        }
    });

    // Update balance
    if removed_amount > 0 {
        WALLET_BALANCE.with(|balance| {
            let mut balance = balance.borrow_mut();
            *balance = balance.saturating_sub(removed_amount);
        });
    }

    Ok(())
}

/// Get total wallet balance in sompis
#[wasm_bindgen]
pub fn kaspa_wallet_get_balance() -> u64 {
    WALLET_BALANCE.with(|balance| *balance.borrow())
}

/// Get all spendable UTXOs as JSON
#[wasm_bindgen]
pub fn kaspa_wallet_get_spendable_utxos() -> Result<JsValue, JsValue> {
    WALLET_UTXOS.with(|utxos| {
        let utxos = utxos.borrow();
        let mut all_utxos = Vec::new();

        for utxo_list in utxos.values() {
            all_utxos.extend(utxo_list.clone());
        }

        serde_wasm_bindgen::to_value(&all_utxos)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Get spendable UTXOs with minimum amount filter
#[wasm_bindgen]
pub fn kaspa_wallet_get_spendable_utxos_min(min_amount: u64) -> Result<JsValue, JsValue> {
    WALLET_UTXOS.with(|utxos| {
        let utxos = utxos.borrow();
        let mut filtered_utxos = Vec::new();

        for utxo_list in utxos.values() {
            for utxo in utxo_list {
                if utxo.amount >= min_amount {
                    filtered_utxos.push(utxo.clone());
                }
            }
        }

        serde_wasm_bindgen::to_value(&filtered_utxos)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    })
}

/// Clear all UTXOs (useful for wallet reset)
#[wasm_bindgen]
pub fn kaspa_wallet_clear_utxos() {
    WALLET_UTXOS.with(|utxos| {
        utxos.borrow_mut().clear();
    });
    WALLET_BALANCE.with(|balance| {
        *balance.borrow_mut() = 0;
    });
}

// ============================================================================
// Address Usage Tracking
// ============================================================================

/// Mark an address as used
#[wasm_bindgen]
pub fn kaspa_wallet_mark_address_used(address: String) -> Result<(), JsValue> {
    WALLET.with(|w| {
        let mut wallet = w.borrow_mut();
        let wallet = wallet.as_mut()
            .ok_or_else(|| JsValue::from_str("Wallet not initialized"))?;

        // Check receive addresses
        for addr_info in &mut wallet.receive_addresses {
            if addr_info.address == address {
                addr_info.used = true;
                return Ok(());
            }
        }

        // Check change addresses
        for addr_info in &mut wallet.change_addresses {
            if addr_info.address == address {
                addr_info.used = true;
                return Ok(());
            }
        }

        Err(JsValue::from_str("Address not found in wallet"))
    })
}

/// Get next unused receive address
#[wasm_bindgen]
pub fn kaspa_wallet_get_next_receive_address() -> Result<String, JsValue> {
    WALLET.with(|w| {
        let wallet = w.borrow();
        let wallet = wallet.as_ref()
            .ok_or_else(|| JsValue::from_str("Wallet not initialized"))?;

        for addr_info in &wallet.receive_addresses {
            if !addr_info.used {
                return Ok(addr_info.address.clone());
            }
        }

        Err(JsValue::from_str("No unused receive addresses available"))
    })
}

/// Get next unused change address
#[wasm_bindgen]
pub fn kaspa_wallet_get_next_change_address() -> Result<String, JsValue> {
    WALLET.with(|w| {
        let wallet = w.borrow();
        let wallet = wallet.as_ref()
            .ok_or_else(|| JsValue::from_str("Wallet not initialized"))?;

        for addr_info in &wallet.change_addresses {
            if !addr_info.used {
                return Ok(addr_info.address.clone());
            }
        }

        Err(JsValue::from_str("No unused change addresses available"))
    })
}

// Transaction signing is handled by kaspa-wallet-core
// See tx_signer.rs for the implementation
