//! Transaction Signing using kaspa-consensus-core
//!
//! This module provides transaction signing functionality using Kaspa's
//! official signing utilities from kaspa-consensus-core.

use wasm_bindgen::prelude::*;
use kaspa_consensus_core::tx::{Transaction, ScriptPublicKey, SignableTransaction, ScriptVec};
use kaspa_consensus_core::tx::UtxoEntry;
use kaspa_consensus_core::sign::sign_with_multiple_v2;
use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use crate::kaspa::wallet_bridge::{WALLET, WALLET_UTXOS};

/// Sign a transaction using kaspa-consensus-core's official signing
///
/// Takes an unsigned transaction JSON and returns a signed transaction JSON
#[wasm_bindgen]
pub async fn kaspa_sign_transaction(tx_json: String) -> Result<String, JsValue> {
    // Parse the unsigned transaction
    let tx: Transaction = serde_json::from_str(&tx_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse transaction: {}", e)))?;

    // Get private keys for all inputs
    let private_keys = get_private_keys_for_inputs(&tx)?;

    web_sys::console::log_1(&format!("Signing with {} private keys", private_keys.len()).into());

    // Get UTXO entries for the transaction inputs
    let utxo_entries = get_utxo_entries_for_tx(&tx)?;

    // Debug: Log UTXO entries
    for (i, entry) in utxo_entries.iter().enumerate() {
        web_sys::console::log_1(&format!(
            "UTXO {}: amount={}, script_version={}, script_len={}, script={}",
            i, entry.amount, entry.script_public_key.version(),
            entry.script_public_key.script().len(),
            hex::encode(entry.script_public_key.script())
        ).into());
    }

    // Create SignableTransaction with UTXO entries
    let signable_tx = SignableTransaction::with_entries(tx, utxo_entries);

    // Debug: Log transaction details BEFORE signing
    web_sys::console::log_1(&format!("=== Transaction Details Before Signing ===").into());
    web_sys::console::log_1(&format!("TX version: {}", signable_tx.tx.version).into());
    web_sys::console::log_1(&format!("TX lock_time: {}", signable_tx.tx.lock_time).into());
    web_sys::console::log_1(&format!("TX subnetwork_id: {}", hex::encode(signable_tx.tx.subnetwork_id.as_ref() as &[u8])).into());
    web_sys::console::log_1(&format!("TX gas: {}", signable_tx.tx.gas).into());
    web_sys::console::log_1(&format!("TX payload len: {}", signable_tx.tx.payload.len()).into());

    for (i, input) in signable_tx.tx.inputs.iter().enumerate() {
        web_sys::console::log_1(&format!(
            "Input {}: outpoint={}:{}, sequence={}, sig_op_count={}",
            i,
            input.previous_outpoint.transaction_id,
            input.previous_outpoint.index,
            input.sequence,
            input.sig_op_count
        ).into());
    }

    for (i, output) in signable_tx.tx.outputs.iter().enumerate() {
        web_sys::console::log_1(&format!(
            "Output {}: value={}, script_version={}, script={}",
            i,
            output.value,
            output.script_public_key.version(),
            hex::encode(output.script_public_key.script())
        ).into());
    }

    // Debug: Compute and log sighash for input 0
    {
        let reused_values = SigHashReusedValuesUnsync::new();
        let verifiable = signable_tx.as_verifiable();
        for i in 0..signable_tx.tx.inputs.len() {
            let sighash = calc_schnorr_signature_hash(&verifiable, i, SIG_HASH_ALL, &reused_values);
            web_sys::console::log_1(&format!(
                "Computed sighash for input {}: {}",
                i, sighash
            ).into());
        }
    }

    // Convert private keys to the format expected by sign_with_multiple_v2
    let privkey_refs: Vec<[u8; 32]> = private_keys.iter().map(|k| *k).collect();

    // Sign using Kaspa's official signing function
    let signed = sign_with_multiple_v2(signable_tx, &privkey_refs);

    let signed_tx = match signed {
        kaspa_consensus_core::sign::Signed::Fully(tx) => tx,
        kaspa_consensus_core::sign::Signed::Partially(tx) => {
            web_sys::console::log_1(&"Warning: Transaction only partially signed".into());
            tx
        }
    };

    // Debug: Log signature scripts
    for (i, input) in signed_tx.tx.inputs.iter().enumerate() {
        web_sys::console::log_1(&format!(
            "Input {} sig_script: {} (len={})",
            i, hex::encode(&input.signature_script), input.signature_script.len()
        ).into());
    }

    // Serialize signed transaction
    serde_json::to_string(&signed_tx.tx)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize signed transaction: {}", e)))
}

/// Get private keys for all transaction inputs
fn get_private_keys_for_inputs(tx: &Transaction) -> Result<Vec<[u8; 32]>, JsValue> {
    use kaspa_bip32::{ChildNumber, ExtendedPrivateKey, SecretKey as Bip32SecretKey, Mnemonic as BipMnemonic, Language, Prefix};

    // Get mnemonic from wallet
    let (mnemonic, is_testnet) = WALLET.with(|w| {
        let wallet = w.borrow();
        let wallet = wallet.as_ref()
            .ok_or_else(|| JsValue::from_str("Wallet not initialized"))?;
        Ok::<_, JsValue>((wallet.mnemonic.clone(), wallet.is_testnet))
    })?;

    // Create master key from mnemonic
    let mnemonic_obj = BipMnemonic::new(&mnemonic, Language::English)
        .map_err(|e| JsValue::from_str(&format!("Invalid mnemonic: {}", e)))?;

    let xprv = ExtendedPrivateKey::<Bip32SecretKey>::new(mnemonic_obj.to_seed(""))
        .map_err(|e| JsValue::from_str(&format!("Failed to create extended key: {}", e)))?;

    let mut private_keys = Vec::new();

    for input in &tx.inputs {
        let tx_id = input.previous_outpoint.transaction_id.to_string();
        let index = input.previous_outpoint.index;

        // Find which address owns this UTXO
        let utxo_address = find_utxo_address(&tx_id, index)?;

        // Find key index for this address
        let (key_index, is_change) = find_key_index_for_address(&utxo_address)?;

        web_sys::console::log_1(&format!(
            "Input: UTXO {}:{}, address={}, key_index={}, is_change={}",
            tx_id, index, utxo_address, key_index, is_change
        ).into());

        // Derive private key: m/44'/111111'/0'/[change]/[index]
        let change_type = if is_change { 1u32 } else { 0u32 };

        let purpose_key = xprv.derive_child(ChildNumber::new(44, true)
            .map_err(|e| JsValue::from_str(&format!("Failed to create purpose child: {}", e)))?)
            .map_err(|e| JsValue::from_str(&format!("Failed to derive purpose: {}", e)))?;

        let coin_key = purpose_key.derive_child(ChildNumber::new(111111, true)
            .map_err(|e| JsValue::from_str(&format!("Failed to create coin child: {}", e)))?)
            .map_err(|e| JsValue::from_str(&format!("Failed to derive coin: {}", e)))?;

        let account_key = coin_key.derive_child(ChildNumber::new(0, true)
            .map_err(|e| JsValue::from_str(&format!("Failed to create account child: {}", e)))?)
            .map_err(|e| JsValue::from_str(&format!("Failed to derive account: {}", e)))?;

        let change_key = account_key.derive_child(ChildNumber::new(change_type, false)
            .map_err(|e| JsValue::from_str(&format!("Failed to create change child: {}", e)))?)
            .map_err(|e| JsValue::from_str(&format!("Failed to derive change: {}", e)))?;

        let final_key = change_key.derive_child(ChildNumber::new(key_index, false)
            .map_err(|e| JsValue::from_str(&format!("Failed to create index child: {}", e)))?)
            .map_err(|e| JsValue::from_str(&format!("Failed to derive index: {}", e)))?;

        let privkey = final_key.private_key();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&privkey.secret_bytes()[..]);

        // Debug: Log derived public key
        let secp = secp256k1::Secp256k1::new();
        let secret_key = secp256k1::SecretKey::from_slice(&key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {}", e)))?;
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let pubkey = keypair.x_only_public_key().0;
        web_sys::console::log_1(&format!(
            "Derived pubkey for input: {}",
            hex::encode(pubkey.serialize())
        ).into());

        private_keys.push(key_bytes);
    }

    Ok(private_keys)
}

/// Get UTXO entries for transaction inputs
fn get_utxo_entries_for_tx(tx: &Transaction) -> Result<Vec<UtxoEntry>, JsValue> {
    let mut entries = Vec::new();

    for input in &tx.inputs {
        let tx_id = input.previous_outpoint.transaction_id.to_string();
        let index = input.previous_outpoint.index;

        // Find UTXO in our storage
        let utxo = WALLET_UTXOS.with(|utxos| {
            let utxos = utxos.borrow();
            for utxo_list in utxos.values() {
                for utxo in utxo_list {
                    if utxo.transaction_id == tx_id && utxo.index == index {
                        return Ok(utxo.clone());
                    }
                }
            }
            Err(JsValue::from_str(&format!("UTXO not found: {}:{}", tx_id, index)))
        })?;

        // Create UtxoEntry with correct ScriptPublicKey
        // The stored script_public_key is just the script bytes (without version prefix)
        // Use the actual version from the UTXO (stored when fetched from RPC)
        let script_pubkey = ScriptPublicKey::new(
            utxo.script_public_key_version,
            ScriptVec::from_slice(&utxo.script_public_key)
        );

        let entry = UtxoEntry::new(
            utxo.amount,
            script_pubkey,
            0,     // block_daa_score - not used in sighash
            false, // is_coinbase - not used in sighash
        );

        entries.push(entry);
    }

    Ok(entries)
}

/// Find which address owns a UTXO
fn find_utxo_address(tx_id: &str, index: u32) -> Result<String, JsValue> {
    WALLET_UTXOS.with(|utxos| {
        let utxos = utxos.borrow();
        for utxo_list in utxos.values() {
            for utxo in utxo_list {
                if utxo.transaction_id == tx_id && utxo.index == index {
                    return Ok(utxo.address.clone());
                }
            }
        }
        Err(JsValue::from_str(&format!("UTXO not found: {}:{}", tx_id, index)))
    })
}

/// Find the key index and type (receive/change) for an address
fn find_key_index_for_address(address: &str) -> Result<(u32, bool), JsValue> {
    WALLET.with(|w| {
        let wallet = w.borrow();
        let wallet = wallet.as_ref()
            .ok_or_else(|| JsValue::from_str("Wallet not initialized"))?;

        // Check receive addresses
        for addr_info in &wallet.receive_addresses {
            if addr_info.address == address {
                return Ok((addr_info.index, false)); // false = receive address
            }
        }

        // Check change addresses
        for addr_info in &wallet.change_addresses {
            if addr_info.address == address {
                return Ok((addr_info.index, true)); // true = change address
            }
        }

        Err(JsValue::from_str(&format!("Address not found in wallet: {}", address)))
    })
}
