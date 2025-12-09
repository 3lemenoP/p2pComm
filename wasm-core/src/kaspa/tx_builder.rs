//! Kaspa Transaction Builder for WASM
//!
//! Provides transaction building functionality for P2PComm:
//! - Message payload embedding (up to 98 KB)
//! - Dust output creation for recipient notification
//! - Fee calculation

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

use kaspa_consensus_core::tx::{
    Transaction, TransactionInput, TransactionOutput, TransactionOutpoint,
    ScriptPublicKey, ScriptVec,
};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_addresses::Address;
use kaspa_hashes::Hash;

/// Kaspa amounts are in sompis (1 KAS = 100,000,000 sompis)
pub const SOMPI_PER_KASPA: u64 = 100_000_000;

/// Dust amount for recipient notification (0.2 KAS = 20,000,000 sompis)
/// KIP-9 storage mass penalizes small outputs heavily (mass = 10^12 / output_value)
/// Outputs below ~0.1 KAS exceed the 100,000 mass limit. We use 0.2 KAS for safety.
pub const DUST_AMOUNT: u64 = 20_000_000;

/// Maximum payload size in bytes (Kaspa limit is ~100 KB, we use 98 KB to be safe)
pub const MAX_PAYLOAD_SIZE: usize = 98_000;

/// Minimum fee per transaction (in sompis)
pub const MIN_FEE: u64 = 1_000;

/// Fee per byte (in sompis) - rough estimate
pub const FEE_PER_BYTE: u64 = 10;

/// Kaspa script opcodes
const OP_DATA_32: u8 = 0x20; // Push next 32 bytes as data
const OP_DATA_33: u8 = 0x21; // Push next 33 bytes as data
const OP_CHECK_SIG: u8 = 0xAC; // ECDSA signature check
const OP_CHECK_SIG_ECDSA: u8 = 0xAD; // ECDSA signature check (secp256k1)

/// UTXO input for building transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInput {
    pub transaction_id: String,
    pub index: u32,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
}

/// Transaction output info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutputInfo {
    pub address: String,
    pub amount: u64,
}

/// Built transaction ready for signing/submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltTransaction {
    pub transaction_json: String,
    pub total_input: u64,
    pub total_output: u64,
    pub fee: u64,
    pub payload_size: usize,
}

/// Create a standard P2PK (Pay-to-Public-Key) script from address payload
///
/// Constructs: [OpData32][32-byte-pubkey][OpCheckSig]
/// or for ECDSA: [OpData33][33-byte-pubkey][OpCheckSigECDSA]
fn build_p2pk_script(address: &Address) -> Result<Vec<u8>, JsValue> {
    let payload_len = address.payload.len();

    match payload_len {
        32 => {
            // Standard Schnorr signature: OpData32 + pubkey + OpCheckSig
            let mut script = Vec::with_capacity(34);
            script.push(OP_DATA_32);
            script.extend_from_slice(&address.payload);
            script.push(OP_CHECK_SIG);
            Ok(script)
        }
        33 => {
            // ECDSA signature: OpData33 + pubkey + OpCheckSigECDSA
            let mut script = Vec::with_capacity(35);
            script.push(OP_DATA_33);
            script.extend_from_slice(&address.payload);
            script.push(OP_CHECK_SIG_ECDSA);
            Ok(script)
        }
        _ => Err(JsValue::from_str(&format!(
            "Unsupported payload length: {} bytes (expected 32 or 33)",
            payload_len
        )))
    }
}

/// Build a transaction with a payload for sending messages
///
/// # Arguments
/// * `utxos_json` - JSON array of UtxoInput objects to spend
/// * `recipient_address` - Address to send dust notification to
/// * `change_address` - Address to return change to
/// * `payload` - Message payload bytes (will be embedded in transaction)
#[wasm_bindgen]
pub fn kaspa_build_payload_transaction(
    utxos_json: String,
    recipient_address: String,
    change_address: String,
    payload: Vec<u8>,
) -> Result<JsValue, JsValue> {
    // Validate payload size
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(JsValue::from_str(&format!(
            "Payload too large: {} bytes (max {})",
            payload.len(),
            MAX_PAYLOAD_SIZE
        )));
    }

    // Parse UTXOs
    let utxos: Vec<UtxoInput> = serde_json::from_str(&utxos_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse UTXOs: {}", e)))?;

    if utxos.is_empty() {
        return Err(JsValue::from_str("No UTXOs provided"));
    }

    // Calculate total input
    let total_input: u64 = utxos.iter().map(|u| u.amount).sum();

    // Build inputs
    let mut inputs = Vec::new();
    for utxo in &utxos {
        let tx_id_bytes = hex::decode(&utxo.transaction_id)
            .map_err(|e| JsValue::from_str(&format!("Invalid transaction ID: {}", e)))?;

        if tx_id_bytes.len() != 32 {
            return Err(JsValue::from_str(&format!(
                "Transaction ID must be 32 bytes, got {}",
                tx_id_bytes.len()
            )));
        }

        let tx_hash = Hash::from_slice(&tx_id_bytes);

        let outpoint = TransactionOutpoint {
            transaction_id: tx_hash.into(),
            index: utxo.index,
        };

        let input = TransactionInput {
            previous_outpoint: outpoint,
            signature_script: vec![],
            sequence: 0,  // Must be 0, matching official Kaspa Generator
            sig_op_count: 1,
        };

        inputs.push(input);
    }

    // Build outputs
    let mut outputs = Vec::new();

    // 1. Dust output to recipient (notification)
    let recipient_addr = Address::try_from(recipient_address.as_str())
        .map_err(|e| JsValue::from_str(&format!("Invalid recipient address: {}", e)))?;

    // Determine script version based on address type
    let recipient_version = match recipient_addr.version {
        kaspa_addresses::Version::PubKey => 0,
        kaspa_addresses::Version::PubKeyECDSA => 0,
        kaspa_addresses::Version::ScriptHash => 1,
    };

    web_sys::console::log_1(&format!("Recipient Address: {}", recipient_address).into());
    web_sys::console::log_1(&format!("Recipient Version: {}", recipient_version).into());
    web_sys::console::log_1(&format!("Recipient Payload Len: {}", recipient_addr.payload.len()).into());

    // Build proper P2PK script with opcodes
    let recipient_script_bytes = if recipient_version == 0 {
        // P2PK: Build standard script with opcodes
        build_p2pk_script(&recipient_addr)?
    } else {
        // P2SH: Use payload directly (script hash)
        recipient_addr.payload.to_vec()
    };

    web_sys::console::log_1(&format!("Recipient Script Bytes: {}", hex::encode(&recipient_script_bytes)).into());

    let recipient_script = ScriptPublicKey::new(
        recipient_version,
        ScriptVec::from_slice(&recipient_script_bytes),
    );

    outputs.push(TransactionOutput {
        value: DUST_AMOUNT,
        script_public_key: recipient_script,
    });

    // Calculate fee
    let estimated_size = estimate_transaction_size(inputs.len(), 2, payload.len());
    let fee = std::cmp::max(MIN_FEE, estimated_size as u64 * FEE_PER_BYTE);

    // Calculate change
    let total_output = DUST_AMOUNT;
    let change_amount = total_input.checked_sub(total_output + fee)
        .ok_or_else(|| JsValue::from_str(&format!(
            "Insufficient funds: have {} sompis, need {} + {} fee",
            total_input, total_output, fee
        )))?;

    // 2. Change output (if there's any)
    if change_amount > DUST_AMOUNT {
        let change_addr = Address::try_from(change_address.as_str())
            .map_err(|e| JsValue::from_str(&format!("Invalid change address: {}", e)))?;

        let change_version = match change_addr.version {
            kaspa_addresses::Version::PubKey => 0,
            kaspa_addresses::Version::PubKeyECDSA => 0,
            kaspa_addresses::Version::ScriptHash => 1,
        };

        // Build proper P2PK script with opcodes for change output
        let change_script_bytes = if change_version == 0 {
            build_p2pk_script(&change_addr)?
        } else {
            change_addr.payload.to_vec()
        };

        let change_script = ScriptPublicKey::new(
            change_version,
            ScriptVec::from_slice(&change_script_bytes),
        );

        outputs.push(TransactionOutput {
            value: change_amount,
            script_public_key: change_script,
        });
    }

    // Build transaction
    let tx = Transaction::new(
        0,                          // version
        inputs,
        outputs,
        0,                          // lock_time
        SUBNETWORK_ID_NATIVE,       // subnetwork_id
        0,                          // gas
        payload,                    // payload
    );

    // Serialize transaction to JSON
    let tx_json = serde_json::to_string(&tx)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize transaction: {}", e)))?;

    web_sys::console::log_1(&format!("Tx JSON: {}", tx_json).into());

    let result = BuiltTransaction {
        transaction_json: tx_json,
        total_input,
        total_output: DUST_AMOUNT + change_amount,
        fee,
        payload_size: tx.payload.len(),
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Estimate transaction size in bytes
fn estimate_transaction_size(num_inputs: usize, num_outputs: usize, payload_size: usize) -> usize {
    // Base transaction overhead
    let base_size = 10;
    // Each input ~148 bytes (with signature)
    let input_size = num_inputs * 148;
    // Each output ~34 bytes
    let output_size = num_outputs * 34;
    // Payload
    base_size + input_size + output_size + payload_size
}

/// Calculate fee for a given transaction size
#[wasm_bindgen]
pub fn kaspa_calculate_fee(num_inputs: u32, num_outputs: u32, payload_size: u32) -> u64 {
    let size = estimate_transaction_size(
        num_inputs as usize,
        num_outputs as usize,
        payload_size as usize,
    );
    std::cmp::max(MIN_FEE, size as u64 * FEE_PER_BYTE)
}

/// Get the dust amount constant
#[wasm_bindgen]
pub fn kaspa_get_dust_amount() -> u64 {
    DUST_AMOUNT
}

/// Get the max payload size constant
#[wasm_bindgen]
pub fn kaspa_get_max_payload_size() -> u32 {
    MAX_PAYLOAD_SIZE as u32
}

/// Convert KAS to sompis
#[wasm_bindgen]
pub fn kaspa_kas_to_sompis(kas: f64) -> u64 {
    (kas * SOMPI_PER_KASPA as f64) as u64
}

/// Convert sompis to KAS
#[wasm_bindgen]
pub fn kaspa_sompis_to_kas(sompis: u64) -> f64 {
    sompis as f64 / SOMPI_PER_KASPA as f64
}
