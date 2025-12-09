/// Transaction Builder for P2PComm
///
/// This module provides transaction building functionality with:
/// - Message payload embedding (up to 98 KB)
/// - Dust output creation (0.00001 KAS for recipient notification)
/// - Transaction signing with wallet keys
/// - Fee calculation and optimization
/// - RPC client integration for testnet submission

use anyhow::{Result, Context, bail};
use kaspa_consensus_core::tx::{
    Transaction, TransactionInput, TransactionOutput, TransactionOutpoint,
    ScriptPublicKey, ScriptVec,
};
use kaspa_addresses::Address;
use kaspa_hashes::Hash;

/// Kaspa amounts are in sompis (1 KAS = 100,000,000 sompis)
pub const SOMPI_PER_KASPA: u64 = 100_000_000;

/// Dust amount for recipient notification (0.00001 KAS = 1,000 sompis)
pub const DUST_AMOUNT: u64 = 1_000;

/// Maximum payload size in bytes (Kaspa limit is ~100 KB, we use 98 KB to be safe)
pub const MAX_PAYLOAD_SIZE: usize = 98_000;

/// Minimum fee per transaction (in sompis)
pub const MIN_FEE: u64 = 1_000;

/// Fee per byte (in sompis) - rough estimate, will be refined
pub const FEE_PER_BYTE: u64 = 10;

/// Transaction builder for creating Kaspa transactions with payloads
pub struct TransactionBuilder {
    /// Inputs (UTXOs being spent)
    inputs: Vec<TransactionInput>,
    /// Outputs (where funds go)
    outputs: Vec<TransactionOutput>,
    /// Payload data (encrypted message)
    payload: Option<Vec<u8>>,
    /// Change address (where leftover funds return)
    change_address: Option<Address>,
    /// Total input amount (in sompis)
    total_input: u64,
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            payload: None,
            change_address: None,
            total_input: 0,
        }
    }

    /// Add an input UTXO to spend
    pub fn add_input(
        &mut self,
        transaction_id: &str,
        index: u32,
        amount: u64,
        _script_public_key: Vec<u8>,
    ) -> Result<&mut Self> {
        // Parse transaction ID from hex string
        let tx_id_bytes = hex::decode(transaction_id)
            .context("Failed to decode transaction ID")?;

        if tx_id_bytes.len() != 32 {
            bail!("Transaction ID must be 32 bytes, got {}", tx_id_bytes.len());
        }

        // Create Hash from bytes
        let tx_hash = Hash::from_slice(&tx_id_bytes);

        // Create outpoint
        let outpoint = TransactionOutpoint {
            transaction_id: tx_hash.into(),
            index,
        };

        // Create input
        let input = TransactionInput {
            previous_outpoint: outpoint,
            signature_script: vec![],
            sequence: u64::MAX,
            sig_op_count: 1,
        };

        self.inputs.push(input);
        self.total_input += amount;

        Ok(self)
    }

    /// Add a dust output to notify recipient
    pub fn add_dust_output(&mut self, recipient_address: &str) -> Result<&mut Self> {
        let address = Address::try_from(recipient_address)
            .context("Failed to parse recipient address")?;

        let script_public_key = ScriptPublicKey::new(
            0, // version
            ScriptVec::from_slice(&address.payload),
        );

        let output = TransactionOutput {
            value: DUST_AMOUNT,
            script_public_key,
        };

        self.outputs.push(output);

        Ok(self)
    }

    /// Set the payload (encrypted message)
    pub fn set_payload(&mut self, payload: Vec<u8>) -> Result<&mut Self> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            bail!(
                "Payload too large: {} bytes (max: {} bytes)",
                payload.len(),
                MAX_PAYLOAD_SIZE
            );
        }

        self.payload = Some(payload);

        Ok(self)
    }

    /// Set the change address (where leftover funds return)
    pub fn set_change_address(&mut self, address: &str) -> Result<&mut Self> {
        let addr = Address::try_from(address)
            .context("Failed to parse change address")?;

        self.change_address = Some(addr);

        Ok(self)
    }

    /// Calculate the total fee required for this transaction
    pub fn calculate_fee(&self) -> u64 {
        // Rough size estimation:
        // - Each input: ~150 bytes
        // - Each output: ~35 bytes
        // - Payload: actual size
        // - Overhead: ~50 bytes

        let input_size = self.inputs.len() * 150;
        let output_size = self.outputs.len() * 35;
        let payload_size = self.payload.as_ref().map(|p| p.len()).unwrap_or(0);
        let overhead = 50;

        let estimated_size = input_size + output_size + payload_size + overhead;
        let fee = (estimated_size as u64) * FEE_PER_BYTE;

        // Ensure minimum fee
        fee.max(MIN_FEE)
    }

    /// Build the transaction (without signing)
    pub fn build(&mut self) -> Result<Transaction> {
        // Validate inputs
        if self.inputs.is_empty() {
            bail!("Transaction must have at least one input");
        }

        if self.change_address.is_none() {
            bail!("Change address must be set");
        }

        // Calculate fee
        let fee = self.calculate_fee();

        // Calculate total output amount
        let total_output: u64 = self.outputs.iter().map(|o| o.value).sum();

        // Ensure we have enough funds
        if self.total_input < total_output + fee {
            bail!(
                "Insufficient funds: need {} sompis (outputs: {}, fee: {}), have {} sompis",
                total_output + fee,
                total_output,
                fee,
                self.total_input
            );
        }

        // Calculate change amount
        let change = self.total_input - total_output - fee;

        // Add change output if there's any change
        if change > 0 {
            let change_addr = self.change_address.as_ref().unwrap();
            let script_public_key = ScriptPublicKey::new(
                0, // version
                ScriptVec::from_slice(&change_addr.payload),
            );

            let change_output = TransactionOutput {
                value: change,
                script_public_key,
            };

            self.outputs.push(change_output);
        }

        // Create transaction
        let tx = Transaction::new(
            0, // version
            self.inputs.clone(),
            self.outputs.clone(),
            0, // lock_time
            Default::default(), // subnetwork_id
            0, // gas
            self.payload.clone().unwrap_or_default(),
        );

        Ok(tx)
    }

    /// Get transaction summary for debugging
    pub fn summary(&self) -> String {
        let total_output: u64 = self.outputs.iter().map(|o| o.value).sum();
        let fee = self.calculate_fee();
        let change = if self.total_input > total_output + fee {
            self.total_input - total_output - fee
        } else {
            0
        };

        format!(
            "Transaction Summary:\n\
             - Inputs: {} ({} sompis / {} KAS)\n\
             - Outputs: {} ({} sompis / {} KAS)\n\
             - Fee: {} sompis / {} KAS\n\
             - Change: {} sompis / {} KAS\n\
             - Payload: {} bytes",
            self.inputs.len(),
            self.total_input,
            self.total_input as f64 / SOMPI_PER_KASPA as f64,
            self.outputs.len(),
            total_output,
            total_output as f64 / SOMPI_PER_KASPA as f64,
            fee,
            fee as f64 / SOMPI_PER_KASPA as f64,
            change,
            change as f64 / SOMPI_PER_KASPA as f64,
            self.payload.as_ref().map(|p| p.len()).unwrap_or(0)
        )
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to convert KAS to sompis
pub fn kas_to_sompis(kas: f64) -> u64 {
    (kas * SOMPI_PER_KASPA as f64) as u64
}

/// Helper function to convert sompis to KAS
pub fn sompis_to_kas(sompis: u64) -> f64 {
    sompis as f64 / SOMPI_PER_KASPA as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_builder_new() {
        let builder = TransactionBuilder::new();
        assert_eq!(builder.inputs.len(), 0);
        assert_eq!(builder.outputs.len(), 0);
        assert!(builder.payload.is_none());
        assert!(builder.change_address.is_none());
        assert_eq!(builder.total_input, 0);
    }

    #[test]
    fn test_kas_conversion() {
        assert_eq!(kas_to_sompis(1.0), 100_000_000);
        assert_eq!(kas_to_sompis(0.5), 50_000_000);
        assert_eq!(kas_to_sompis(0.00001), 1_000);

        assert_eq!(sompis_to_kas(100_000_000), 1.0);
        assert_eq!(sompis_to_kas(50_000_000), 0.5);
        assert_eq!(sompis_to_kas(1_000), 0.00001);
    }

    #[test]
    fn test_dust_amount() {
        assert_eq!(DUST_AMOUNT, 1_000);
        assert_eq!(sompis_to_kas(DUST_AMOUNT), 0.00001);
    }

    #[test]
    fn test_payload_size_limit() {
        let mut builder = TransactionBuilder::new();

        // Should accept payload under limit
        let small_payload = vec![0u8; 1000];
        assert!(builder.set_payload(small_payload).is_ok());

        // Should reject payload over limit
        let large_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(builder.set_payload(large_payload).is_err());
    }

    #[test]
    fn test_fee_calculation() {
        let mut builder = TransactionBuilder::new();

        // Fee for empty transaction
        let fee_empty = builder.calculate_fee();
        assert!(fee_empty >= MIN_FEE);

        // Fee increases with inputs
        builder.add_input(
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            1_000_000,
            vec![],
        ).unwrap();
        let fee_with_input = builder.calculate_fee();
        assert!(fee_with_input > fee_empty);

        // Fee increases with payload
        builder.set_payload(vec![0u8; 1000]).unwrap();
        let fee_with_payload = builder.calculate_fee();
        assert!(fee_with_payload > fee_with_input);
    }

    #[test]
    fn test_build_requires_inputs() {
        let mut builder = TransactionBuilder::new();
        builder.set_change_address("kaspatest:qrpupyeqkk6hj8793pj2a7jggf38dduq9sv3l0k4ax3re4snglyakwp8s29ex").unwrap();

        // Should fail without inputs
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_build_requires_change_address() {
        let mut builder = TransactionBuilder::new();
        builder.add_input(
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            1_000_000,
            vec![],
        ).unwrap();

        // Should fail without change address
        assert!(builder.build().is_err());
    }
}
