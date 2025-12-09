/// Wallet Manager for P2PComm
///
/// This module provides HD wallet functionality with:
/// - Deterministic derivation from user password
/// - Address pool management (receive/change addresses)
/// - UTXO tracking and balance management
/// - Integration with message payload system

use anyhow::{Result, Context, bail};
use kaspa_addresses::{Address, Prefix as AddressPrefix};
use kaspa_wallet_keys::derivation::gen1::{WalletDerivationManager, PubkeyDerivationManager};
use kaspa_wallet_keys::derivation::traits::WalletDerivationManagerTrait;
use kaspa_bip32::{Mnemonic, Language, ExtendedPrivateKey, SecretKey, Prefix};
use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutput, TransactionId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};

/// UTXO (Unspent Transaction Output) representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub transaction_id: String,
    pub index: u32,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub address: String,
    pub is_coinbase: bool,
}

/// Address info with derivation path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    pub address: String,
    pub index: u32,
    pub is_change: bool,
    pub used: bool,
}

/// Wallet configuration
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// Number of receive addresses to pre-generate
    pub receive_gap_limit: u32,
    /// Number of change addresses to pre-generate
    pub change_gap_limit: u32,
    /// Minimum confirmations for UTXO to be spendable
    pub min_confirmations: u64,
    /// Network (testnet/mainnet)
    pub is_testnet: bool,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            receive_gap_limit: 20,
            change_gap_limit: 10,
            min_confirmations: 1,
            is_testnet: true,
        }
    }
}

/// Main P2PComm Wallet Manager
pub struct P2PCommWallet {
    /// Wallet derivation manager (for key derivation)
    derivation_manager: WalletDerivationManager,
    /// Mnemonic phrase (encrypted in production)
    mnemonic: String,
    /// Master extended private key string
    xprv_str: String,
    /// Configuration
    config: WalletConfig,
    /// Receive addresses (index -> AddressInfo)
    receive_addresses: HashMap<u32, AddressInfo>,
    /// Change addresses (index -> AddressInfo)
    change_addresses: HashMap<u32, AddressInfo>,
    /// UTXOs by address
    utxos: Arc<Mutex<HashMap<String, Vec<Utxo>>>>,
    /// Balance cache
    balance: Arc<Mutex<u64>>,
}

impl P2PCommWallet {
    /// Create new wallet from password
    ///
    /// This derives a deterministic mnemonic from the user's password
    /// using a KDF (key derivation function) to ensure the wallet can be
    /// recreated from the same password.
    pub fn from_password(password: &str, config: WalletConfig) -> Result<Self> {
        // Use password as seed for deterministic mnemonic generation
        // In production, this should use Argon2id or PBKDF2
        // For now, using simple SHA256 hash as seed
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"p2pcomm-kaspa-wallet-v1"); // Salt for domain separation
        let hash = hasher.finalize();

        // Generate mnemonic from hash (deterministic)
        let mnemonic = Mnemonic::from_entropy(hash.to_vec(), Language::English)
            .context("Failed to create mnemonic from password")?;

        Self::from_mnemonic(mnemonic.phrase(), config)
    }

    /// Create wallet from existing mnemonic
    pub fn from_mnemonic(mnemonic: &str, config: WalletConfig) -> Result<Self> {
        // Parse mnemonic
        let mnemonic_obj = Mnemonic::new(mnemonic, Language::English)
            .context("Failed to parse mnemonic")?;

        // Create extended private key from mnemonic
        let xprv = ExtendedPrivateKey::<SecretKey>::new(mnemonic_obj.to_seed(""))
            .context("Failed to create extended private key")?;

        // Convert to string format (KTRV for testnet, KPRV for mainnet)
        let prefix = if config.is_testnet { Prefix::KTRV } else { Prefix::KPRV };
        let xprv_str = xprv.to_string(prefix).to_string();

        // Create wallet derivation manager
        let derivation_manager = WalletDerivationManager::from_master_xprv(
            &xprv_str,
            false,  // is_multisig = false
            0,      // account_index = 0
            None    // cosigner_index = None
        ).context("Failed to create wallet derivation manager")?;

        let mut wallet = Self {
            derivation_manager,
            mnemonic: mnemonic.to_string(),
            xprv_str,
            config: config.clone(),
            receive_addresses: HashMap::new(),
            change_addresses: HashMap::new(),
            utxos: Arc::new(Mutex::new(HashMap::new())),
            balance: Arc::new(Mutex::new(0)),
        };

        // Pre-generate addresses according to gap limit
        wallet.generate_addresses()?;

        Ok(wallet)
    }

    /// Generate addresses up to gap limit
    fn generate_addresses(&mut self) -> Result<()> {
        let addr_prefix = if self.config.is_testnet {
            AddressPrefix::Testnet
        } else {
            AddressPrefix::Mainnet
        };

        // Generate receive addresses
        for index in 0..self.config.receive_gap_limit {
            let pubkey = self.derivation_manager.derive_receive_pubkey(index)
                .context("Failed to derive receive pubkey")?;

            let address = PubkeyDerivationManager::create_address(
                &pubkey,
                addr_prefix,
                false  // use schnorr
            ).context("Failed to create address")?;

            self.receive_addresses.insert(index, AddressInfo {
                address: address.to_string(),
                index,
                is_change: false,
                used: false,
            });
        }

        // Generate change addresses
        for index in 0..self.config.change_gap_limit {
            let pubkey = self.derivation_manager.derive_change_pubkey(index)
                .context("Failed to derive change pubkey")?;

            let address = PubkeyDerivationManager::create_address(
                &pubkey,
                addr_prefix,
                false  // use schnorr
            ).context("Failed to create address")?;

            self.change_addresses.insert(index, AddressInfo {
                address: address.to_string(),
                index,
                is_change: true,
                used: false,
            });
        }

        Ok(())
    }

    /// Get the primary receive address (index 0)
    pub fn get_primary_address(&self) -> Result<String> {
        self.receive_addresses
            .get(&0)
            .map(|info| info.address.clone())
            .context("Primary address not found")
    }

    /// Get next unused receive address
    pub fn get_next_receive_address(&mut self) -> Result<String> {
        for index in 0..self.config.receive_gap_limit {
            if let Some(addr_info) = self.receive_addresses.get(&index) {
                if !addr_info.used {
                    return Ok(addr_info.address.clone());
                }
            }
        }
        bail!("No unused receive addresses available")
    }

    /// Get next unused change address
    pub fn get_next_change_address(&mut self) -> Result<String> {
        for index in 0..self.config.change_gap_limit {
            if let Some(addr_info) = self.change_addresses.get(&index) {
                if !addr_info.used {
                    return Ok(addr_info.address.clone());
                }
            }
        }
        bail!("No unused change addresses available")
    }

    /// Mark address as used
    pub fn mark_address_used(&mut self, address: &str) {
        // Check receive addresses
        for addr_info in self.receive_addresses.values_mut() {
            if addr_info.address == address {
                addr_info.used = true;
                return;
            }
        }
        // Check change addresses
        for addr_info in self.change_addresses.values_mut() {
            if addr_info.address == address {
                addr_info.used = true;
                return;
            }
        }
    }

    /// Get all addresses (for monitoring)
    pub fn get_all_addresses(&self) -> Vec<String> {
        let mut addresses = Vec::new();

        // Add receive addresses
        for addr_info in self.receive_addresses.values() {
            addresses.push(addr_info.address.clone());
        }

        // Add change addresses
        for addr_info in self.change_addresses.values() {
            addresses.push(addr_info.address.clone());
        }

        addresses
    }

    /// Add UTXO to wallet
    pub fn add_utxo(&self, utxo: Utxo) -> Result<()> {
        let mut utxos = self.utxos.lock()
            .map_err(|e| anyhow::anyhow!("Failed to lock UTXOs: {}", e))?;

        utxos.entry(utxo.address.clone())
            .or_insert_with(Vec::new)
            .push(utxo.clone());

        // Update balance
        let mut balance = self.balance.lock()
            .map_err(|e| anyhow::anyhow!("Failed to lock balance: {}", e))?;
        *balance += utxo.amount;

        Ok(())
    }

    /// Remove spent UTXO
    pub fn remove_utxo(&self, tx_id: &str, index: u32) -> Result<()> {
        let mut utxos = self.utxos.lock()
            .map_err(|e| anyhow::anyhow!("Failed to lock UTXOs: {}", e))?;

        let mut removed_amount = 0u64;

        for utxo_list in utxos.values_mut() {
            utxo_list.retain(|utxo| {
                if utxo.transaction_id == tx_id && utxo.index == index {
                    removed_amount = utxo.amount;
                    false // Remove this UTXO
                } else {
                    true // Keep this UTXO
                }
            });
        }

        // Update balance
        if removed_amount > 0 {
            let mut balance = self.balance.lock()
                .map_err(|e| anyhow::anyhow!("Failed to lock balance: {}", e))?;
            *balance = balance.saturating_sub(removed_amount);
        }

        Ok(())
    }

    /// Get total balance
    pub fn get_balance(&self) -> Result<u64> {
        let balance = self.balance.lock()
            .map_err(|e| anyhow::anyhow!("Failed to lock balance: {}", e))?;
        Ok(*balance)
    }

    /// Get spendable UTXOs
    pub fn get_spendable_utxos(&self) -> Result<Vec<Utxo>> {
        let utxos = self.utxos.lock()
            .map_err(|e| anyhow::anyhow!("Failed to lock UTXOs: {}", e))?;

        let mut all_utxos = Vec::new();
        for utxo_list in utxos.values() {
            all_utxos.extend(utxo_list.clone());
        }

        Ok(all_utxos)
    }

    /// Get mnemonic (for backup)
    pub fn get_mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Export wallet info for debugging
    pub fn export_info(&self) -> Result<String> {
        let info = serde_json::json!({
            "primary_address": self.get_primary_address()?,
            "balance": self.get_balance()?,
            "receive_addresses": self.receive_addresses.values().collect::<Vec<_>>(),
            "change_addresses": self.change_addresses.values().collect::<Vec<_>>(),
            "utxo_count": self.get_spendable_utxos()?.len(),
        });
        Ok(serde_json::to_string_pretty(&info)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_from_password() {
        let config = WalletConfig::default();
        let wallet = P2PCommWallet::from_password("test_password_123", config).unwrap();

        assert!(!wallet.get_primary_address().unwrap().is_empty());
        assert_eq!(wallet.receive_addresses.len(), 20); // Gap limit
        assert_eq!(wallet.change_addresses.len(), 10);
    }

    #[test]
    fn test_wallet_deterministic() {
        let config = WalletConfig::default();
        let wallet1 = P2PCommWallet::from_password("same_password", config.clone()).unwrap();
        let wallet2 = P2PCommWallet::from_password("same_password", config).unwrap();

        // Same password should generate same addresses
        assert_eq!(wallet1.get_primary_address().unwrap(), wallet2.get_primary_address().unwrap());
    }

    #[test]
    fn test_address_generation() {
        let config = WalletConfig::default();
        let mut wallet = P2PCommWallet::from_password("test", config).unwrap();

        let addr1 = wallet.get_next_receive_address().unwrap();
        let addr2 = wallet.get_next_receive_address().unwrap();

        // Both should return the first unused address
        assert_eq!(addr1, addr2);

        // Mark as used
        wallet.mark_address_used(&addr1);

        let addr3 = wallet.get_next_receive_address().unwrap();
        assert_ne!(addr1, addr3); // Should return next address
    }

    #[test]
    fn test_utxo_management() {
        let config = WalletConfig::default();
        let wallet = P2PCommWallet::from_password("test", config).unwrap();

        let addr = wallet.get_primary_address().unwrap();

        // Add UTXO
        let utxo = Utxo {
            transaction_id: "test_tx_1".to_string(),
            index: 0,
            amount: 100000,
            script_public_key: vec![],
            address: addr.clone(),
            is_coinbase: false,
        };

        wallet.add_utxo(utxo).unwrap();
        assert_eq!(wallet.get_balance().unwrap(), 100000);

        // Remove UTXO
        wallet.remove_utxo("test_tx_1", 0).unwrap();
        assert_eq!(wallet.get_balance().unwrap(), 0);
    }

    #[test]
    fn test_all_addresses() {
        let config = WalletConfig {
            receive_gap_limit: 5,
            change_gap_limit: 3,
            ..Default::default()
        };
        let wallet = P2PCommWallet::from_password("test", config).unwrap();

        let addresses = wallet.get_all_addresses();
        assert_eq!(addresses.len(), 8); // 5 receive + 3 change
    }
}
