use anyhow::{Result, Context};
use kaspa_addresses::{Address, Prefix as AddressPrefix};
use kaspa_wallet_keys::derivation::gen1::{WalletDerivationManager, PubkeyDerivationManager};
use kaspa_wallet_keys::derivation::traits::WalletDerivationManagerTrait;
use kaspa_bip32::{Mnemonic, Language, ExtendedPrivateKey, SecretKey, Prefix, PrivateKey, PublicKey};
use std::path::PathBuf;

pub struct TestWallet {
    pub mnemonic: String,
    pub address: Address,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl TestWallet {
    /// Generate a new test wallet with mnemonic phrase
    pub fn generate() -> Result<Self> {
        // Generate random entropy for 24-word mnemonic
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let entropy: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();

        // Create mnemonic from entropy
        let mnemonic = Mnemonic::from_entropy(entropy, Language::English)
            .context("Failed to create mnemonic from entropy")?;
        let mnemonic_str = mnemonic.phrase();

        // Create wallet from mnemonic
        Self::from_mnemonic(mnemonic_str)
    }

    /// Restore wallet from mnemonic phrase
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        // Parse mnemonic
        let mnemonic = Mnemonic::new(mnemonic, Language::English)
            .context("Failed to parse mnemonic")?;

        // Create extended private key from mnemonic
        let xprv = ExtendedPrivateKey::<SecretKey>::new(mnemonic.to_seed(""))
            .context("Failed to create extended private key")?;

        // Convert to string format (KTRV for testnet)
        let xprv_str = xprv.to_string(Prefix::KTRV).to_string();

        // Store the private key bytes
        let private_key_bytes = xprv.private_key().to_bytes().to_vec();

        // Create wallet derivation manager
        let wallet = WalletDerivationManager::from_master_xprv(
            &xprv_str,
            false,  // is_multisig = false
            0,      // account_index = 0
            None    // cosigner_index = None
        ).context("Failed to create wallet derivation manager")?;

        // Derive the first receive address (index 0)
        let pubkey = wallet.derive_receive_pubkey(0)
            .context("Failed to derive receive pubkey")?;

        // Create address from public key (testnet, schnorr signature)
        let address = PubkeyDerivationManager::create_address(
            &pubkey,
            AddressPrefix::Testnet,
            false  // ecdsa = false (use schnorr)
        ).context("Failed to create address from pubkey")?;

        // Get public key bytes
        let public_key_bytes = pubkey.to_bytes().to_vec();

        Ok(Self {
            mnemonic: mnemonic.phrase().to_string(),
            address,
            private_key: private_key_bytes,
            public_key: public_key_bytes,
        })
    }

    /// Save wallet mnemonic to file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create wallet directory")?;
        }

        std::fs::write(path, &self.mnemonic)
            .context("Failed to save wallet to file")?;
        Ok(())
    }

    /// Load wallet from file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let mnemonic = std::fs::read_to_string(path)
            .context("Failed to read wallet file")?;
        Self::from_mnemonic(mnemonic.trim())
    }

    /// Get address as string
    pub fn address_string(&self) -> String {
        self.address.to_string()
    }

    /// Get public key as hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    /// Get private key as hex string (for debugging only!)
    pub fn private_key_hex(&self) -> String {
        hex::encode(&self.private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_generation() {
        let wallet = TestWallet::generate().unwrap();
        assert!(!wallet.mnemonic.is_empty());
        assert_eq!(wallet.public_key.len(), 33);  // Compressed public key
        assert_eq!(wallet.private_key.len(), 32);
    }

    #[test]
    fn test_wallet_restore() {
        let wallet1 = TestWallet::generate().unwrap();
        let mnemonic = wallet1.mnemonic.clone();

        let wallet2 = TestWallet::from_mnemonic(&mnemonic).unwrap();
        assert_eq!(wallet1.address_string(), wallet2.address_string());
        assert_eq!(wallet1.public_key, wallet2.public_key);
        assert_eq!(wallet1.private_key, wallet2.private_key);
    }
}
