use anyhow::Result;
use crate::utils;
use std::path::PathBuf;

pub async fn run() -> Result<()> {
    utils::header("Test 02: Wallet Generation and Management");

    // Test 1: Generate new wallet
    utils::section("Generating new wallet");
    let spinner = utils::spinner("Generating 24-word mnemonic...");

    let wallet = utils::TestWallet::generate()?;

    spinner.finish_and_clear();
    utils::success("Wallet generated successfully");

    utils::data("Mnemonic", &wallet.mnemonic);
    utils::data("Address", &wallet.address_string());
    utils::data("Public Key", &wallet.public_key_hex());

    // Show first 16 chars of private key (for security)
    let priv_key_preview = format!("{}...", &wallet.private_key_hex()[..16]);
    utils::data("Private Key (preview)", &priv_key_preview);

    // Test 2: Save wallet to file
    utils::section("Saving wallet to file");
    let wallet_path = PathBuf::from("./wallet/test-wallet.txt");

    // Ensure wallet directory exists
    if let Some(parent) = wallet_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let save_spinner = utils::spinner("Writing wallet to disk...");
    wallet.save_to_file(&wallet_path)?;
    save_spinner.finish_and_clear();
    utils::success(&format!("Wallet saved to {:?}", wallet_path));

    // Test 3: Load wallet from file
    utils::section("Loading wallet from file");
    let load_spinner = utils::spinner("Reading wallet from disk...");
    let loaded_wallet = utils::TestWallet::load_from_file(&wallet_path)?;
    load_spinner.finish_and_clear();
    utils::success("Wallet loaded successfully");

    // Verify loaded wallet matches original
    if wallet.address_string() == loaded_wallet.address_string() {
        utils::success("Address verification passed");
    } else {
        utils::error("Address verification failed!");
        anyhow::bail!("Loaded wallet doesn't match original");
    }

    if wallet.public_key == loaded_wallet.public_key {
        utils::success("Public key verification passed");
    } else {
        utils::error("Public key verification failed!");
        anyhow::bail!("Loaded public key doesn't match original");
    }

    // Test 4: Restore wallet from mnemonic
    utils::section("Restoring wallet from mnemonic");
    let restore_spinner = utils::spinner("Deriving keys from mnemonic...");
    let restored_wallet = utils::TestWallet::from_mnemonic(&wallet.mnemonic)?;
    restore_spinner.finish_and_clear();
    utils::success("Wallet restored from mnemonic");

    // Verify restored wallet matches original
    if wallet.address_string() == restored_wallet.address_string() {
        utils::success("Restored address matches original");
    } else {
        utils::error("Restored address doesn't match!");
        anyhow::bail!("Restored wallet doesn't match original");
    }

    // Test 5: Generate multiple wallets
    utils::section("Testing wallet uniqueness");
    let gen_spinner = utils::spinner("Generating 5 unique wallets...");

    let mut addresses = vec![];
    for _ in 0..5 {
        let w = utils::TestWallet::generate()?;
        addresses.push(w.address_string());
    }

    gen_spinner.finish_and_clear();

    // Check all addresses are unique
    let mut unique_addresses = addresses.clone();
    unique_addresses.sort();
    unique_addresses.dedup();

    if unique_addresses.len() == addresses.len() {
        utils::success(&format!("All {} addresses are unique", addresses.len()));
    } else {
        utils::error("Duplicate addresses detected!");
        anyhow::bail!("Wallet generation not producing unique addresses");
    }

    // Display the unique addresses
    for (i, addr) in addresses.iter().enumerate() {
        utils::data(&format!("Wallet {}", i + 1), addr);
    }

    utils::success("Test 02 completed");
    Ok(())
}
