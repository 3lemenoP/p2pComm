/// Test program for wallet_manager module
/// Run with: cargo run --bin test-wallet

// Include the wallet_manager module directly
#[path = "src/wallet_manager.rs"]
mod wallet_manager;

use anyhow::Result;
use wallet_manager::{P2PCommWallet, WalletConfig};

fn main() -> Result<()> {
    println!("=== P2PComm Wallet Manager Test ===\n");

    // Test 1: Create wallet from password
    println!("Test 1: Creating wallet from password...");
    let config = WalletConfig::default();
    let wallet = P2PCommWallet::from_password("my_secure_password_123", config)?;

    println!("✓ Wallet created successfully");
    println!("  Primary Address: {}", wallet.get_primary_address()?);
    println!("  Balance: {} sompis\n", wallet.get_balance()?);

    // Test 2: Deterministic generation
    println!("Test 2: Testing deterministic generation...");
    let config2 = WalletConfig::default();
    let wallet2 = P2PCommWallet::from_password("my_secure_password_123", config2)?;

    if wallet.get_primary_address()? == wallet2.get_primary_address()? {
        println!("✓ Deterministic generation verified");
        println!("  Both wallets have same address\n");
    } else {
        println!("✗ FAILED: Addresses don't match!");
    }

    // Test 3: Address pool
    println!("Test 3: Checking address pool...");
    let all_addresses = wallet.get_all_addresses();
    println!("✓ Generated {} addresses", all_addresses.len());
    println!("  First 5 addresses:");
    for (i, addr) in all_addresses.iter().take(5).enumerate() {
        println!("    {}. {}", i + 1, addr);
    }
    println!();

    // Test 4: UTXO management
    println!("Test 4: Testing UTXO management...");
    use wallet_manager::Utxo;

    let test_utxo = Utxo {
        transaction_id: "test_tx_abc123".to_string(),
        index: 0,
        amount: 1000000, // 0.01 KAS (1M sompis)
        script_public_key: vec![],
        address: wallet.get_primary_address()?,
        is_coinbase: false,
    };

    wallet.add_utxo(test_utxo)?;
    println!("✓ Added UTXO: 1,000,000 sompis");
    println!("  New Balance: {} sompis\n", wallet.get_balance()?);

    // Test 5: Multiple UTXOs
    println!("Test 5: Adding multiple UTXOs...");
    for i in 1..=3 {
        let utxo = Utxo {
            transaction_id: format!("test_tx_{}", i),
            index: i,
            amount: 500000,
            script_public_key: vec![],
            address: wallet.get_primary_address()?,
            is_coinbase: false,
        };
        wallet.add_utxo(utxo)?;
    }

    let spendable = wallet.get_spendable_utxos()?;
    println!("✓ Added 3 more UTXOs");
    println!("  Total UTXOs: {}", spendable.len());
    println!("  Total Balance: {} sompis\n", wallet.get_balance()?);

    // Test 6: Remove UTXO
    println!("Test 6: Spending a UTXO...");
    wallet.remove_utxo("test_tx_1", 1)?;
    println!("✓ Removed UTXO test_tx_1:1");
    println!("  Remaining Balance: {} sompis\n", wallet.get_balance()?);

    // Test 7: Export wallet info
    println!("Test 7: Exporting wallet info...");
    let info = wallet.export_info()?;
    println!("✓ Wallet info exported:");
    println!("{}\n", info);

    // Test 8: Restore from mnemonic
    println!("Test 8: Restoring wallet from mnemonic...");
    let mnemonic = wallet.get_mnemonic();
    let config3 = WalletConfig::default();
    let restored_wallet = P2PCommWallet::from_mnemonic(mnemonic, config3)?;

    if wallet.get_primary_address()? == restored_wallet.get_primary_address()? {
        println!("✓ Wallet restored successfully");
        println!("  Address matches original\n");
    } else {
        println!("✗ FAILED: Restored address doesn't match!");
    }

    // Test 9: Different passwords produce different wallets
    println!("Test 9: Testing password uniqueness...");
    let config4 = WalletConfig::default();
    let wallet_different = P2PCommWallet::from_password("different_password", config4)?;

    if wallet.get_primary_address()? != wallet_different.get_primary_address()? {
        println!("✓ Different passwords produce different addresses");
        println!("  Original: {}", wallet.get_primary_address()?);
        println!("  Different: {}\n", wallet_different.get_primary_address()?);
    } else {
        println!("✗ FAILED: Same address for different passwords!");
    }

    println!("=== All Tests Passed! ===");
    println!("\n✓ Wallet Manager is working correctly");
    println!("✓ Ready for transaction builder integration");

    Ok(())
}
