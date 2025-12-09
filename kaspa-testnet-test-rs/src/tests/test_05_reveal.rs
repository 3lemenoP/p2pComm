use anyhow::Result;
use crate::utils;
use std::path::PathBuf;

pub async fn run() -> Result<()> {
    utils::header("Test 05: P2SH Reveal Transaction");

    // Step 1: Load reveal script from Test 04
    utils::section("Loading reveal script");

    let script_path = PathBuf::from("./results/reveal-script.bin");
    if !script_path.exists() {
        utils::error("Reveal script not found!");
        utils::info("Please run Test 04 first to generate the reveal script");
        return Ok(());
    }

    let reveal_script = std::fs::read(&script_path)?;
    utils::success(&format!("Reveal script loaded ({} bytes)", reveal_script.len()));
    utils::data("Script Hash", &utils::to_hex(&utils::script_hash(&reveal_script)));

    // Step 2: Parse script contents
    utils::section("Parsing reveal script");

    utils::info("Script structure:");
    utils::info("  1. Public key (for signature verification)");
    utils::info("  2. OpCheckSig");
    utils::info("  3. OpFalse OpIf ... OpEndIf (data container)");
    utils::info("  4. Protocol identifier: 'p2pcomm'");
    utils::info("  5. Protocol version: 1");
    utils::info("  6. Peer announcement JSON data");

    // Display script hex
    let script_hex = utils::to_hex(&reveal_script);
    let preview_len = 128.min(script_hex.len());
    utils::data("Script Hex (preview)", &format!("{}...", &script_hex[..preview_len]));

    // Step 3: Explain reveal transaction process
    utils::section("Reveal transaction process");

    utils::info("To create a reveal transaction:");
    utils::info("  1. Find the UTXO created by the commit transaction");
    utils::info("  2. Create transaction spending from P2SH address");
    utils::info("  3. Provide the reveal script in the ScriptSig");
    utils::info("  4. When validated, the script executes and data becomes visible");
    utils::info("  5. The OpFalse OpIf wrapper prevents execution, only stores data");

    // Step 4: Transaction structure
    utils::section("Transaction structure");

    utils::info("Input:");
    utils::info("  - Previous UTXO: <commit_transaction_hash>:<output_index>");
    utils::info("  - ScriptSig: <signature> <reveal_script>");
    utils::info("  - The reveal script must hash to the P2SH address");

    utils::info("Output:");
    utils::info("  - Send funds back to wallet (minus fees)");
    utils::info("  - Or send to any other address");

    // Step 5: Verification process
    utils::section("Script verification");

    utils::info("When the reveal transaction is processed:");
    utils::info("  1. Network hashes the provided reveal script");
    utils::info("  2. Compares hash to P2SH commit address");
    utils::info("  3. If match, script is valid");
    utils::info("  4. Script executes: OpCheckSig verifies signature");
    utils::info("  5. Data section (OpFalse OpIf) is parsed but not executed");
    utils::info("  6. Transaction is accepted, data is now on-chain");

    // Step 6: Indexer requirements
    utils::section("Indexer requirements");

    utils::info("An indexer would:");
    utils::info("  1. Monitor for transactions with reveal scripts");
    utils::info("  2. Parse scripts for 'p2pcomm' protocol identifier");
    utils::info("  3. Extract version and payload data");
    utils::info("  4. Validate payload structure");
    utils::info("  5. Store peer announcements in database");
    utils::info("  6. Provide API for querying active peers");

    // Step 7: Cost analysis
    utils::section("Cost analysis");

    let commit_fee = 10000u64; // ~0.0001 KAS
    let reveal_fee = 15000u64; // ~0.00015 KAS (larger due to script)
    let total_fee = commit_fee + reveal_fee;

    utils::data("Commit Transaction Fee", &format!("{} sompi (~{:.6} KAS)", commit_fee, commit_fee as f64 / 1e8));
    utils::data("Reveal Transaction Fee", &format!("{} sompi (~{:.6} KAS)", reveal_fee, reveal_fee as f64 / 1e8));
    utils::data("Total Cost (2 tx)", &format!("{} sompi (~{:.6} KAS)", total_fee, total_fee as f64 / 1e8));

    utils::info("Note: Actual fees depend on script size and network congestion");

    // Step 8: Save test results
    utils::section("Saving test results");

    let results = serde_json::json!({
        "test": "Test 05: P2SH Reveal Transaction",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "reveal_script": {
            "size_bytes": reveal_script.len(),
            "hash": utils::to_hex(&utils::script_hash(&reveal_script)),
            "hex_preview": &script_hex[..preview_len],
        },
        "cost_analysis": {
            "commit_fee_sompi": commit_fee,
            "reveal_fee_sompi": reveal_fee,
            "total_sompi": total_fee,
            "total_kas": total_fee as f64 / 1e8,
        },
        "notes": [
            "Actual transaction creation requires full wallet integration",
            "This test demonstrates the P2SH reveal process conceptually",
            "See KASPA_P2SH_IMPLEMENTATION.md for full implementation guide"
        ]
    });

    let results_path = PathBuf::from("./results/test-05-results.json");
    std::fs::write(&results_path, serde_json::to_string_pretty(&results)?)?;
    utils::success(&format!("Results saved to {:?}", results_path));

    utils::success("Test 05 completed");
    utils::info("Note: Actual transaction creation requires full wallet integration");
    Ok(())
}
