mod tests;
mod utils;
mod wallet_manager;
mod transaction_builder;
mod rpc_client;
mod payload_manager;
mod delivery_strategy;
mod utxo_monitor;
mod message_extractor;
mod message_reception;
mod webrtc_signaling;
mod peer_discovery;

use anyhow::Result;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::init();

    // Welcome banner
    utils::header("Kaspa P2SH Testnet Test Suite");
    utils::info("Testing P2SH commit-reveal pattern for P2PComm peer discovery");
    utils::info("Repository: https://github.com/kaspanet/rusty-kaspa");
    println!();

    let start_time = Instant::now();
    let mut results = Vec::new();

    // Test 01: RPC Connection - Now using correct endpoint
    match run_test("Test 01: RPC Connection", tests::test_01_connection::run()).await {
        Ok(_) => results.push(("Test 01", true)),
        Err(e) => {
            utils::error(&format!("Test 01 failed: {}", e));
            results.push(("Test 01", false));
        }
    }

    // Test 02: Wallet Generation
    match run_test("Test 02: Wallet Generation", tests::test_02_wallet::run()).await {
        Ok(_) => results.push(("Test 02", true)),
        Err(e) => {
            utils::error(&format!("Test 02 failed: {}", e));
            results.push(("Test 02", false));
        }
    }

    // Test 03: Script Builder
    match run_test("Test 03: Script Builder", tests::test_03_script_builder::run()).await {
        Ok(_) => results.push(("Test 03", true)),
        Err(e) => {
            utils::error(&format!("Test 03 failed: {}", e));
            results.push(("Test 03", false));
        }
    }

    // Test 04: Commit Transaction
    match run_test("Test 04: Commit Transaction", tests::test_04_commit::run()).await {
        Ok(_) => results.push(("Test 04", true)),
        Err(e) => {
            utils::error(&format!("Test 04 failed: {}", e));
            results.push(("Test 04", false));
        }
    }

    // Test 05: Reveal Transaction - DISABLED (requires Kaspa testnet)
    // match run_test("Test 05: Reveal Transaction", tests::test_05_reveal::run()).await {
    //     Ok(_) => results.push(("Test 05", true)),
    //     Err(e) => {
    //         utils::error(&format!("Test 05 failed: {}", e));
    //         results.push(("Test 05", false));
    //     }
    // }
    utils::info("Test 05: Reveal Transaction - Skipped (requires Kaspa testnet)");

    // Test 06: Full P2SH Flow - DISABLED (requires Kaspa testnet)
    // match run_test("Test 06: Full P2SH Flow", tests::test_06_full_flow::run()).await {
    //     Ok(_) => results.push(("Test 06", true)),
    //     Err(e) => {
    //         utils::error(&format!("Test 06 failed: {}", e));
    //         results.push(("Test 06", false));
    //     }
    // }
    utils::info("Test 06: Full P2SH Flow - Skipped (requires Kaspa testnet)");

    // Final summary
    let duration = start_time.elapsed();
    let passed = results.iter().filter(|(_, success)| *success).count();
    let failed = results.len() - passed;

    utils::header("Test Results Summary");
    for (name, success) in &results {
        if *success {
            utils::success(name);
        } else {
            utils::error(name);
        }
    }

    println!();
    utils::result_summary(passed, failed, results.len());
    utils::data("Total Duration", &format!("{:.2}s", duration.as_secs_f64()));

    if failed == 0 {
        utils::success("All tests passed!");
    } else {
        utils::warning(&format!("{} test(s) failed", failed));
    }

    println!();
    utils::info("Next steps:");
    utils::info("  1. Review results in ./results/ directory");
    utils::info("  2. Check KASPA_P2SH_IMPLEMENTATION.md for full guide");
    utils::info("  3. Fund wallet and test on live testnet");
    utils::info("  4. Build indexer to extract peer announcements");
    utils::info("  5. Integrate with P2PComm WASM core");

    Ok(())
}

async fn run_test<F>(name: &str, test_future: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    println!();
    utils::section(&format!("Running {}", name));
    let start = Instant::now();

    let result = test_future.await;

    let duration = start.elapsed();
    if result.is_ok() {
        utils::success(&format!("{} completed in {:.2}s", name, duration.as_secs_f64()));
    } else {
        utils::error(&format!("{} failed after {:.2}s", name, duration.as_secs_f64()));
    }

    result
}
