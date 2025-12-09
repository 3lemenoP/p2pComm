// Temporary offline test runner for Tests 02 and 03 only
mod tests;
mod utils;

use anyhow::Result;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::init();

    // Welcome banner
    utils::header("Kaspa P2SH Testnet Test Suite - Offline Tests");
    utils::info("Running offline tests only (Test 02 and Test 03)");
    utils::info("Repository: https://github.com/kaspanet/rusty-kaspa");
    println!();

    let start_time = Instant::now();
    let mut results = Vec::new();

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
        utils::success("All offline tests passed!");
    } else {
        utils::warning(&format!("{} test(s) failed", failed));
    }

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
