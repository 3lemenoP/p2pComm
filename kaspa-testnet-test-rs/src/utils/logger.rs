use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub fn header(text: &str) {
    println!("\n{}", "=".repeat(80).bright_blue());
    println!("{}", text.bright_cyan().bold());
    println!("{}\n", "=".repeat(80).bright_blue());
}

pub fn section(text: &str) {
    println!("\n{} {}", "▶".bright_green(), text.bright_white().bold());
}

pub fn success(text: &str) {
    println!("{} {}", "✓".bright_green(), text);
}

pub fn error(text: &str) {
    println!("{} {}", "✗".bright_red(), text.red());
}

pub fn warning(text: &str) {
    println!("{} {}", "⚠".bright_yellow(), text.yellow());
}

pub fn info(text: &str) {
    println!("{} {}", "ℹ".bright_blue(), text);
}

pub fn data(label: &str, value: &str) {
    println!("  {} {}", format!("{}:", label).bright_white(), value.cyan());
}

pub fn json_data(label: &str, data: &serde_json::Value) {
    println!("  {} {}", format!("{}:", label).bright_white(),
        serde_json::to_string_pretty(data).unwrap().cyan());
}

pub fn spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

pub fn progress_bar(len: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );
    pb.set_message(message.to_string());
    pb
}

pub fn result_summary(passed: usize, failed: usize, total: usize) {
    println!("\n{}", "=".repeat(80).bright_blue());
    println!("{}", "TEST RESULTS".bright_cyan().bold());
    println!("{}", "=".repeat(80).bright_blue());
    println!("  {} {}/{} tests passed", "✓".bright_green(), passed, total);
    if failed > 0 {
        println!("  {} {}/{} tests failed", "✗".bright_red(), failed, total);
    }
    println!("{}\n", "=".repeat(80).bright_blue());
}
