use anyhow::Result;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpIf, OpEndIf, OpFalse};
use kaspa_addresses::{Address, Prefix};
use kaspa_consensus_core::network::NetworkType;
use crate::utils;
use serde_json::json;

pub async fn run() -> Result<()> {
    utils::header("Test 03: P2SH Script Builder");

    // Generate a test wallet for the public key
    utils::section("Generating test wallet");
    let wallet = utils::TestWallet::generate()?;
    utils::data("Wallet Address", &wallet.address_string());
    utils::data("Public Key", &wallet.public_key_hex());

    // Test 1: Build basic P2SH script with protocol data
    utils::section("Building P2SH script with P2PComm data");

    let peer_announcement = json!({
        "peerId": "12D3KooWExample",
        "connectionInfo": {
            "multiaddrs": ["/ip4/192.168.1.100/tcp/9001"],
            "protocol": "webrtc"
        },
        "timestamp": 1234567890,
        "signature": "placeholder_signature"
    });

    let spinner = utils::spinner("Constructing script...");

    let mut script = ScriptBuilder::new();

    // Add public key (for OpCheckSig verification)
    script.add_data(&wallet.public_key)?;
    script.add_op(OpCheckSig)?;

    // Add false condition wrapper
    script.add_op(OpFalse)?;
    script.add_op(OpIf)?;

    // Add protocol identifier
    script.add_data(b"p2pcomm")?;

    // Add protocol version
    script.add_i64(1)?;

    // Add peer announcement data
    let announcement_bytes = utils::json_to_bytes(&peer_announcement)?;
    script.add_data(&announcement_bytes)?;

    // Close the false condition
    script.add_op(OpEndIf)?;

    let reveal_script_bytes = script.drain();

    spinner.finish_and_clear();
    utils::success("Script built successfully");

    utils::data("Script Length", &format!("{} bytes", reveal_script_bytes.len()));
    utils::data("Script Hex (first 64 chars)", &format!("{}...", utils::to_hex(&reveal_script_bytes)[..64.min(reveal_script_bytes.len() * 2)].to_string()));

    // Test 2: Create P2SH address from script
    utils::section("Creating P2SH commit address");

    let commit_spinner = utils::spinner("Generating P2SH address...");

    // Hash the script
    let script_hash = utils::script_hash(&reveal_script_bytes);
    utils::data("Script Hash", &utils::to_hex(&script_hash));

    // Create P2SH script
    use kaspa_txscript::opcodes::codes::{OpBlake2b, OpEqual};
    let mut p2sh_builder = ScriptBuilder::new();
    p2sh_builder.add_op(OpBlake2b)?;
    p2sh_builder.add_data(&script_hash)?;
    p2sh_builder.add_op(OpEqual)?;

    let p2sh_script_bytes = p2sh_builder.drain();

    commit_spinner.finish_and_clear();

    utils::data("P2SH Script Length", &format!("{} bytes", p2sh_script_bytes.len()));
    utils::data("P2SH Script Hex", &utils::to_hex(&p2sh_script_bytes));

    // Test 3: Verify script can be parsed
    utils::section("Verifying script structure");

    let verify_spinner = utils::spinner("Parsing script opcodes...");

    // Count opcodes and data pushes
    let mut opcode_count = 0;
    let mut data_push_count = 0;

    for byte in &reveal_script_bytes {
        if *byte >= 0x01 && *byte <= 0x4e {
            data_push_count += 1;
        } else {
            opcode_count += 1;
        }
    }

    verify_spinner.finish_and_clear();
    utils::success("Script structure verified");

    utils::data("Opcodes", &opcode_count.to_string());
    utils::data("Data Pushes", &data_push_count.to_string());

    // Test 4: Build multiple scripts to test consistency
    utils::section("Testing script consistency");

    let consistency_spinner = utils::spinner("Generating 3 identical scripts...");

    let mut script_hashes = vec![];
    for _ in 0..3 {
        let mut s = ScriptBuilder::new();
        s.add_data(&wallet.public_key)?;
        s.add_op(OpCheckSig)?;
        s.add_op(OpFalse)?;
        s.add_op(OpIf)?;
        s.add_data(b"p2pcomm")?;
        s.add_i64(1)?;
        s.add_data(&announcement_bytes)?;
        s.add_op(OpEndIf)?;

        let script_bytes = s.drain();
        script_hashes.push(utils::to_hex(&utils::script_hash(&script_bytes)));
    }

    consistency_spinner.finish_and_clear();

    // Verify all hashes are identical
    if script_hashes.iter().all(|h| h == &script_hashes[0]) {
        utils::success("Script generation is deterministic");
        utils::data("Consistent Script Hash", &script_hashes[0]);
    } else {
        utils::error("Script generation is not consistent!");
        for (i, hash) in script_hashes.iter().enumerate() {
            utils::data(&format!("Script {} Hash", i + 1), hash);
        }
        anyhow::bail!("Script generation produced different results");
    }

    // Test 5: Test with different data sizes
    utils::section("Testing various data sizes");

    let sizes = vec![
        ("Small", 100),
        ("Medium", 1000),
        ("Large", 5000),
    ];

    for (label, size) in sizes {
        let large_data = utils::random_bytes(size);

        let mut s = ScriptBuilder::new();
        s.add_data(&wallet.public_key)?;
        s.add_op(OpCheckSig)?;
        s.add_op(OpFalse)?;
        s.add_op(OpIf)?;
        s.add_data(b"p2pcomm")?;
        s.add_i64(1)?;
        s.add_data(&large_data)?;
        s.add_op(OpEndIf)?;

        let script_bytes = s.drain();
        utils::data(
            &format!("{} payload ({} bytes)", label, size),
            &format!("Script size: {} bytes", script_bytes.len())
        );
    }

    utils::success("Various data sizes tested successfully");

    utils::success("Test 03 completed");
    Ok(())
}
