//! Explicit integration check: actual Prague sidecars and the native KZG precompile.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{fs, path::Path};
use vess_bench::chain::{
    self, Arg, Devnet, FieldPublication, BLOBS_PER_TRANSACTION, FIELD_PAYLOAD_BYTES,
};

#[test]
#[ignore = "requires anvil and forge-built E2EPublication artifact"]
fn ten_real_blobs_are_published_in_two_transactions() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let output = std::env::var_os("VESS_MULTIBLOB_TEST_OUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temp.path().to_owned());
    let mut d = Devnet::start_empty(&output)?;
    let artifact: Value = serde_json::from_slice(&fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("contract-out/E2EPublication.sol/E2EPublication.json"),
    )?)?;
    let mut code = chain::unhex(
        artifact["bytecode"]["object"]
            .as_str()
            .context("bytecode")?,
    )?;
    code.extend(chain::address(&d.accounts[0])?);
    let receipt = d.send(None, code, 0, 0, "deploy-publication-test")?;
    ensure!(chain::hex_u64(&receipt["status"])? == 1, "deploy");
    d.verifier = receipt["contractAddress"]
        .as_str()
        .context("address")?
        .to_owned();
    let root = chain::field_hash(b"ten real blob test");
    let payload: Vec<_> = (0..9 * FIELD_PAYLOAD_BYTES + 17)
        .map(|i| (i % 251) as u8)
        .collect();
    let p = FieldPublication::new(root, &payload)?;
    ensure!(p.blobs.len() == 10, "ten fragments required");
    let mut gas = 0;
    let mut blob_gas = 0;
    for (batch, blobs) in p.blobs.chunks(BLOBS_PER_TRANSACTION).enumerate() {
        let data = chain::calldata(
            "append(uint256,bytes32,bytes32,uint256,uint256,bytes)",
            &[
                Arg::Word(chain::word(1)),
                Arg::Word(root),
                Arg::Word(chain::word(7)),
                Arg::Word(chain::word(payload.len() as u64)),
                Arg::Word(chain::word((batch * BLOBS_PER_TRANSACTION) as u64)),
                Arg::Bytes(
                    blobs
                        .iter()
                        .flat_map(|b| b.point_proofs[0].clone())
                        .collect(),
                ),
            ],
        );
        let r = d.blobs_send(data, &blobs.iter().collect::<Vec<_>>(), "real-blob-batch")?;
        ensure!(
            chain::hex_u64(&r["status"])? == 1,
            "real blob batch rejected"
        );
        ensure!(
            chain::hex_u64(&r["blobGasUsed"])? == blobs.len() as u64 * 131072,
            "actual blob gas"
        );
        ensure!(
            r["logs"].as_array().context("logs")?.len() == blobs.len(),
            "stored blob events"
        );
        gas += chain::hex_u64(&r["gasUsed"])?;
        blob_gas += chain::hex_u64(&r["blobGasUsed"])?;
        let result = chain::rpc(
            &d.url,
            "eth_call",
            json!([{"to":d.verifier,"data":chain::hhex(&chain::calldata("progress(uint256)", &[Arg::Word(chain::word(1))]))},"latest"]),
        )?;
        let words = chain::unhex(result.as_str().context("progress")?)?;
        ensure!(
            words[..32] == root
                && words[64..96] == chain::word(payload.len() as u64)
                && words[96..128] == chain::word(if batch == 0 { 9 } else { 10 }),
            "on-chain ordered progress"
        );
    }
    for (i, blob) in p.blobs.iter().enumerate() {
        let result = chain::rpc(
            &d.url,
            "eth_call",
            json!([{"to":d.verifier,"data":chain::hhex(&chain::calldata("versionAt(uint256,uint256)", &[Arg::Word(chain::word(1)),Arg::Word(chain::word(i as u64))]))},"latest"]),
        )?;
        ensure!(
            chain::unhex(result.as_str().context("version")?)? == blob.versioned,
            "ordered hash"
        );
    }
    fs::write(
        output.join("test_result.json"),
        serde_json::to_vec_pretty(
            &json!({"passed":true,"blobs":10,"transactions":2,"payload_bytes":payload.len(),"execution_gas":gas,"blob_gas":blob_gas,"scope":"real publication module; synthetic payload, not a lifecycle performance observation"}),
        )?,
    )?;
    Ok(())
}
