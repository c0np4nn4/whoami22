//! Exercise both ordinary and generation senders above the old 30M allowance.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{fs, path::Path};
use vess_bench::{
    chain::{self, Arg, Devnet},
    e2e::{core::*, generation, model::Proposal, wire::NodeConfig},
};

#[test]
#[ignore = "requires Anvil and forge-built lifecycle contracts"]
fn generation_at_t1024_exceeds_old_gas_limit_and_is_mined() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let out = std::env::var_os("VESS_GAS_TEST_OUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temp.path().to_owned());
    let mut d = Devnet::start_empty(&out.join("chain"))?;
    let artifact: Value = serde_json::from_slice(&fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("contract-out/E2EVess.sol/E2EVess.json"),
    )?)?;
    let r = d.send(
        None,
        chain::unhex(
            artifact["bytecode"]["object"]
                .as_str()
                .context("bytecode")?,
        )?,
        0,
        0,
        "deploy-gas-test",
    )?;
    ensure!(chain::hex_u64(&r["status"])? == 1, "deployment");
    d.verifier = r["contractAddress"].as_str().context("address")?.to_owned();
    let wa = |n| Arg::Word(chain::word(n));
    d.transact(
        "configureGeneration(uint256,uint256,uint256,uint256)",
        vec![wa(4), wa(2), wa(1), wa(120)],
        0,
        0,
        "configure",
    )?;
    let owner = chain::address(&d.accounts[6])?;
    d.transact(
        "setGenerationOwner(address)",
        vec![Arg::Word(owner)],
        0,
        0,
        "owner",
    )?;
    d.transact("openGeneration(uint256)", vec![wa(0)], 0, 0, "open")?;
    let p = Params {
        n: 4,
        k: 2,
        f: 1,
        t: 1024,
    };
    d.transact(
        "publishInitialConstant(bytes)",
        vec![Arg::Bytes(enc(&(p, vec![g(); 2])))],
        6,
        0,
        "owner-constant",
    )?;
    for id in 1..=4 {
        let account = chain::address(&d.accounts[id])?;
        d.transact(
            "register(uint256,uint256,uint256,uint256,address)",
            vec![wa(id as u64), wa(0), wa(1), wa(2), Arg::Word(account)],
            0,
            0,
            "register",
        )?;
    }
    let mut cfg = NodeConfig {
        run: "gas-validation".into(),
        id: 1,
        role: "dealer".into(),
        port: 0,
        dir: out.join("nodes/dealer-1"),
        tls: out.join("unused-tls"),
        peers: vec![],
        rpc: d.url.clone(),
        contract: d.verifier.clone(),
        n: 4,
        k: 2,
        f: 1,
        participant_corruption_budget: 1,
        outgoing_recipient_budget: 2,
        timeout_ms: 120000,
    };
    // Actual JRSS commitment dimensions/serialization, without private shares
    // entering the transaction. This checks transport, not an entire lifecycle.
    let contribution = contribute_initial(p);
    let source = chain::word(1);
    let proposal = Proposal {
        nonce: 0,
        source,
        commitments: contribution.commitments.clone(),
        sig: sign(
            Scalar::from(1),
            digest(&(0u64, source, &contribution.commitments)),
        ),
    };
    generation::publish(&cfg, 0, 0, &proposal)?;
    let normal = d.transact(
        "publishGeneration(uint256,uint256,uint256,bytes)",
        vec![wa(0), wa(0), wa(2), Arg::Bytes(enc(&proposal))],
        2,
        0,
        "large-normal-sender",
    )?;
    ensure!(
        chain::hex_u64(&normal["status"])? == 1 && chain::hex_u64(&normal["gasUsed"])? > 30_000_000,
        "ordinary sender still capped"
    );
    for id in [3, 4] {
        cfg.id = id;
        cfg.dir = out.join(format!("nodes/dealer-{id}"));
        generation::publish(&cfg, 0, 0, &proposal)?;
    }
    let transcript = generation::snapshot_while::<Proposal, _>(&cfg, 0, 0, || true)?;
    ensure!(
        transcript.len() == 4 && transcript.iter().all(|(_, v)| enc(v) == enc(&proposal)),
        "stored transcript mismatch"
    );
    let mut gas = Vec::new();
    for f in fs::read_dir(out.join("chain"))? {
        let f = f?.path();
        if f.extension().is_some_and(|v| v == "json")
            && f.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("generation-")
        {
            let v: Value = serde_json::from_slice(&fs::read(f)?)?;
            let used = chain::hex_u64(&v["receipt"]["gasUsed"])?;
            ensure!(
                chain::hex_u64(&v["receipt"]["status"])? == 1 && used > 30_000_000,
                "generation sender still capped"
            );
            gas.push(used);
        }
    }
    ensure!(gas.len() == 3, "generation receipt evidence");
    let manifest: Value =
        serde_json::from_slice(&fs::read(out.join("chain/chain_manifest.json"))?)?;
    ensure!(
        manifest["block_gas_limit_enforced"] == false
            && manifest["execution_gas_policy"] == chain::E2E_GAS_POLICY,
        "gas policy evidence"
    );
    fs::write(
        out.join("test_result.json"),
        serde_json::to_vec_pretty(
            &json!({"passed":true,"t":1024,"n_D":4,"k_D":2,"payload_bytes":enc(&proposal).len(),"ordinary_sender_gas":chain::hex_u64(&normal["gasUsed"])?,"generation_sender_gas":gas,"scope":"actual public generation phase; not a full lifecycle"}),
        )?,
    )?;
    Ok(())
}
