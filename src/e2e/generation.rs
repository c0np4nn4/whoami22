//! Chain-backed reliable broadcast for the paper's VSS generation interface.
//! Private subshares continue to use mutually authenticated TLS. Only public
//! commitments, complaints, complaint answers and signed output vectors enter
//! this immutable bulletin board; all dealers read the same frozen transcript.
use super::{core::*, model::*, wire::NodeConfig};
use crate::chain::{self, word, Arg};
use anyhow::{ensure, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use std::{
    fs,
    time::{Duration, Instant},
};

fn number(bytes: &[u8]) -> Result<u64> {
    ensure!(
        bytes.len() == 32 && bytes[..24].iter().all(|v| *v == 0),
        "ABI number"
    );
    Ok(u64::from_be_bytes(bytes[24..].try_into()?))
}

fn send(cfg: &NodeConfig, sig: &str, args: &[Arg], nonce: u64, phase: u64) -> Result<()> {
    let accounts = chain::rpc(&cfg.rpc, "eth_accounts", json!([]))?;
    let account_index = if cfg.role == "owner" {
        cfg.n + 2
    } else {
        cfg.id as usize
    };
    let account = accounts
        .get(account_index)
        .and_then(|v| v.as_str())
        .context("generation transaction account")?;
    let mut transaction =
        json!({"from":account,"to":cfg.contract,"data":chain::hhex(&chain::calldata(sig,args))});
    let (estimate, gas_limit) = chain::estimate_transaction_gas(&cfg.rpc, &transaction)
        .with_context(|| {
            format!(
                "generation gas estimate: nonce {nonce}, phase {phase}, node {}",
                cfg.id
            )
        })?;
    transaction["gas"] = json!(format!("0x{gas_limit:x}"));
    let hash = chain::rpc(
        &cfg.rpc,
        "eth_sendTransaction",
        json!([transaction.clone()]),
    )?;
    let hash = hash.as_str().context("generation transaction hash")?;
    let chain_dir = cfg
        .dir
        .parent()
        .and_then(|v| v.parent())
        .context("trial directory")?
        .join("chain");
    fs::create_dir_all(&chain_dir)?;
    // The non-.json extension keeps incomplete submissions out of the receipt
    // audit, while retaining the hash and exact public request after a timeout.
    fs::write(
        chain_dir.join(format!("generation-{nonce}-{phase}-{hash}.submitted")),
        serde_json::to_vec_pretty(&json!({"transaction_hash":hash,"transaction":transaction,
            "estimated_gas":estimate,"gas_limit":gas_limit,"generation_nonce":nonce,
            "generation_phase":phase,"dealer":cfg.id}))?,
    )?;
    let begin = Instant::now();
    let receipt = loop {
        let receipt = chain::rpc(&cfg.rpc, "eth_getTransactionReceipt", json!([hash]))?;
        if !receipt.is_null() {
            break receipt;
        }
        ensure!(
            begin.elapsed() < Duration::from_millis(cfg.timeout_ms),
            "generation transaction inclusion timeout: {hash}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    // Keep public-generation gas in the same receipt corpus as lifecycle gas.
    fs::write(
        chain_dir.join(format!("generation-{nonce}-{phase}-{hash}.json")),
        serde_json::to_vec_pretty(
            &json!({"receipt":receipt,"transaction":transaction,"generation_nonce":nonce,"generation_phase":phase,"dealer":cfg.id}),
        )?,
    )?;
    ensure!(
        chain::hex_u64(&receipt["status"])? == 1,
        "generation broadcast reverted {hash}"
    );
    Ok(())
}

pub fn publish<T: Serialize>(cfg: &NodeConfig, nonce: u64, phase: u64, payload: &T) -> Result<()> {
    send(
        cfg,
        "publishGeneration(uint256,uint256,uint256,bytes)",
        &[
            Arg::Word(word(nonce)),
            Arg::Word(word(phase)),
            Arg::Word(word(cfg.id)),
            Arg::Bytes(enc(payload)),
        ],
        nonce,
        phase,
    )
}

pub fn publish_initial(cfg: &NodeConfig, p: Params, commitments: &[Point]) -> Result<()> {
    send(
        cfg,
        "publishInitialConstant(bytes)",
        &[Arg::Bytes(enc(&(p, commitments)))],
        0,
        4,
    )
}

pub fn initial(cfg: &NodeConfig) -> Result<(Params, Vec<Point>)> {
    let bytes = query(cfg, "initialConstant()", &[])?;
    ensure!(
        bytes.len() >= 64 && number(&bytes[..32])? == 32,
        "initial constant ABI"
    );
    let len = number(&bytes[32..64])? as usize;
    ensure!(
        len > 0 && len <= bytes.len() - 64,
        "initial constant length"
    );
    decode(&bytes[64..64 + len])
}

pub fn signing_keys(cfg: &NodeConfig) -> Result<Vec<Point>> {
    (1..=cfg.n as u64)
        .map(|id| {
            let epoch = query_word(cfg, "keyEpoch(uint256)", &[Arg::Word(word(id))])?;
            let bytes = query(
                cfg,
                "dealerKeys(uint256,uint256)",
                &[Arg::Word(word(id)), Arg::Word(epoch)],
            )?;
            ensure!(bytes.len() == 64, "dealer signing key ABI");
            let key = point(&[bytes[..32].try_into()?, bytes[32..].try_into()?])?;
            ensure!(
                key != Pair::zero().commit(),
                "registered dealer signing key"
            );
            Ok(key)
        })
        .collect()
}

/// Wait for the canonical phase boundary. With all dealers responsive the last
/// publication closes it immediately. With omissions the on-chain deadline
/// closes it once n-f broadcasts are present. The deadline is a synchrony
/// assumption, not a claim that arbitrary network delays are tolerated.
pub fn snapshot_while<T: DeserializeOwned, F: Fn() -> bool>(
    cfg: &NodeConfig,
    nonce: u64,
    phase: u64,
    active: F,
) -> Result<Vec<(u64, T)>> {
    let started = Instant::now();
    let round_seconds = number(&query_word(cfg, "generationRoundSeconds()", &[])?)?;
    loop {
        ensure!(active(), "generation snapshot cancelled");
        let value = query(
            cfg,
            "generationPhase(uint256,uint256)",
            &[Arg::Word(word(nonce)), Arg::Word(word(phase))],
        )?;
        ensure!(value.len() == 96, "generation phase ABI");
        if number(&value[64..])? == 1 {
            break;
        }
        ensure!(
            started.elapsed()
                < Duration::from_millis(cfg.timeout_ms.saturating_mul(2).saturating_add(5000)),
            "generation quorum timeout"
        );
        if number(&value[..32])? >= (cfg.n - cfg.f) as u64 {
            let block = chain::rpc(&cfg.rpc, "eth_getBlockByNumber", json!(["latest", false]))?;
            // Anvil's timestamp advances on the next transaction. Wall time is
            // used only to trigger that transaction, whose deadline is checked
            // by the contract itself.
            if chain::hex_u64(&block["timestamp"])? > number(&value[32..64])?
                || started.elapsed() > Duration::from_secs(round_seconds.saturating_add(2))
            {
                send(
                    cfg,
                    "closeGeneration(uint256,uint256)",
                    &[Arg::Word(word(nonce)), Arg::Word(word(phase))],
                    nonce,
                    phase,
                )?;
            }
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    let mut result = Vec::new();
    for id in 1..=cfg.n as u64 {
        ensure!(active(), "generation transcript read cancelled");
        let bytes = query(
            cfg,
            "generationMessage(uint256,uint256,uint256)",
            &[
                Arg::Word(word(nonce)),
                Arg::Word(word(phase)),
                Arg::Word(word(id)),
            ],
        )?;
        ensure!(
            bytes.len() >= 64 && number(&bytes[..32])? == 32,
            "generation bytes ABI"
        );
        let len = number(&bytes[32..64])? as usize;
        ensure!(len <= bytes.len() - 64, "generation bytes length");
        if len != 0 {
            // Malformed Byzantine broadcasts count towards delivery, but never
            // towards the valid VSS/qualified/output family at the caller.
            if let Ok(message) = decode(&bytes[64..64 + len]) {
                result.push((id, message));
            }
        }
    }
    Ok(result)
}
