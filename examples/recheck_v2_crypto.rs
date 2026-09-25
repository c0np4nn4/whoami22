//! Read-only replay of retained VESS artifacts. Never prints private values.
use anyhow::{ensure, Context, Result};
use c_kzg::{ethereum_kzg_settings, Blob};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
};
use vess_bench::{
    chain::Word,
    e2e::{core::*, model::*},
};

// Exact bincode field order of node.rs; round-trip equality rejects schema drift.
#[derive(Serialize, Deserialize)]
struct Candidate {
    request: Generation,
    row: Vec<Pair>,
    state: Option<State>,
}
#[derive(Serialize, Deserialize)]
struct Disk {
    sk: Scalar,
    rsk: Scalar,
    key_epoch: u64,
    source: Option<State>,
    row: Vec<Pair>,
    owner_secret: Option<Pair>,
    candidate: Option<Candidate>,
    plan: Option<Plan>,
    certificate: Option<Certificate>,
    reservations: BTreeMap<u64, Word>,
    header: Option<Header>,
    share: Option<Pair>,
    staged: Option<Staged>,
    applied: BTreeSet<u64>,
    fault: String,
}
fn disk(path: &Path) -> Result<Disk> {
    let bytes = fs::read(path)?;
    let value: Disk = decode(&bytes).context("private-state schema")?;
    ensure!(
        enc(&value) == bytes,
        "private-state round trip: {}",
        path.display()
    );
    Ok(value)
}
fn read_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 3,
        "usage: recheck_v2_crypto SUITE OUTPUT_DIRECTORY"
    );
    let root = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    fs::create_dir_all(out)?;
    let mut stream = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join("crypto_checks.jsonl"))?;
    let statuses: Vec<Value> = fs::read_to_string(root.join("status.jsonl"))?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let mut total_trials = 0;
    let mut total_bundles = 0;
    let mut total_records = 0;
    let mut total_participants = 0;
    let mut total_dealers = 0;
    let mut rows = Vec::new();
    for status in statuses.iter().filter(|s| s["status"] == "completed") {
        let profile = status["name"].as_str().context("profile name")?;
        let run = root.join("runs").join(profile);
        let cfg: vess_bench::e2e::runner::Config =
            toml::from_str(&fs::read_to_string(run.join("config.toml"))?)?;
        let mut paths = fs::read_dir(&run)?
            .map(|p| Ok(p?.path()))
            .collect::<Result<Vec<_>>>()?;
        paths.sort();
        for trial in paths
            .iter()
            .filter(|p| p.is_dir() && p.join("completion.json").exists())
        {
            let name = trial.file_name().unwrap().to_string_lossy();
            eprintln!("REPLAY {profile}/{name}");
            let mut paths = fs::read_dir(trial.join("public"))?
                .map(|p| Ok(p?.path()))
                .collect::<Result<Vec<_>>>()?;
            paths.retain(|p| p.extension().is_some_and(|s| s == "bundle"));
            paths.sort_by_key(|p| {
                p.file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .parse::<u64>()
                    .unwrap()
            });
            let mut bundles = Vec::new();
            let mut evidence = Vec::new();
            let mut record_count = 0;
            for path in paths {
                let payload = fs::read(&path)?;
                let b: Bundle = decode(&payload)?;
                ensure!(enc(&b) == payload, "bundle round trip");
                b.validate()?;
                for s in [&b.source, &b.target] {
                    let rebuilt = state(s.epoch, s.params, s.vectors.clone())?;
                    ensure!(rebuilt.id() == s.id(), "public polynomial consistency");
                    ensure!(
                        s.params.t == cfg.thresholds[s.epoch as usize],
                        "threshold schedule"
                    );
                    ensure!(
                        [s.params.n, s.params.k, s.params.f]
                            == vess_bench::e2e::runner::committee_parameters(cfg.committees[0])?,
                        "committee"
                    );
                }
                ensure!(b.target.epoch == b.source.epoch + 1, "adjacent epochs");
                ensure!(
                    b.source.public[0] == b.target.public[0],
                    "public secret unchanged"
                );
                for r in &b.records {
                    context(
                        r,
                        &b.manifest.source,
                        &b.manifest.target,
                        b.manifest.nonce,
                        false,
                    )?;
                    let key = &b.manifest.keys[r.dealer() - 1];
                    ensure!(r.key_epoch() == key.key_epoch, "historical signer epoch");
                    authenticated(r, key.pk)?;
                    record_count += 1;
                }
                let mut expected = vec![0u8; 131072];
                expected[16..32].copy_from_slice(&b.manifest.record_root[..16]);
                expected[48..64].copy_from_slice(&b.manifest.record_root[16..]);
                ensure!(payload.len() <= 4094 * 31, "one-blob capacity");
                for (i, chunk) in payload.chunks(31).enumerate() {
                    expected[(i + 2) * 32 + 1..(i + 2) * 32 + 1 + chunk.len()]
                        .copy_from_slice(chunk);
                }
                let stored_blob = fs::read(path.with_extension("blob"))?;
                ensure!(
                    stored_blob == expected,
                    "actual blob bytes do not encode bundle"
                );
                let blob = Blob::from_bytes(&stored_blob)?;
                let commitment = ethereum_kzg_settings(0)
                    .blob_to_kzg_commitment(&blob)?
                    .to_bytes();
                let mut versioned: [u8; 32] = Sha256::digest(commitment.as_ref()).into();
                versioned[0] = 1;
                // Both archive replicas must retain the published byte sequence.
                for archive in [9001, 9002] {
                    let p = trial.join(format!(
                        "nodes/archive-{archive}/{}.bundle",
                        hex::encode(b.manifest.id())
                    ));
                    ensure!(fs::read(&p)? == payload, "archive/public bundle mismatch");
                }
                evidence.push(json!({"nonce": b.manifest.nonce, "epoch": b.target.epoch,
                    "source":hex::encode(b.source.id()), "target":hex::encode(b.target.id()),
                    "metadata":hex::encode(b.manifest.id()), "record_root":hex::encode(b.manifest.record_root),
                    "reservation":hex::encode(b.manifest.reservation),
                    "key_epochs":b.manifest.keys.iter().map(|k| k.key_epoch).collect::<Vec<_>>(),
                    "record_hashes":b.records.iter().map(|r| hex::encode(r.hash())).collect::<Vec<_>>(),
                    "payload_bytes":payload.len(), "blob_sha256":hex::encode(Sha256::digest(&stored_blob)),
                    "versioned_hash":format!("0x{}",hex::encode(versioned))}));
                bundles.push(b);
            }
            let completion = read_json(&trial.join("completion.json"))?;
            let faults = completion["faults"].as_bool().context("fault flag")?;
            ensure!(
                bundles.len() == 3 + usize::from(faults),
                "publication count"
            );
            let committed: Vec<_> = bundles
                .iter()
                .filter(|b| !(faults && b.manifest.nonce == 1))
                .collect();
            ensure!(committed.len() == 3, "commit count");
            for pair in committed.windows(2) {
                ensure!(
                    pair[0].target.id() == pair[1].source.id(),
                    "continuous public state"
                );
            }
            if faults {
                ensure!(
                    bundles[0].source.id() == bundles[1].source.id(),
                    "abort source retained"
                );
                ensure!(
                    bundles[0].target.id() != bundles[1].target.id(),
                    "abort must use fresh candidate"
                );
            }
            let final_state = &committed.last().context("final publication")?.target;
            let owner = disk(&trial.join("nodes/owner-8001/private.bin"))?;
            let secret = owner.owner_secret.context("owner oracle")?;
            ensure!(
                secret.commit() == final_state.public[0],
                "owner oracle commitment"
            );
            let population = *cfg.populations.last().context("population")?;
            let mut shares = Vec::new();
            for id in 1..=population as u64 {
                let d = disk(&trial.join(format!("nodes/participant-{}/private.bin", 1000 + id)))?;
                ensure!(
                    enc(d.header.as_ref().context("participant header")?)
                        == enc(&Header::from(final_state)),
                    "participant final header: {profile}/{name}/{id}"
                );
                ensure!(
                    d.staged.is_none(),
                    "staged token remains after final commit"
                );
                let share = d.share.context("participant share")?;
                ensure!(
                    share.commit() == peval(&final_state.public, Scalar::from(id)),
                    "final share invalid: {profile}/{name}/{id}"
                );
                shares.push((id, share));
            }
            let t = final_state.params.t;
            ensure!(combine(&shares[..t])? == secret, "first-t reconstruction");
            ensure!(
                combine(&shares[population - t..])? == secret,
                "last-t reconstruction"
            );
            for id in 1..=final_state.params.n {
                let d = disk(&trial.join(format!("nodes/dealer-{id}/private.bin")))?;
                ensure!(
                    d.source.as_ref().context("dealer state")?.id() == final_state.id(),
                    "dealer final state"
                );
                ensure!(
                    d.candidate.is_none() && d.plan.is_none() && d.certificate.is_none(),
                    "dealer pending state"
                );
                ensure!(d.row.len() == t, "dealer row threshold");
                ensure!(
                    d.row.iter().map(|x| x.commit()).collect::<Vec<_>>()
                        == final_state.vectors[id - 1],
                    "dealer final row commitments"
                );
            }
            let row = json!({"profile":profile,"trial":name,"passed":true,
                "participant_shares_verified":population,"dealer_rows_verified":final_state.params.n,
                "fresh_reconstructions":2,"authenticated_records":record_count,"bundles":evidence});
            writeln!(stream, "{}", row)?;
            stream.flush()?;
            total_trials += 1;
            total_bundles += bundles.len();
            total_records += record_count;
            total_participants += population;
            total_dealers += final_state.params.n;
            rows.push(row);
        }
    }
    let result = json!({"passed":true,"trials":total_trials,"bundles":total_bundles,
        "authenticated_records":total_records,"participant_shares_verified":total_participants,
        "dealer_rows_verified":total_dealers,"fresh_reconstructions":2*total_trials,
        "note":"Retained synthetic private states were read locally; no secrets were written to this output."});
    fs::write(
        out.join("crypto_summary.json"),
        serde_json::to_vec_pretty(&result)?,
    )?;
    println!("{}", result);
    Ok(())
}
