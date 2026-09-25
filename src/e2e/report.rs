use super::{core::*, model::*, runner::Config};
use crate::chain::{self, Word};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Write},
    path::Path,
};
type MeasurementKey = (usize, String, String, u64, usize, usize, u64, u64);
type Measurements = BTreeMap<MeasurementKey, Vec<f64>>;

fn recipient(row: &Value) -> u64 {
    row["data"]["recipient"].as_u64().unwrap_or_else(|| {
        // Earlier single-recipient runs omitted this field.
        u64::from(row["metric"] == "offline_catchup")
    })
}

fn measurement_key(row: &Value) -> Result<MeasurementKey> {
    Ok((
        row["committee"][0].as_u64().context("committee")? as usize,
        row["scenario"].as_str().context("scenario")?.to_owned(),
        row["metric"].as_str().context("metric")?.to_owned(),
        row["epoch"].as_u64().context("epoch")?,
        row["t"].as_u64().context("threshold")? as usize,
        row["N"].as_u64().context("population")? as usize,
        row["data"]["nonce"].as_u64().unwrap_or(0),
        recipient(row),
    ))
}

fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn csv_row(cells: &[String]) -> String {
    format!(
        "{}\n",
        cells
            .iter()
            .map(|s| csv_cell(s))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let widths = headers
        .iter()
        .enumerate()
        .map(|(i, header)| {
            rows.iter()
                .map(|row| row[i].len())
                .fold(header.len(), usize::max)
        })
        .collect::<Vec<_>>();
    let border = format!(
        "+{}+\n",
        widths
            .iter()
            .map(|width| "-".repeat(width + 2))
            .collect::<Vec<_>>()
            .join("+")
    );
    let mut output = border.clone();
    for (index, cells) in std::iter::once(headers.iter().map(|h| h.to_string()).collect::<Vec<_>>())
        .chain(rows.iter().cloned())
        .enumerate()
    {
        output.push('|');
        for (cell, width) in cells.iter().zip(&widths) {
            output.push_str(&format!(" {cell:<width$} |"));
        }
        output.push('\n');
        if index == 0 {
            output.push_str(&border);
        }
    }
    output.push_str(&border);
    output
}

fn scenario_label(scenario: &str) -> &str {
    match scenario {
        "baseline" => "Normal",
        "integrated_faults" => "Integrated faults",
        other => other,
    }
}

fn console_report(
    input: &Path,
    report: &Path,
    config: &Config,
    audit: &Value,
    groups: &Measurements,
) -> String {
    let mut output = format!(
        "\nE2E benchmark: {}\nResults: {}\nEvidence audit: PASS | Lifecycles: {} | Verified reconstructions: {}\nParticipants by epoch: {:?}\nReconstruction thresholds by epoch: {:?}\n",
        config.name,
        input.display(),
        audit["trials"],
        audit["secret_reconstructions"],
        config.populations,
        config.thresholds,
    );
    output.push_str(&format!(
        "Committee inputs [n_D, k_D, f_D]: {:?}\nFault injection: {}\n",
        config.committees,
        if config.fault_scenarios {
            "enabled in explicit validation profile"
        } else {
            "disabled; dealers and archives remain online"
        },
    ));
    let mut lifecycle = Vec::new();
    let mut stages: BTreeMap<(usize, &str), Vec<_>> = BTreeMap::new();
    for ((dealers, scenario, metric, epoch, threshold, population, attempt, recipient), values) in
        groups
    {
        let minimum = values.iter().copied().fold(f64::INFINITY, f64::min);
        let maximum = values.iter().copied().fold(0., f64::max);
        if metric == "lifecycle" {
            lifecycle.push(vec![
                dealers.to_string(),
                scenario_label(scenario).to_owned(),
                values.len().to_string(),
                format!("{:.3}", median(values) / 1000.),
                format!("{:.3}", minimum / 1000.),
                format!("{:.3}", maximum / 1000.),
            ]);
        } else {
            stages.entry((*dealers, scenario)).or_default().push((
                *epoch,
                *attempt,
                metric,
                vec![
                    epoch.to_string(),
                    threshold.to_string(),
                    population.to_string(),
                    attempt.to_string(),
                    if *recipient == 0 {
                        "-".into()
                    } else {
                        recipient.to_string()
                    },
                    metric.to_owned(),
                    values.len().to_string(),
                    format!("{:.3}", median(values)),
                    format!("{minimum:.3}"),
                    format!("{maximum:.3}"),
                ],
            ));
        }
    }
    if audit["multipart_evidence_checked"] == true {
        output.push_str(&format!("\nAudited publication totals: {} blobs / {} transactions / {} physical bytes\nPublication execution gas: {}; blob gas: {}\n", audit["publication_blob_count"], audit["publication_transaction_count"], audit["publication_physical_bytes"], audit["publication_execution_gas"], audit["publication_blob_gas"]));
    }
    output.push_str("\nWhole lifecycle (seconds)\n");
    output.push_str(&table(
        &[
            "Dealers",
            "Scenario",
            "Runs",
            "Median (s)",
            "Min (s)",
            "Max (s)",
        ],
        &lifecycle,
    ));
    output.push_str("Includes validation reconstructions; initial chain/contract/process setup is separate.\nRuns=1 is one observation, not a statistical performance estimate.\n");
    output.push_str("\nMeasured stages (milliseconds)\nt: reconstruction threshold; N: participants; Attempt: transition nonce (0 = unspecified/not applicable).\nRecipient identifies an individual participant; Samples counts observations for that participant and transition, never different participants as repetitions.\nStage intervals can overlap; do not sum them to obtain lifecycle latency.\n");
    for ((dealers, scenario), mut rows) in stages {
        rows.sort_by(|a, b| (&a.0, &a.1, a.2).cmp(&(&b.0, &b.1, b.2)));
        output.push_str(&format!(
            "\n{dealers} dealers / {}\n",
            scenario_label(scenario)
        ));
        output.push_str(&table(
            &[
                "Epoch",
                "t",
                "N",
                "Attempt",
                "Recipient",
                "Metric",
                "Samples",
                "Median (ms)",
                "Min (ms)",
                "Max (ms)",
            ],
            &rows.into_iter().map(|row| row.3).collect::<Vec<_>>(),
        ));
    }
    output.push_str(&format!(
        "\nCSV (whole lifecycle, seconds): {}\nCSV (grouped measurements, milliseconds): {}\nCSV (individual observations): {}\nTeX report: {}\n",
        input.join("lifecycle.csv").display(),
        input.join("summary.csv").display(),
        input.join("measurements.csv").display(),
        report.display(),
    ));
    output
}

fn median(v: &[f64]) -> f64 {
    let mut v = v.to_vec();
    v.sort_by(f64::total_cmp);
    let n = v.len();
    if n.is_multiple_of(2) {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    }
}
fn esc(s: &str) -> String {
    s.replace('\\', "\\textbackslash{}")
        .replace('_', "\\_")
        .replace('&', "\\&")
        .replace('%', "\\%")
        .replace('#', "\\#")
}
fn read_json(p: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}

fn validate_catchup_metrics(
    rows: &[&Value],
    count: usize,
    committed: &BTreeMap<u64, u64>,
    applications: &BTreeMap<(u64, u64), u64>,
) -> Result<()> {
    let expected = (1..=count as u64).collect::<BTreeSet<_>>();
    let expected_epochs = BTreeSet::from([1u64, 2]);
    let mut transitions = BTreeMap::new();
    let mut participants = BTreeMap::new();
    let mut aggregate = None;
    for row in rows {
        match row["metric"].as_str().unwrap_or("") {
            "offline_catchup" => {
                let id = row["data"]["recipient"]
                    .as_u64()
                    .context("catch-up recipient")?;
                let epoch = row["epoch"].as_u64().context("catch-up epoch")?;
                let nonce = row["data"]["nonce"].as_u64().context("catch-up nonce")?;
                let records = row["data"]["records_read"]
                    .as_u64()
                    .context("catch-up records")?;
                ensure!(
                    expected.contains(&id) && expected_epochs.contains(&epoch),
                    "unexpected catch-up recipient/epoch"
                );
                ensure!(
                    committed.get(&epoch) == Some(&nonce),
                    "catch-up metric has wrong committed attempt"
                );
                ensure!(
                    applications.get(&(id, nonce)) == Some(&records),
                    "catch-up metric lacks matching participant application evidence"
                );
                let duration = row["duration_ns"].as_u64().context("catch-up duration")?;
                ensure!(
                    transitions
                        .insert((id, epoch), (records, duration))
                        .is_none(),
                    "duplicate recipient transition measurement"
                );
            }
            "participant_catchup" => {
                let id = row["data"]["recipient"]
                    .as_u64()
                    .context("participant catch-up recipient")?;
                ensure!(
                    expected.contains(&id) && participants.insert(id, *row).is_none(),
                    "duplicate/unexpected participant catch-up measurement"
                );
            }
            "offline_return_and_catchup" | "offline_maintenance_window" => {
                ensure!(
                    aggregate.replace(*row).is_none(),
                    "duplicate group catch-up measurement"
                );
            }
            _ => {}
        }
    }
    ensure!(
        transitions.len() == count * 2 && participants.len() == count,
        "missing participant catch-up measurements"
    );
    for (id, row) in participants {
        let first = transitions
            .get(&(id, 1))
            .context("missing first catch-up transition")?;
        let second = transitions
            .get(&(id, 2))
            .context("missing second catch-up transition")?;
        ensure!(
            row["epoch"] == 2
                && row["data"]["target_epoch"] == 2
                && row["data"]["missed_epochs"] == 2
                && row["data"]["completed_epochs"] == json!([1, 2])
                && row["data"]["records_read"].as_u64() == Some(first.0 + second.0),
            "participant catch-up summary mismatch"
        );
        ensure!(
            row["duration_ns"]
                .as_u64()
                .context("participant catch-up duration")?
                >= first.1 + second.1,
            "participant interval excludes a recovered transition"
        );
    }
    let aggregate = aggregate.context("missing group catch-up measurement")?;
    let ids = aggregate["data"]["participants"]
        .as_array()
        .context("group catch-up participants")?
        .iter()
        .map(|id| id.as_u64().context("group participant identifier"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        ids.len() == count
            && ids.into_iter().collect::<BTreeSet<_>>() == expected
            && aggregate["data"]["missed_epochs"] == 2
            && aggregate["epoch"] == 2,
        "group catch-up participant coverage"
    );
    ensure!(
        aggregate["data"]["concurrency"]
            .as_u64()
            .is_some_and(|n| n > 0),
        "group catch-up concurrency"
    );
    let group_duration = aggregate["duration_ns"]
        .as_u64()
        .context("group catch-up duration")?;
    for row in rows
        .iter()
        .filter(|row| row["metric"] == "participant_catchup")
    {
        ensure!(
            group_duration >= row["duration_ns"].as_u64().unwrap(),
            "group interval excludes a participant"
        );
    }
    Ok(())
}

fn configured_offline_count(config: &toml::Value, manifest: &Value) -> Result<Option<usize>> {
    let from_config = config
        .get("offline_participants")
        .map(|value| {
            let n = value
                .as_integer()
                .context("configured offline participant count")?;
            usize::try_from(n).context("offline participant count range")
        })
        .transpose()?;
    let from_manifest = manifest["config"]
        .get("offline_participants")
        .map(|value| {
            let n = value
                .as_u64()
                .context("manifest offline participant count")?;
            usize::try_from(n).context("offline participant count range")
        })
        .transpose()?;
    if let (Some(raw), Some(resolved)) = (from_config, from_manifest) {
        ensure!(
            raw == resolved,
            "offline participant configuration differs from execution manifest"
        );
    }
    Ok(from_manifest.or(from_config))
}
// Recompute exact ordered sidecars from the authenticated serialized bundle.
// Receipt matching below then binds these bytes to actual type-3 transactions.
fn publication_evidence(dir: &Path, b: &Bundle) -> Result<Vec<(String, Value)>> {
    use chain::{Arg, FieldPublication, BLOBS_PER_TRANSACTION};
    let bytes = enc(b);
    let p = read_json(&dir.join(format!("{}.publication.json", b.manifest.nonce)))?;
    ensure!(
        p["schema"] == 1
            && p["payload_bytes"] == bytes.len()
            && p["root"] == chain::hhex(&b.manifest.record_root),
        "publication manifest"
    );
    let expected = FieldPublication::new(b.manifest.record_root, &bytes)?;
    let fragments = p["fragments"].as_array().context("publication fragments")?;
    let batches = p["batches"].as_array().context("publication batches")?;
    ensure!(
        fragments.len() == expected.blobs.len()
            && batches.len() == expected.blobs.len().div_ceil(BLOBS_PER_TRANSACTION),
        "publication fragment/batch count"
    );
    for (i, (fragment, blob)) in fragments.iter().zip(&expected.blobs).enumerate() {
        let file = format!("{}.{}.blob", b.manifest.nonce, i);
        ensure!(
            fragment["file"] == file
                && fragment["versioned_hash"] == chain::hhex(&blob.versioned)
                && fs::read(dir.join(file))? == blob.bytes,
            "ordered blob bytes/hash mismatch"
        );
    }
    let mut out = Vec::new();
    for (index, blobs) in expected.blobs.chunks(BLOBS_PER_TRANSACTION).enumerate() {
        let offset = index * BLOBS_PER_TRANSACTION;
        let batch = &batches[index];
        ensure!(
            batch["offset"] == offset && batch["count"] == blobs.len(),
            "batch order/count"
        );
        let input = chain::calldata(
            "publish(uint256,bytes32,bytes32,bytes32[],uint256,uint256,bytes)",
            &[
                Arg::Word(chain::word(b.manifest.nonce)),
                Arg::Word(b.manifest.record_root),
                Arg::Word(b.manifest.id()),
                Arg::Words(b.manifest.target.roots.clone()),
                Arg::Word(chain::word(bytes.len() as u64)),
                Arg::Word(chain::word(offset as u64)),
                Arg::Bytes(
                    blobs
                        .iter()
                        .flat_map(|b| b.point_proofs[0].clone())
                        .collect(),
                ),
            ],
        );
        out.push((batch["transaction_hash"].as_str().context("batch transaction hash")?.to_owned(),
            json!({"nonce":b.manifest.nonce,"offset":offset,"input":chain::hhex(&input),
                "versions":blobs.iter().map(|b|chain::hhex(&b.versioned)).collect::<Vec<_>>(),
                "sha256":blobs.iter().map(|b| {use sha2::{Digest,Sha256};hex::encode(Sha256::digest(&b.bytes))}).collect::<Vec<_>>() })));
    }
    Ok(out)
}

pub fn audit(dir: &Path) -> Result<Value> {
    // New executables persist resolved defaults in manifest.config, including
    // when an old input configuration omits the new field. Genuine old runs
    // omit it in both places and retain their existing audit.
    let config: toml::Value = toml::from_str(&fs::read_to_string(dir.join("config.toml"))?)?;
    let manifest = read_json(&dir.join("manifest.json"))?;
    let configured_offline = configured_offline_count(&config, &manifest)?;
    let samples = if configured_offline.is_some() {
        fs::read_to_string(dir.join("samples.jsonl"))?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    let multipart = manifest["publication_encoding"] == "field-root-ordered-blobs-v1";
    let mut publication_blobs = 0u64;
    let mut publication_transactions = 0u64;
    let mut publication_execution_gas = 0u64;
    let mut publication_blob_gas = 0u64;
    let mut bundles = 0;
    let mut records = 0;
    let mut receipts = 0;
    let mut gas = 0u64;
    let mut blobgas = 0u64;
    let mut tokens = 0;
    let mut applied = 0;
    let mut reconstructions = 0;
    let mut trials = 0;
    let mut catchup_participants_checked = 0;
    let mut txids = BTreeSet::new();
    let mut audit_rows = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if !path.is_dir() || !path.join("completion.json").exists() {
            continue;
        }
        trials += 1;
        let completion = read_json(&path.join("completion.json"))?;
        ensure!(completion["passed"] == true, "trial not passed");
        let oracle = if path.join("correctness_oracle.json").exists() {
            Some(read_json(&path.join("correctness_oracle.json"))?)
        } else {
            None
        };
        let mut publications = BTreeMap::new();
        let mut expected_batches = BTreeMap::new();
        for e in fs::read_dir(path.join("public"))? {
            let p = e?.path();
            if p.extension().is_some_and(|x| x == "bundle") {
                let b: Bundle = decode(&fs::read(p)?)?;
                b.validate()?;
                let recalculated =
                    state(b.target.epoch, b.target.params, b.target.vectors.clone())?;
                ensure!(
                    recalculated.id() == b.target.id() && b.source.public[0] == b.target.public[0],
                    "public state consistency"
                );
                for r in &b.records {
                    context(
                        r,
                        &b.manifest.source,
                        &b.manifest.target,
                        b.manifest.nonce,
                        false,
                    )?;
                    let m = &b.manifest.keys[r.dealer() - 1];
                    ensure!(r.key_epoch() == m.key_epoch, "key snapshot");
                    signed_record(r, m.pk)?;
                    records += 1;
                }
                if multipart {
                    for (hash, evidence) in publication_evidence(&path.join("public"), &b)? {
                        ensure!(
                            expected_batches.insert(hash, evidence).is_none(),
                            "duplicate batch transaction"
                        );
                    }
                }
                publications.insert(b.manifest.nonce, b.manifest);
                bundles += 1;
            }
        }
        let mut commits = BTreeMap::new();
        let mut committed_epochs = BTreeMap::new();
        let mut catchup_applications = BTreeMap::new();
        for e in fs::read_dir(path.join("chain"))? {
            let p = e?.path();
            if p.extension().is_none_or(|s| s != "json")
                || p.file_name().unwrap() == "chain_manifest.json"
            {
                continue;
            }
            let v = read_json(&p)?;
            if v.get("receipt").is_none() {
                continue;
            }
            let r = &v["receipt"];
            ensure!(
                chain::hex_u64(&r["status"])? == 1,
                "failed receipt {}",
                p.display()
            );
            let key = (
                path.file_name().unwrap().to_string_lossy().to_string(),
                r["transactionHash"].to_string(),
            );
            ensure!(txids.insert(key), "duplicate transaction receipt");
            receipts += 1;
            gas += chain::hex_u64(&r["gasUsed"])?;
            if !r["blobGasUsed"].is_null() {
                blobgas += chain::hex_u64(&r["blobGasUsed"])?;
            }
            if let Some(expected) = expected_batches.remove(
                r["transactionHash"]
                    .as_str()
                    .context("receipt transaction hash")?,
            ) {
                let versions = expected["versions"].as_array().context("blob versions")?;
                let tx = &v["transaction"];
                ensure!(
                    tx["type"] == 3
                        && tx["input"] == expected["input"]
                        && tx["versioned_hashes"] == expected["versions"]
                        && tx["blob_sha256"] == expected["sha256"]
                        && tx["physical_blob_bytes"] == versions.len() * 131072
                        && chain::hex_u64(&r["blobGasUsed"])? == versions.len() as u64 * 131072,
                    "publication receipt/sidecar binding"
                );
                let blob_event =
                    chain::hhex(&chain::keccak(b"BlobStored(uint256,uint256,bytes32)"));
                let events = r["logs"]
                    .as_array()
                    .context("blob logs")?
                    .iter()
                    .filter(|l| l["topics"][0] == blob_event)
                    .collect::<Vec<_>>();
                ensure!(events.len() == versions.len(), "blob storage event count");
                for (i, event) in events.iter().enumerate() {
                    ensure!(
                        chain::hex_u64(&event["topics"][1])? == expected["nonce"].as_u64().unwrap()
                            && chain::hex_u64(&event["topics"][2])?
                                == expected["offset"].as_u64().unwrap() + i as u64
                            && event["data"] == versions[i],
                        "ordered on-chain blob event"
                    );
                }
                publication_blobs += versions.len() as u64;
                publication_transactions += 1;
                publication_execution_gas += chain::hex_u64(&r["gasUsed"])?;
                publication_blob_gas += chain::hex_u64(&r["blobGasUsed"])?;
            } else {
                ensure!(
                    !multipart || v["transaction"]["type"] != 3,
                    "unaccounted blob transaction"
                );
            }
            let sig = chain::hhex(&chain::keccak(
                b"EpochCommit(uint256,bytes32,bytes32,bytes32,bytes32)",
            ));
            for l in r["logs"].as_array().context("receipt logs")? {
                if l["topics"][0] == sig {
                    let nonce = chain::hex_u64(&l["topics"][1])?;
                    let target = chain::unhex(l["topics"][3].as_str().unwrap())?;
                    let source = chain::unhex(l["topics"][2].as_str().unwrap())?;
                    let data = chain::unhex(l["data"].as_str().unwrap())?;
                    let m = publications.get(&nonce).context("commit publication")?;
                    ensure!(
                        target == m.target.id
                            && source == m.source.id
                            && data == [m.record_root, m.id()].concat(),
                        "commit event binding"
                    );
                    commits.insert(nonce, m.target.id);
                    ensure!(
                        committed_epochs.insert(m.target.epoch, nonce).is_none(),
                        "duplicate committed epoch"
                    );
                }
            }
        }
        ensure!(
            expected_batches.is_empty(),
            "missing publication transaction receipts"
        );
        for e in fs::read_dir(path.join("nodes"))? {
            let p = e?.path().join("events.jsonl");
            if !p.exists() {
                continue;
            }
            let mut certified = BTreeSet::new();
            for line in fs::read_to_string(p)?.lines() {
                let v: Value = serde_json::from_str(line)?;
                match v["kind"].as_str().unwrap_or("") {
                    "certificate_signed" => {
                        certified.insert(v["data"]["digest"].as_str().unwrap().to_owned());
                    }
                    "token_release" => {
                        ensure!(
                            certified
                                .contains(v["data"]["digest"].as_str().context("release digest")?),
                            "release before local certificate signature"
                        );
                        tokens += 1;
                    }
                    "commit_applied" | "catchup_applied" => {
                        let nonce = v["data"]["nonce"].as_u64().context("nonce")?;
                        let target: Word =
                            chain::unhex(v["data"]["target"].as_str().context("target")?)?
                                .try_into()
                                .map_err(|_| anyhow::anyhow!("target length"))?;
                        ensure!(
                            commits.get(&nonce) == Some(&target),
                            "apply without matching canonical commit"
                        );
                        if v["kind"] == "catchup_applied" && configured_offline.is_some() {
                            ensure!(v["role"] == "participant", "catch-up application role");
                            let id = v["node"]
                                .as_u64()
                                .and_then(|n| n.checked_sub(1000))
                                .context("catch-up node identifier")?;
                            let count = v["data"]["records"]
                                .as_u64()
                                .context("catch-up application records")?;
                            ensure!(
                                catchup_applications.insert((id, nonce), count).is_none(),
                                "duplicate participant catch-up application"
                            );
                        }
                        applied += 1;
                    }
                    "secret_reconstructed" => {
                        if let Some(oracle) = &oracle {
                            ensure!(
                                v["data"]["commitment_verified"] == true
                                    && v["data"]["secret_digest"] == oracle["secret_pair_digest"],
                                "reconstruction digest oracle"
                            );
                        } else {
                            ensure!(v["data"]["matches_owner"] == true, "legacy reconstruction");
                        }
                        reconstructions += 1;
                    }
                    _ => {}
                }
            }
        }
        if let Some(count) = configured_offline {
            let name = path.file_name().unwrap().to_string_lossy();
            let rows = samples
                .iter()
                .filter(|r| r["run"].as_str() == Some(name.as_ref()))
                .collect::<Vec<_>>();
            if completion["faults"] != true {
                validate_catchup_metrics(&rows, count, &committed_epochs, &catchup_applications)
                    .with_context(|| format!("catch-up evidence for {name}"))?;
                catchup_participants_checked += count;
            }
        }
        ensure!(commits.len() >= 3, "continuous epochs missing");
        audit_rows.push(json!({"trial":path.file_name().unwrap().to_string_lossy(),"committed_epochs":commits.len(),"validated":true}));
    }
    ensure!(
        trials > 0 && reconstructions >= trials * 4,
        "no completed lifecycle evidence"
    );
    let result = json!({"passed":true,"trials":trials,"bundles":bundles,"multipart_evidence_checked":multipart,"publication_blob_count":publication_blobs,"publication_transaction_count":publication_transactions,"publication_execution_gas":publication_execution_gas,"publication_blob_gas":publication_blob_gas,"publication_physical_bytes":publication_blobs*131072,"authenticated_records":records,"receipt_count":receipts,"execution_gas":gas,"blob_gas":blobgas,"release_events":tokens,"canonical_apply_events":applied,"secret_reconstructions":reconstructions,"catchup_participants_checked":catchup_participants_checked,"catchup_transitions_checked":catchup_participants_checked*2,"trial_evidence":audit_rows});
    fs::write(dir.join("audit.json"), serde_json::to_vec_pretty(&result)?)?;
    Ok(result)
}
pub fn write(input: &Path, out: &Path) -> Result<()> {
    let audit = audit(input)?;
    let config = Config::load(&input.join("config.toml"))?;
    let rows = fs::read_to_string(input.join("samples.jsonl"))?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    // Attempts and different participants are not independent repetitions.
    // Preserve both identities when grouping observations across lifecycles.
    let mut groups = Measurements::new();
    for r in &rows {
        let Some(ns) = r["duration_ns"].as_u64() else {
            continue;
        };
        groups
            .entry(measurement_key(r)?)
            .or_default()
            .push(ns as f64 / 1e6);
    }
    let mut csv = String::from(
        "dealers,scenario,metric,epoch,t,N,attempt_nonce,samples,median_ms,min_ms,max_ms,recipient\n",
    );
    let mut lifecycle_csv = String::from("dealers,scenario,samples,median_s,min_s,max_s\n");
    for ((n, s, m, e, t, p, a, recipient), v) in &groups {
        csv += &format!(
            "{n},{s},{m},{e},{t},{p},{a},{},{:.6},{:.6},{:.6},{recipient}\n",
            v.len(),
            median(v),
            v.iter().copied().fold(f64::INFINITY, f64::min),
            v.iter().copied().fold(0., f64::max)
        );
        if m == "lifecycle" {
            lifecycle_csv += &format!(
                "{n},{s},{},{:.6},{:.6},{:.6}\n",
                v.len(),
                median(v) / 1000.,
                v.iter().copied().fold(f64::INFINITY, f64::min) / 1000.,
                v.iter().copied().fold(0., f64::max) / 1000.
            );
        }
    }
    fs::write(input.join("summary.csv"), csv)?;
    fs::write(input.join("lifecycle.csv"), lifecycle_csv)?;
    let mut raw_csv = String::from("run,trial,dealers,scenario,metric,epoch,t,N,attempt_nonce,recipient,duration_ns,duration_ms,data_json\n");
    let mut catchup_csv = String::from("run,trial,dealers,scenario,recipient,epoch,t,N,attempt_nonce,duration_ms,records_read,localized,vector_fetches,bytes\n");
    let mut participant_csv = String::from("run,trial,dealers,scenario,recipient,target_epoch,missed_epochs,records_read,duration_ms\n");
    let mut group_csv = String::from(
        "run,trial,dealers,scenario,return_epoch,participants,concurrency,duration_ms\n",
    );
    let mut participant_rows = Vec::new();
    let mut catchup_group_rows = Vec::new();
    for r in &rows {
        let Some(ns) = r["duration_ns"].as_u64() else {
            continue;
        };
        let (dealers, scenario, metric, epoch, t, population, nonce, recipient) =
            measurement_key(r)?;
        let run = r["run"].as_str().context("measurement run")?.to_owned();
        let trial = r["trial"].to_string();
        let milliseconds = format!("{:.6}", ns as f64 / 1e6);
        let data = &r["data"];
        raw_csv.push_str(&csv_row(&[
            run.clone(),
            trial.clone(),
            dealers.to_string(),
            scenario.clone(),
            metric.clone(),
            epoch.to_string(),
            t.to_string(),
            population.to_string(),
            nonce.to_string(),
            recipient.to_string(),
            ns.to_string(),
            milliseconds.clone(),
            data.to_string(),
        ]));
        if metric == "offline_catchup" {
            catchup_csv.push_str(&csv_row(&[
                run.clone(),
                trial.clone(),
                dealers.to_string(),
                scenario.clone(),
                recipient.to_string(),
                epoch.to_string(),
                t.to_string(),
                population.to_string(),
                nonce.to_string(),
                milliseconds.clone(),
                data["records_read"].to_string(),
                data["localized"].to_string(),
                data["vector_fetches"].to_string(),
                data["bytes"].to_string(),
            ]));
        } else if metric == "participant_catchup" {
            participant_csv.push_str(&csv_row(&[
                run.clone(),
                trial.clone(),
                dealers.to_string(),
                scenario.clone(),
                recipient.to_string(),
                epoch.to_string(),
                data["missed_epochs"].to_string(),
                data["records_read"].to_string(),
                milliseconds.clone(),
            ]));
            participant_rows.push(vec![
                run,
                recipient.to_string(),
                epoch.to_string(),
                data["missed_epochs"].to_string(),
                data["records_read"].to_string(),
                format!("{:.3}", ns as f64 / 1e6),
            ]);
        } else if metric == "offline_return_and_catchup" || metric == "offline_maintenance_window" {
            let count = data["participants"].as_array().map_or(1, Vec::len);
            let concurrency = data["concurrency"].as_u64().unwrap_or(1);
            group_csv.push_str(&csv_row(&[
                run.clone(),
                trial,
                dealers.to_string(),
                scenario,
                epoch.to_string(),
                count.to_string(),
                concurrency.to_string(),
                milliseconds,
            ]));
            catchup_group_rows.push(vec![
                run,
                epoch.to_string(),
                count.to_string(),
                concurrency.to_string(),
                format!("{:.3}", ns as f64 / 1e6),
            ]);
        }
    }
    fs::write(input.join("measurements.csv"), raw_csv)?;
    fs::write(input.join("catchup.csv"), catchup_csv)?;
    fs::write(input.join("participant_catchup.csv"), participant_csv)?;
    fs::write(input.join("catchup_groups.csv"), group_csv)?;
    let mut publication_rows = Vec::new();
    let mut publication_csv = String::from("run,dealers,epoch,attempt_nonce,payload_bytes,blob_count,publication_transactions,physical_blob_bytes\n");
    for r in rows
        .iter()
        .filter(|r| r["metric"] == "archive_blob_publication")
    {
        if r["data"]["blob_count"].is_null() {
            continue;
        }
        let data = &r["data"];
        let row = vec![
            r["run"].as_str().context("run")?.to_owned(),
            r["committee"][0].to_string(),
            r["epoch"].to_string(),
            data["nonce"].to_string(),
            data["payload_bytes"].to_string(),
            data["blob_count"].to_string(),
            data["publication_transactions"].to_string(),
            data["physical_blob_bytes"].to_string(),
        ];
        publication_csv.push_str(&format!("{}\n", row.join(",")));
        publication_rows.push(row);
    }
    fs::write(input.join("publications.csv"), publication_csv)?;
    let mut tex = String::from(
        r"\documentclass[10pt,a4paper]{article}
\usepackage[margin=20mm]{geometry}
\usepackage{booktabs,longtable,hyperref}
\setlength{\emergencystretch}{3em}
\title{End-to-End Lifecycle Benchmark}
\author{}
\date{}
\begin{document}\maketitle
\section{Scope and workload}
The implementation executes share initialization, enrollment, continuous epoch transitions, archive recovery and secret reconstruction using separate owner, dealer, participant and archive processes. Private messages use mutually authenticated TLS 1.3. Anvil provides transaction inclusion and the ordered public generation transcript; these are local-process measurements, without public-network consensus finality. Every accepted share and reconstructed secret is checked using the public commitments.
",
    );
    tex+=&format!("Committee configurations are {:?}, with entries $(n_D,k_D,f_D)$ denoting the number of dealers, the dealer sharing threshold, and the explicitly configured protocol fault bound. The configured bound is used unchanged in protocol quorum checks; it is not an injected-fault count. Participant populations are {:?}; participant reconstruction thresholds are {:?}. Each configuration has {} independent baseline lifecycle(s).\n",config.committees,config.populations,config.thresholds,config.repeats);
    if read_json(&input.join("manifest.json"))?["execution_gas_policy"] == chain::E2E_GAS_POLICY {
        tex.push_str("The local Anvil execution disables block gas-limit enforcement and uses the maximum representable block gas field. Each transaction receives an estimated gas allowance with headroom; execution gas is still measured from receipts. These observations do not establish feasibility under a public network's block gas budget.\n");
    }
    if !config.fault_scenarios {
        tex.push_str(&format!("No corruption or dealer/archive failure is injected. All dealers and both archives remain online throughout the measured lifecycle. The same {} participant(s) go offline for two transitions and then recover from the published records, with at most {} concurrent recovery workers. Each participant applies the two missed transitions in order. All records remain available. Successful share verification and reconstructed-secret digest checks validate the execution; malformed inputs, forced aborts, dispute calls and negative API tests are outside this workload.\n", config.offline_participants, config.catchup_concurrency));
    }
    tex.push_str(r"A pending enrollment stores verified partials, and installs a share only after canonical registry completion. Transition generation uses the qualified-set ReShare/JRSS procedure. Release reservations are recorded before update material is released. Liveness probes the complete active registry and classifies missing responses at the configured deadline. Online recipients verify and durably stage their tokens before acknowledging the candidate. Offline return checks authenticated records and uses aggregate verification before localization.

\section{Measurement definition}
Lifecycle latency is a single observer wall-clock interval from initialization through the final reconstruction. It includes enrollment and participant startup, growth, liveness classification, generation, reservation, publication, application, key rotation and archive recovery. Contract deployment and initial process setup are separately timed. The validation workload also reconstructs the secret initially and after each committed epoch; these checks are included in lifecycle latency. Component medians are never summed to create a lifecycle observation.

Independent lifecycles are the repetition unit. A single observation is not a statistical performance estimate. The table reports sample counts and observed ranges; epochs and attempts within a run are correlated. Attempt identifiers remain separate in the detailed CSV. Anvil uses immediate mining plus a one-second mining interval. CPU scheduling, first-use initialization, TLS establishment and transaction inclusion all contribute to the observed time.

\section{Complete lifecycle observations}
\begin{tabular}{rlrrrr}\toprule
Dealers & Scenario & Runs & Median (s) & Minimum (s) & Maximum (s)\\\midrule
");
    for ((n, s, m, _, _, _, _, _), v) in &groups {
        if m == "lifecycle" {
            tex += &format!(
                "{} & {} & {} & {:.3} & {:.3} & {:.3} \\\\\n",
                n,
                esc(s),
                v.len(),
                median(v) / 1000.,
                v.iter().copied().fold(f64::INFINITY, f64::min) / 1000.,
                v.iter().copied().fold(0., f64::max) / 1000.
            );
        }
    }
    tex.push_str(r"\bottomrule\end{tabular}
\section{Measured stages}
Here $t$ is the participant reconstruction threshold and $N$ is the number of registered participant processes. Enrollment before a transition uses the source epoch's threshold. The nonce identifies a particular transition attempt; zero denotes a measurement outside a single attempt.
\scriptsize
\begin{longtable}{rlrrrrrlrr}\toprule
Dealers & Scenario & Epoch & $t$ & $N$ & Nonce & Recipient & Measurement & Samples & Median (ms)\\\midrule\endhead
");
    for ((n, s, m, e, t, p, a, recipient), v) in &groups {
        if m != "lifecycle" {
            tex += &format!(
                "{} & {} & {} & {} & {} & {} & {} & {} & {} & {:.3} \\\\\n",
                n,
                esc(s),
                e,
                t,
                p,
                a,
                recipient,
                esc(m),
                v.len(),
                median(v)
            );
        }
    }
    tex.push_str(r"\bottomrule\end{longtable}\normalsize
\section{Catch-up measurement}
The group return interval includes participant process restart and recovery of all missed transitions by every returning participant. Recovery across participants uses the configured worker limit; transitions for the same participant remain sequential. A participant's recovery interval measures its two successive recovery calls after process startup and worker dispatch. These individual intervals overlap in time and must not be summed to obtain the group wall-clock interval. Participant identities and transition nonces remain separate in the CSV observations and stage table; different participants are not statistical repetitions.
\section{Implementation choices}
The difference-record path uses BN254 commitments, signatures and the Diffie--Hellman encryption instance with ephemeral proof of possession. The ABI representation of a signed record occupies 800 bytes, excluding framing. It is a concrete encoding; the manuscript's compressed-record size model is not reused for these payloads. The outer Merkle tree uses an explicitly domain-separated 248-bit hash, with its root encoded in the first blob field element. One native KZG opening per blob authenticates that common root during publication; record admission uses the first blob's root opening. Coefficient-vector roots are leaves of this outer tree; a final consistency step authenticates both coefficient and outer-tree membership. This concrete suite is not claimed to provide the manuscript's nominal 128-bit security level.

Public generation messages are sent to the chain bulletin board and their transaction costs belong to the measured implementation. Issuance completion evaluates the supplied dealer commitment vectors on chain, so its cost grows with both dealer threshold and participant threshold. A comparison with component operation counts must account for these choices.

\section{Evidence and interpretation}
");
    tex+=&format!("The artifact audit validated {} completed lifecycles, {} publication bundles, {} signed records, {} transaction receipts, {} release events, {} canonical application events and {} secret reconstruction checks. Total execution gas is {}; total blob gas is {}. These are totals across independent local chains, including setup, rather than the cost of one transition.\n",audit["trials"],audit["bundles"],audit["authenticated_records"],audit["receipt_count"],audit["release_events"],audit["canonical_apply_events"],audit["secret_reconstructions"],audit["execution_gas"],audit["blob_gas"]);
    if audit["multipart_evidence_checked"] == true {
        tex += &format!("The publication audit additionally matched {} blobs across {} publication transactions ({} physical bytes), including ordered file contents, versioned hashes, root openings, calldata and storage events.\n", audit["publication_blob_count"], audit["publication_transaction_count"], audit["publication_physical_bytes"]);
    }
    if config.fault_scenarios {
        tex.push_str("This explicitly selected fault-validation profile additionally exercises malformed-record accountability and availability requests. Those injected cases are separate from the normal lifecycle benchmark.\n");
    }
    tex.push_str(r"These experiments measure the selected local lifecycle. They do not prove the security theorem, physical secure erasure, long-term archive availability or WAN performance. Committee membership is fixed within a lifecycle. Snapshot-mode comparison is outside this workload. Bundles are divided into ordered blobs when necessary, with at most 9 blobs per Prague transaction. Publication time and receipt gas include all batches; commitment is permitted only after the complete bundle has been posted.
\end{document}
");
    fs::write(out, tex)?;
    io::stdout()
        .lock()
        .write_all(console_report(input, out, &config, &audit, &groups).as_bytes())?;
    if !catchup_group_rows.is_empty() {
        let text = format!(
            "\nOffline return and group completion (milliseconds; includes process restart)\n{}CSV: {}\n",
            table(&["Run", "Return epoch", "Participants", "Concurrency", "Wall time (ms)"], &catchup_group_rows),
            input.join("catchup_groups.csv").display(),
        );
        io::stdout().lock().write_all(text.as_bytes())?;
    }
    if !participant_rows.is_empty() {
        let text = format!(
            "\nIndividual catch-up (milliseconds; both missed transitions, excluding process restart and worker-queue delay)\n{}Participant intervals overlap; their sum is not the group completion time.\nCSV (individual totals): {}\nCSV (each recovered transition): {}\n",
            table(&["Run", "Recipient", "Target epoch", "Transitions", "Records", "Wall time (ms)"], &participant_rows),
            input.join("participant_catchup.csv").display(), input.join("catchup.csv").display(),
        );
        io::stdout().lock().write_all(text.as_bytes())?;
    }
    if !publication_rows.is_empty() {
        let text = format!(
            "\nPublication storage (one row per attempt)\n{}CSV: {}\n",
            table(
                &[
                    "Run",
                    "Dealers",
                    "Epoch",
                    "Attempt",
                    "Payload B",
                    "Blobs",
                    "Txs",
                    "Physical B"
                ],
                &publication_rows
            ),
            input.join("publications.csv").display()
        );
        io::stdout().lock().write_all(text.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_rows() -> Vec<Value> {
        let mut rows = Vec::new();
        for recipient in 1..=2 {
            for epoch in 1..=2 {
                rows.push(
                    json!({"committee":[4,2],"scenario":"baseline","metric":"offline_catchup",
                    "epoch":epoch,"t":8,"N":12,"duration_ns":10,
                    "data":{"recipient":recipient,"nonce":epoch,"records_read":2}}),
                );
            }
            rows.push(json!({"metric":"participant_catchup","epoch":2,"duration_ns":25,
                "data":{"recipient":recipient,"target_epoch":2,"missed_epochs":2,"completed_epochs":[1,2],"records_read":4}}));
        }
        rows.push(
            json!({"metric":"offline_return_and_catchup","epoch":2,"duration_ns":30,
            "data":{"participants":[1,2],"concurrency":2,"missed_epochs":2}}),
        );
        rows
    }

    fn verify(rows: &[Value], applications: &BTreeMap<(u64, u64), u64>) -> Result<()> {
        validate_catchup_metrics(
            &rows.iter().collect::<Vec<_>>(),
            2,
            &BTreeMap::from([(1, 1), (2, 2)]),
            applications,
        )
    }

    #[test]
    fn different_recipients_and_attempts_are_distinct_measurements() -> Result<()> {
        let rows = recovery_rows();
        let mut groups = Measurements::new();
        for row in rows.iter().filter(|r| r["metric"] == "offline_catchup") {
            groups.entry(measurement_key(row)?).or_default().push(1.);
        }
        assert_eq!(groups.len(), 4);
        assert!(groups.values().all(|v| v.len() == 1));
        let mut legacy = rows[0].clone();
        legacy["data"].as_object_mut().unwrap().remove("recipient");
        assert_eq!(recipient(&legacy), 1);
        Ok(())
    }

    #[test]
    fn multi_participant_audit_requires_every_recovery_and_matching_node_evidence() -> Result<()> {
        let rows = recovery_rows();
        let applications = BTreeMap::from([((1, 1), 2), ((1, 2), 2), ((2, 1), 2), ((2, 2), 2)]);
        verify(&rows, &applications)?;
        let mut incomplete = rows.clone();
        incomplete.remove(3);
        assert!(verify(&incomplete, &applications).is_err());
        let mut missing_application = applications.clone();
        missing_application.remove(&(2, 2));
        assert!(verify(&rows, &missing_application).is_err());
        let mut wrong_recipient = rows.clone();
        wrong_recipient[3]["data"]["recipient"] = json!(1);
        assert!(verify(&wrong_recipient, &applications).is_err());
        let mut missing_participant = rows.clone();
        missing_participant.remove(5);
        assert!(verify(&missing_participant, &applications).is_err());
        let mut mismatched_total = rows.clone();
        mismatched_total[5]["data"]["records_read"] = json!(2);
        assert!(verify(&mismatched_total, &applications).is_err());
        Ok(())
    }

    #[test]
    fn csv_quotes_structured_data_and_embedded_punctuation() {
        assert_eq!(
            csv_cell("{\"recipient\":1,\"epoch\":2}"),
            "\"{\"\"recipient\"\":1,\"\"epoch\"\":2}\""
        );
        assert_eq!(csv_cell("plain"), "plain");
    }

    #[test]
    fn resolved_manifest_defaults_enable_new_audit_for_old_input_configs() -> Result<()> {
        let old_config: toml::Value = toml::from_str("name = 'old-input'")?;
        assert_eq!(
            configured_offline_count(&old_config, &json!({"config":{"name":"old-input"}}))?,
            None
        );
        assert_eq!(
            configured_offline_count(&old_config, &json!({"config":{"offline_participants":1}}))?,
            Some(1)
        );
        let new_config: toml::Value = toml::from_str("offline_participants = 16")?;
        assert_eq!(
            configured_offline_count(&new_config, &json!({"config":{}}))?,
            Some(16)
        );
        assert_eq!(
            configured_offline_count(&new_config, &json!({"config":{"offline_participants":16}}))?,
            Some(16)
        );
        assert!(configured_offline_count(
            &new_config,
            &json!({"config":{"offline_participants":1}})
        )
        .is_err());
        assert!(configured_offline_count(
            &old_config,
            &json!({"config":{"offline_participants":"invalid"}})
        )
        .is_err());
        Ok(())
    }
}
