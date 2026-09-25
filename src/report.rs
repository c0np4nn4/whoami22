use anyhow::{ensure, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, io::Write, path::Path};
#[derive(Clone, Serialize, Deserialize)]
pub struct Summary {
    pub benchmark: String,
    pub case: String,
    pub dimensions: Value,
    pub evidence: String,
    pub n: usize,
    pub median_ns: f64,
    pub p95_ns: f64,
    pub p99_ns: f64,
    pub ci95_median_ns: [f64; 2],
    pub gas_median: Option<f64>,
}
fn quant(v: &[f64], q: f64) -> f64 {
    if v.is_empty() {
        return 0.;
    }
    let pos = (v.len() - 1) as f64 * q;
    let i = pos.floor() as usize;
    v[i] + (v[pos.ceil() as usize] - v[i]) * (pos - i as f64)
}
pub fn read(input: &Path) -> Result<Vec<Value>> {
    let mut rows: Vec<Value> = fs::read_to_string(input.join("samples.jsonl"))?
        .lines()
        .map(|l| Ok(serde_json::from_str(l)?))
        .collect::<Result<_>>()?;
    // Aggregate from individual receipt-backed observations, including rejected witnesses.
    // Original JSONL is immutable; preserve the runner's aggregate for a transparent audit.
    let (mut gas, mut count, mut midpoint) = (0u64, 0u64, 0u64);
    let mut hashes = Vec::new();
    for row in &mut rows {
        if row["benchmark"] != "B15" {
            continue;
        }
        let case = row["case"].as_str().unwrap_or("").to_owned();
        if case == "bisection_admission" {
            gas = 0;
            count = 0;
            midpoint = 0;
            hashes.clear();
        }
        if case == "complete_dispute" && count > 0 {
            let recorded_gas = row["metrics"]["gas"].clone();
            let recorded_count = row["metrics"]["transactions"].clone();
            row["metrics"]["runner_recorded_gas"] = recorded_gas;
            row["metrics"]["runner_recorded_transactions"] = recorded_count;
            row["metrics"]["gas"] = json!(gas);
            row["metrics"]["transactions"] = json!(count);
            row["metrics"]["midpoint_transactions"] = json!(midpoint);
            row["metrics"]["receipt_transaction_hashes"] = json!(hashes);
        } else if row["metrics"].get("transaction_hash").is_some() {
            gas += row["metrics"]["gas"].as_u64().unwrap_or(0);
            count += 1;
            if case == "bisection_midpoint" {
                midpoint += 1;
            }
            hashes.push(row["metrics"]["transaction_hash"].clone());
        }
    }
    Ok(rows)
}
pub fn analyze(input: &Path) -> Result<()> {
    let rows = read(input)?;
    let accounting: Vec<_> = rows
        .iter()
        .filter(|v| v["case"] == "complete_dispute")
        .collect();
    fs::write(
        input.join("dispute_accounting.json"),
        serde_json::to_vec_pretty(&accounting)?,
    )?;
    let mut groups: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for v in &rows {
        if v["wall_ns"].as_u64().unwrap_or(0) == 0 {
            continue;
        }
        let mut dims = serde_json::Map::new();
        for key in [
            "t",
            "source_t",
            "target_t",
            "n",
            "k",
            "f",
            "N",
            "L",
            "concurrency",
            "cache",
            "kind",
            "abort_count",
            "offered_rate_per_s",
            "bad",
        ] {
            if let Some(value) = v["metrics"].get(key) {
                dims.insert(key.into(), value.clone());
            }
        }
        let key = serde_json::to_string(&json!([v["benchmark"], v["case"], v["evidence"], dims]))?;
        groups.entry(key).or_default().push(v);
    }
    let mut out = Vec::new();
    for (index, (key, rows)) in groups.into_iter().enumerate() {
        let key: Value = serde_json::from_str(&key)?;
        let mut times: Vec<_> = rows
            .iter()
            .map(|v| v["wall_ns"].as_u64().unwrap() as f64)
            .collect();
        times.sort_by(f64::total_cmp);
        let mut random = crate::crypto::rng(9481, "bootstrap", index as u64);
        let mut boots = Vec::new();
        for _ in 0..2000 {
            let mut b: Vec<_> = (0..times.len())
                .map(|_| times[random.gen_range(0..times.len())])
                .collect();
            b.sort_by(f64::total_cmp);
            boots.push(quant(&b, 0.5));
        }
        boots.sort_by(f64::total_cmp);
        let mut gas: Vec<_> = rows
            .iter()
            .filter_map(|v| v["metrics"]["gas"].as_u64().map(|g| g as f64))
            .collect();
        gas.sort_by(f64::total_cmp);
        out.push(Summary {
            benchmark: key[0].as_str().unwrap().into(),
            case: key[1].as_str().unwrap().into(),
            evidence: key[2].as_str().unwrap().into(),
            dimensions: key[3].clone(),
            n: times.len(),
            median_ns: quant(&times, 0.5),
            p95_ns: quant(&times, 0.95),
            p99_ns: quant(&times, 0.99),
            ci95_median_ns: [quant(&boots, 0.025), quant(&boots, 0.975)],
            gas_median: if gas.is_empty() {
                None
            } else {
                Some(quant(&gas, 0.5))
            },
        });
    }
    fs::write(input.join("summary.json"), serde_json::to_vec_pretty(&out)?)?;
    let mut csv = fs::File::create(input.join("summary.csv"))?;
    writeln!(csv,"benchmark,case,dimensions,n,median_ms,p95_ms,p99_ms,median_ci_low_ms,median_ci_high_ms,gas_median")?;
    for s in &out {
        writeln!(
            csv,
            "{},{},\"{}\",{},{:.6},{:.6},{:.6},{:.6},{:.6},{}",
            s.benchmark,
            s.case,
            s.dimensions.to_string().replace('"', "\"\""),
            s.n,
            s.median_ns / 1e6,
            s.p95_ns / 1e6,
            s.p99_ns / 1e6,
            s.ci95_median_ns[0] / 1e6,
            s.ci95_median_ns[1] / 1e6,
            s.gas_median.map(|v| v.to_string()).unwrap_or_default()
        )?;
    }
    Ok(())
}
fn tex(s: &str) -> String {
    s.replace('\\', "\\textbackslash{}")
        .replace('_', "\\_")
        .replace('%', "\\%")
        .replace('&', "\\&")
        .replace('#', "\\#")
}
pub fn write(input: &Path, out: &Path) -> Result<()> {
    analyze(input)?;
    let rows = read(input)?;
    let summary: Vec<Summary> = serde_json::from_slice(&fs::read(input.join("summary.json"))?)?;
    let manifest: Value = serde_json::from_slice(&fs::read(input.join("manifest.json"))?)?;
    let completion: Value = serde_json::from_slice(&fs::read(input.join("completion.json"))?)?;
    ensure!(
        completion["status"] == "complete",
        "cannot report incomplete run as complete"
    );
    let mut document=String::from("\\documentclass[10pt,a4paper]{article}\n\\usepackage[margin=20mm]{geometry}\n\\setlength{\\emergencystretch}{2em}\n\\usepackage{booktabs,longtable,hyperref,xcolor,graphicx,pgfplots}\n\\pgfplotsset{compat=1.18}\n\\hypersetup{colorlinks=true,urlcolor=blue}\n\\title{VESS: Executable Benchmark Review and Measurements}\n\\author{Independent Rust research implementation}\n\\date{21 September 2026}\n\\begin{document}\n\\maketitle\n");
    document.push_str(&format!("\\begin{{abstract}}\nThis report accompanies an executed Rust artifact associated with \\texttt{{main.tex}}. It contains {} raw observations, including measured components, independent TLS dealer processes, actual local EVM transaction receipts, invariant checks, and explicitly labeled analytical models. The manuscript is preserved unchanged. These measurements do not reproduce the unavailable original implementation or establish the deferred security proofs.\n\\end{{abstract}}\n",rows.len()));
    document.push_str("\\section{Scope and evidence}\nThe authoritative input is \\texttt{local\\_v1.tex}. Its evaluation describes component measurements, omits final PoP checks on some recovery paths, and defers distributed generation and the complete dispute implementation. The new artifact executes those paths with separately identified cryptographic suites. The local protocol uses Ristretto255, SHA-512 domain separation, Schnorr signatures, and MEGa-DH with a hash-derived-base DLEQ proof. Secret scalar multiplication uses the constant-time dalek operations; variable-time MSM is restricted to public verification inputs. The EVM verifier independently uses BN254, Keccak, explicit field encodings, and the actual EC and KZG precompiles. BN254 fixture generation is variable-time and outside transaction measurements. Results from the two suites must not be combined into a claim of one production cryptographic deployment.\n\n");
    document.push_str("\\section{Experimental method}\nIndependent fixture seeds identify repeated trials. Distributed dealer generation and protocol signing use OS randomness in separate processes. TLS 1.3 client authentication is enabled, resumption is disabled, and each RPC establishes a new connection. Measurements use the release profile, thin LTO and one code-generation unit. Application cold cache means an empty vector cache, not a flushed operating-system page cache. Participant samples nested in the same run are not independent trials. Table n counts observations; stateful DA sequences and sequential games share a deployment, so their confidence intervals are descriptive rather than independent-trial guarantees. Contract collateral is pre-funded; registration and deposit receipts are separate. Median confidence intervals use 2,000 deterministic bootstrap resamples; small-sample intervals are descriptive. Tail percentiles from fewer than 100 trials are not reliable estimates of rare events.\n\n");
    document.push_str(&format!("Run directory: \\texttt{{{}}}. Elapsed suite time: {:.1} seconds. Toolchain: \\texttt{{{}}}. CPU affinity/frequency and OS page cache were not pinned. The full CPU, kernel, memory, tool, source-hash and lockfile metadata are saved in \\texttt{{manifest.json}}. All blockchain measurements use Prague Anvil with a 30-million execution-gas limit. Anvil inclusion does not measure consensus-layer finality, public-network latency, or validator availability.\n",tex(&input.display().to_string()),completion["wall_ns"].as_u64().unwrap_or(0)as f64/1e9,tex(manifest["rustc"].as_str().unwrap_or("").lines().next().unwrap_or(""))));
    document.push_str(&hardware_tex(&manifest));
    document.push_str(&figures_and_findings(&summary, &rows));
    document.push_str(&phase_table(&rows));
    document.push_str("\\section{Measured results}\nTimes include only the operation named in each row. The complete machine-readable table, dimensions, confidence intervals, percentiles and raw samples are in \\texttt{summary.csv}, \\texttt{summary.json} and \\texttt{samples.jsonl}. EVM gas is taken from receipts; zero-time formula and invariant rows are excluded from latency aggregation.\n\\scriptsize\n\\begin{longtable}{p{12mm}p{51mm}p{38mm}rrr}\n\\toprule ID & Operation & Dimensions & $n$ & Median ms & Gas \\\\ \\midrule\\endhead\n");
    for s in &summary {
        let selected = (["B01", "B03", "B05", "B07", "B13", "B15", "B17"]
            .contains(&s.benchmark.as_str())
            && !["bisection_midpoint", "fixture_and_trace_generation"].contains(&s.case.as_str()))
            || [
                "plaintext_honest",
                "plaintext_bad_plaintext",
                "admission_honest",
                "da_open",
                "da_response",
                "da_default",
                "two_vector_calldata_publication",
                "concurrent_cas",
                "keyless_batch_binary_isolation",
            ]
            .contains(&s.case.as_str());
        if !selected {
            continue;
        }
        document.push_str(&format!(
            "{} & {} & {} & {} & {:.3} & {} \\\\\n",
            tex(&s.benchmark),
            tex(&s.case.replace('_', " ")),
            dimensions_tex(&s.dimensions),
            s.n,
            s.median_ns / 1e6,
            s.gas_median
                .map(|g| format!("{g:.0}"))
                .unwrap_or_else(|| "--".into())
        ));
    }
    document.push_str("\\bottomrule\n\\end{longtable}\n\\normalsize\n");
    document.push_str("\\section{Correctness and operational findings}\nRecovery authenticates signed records, checks the MEGa proof and plaintext opening, interpolates any two admitted records in the $(5,2,1)$ experiment, and tests the aggregate update. Individual vector localization follows only an aggregate failure. Four records form the publication quorum; two remaining valid records suffice for return. With one inconsistent record and one missing valid record, recovery succeeds using three actual record reads. Missing endpoints, vector bytes and cryptographic record reads are counted separately. The $(7,3,2)$ cancellation regression uses weights $(3,-3,1)$: the aggregate succeeds while no individual dealer is exonerated.\n\nThe reservation log fsyncs framed, checksummed records and uses atomic compare-and-swap. A process exits immediately after fsync to check restart persistence. A torn tail fails closed. Concurrent local writers have one winner. Distributed release requires a verified chain-ordered entry and a distinct-signature quorum certificate. Aborts do not restore exposure budget. Participant staging retains the source share, and replayed application is idempotent. Source and target budget checks and the outgoing reservation cap are enforced separately.\n\nThe EVM execution verifies authenticated blob-root openings, record membership, signatures, PoP and verifiable decryption. The consistency game authenticates both endpoints, all midpoint moves and the final source and target coefficients. Decreasing-threshold identity padding, copied roots, false coefficient witnesses, false challengers, both-wrong traces and timeout are separate cases. Availability tests lock stake, reject duplicate or unrequired challenges, verify response membership, default after the deadline, and check balance conservation including unwithdrawable burn accounting.\n\n");
    let passed = rows
        .iter()
        .filter(|v| v["evidence"] == "invariant" && v["metrics"]["pass"] == true)
        .count();
    document.push_str(&format!("The run recorded {passed} passing invariant observations. Reverted negative transactions are expected outcomes and remain in the raw receipts; they are not discarded as timing outliers. Dispute totals are recomputed from individual transaction observations, including rejected coefficient witnesses; the original runner aggregates remain auditable in \\texttt{{dispute\\_accounting.json}}.\n"));
    document.push_str("\\section{Corrections to manuscript interpretations}\nTwo compressed Ristretto vectors at $T=1024$ occupy $2\\cdot1024\\cdot32=65,536$ raw bytes (64 KiB), before framing and proofs. The manuscript's 128 KiB requires a different representation. Its 379-byte assumed record occupies 403 bytes of payload capacity or 416 physical blob bytes under 31-byte packing. This artifact explicitly serializes additional context, so its actual record size is measured rather than forced to 379. An arbitrary 256-bit root is encoded as two 128-bit limbs in separate BLS field slots. The corresponding assumed-record capacity is 314, whereas 315 assumes only one reserved slot. Full epoch storage also includes dealer and aggregate vectors, certificates and retained sources.\n\nAt $t=1024,\\delta=32$, equal disjoint-set bounds are 991, 495 and 330 for one, two and three sets. A capacity calculation for 2,048 offline recipients is not an admissible transition at that threshold. A $T=1024$ game has 20 midpoint transactions and 7,040 bytes of midpoint sibling hashes; admission, endpoint authentication, final coefficient proofs and publication are additional costs. The receipt-backed complete dispute table includes admission, endpoints and final judgment, and excludes publication only where explicitly labeled.\n\n");
    document.push_str("\\section{Future work evaluated and remaining boundaries}\nF01 is exercised by independent dealer ReShare/JRSS contributions, signed synchronous echo/ready rounds and real complaint answers. This is an all-responsive local experiment; it is not an audited Byzantine broadcast implementation or a WAN liveness proof. F02 is examined using actual decrypted records, graph propagation and matrix rank over the Ristretto scalar field. Its observation model concerns one participant's partials and is not a complete cryptographic leakage characterization. F03 evaluates all five specified coalition strategies using receipt-derived gas with separately declared external prices, gains and probabilities. The preemptive counterexample retains $U_4=3.9$ even when $U_1,U_3<0$; reimbursing service cost still leaves delay gain. F04 is addressed by source, lockfile, configurations, raw samples, receipts and regeneration instructions.\n\nThe lifecycle controller, local ordering endpoint and finalized-header administrator are trusted in this research harness; malicious control-plane RPC injection is outside the exercised payload-fault model. The artifact does not prove physical secure erasure, recovery against compromised OS processes, consensus safety, asynchronous security, or public-chain finality. Dealer configuration files contain synthetic secrets and must not be deployed. External protocol comparisons and multi-recipient cryptographic amortization remain excluded because their functionality/security matching or new proof obligations are unresolved. Snapshot measurements exercise local recovery; the difference-game theorem is not extended to snapshots by inference. Detailed per-ID limitations are documented in the artifact's coverage table.\n\n");
    document.push_str("\\section{Reproduction}\nFrom \\texttt{benchmarks/}, run \\texttt{cargo test --release --locked --offline}, build contracts using \\texttt{forge build}, use the documented run command in the artifact README. Regenerate tables with the \\texttt{analyze} command and this document with the \\texttt{report} command. Each output directory is append-protected against accidental mixing of runs. Receipt files contain input bytes, transaction hashes, status, gas, and event logs. The raw manifest records the exact source hashes.\n\\section{Primary specifications}\nBlob encoding, point-opening input and separate gas accounting follow \\href{https://eips.ethereum.org/EIPS/eip-4844}{EIP-4844}. Prague blob throughput parameters follow \\href{https://eips.ethereum.org/EIPS/eip-7691}{EIP-7691}; calldata costs are taken from receipts under \\href{https://eips.ethereum.org/EIPS/eip-7623}{EIP-7623}. These are fixed-fork measurements, not assertions about the current public-chain schedule.\n\\end{document}\n");
    fs::write(out, document)?;
    Ok(())
}
fn figures_and_findings(summary: &[Summary], rows: &[Value]) -> String {
    let mut out = String::from("\\section{Principal observations}\n");
    for s in summary.iter().filter(|s| {
        s.case == "lifecycle"
            || s.case == "distributed_generation"
            || s.case == "complete_dispute"
                && s.dimensions["source_t"] == 1024
                && s.dimensions["kind"] == "dealer_wrong"
    }) {
        out.push_str(&format!("\\noindent {} ({}) measured {:.3} ms median, with descriptive 95\\% median bootstrap interval [{:.3}, {:.3}] ms over {} trials.{}\\par\n",tex(&s.case.replace('_', " ")),dimensions_tex(&s.dimensions),s.median_ns/1e6,s.ci95_median_ns[0]/1e6,s.ci95_median_ns[1]/1e6,s.n,s.gas_median.map(|g|format!(" Receipt gas median: {g:.0}.")).unwrap_or_default()));
    }
    let record_size = rows
        .iter()
        .find_map(|v| v["metrics"]["raw_record_bytes"].as_u64());
    if let Some(bytes) = record_size {
        out.push_str(&format!(
            "The serialized Ristretto record is {bytes} bytes; membership/framing is additional. "
        ));
    }
    for row in rows
        .iter()
        .filter(|v| v["case"] == "complete_dispute" && v["metrics"]["source_t"] == 1024)
        .take(1)
    {
        out.push_str(&format!("The $T=1024$ dispute used {} transactions including admission and endpoints, of which {} were midpoint moves carrying {} sibling-hash bytes.\n",row["metrics"]["transactions"],row["metrics"]["midpoint_transactions"],row["metrics"]["midpoint_hash_bytes"]));
    }
    out.push_str("\\begin{figure}[htbp]\\centering\n\\begin{tikzpicture}\\begin{axis}[width=.92\\linewidth,height=60mm,xmode=log,log basis x=2,ymode=log,xlabel={Threshold $t$},ylabel={Median recovery time (ms)},legend pos=north west,grid=both]\n");
    for (case, cache, label) in [
        ("happy", "cold", "Happy / empty vector cache"),
        ("one_inconsistent", "cold", "Inconsistent / cold"),
        ("one_inconsistent", "warm", "Inconsistent / warm"),
    ] {
        let mut points: Vec<_> = summary
            .iter()
            .filter(|s| s.case == case && s.dimensions["cache"] == cache)
            .filter_map(|s| Some((s.dimensions["t"].as_u64()?, s.median_ns / 1e6)))
            .collect();
        points.sort_by_key(|p| p.0);
        if points.is_empty() {
            continue;
        }
        out.push_str("\\addplot+[mark=*] coordinates {");
        for (x, y) in points {
            out.push_str(&format!("({x},{y:.6}) "));
        }
        out.push_str(&format!("}};\\addlegendentry{{{label}}}\n"));
    }
    out.push_str("\\end{axis}\\end{tikzpicture}\\caption{Actual filesystem recovery, including PoP, authenticated fetch and aggregate verification. Localization fetch is additional after an inconsistent record. OS page cache is uncontrolled.}\\end{figure}\n");
    out.push_str("\\begin{figure}[htbp]\\centering\n\\begin{tikzpicture}\\begin{axis}[width=.92\\linewidth,height=60mm,xmode=log,log basis x=2,ymode=log,xlabel={Missed transitions $L$},ylabel={Median recovery time (ms)},legend pos=north west,grid=both]\n");
    for (case, label) in [
        ("missed_difference", "Difference chain"),
        ("missed_snapshot", "Latest snapshot"),
    ] {
        let mut points: Vec<_> = summary
            .iter()
            .filter(|s| s.case == case)
            .filter_map(|s| Some((s.dimensions["L"].as_u64()?, s.median_ns / 1e6)))
            .collect();
        points.sort_by_key(|p| p.0);
        if points.is_empty() {
            continue;
        }
        out.push_str("\\addplot+[mark=*] coordinates {");
        for (x, y) in points {
            out.push_str(&format!("({x},{y:.6}) "));
        }
        out.push_str(&format!("}};\\addlegendentry{{{label}}}\n"));
    }
    out.push_str("\\end{axis}\\end{tikzpicture}\\caption{Paired local-suite recovery at $t=16$. Generation, two-mode publication and retained bytes are recorded separately; this plot alone is not a total lifecycle cost comparison.}\\end{figure}\n");
    out.push_str("\\subsection{Publication, exposure and economics}\n\\begin{center}\\small\\begin{tabular}{rrrrr}\\toprule $t$ & Encoded bytes & Blobs & Execution gas & Blob gas \\\\ \\midrule\n");
    for row in rows.iter().filter(|v| v["case"] == "full_publication_pool") {
        let m = &row["metrics"];
        out.push_str(&format!(
            "{} & {} & {} & {} & {} \\\\\n",
            m["t"], m["total_encoded_bytes"], m["blobs"], m["gas"], m["blob_gas"]
        ));
    }
    out.push_str("\\bottomrule\\end{tabular}\\end{center}\nThe shared pool includes both aggregate vectors, retained source/target dealer vectors, records, header, certificate, coordinate registry index and coefficient metadata. The complete authorization registry is measured separately. Execution gas and blob gas must be priced separately.\n\n");
    for row in rows.iter().filter(|v| {
        v["benchmark"] == "R01"
            && ["difference", "snapshot", "mixed"].contains(&v["case"].as_str().unwrap_or(""))
    }) {
        out.push_str(&format!("For {} observations, the exposure experiment recovered {} of 9 state/dealer nodes, with rank {} in the specified nine-variable observation model.\\par\n",tex(row["case"].as_str().unwrap()),row["metrics"]["known_nodes"].as_array().map(Vec::len).unwrap_or(0),row["metrics"]["rank"]));
    }
    if let Some(row) = rows.iter().find(|v| v["case"] == "five_strategy_grid") {
        out.push_str(&format!("The five-strategy economic grid has {} parameter points, of which {} have all five modeled utilities nonpositive. The grid uses {} gas for challenge opening and {} gas for response (medians), with assumed prices, gains and detection probabilities. This finite grid is not a security theorem.\\par\n",row["metrics"]["cases"],row["metrics"]["all_five_nonpositive"],row["metrics"]["measured_challenger_gas"],row["metrics"]["measured_response_gas"]));
    }
    out
}
fn dimensions_tex(d: &Value) -> String {
    let mut parts = Vec::new();
    if let (Some(a), Some(b)) = (d["source_t"].as_u64(), d["target_t"].as_u64()) {
        parts.push(format!("$t:{a}\\to{b}$"));
    }
    if let Some(t) = d["t"].as_u64() {
        parts.push(format!("$t={t}$"));
    }
    if let (Some(n), Some(k), Some(f)) = (d["n"].as_u64(), d["k"].as_u64(), d["f"].as_u64()) {
        parts.push(format!("$({n},{k},{f})$"));
    }
    for key in ["N", "L", "concurrency"] {
        if let Some(value) = d.get(key) {
            parts.push(format!("{}={}", tex(key), value));
        }
    }
    for key in ["cache", "kind"] {
        if let Some(value) = d[key].as_str() {
            parts.push(tex(&value.replace('_', " ")));
        }
    }
    if parts.is_empty() {
        "--".into()
    } else {
        parts.join(", ")
    }
}
fn phase_table(rows: &[Value]) -> String {
    let mut out=String::from("\\subsection{Lifecycle phase costs and cold initialization}\n\\begin{center}\\small\\begin{tabular}{lrr}\\toprule Phase & $N=t=16$ ms & $N=t=64$ ms \\\\ \\midrule\n");
    for (field, label) in [
        ("cluster_setup_ns", "Init and process setup"),
        ("enrollment_ns", "Authorized enrollment"),
        ("liveness_ns", "Authenticated liveness"),
        ("generation_ns", "Distributed generation"),
        ("reservation_ns", "Chain reservation and certificate"),
        ("release_stage_ns", "Release and durable staging"),
        (
            "publication_inclusion_ns",
            "KZG, blob submission and inclusion",
        ),
        ("apply_ns", "Durable participant application"),
        ("catchup_ns", "TLS archive catch-up"),
        ("reconstruct_ns", "Reconstruction"),
    ] {
        out.push_str(label);
        for t in [16u64, 64] {
            let mut vals: Vec<_> = rows
                .iter()
                .filter(|v| v["case"] == "lifecycle" && v["metrics"]["t"] == t)
                .filter_map(|v| v["metrics"][field].as_u64().map(|v| v as f64 / 1e6))
                .collect();
            vals.sort_by(f64::total_cmp);
            out.push_str(&if vals.is_empty() {
                " & --".into()
            } else {
                format!(" & {:.3}", quant(&vals, 0.5))
            });
        }
        out.push_str(" \\\\\n");
    }
    out.push_str("\\bottomrule\\end{tabular}\\end{center}\nPhase medians are descriptive and are not added to construct end-to-end latency. The total is timed directly per trial.\n");
    if let Some(first) = rows
        .iter()
        .find(|v| v["case"] == "lifecycle" && v["metrics"]["t"] == 16 && v["trial"] == 0)
    {
        out.push_str(&format!("The first $t=16$ lifecycle took {:.3} ms, including {:.3} ms in KZG/publication. The first use of C-KZG initializes its cached trusted setup; later calls reuse it. This cold initialization observation is retained, which explains the wide lifecycle confidence interval. No outlier was discarded.\n",first["wall_ns"].as_u64().unwrap()as f64/1e6,first["metrics"]["publication_inclusion_ns"].as_u64().unwrap()as f64/1e6));
    }
    out.push_str("The mixed-mode exposure trace has more independent linear constraints than individually recovered graph nodes, illustrating why graph reachability alone is not a complete leakage characterization. The economic grid fixes service reimbursement to measured response cost, leaving delay gain uncompensated; nonpositive utility at zero delay gain is not a strict deterrence guarantee.\n");
    out
}
fn hardware_tex(m: &Value) -> String {
    let cpu = m["cpu"].as_str().unwrap_or("");
    let model = cpu
        .lines()
        .find(|l| l.starts_with("Model name:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
        .unwrap_or("see manifest");
    let logical = cpu
        .lines()
        .find(|l| l.starts_with("CPU(s):"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
        .unwrap_or("unspecified");
    let kb = m["memory"]
        .as_str()
        .unwrap_or("")
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    format!(
        "\\par Recorded host: {}, {} logical CPUs, {:.1} GiB RAM.\\par\n",
        tex(model),
        tex(logical),
        kb as f64 / 1024. / 1024.
    )
}
