use super::*;
use crate::{crypto::*, ledger::*, protocol::*, storage::*};
use std::{
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
};
pub fn run(c: &Config, r: &mut Recorder) -> Result<()> {
    primitives(c, r)?;
    fault_matrix(c, r)?;
    history(c, r)?;
    budget_sweep(c, r)?;
    participant_crashes(c, r)?;
    committee_sweep(c, r)?;
    transitions(c, r)?;
    Ok(())
}
fn primitives(c: &Config, r: &mut Recorder) -> Result<()> {
    for trial in 0..c.repeats {
        let mut random = rng(c.seed, "primitive", trial as u64);
        let sk = nonzero(&mut random);
        let pair = Pair::sample(&mut random);
        let msg = enc(&pair);
        let poly: Vec<_> = (0..16).map(|_| Pair::sample(&mut random)).collect();
        let start = Instant::now();
        black_box(hg(&[b"bench", &msg]));
        r.sample(
            "B01",
            "hash_to_group",
            trial,
            "measured_component",
            ns(start),
            json!({}),
        )?;
        let start = Instant::now();
        black_box(pair.commitment());
        r.sample(
            "B01",
            "pedersen_commit",
            trial,
            "measured_component",
            ns(start),
            json!({}),
        )?;
        let start = Instant::now();
        let sig = sign(sk, &msg, &mut random);
        r.sample(
            "B01",
            "signature_create",
            trial,
            "measured_component",
            ns(start),
            json!({}),
        )?;
        let start = Instant::now();
        ensure!(verify_sig(sk * g(), &msg, &sig), "signature");
        r.sample(
            "B01",
            "signature_verify",
            trial,
            "measured_component",
            ns(start),
            json!({}),
        )?;
        let start = Instant::now();
        black_box(eval(&poly, Fr::from(7u64)));
        r.sample(
            "B01",
            "polynomial_evaluate",
            trial,
            "measured_component",
            ns(start),
            json!({"t":16}),
        )?;
        let parts: Vec<_> = (1..=16).map(|id| (id, eval(&poly, Fr::from(id)))).collect();
        let start = Instant::now();
        ensure!(combine(&parts)? == poly[0], "interpolation");
        r.sample(
            "B01",
            "lagrange_interpolate",
            trial,
            "measured_component",
            ns(start),
            json!({"t":16}),
        )?;
        let start = Instant::now();
        black_box(enc(&parts));
        r.sample(
            "B01",
            "serialize_pairs",
            trial,
            "measured_component",
            ns(start),
            json!({"t":16,"bytes":enc(&parts).len()}),
        )?;
    }
    Ok(())
}
fn fault_matrix(c: &Config, r: &mut Recorder) -> Result<()> {
    for (n, k, f) in [(4, 2, 1), (5, 2, 1), (7, 3, 2), (8, 3, 2), (10, 4, 3)] {
        for trial in 0..c.distributed_repeats {
            let mut random = rng(c.seed, "fault-matrix", (n * 100 + trial) as u64);
            let src = init(Params { n, k, f, t: 8 }, 0, &mut random)?;
            let dst = generate(&src, 8, &mut random)?;
            let sk = nonzero(&mut random);
            let keys: Vec<_> = (0..n).map(|_| nonzero(&mut random)).collect();
            let pks: Vec<_> = keys.iter().map(|s| s * g()).collect();
            let vs: BTreeMap<_, _> = (0..n)
                .map(|j| {
                    (
                        (j + 1) as u64,
                        (src.vectors[j].clone(), dst.vectors[j].clone()),
                    )
                })
                .collect();
            for case in [
                "bad_signature",
                "bad_pop",
                "bad_plaintext",
                "bad_membership",
                "wrong_attempt",
                "duplicate_dealer",
                "missing_m",
                "missing_m_plus_one",
                "below_k",
            ] {
                let mut records: Vec<_> = (0..n - f)
                    .map(|j| {
                        make_record(
                            &src,
                            &dst,
                            j,
                            1,
                            1,
                            Mode::Difference,
                            sk * g(),
                            keys[j],
                            if (case == "missing_m" || case == "missing_m_plus_one") && j < f {
                                Fr::from((j + 1) as u64)
                            } else {
                                Fr::ZERO
                            },
                            &mut random,
                        )
                    })
                    .collect();
                match case {
                    "bad_signature" => records[0].signature.s += Fr::ONE,
                    "bad_pop" => {
                        records[0].cipher.pop.s += Fr::ONE;
                        records[0].signature = sign(
                            keys[0],
                            &enc(&(&records[0].ad, &records[0].cipher)),
                            &mut random,
                        );
                    }
                    "bad_plaintext" => {
                        records[0].cipher.c.v += Fr::ONE;
                        records[0].signature = sign(
                            keys[0],
                            &enc(&(&records[0].ad, &records[0].cipher)),
                            &mut random,
                        );
                    }
                    _ => {}
                }
                let path = r.dir.join(format!("fault-matrix/{n}-{trial}-{case}"));
                let mut a = Archive::write(&path, &records, &vs)?;
                match case {
                    "bad_membership" => {
                        let mut s: StoredRecord =
                            bincode::deserialize(&fs::read(path.join("record-1.bin"))?)?;
                        s.proof.siblings[0][0] ^= 1;
                        fs::write(path.join("record-1.bin"), enc(&s))?;
                    }
                    "wrong_attempt" => a.meta.nonce += 1,
                    "duplicate_dealer" => {
                        let mut bad = records.clone();
                        bad[1] = bad[0].clone();
                        r.check(
                            "B08",
                            "duplicate_dealer_rejected",
                            Archive::write(&path.join("duplicate"), &bad, &vs).is_err(),
                            json!({"n":n}),
                        )?;
                        continue;
                    }
                    "missing_m" | "missing_m_plus_one" => {
                        let missing =
                            src.params.margin() + usize::from(case == "missing_m_plus_one");
                        for id in f + 1..=f + missing {
                            fs::remove_file(path.join(format!("record-{id}.bin")))?;
                        }
                    }
                    "below_k" => {
                        for id in k..=n - f {
                            fs::remove_file(path.join(format!("record-{id}.bin")))?;
                        }
                    }
                    _ => {}
                }
                let start = Instant::now();
                let result = recover(
                    &a,
                    sk,
                    &pks,
                    k,
                    &delta(&src.public, &dst.public),
                    &mut VectorCache::default(),
                );
                let elapsed = ns(start);
                let expected = !["wrong_attempt", "below_k", "missing_m_plus_one"].contains(&case);
                ensure!(result.is_ok() == expected, "fault matrix {n}/{case}");
                let details = match result {
                    Ok((token, stats)) => {
                        ensure!(src.share(1).plus(token) == dst.share(1), "fault update");
                        json!(stats)
                    }
                    Err(e) => {
                        json!({"error":e.to_string(),"fallback":"authorized_current_epoch_reissuance"})
                    }
                };
                r.sample("B08",case,trial,"measured_filesystem",elapsed,json!({"n":n,"k":k,"f":f,"margin":src.params.margin(),"success":expected,"classification":if case=="missing_m_plus_one"{"out_of_model"}else{"admissible"},"details":details}))?;
            }
        }
    }
    Ok(())
}
fn history(c: &Config, r: &mut Recorder) -> Result<()> {
    for trial in 0..c.distributed_repeats {
        let mut random = rng(c.seed, "history", trial as u64);
        let mut state = init(
            Params {
                n: 4,
                k: 2,
                f: 1,
                t: 16,
            },
            0,
            &mut random,
        )?;
        let origin = state.share(1);
        let sk = nonzero(&mut random);
        let keys: Vec<_> = (0..4).map(|_| nonzero(&mut random)).collect();
        let pks: Vec<_> = keys.iter().map(|s| s * g()).collect();
        let mut chain = Vec::new();
        let mut last_snapshot = None;
        let mut generation_ns = 0u64;
        let mut publication_ns = 0u64;
        let mut difference_bytes = 0;
        for step in 1..=32 {
            let policy = Policy {
                source: state.digest(),
                source_t: 16,
                delta: 1,
                incoming: if step == 1 {
                    BTreeSet::new()
                } else {
                    [1].into()
                },
                rho_out: 1,
            };
            let l = Ledger::create(
                &r.dir.join(format!("history/{trial}/ledger-{step}")),
                policy,
            )?;
            let request = Request {
                old_root: l.root()?,
                nonce: step,
                recipients: [1].into(),
                target: [0; 32],
                target_t: 16,
                target_rho: 1,
                eligible: 16,
                mode: Mode::Difference,
            };
            target_check(&request, 1)?;
            let start = Instant::now();
            let target = generate(&state, 16, &mut random)?;
            generation_ns += ns(start);
            let mut request = request;
            request.target = target.digest();
            l.reserve(request)?;
            let vectors = (0..4)
                .map(|j| {
                    (
                        (j + 1) as u64,
                        (state.vectors[j].clone(), target.vectors[j].clone()),
                    )
                })
                .collect();
            let start = Instant::now();
            for mode in [Mode::Difference, Mode::Snapshot] {
                let records: Vec<_> = (0..3)
                    .map(|j| {
                        make_record(
                            &state,
                            &target,
                            j,
                            1,
                            step,
                            mode,
                            sk * g(),
                            keys[j],
                            Fr::ZERO,
                            &mut random,
                        )
                    })
                    .collect();
                let a = Archive::write(
                    &r.dir.join(format!("history/{trial}/{step}-{mode:?}")),
                    &records,
                    &vectors,
                )?;
                if mode == Mode::Difference {
                    difference_bytes += a.bytes()?;
                    chain.push((a, delta(&state.public, &target.public)));
                } else {
                    last_snapshot = Some(a);
                }
            }
            publication_ns += ns(start);
            state = target;
            if [1, 2, 4, 8, 16, 32].contains(&step) {
                let start = Instant::now();
                let mut recovered = origin;
                let mut reads = 0;
                for (a, expected) in &chain {
                    let (token, stats) =
                        recover(a, sk, &pks, 2, expected, &mut VectorCache::default())?;
                    recovered = recovered.plus(token);
                    reads += stats.records_read;
                }
                ensure!(recovered == state.share(1), "multi-transition difference");
                r.sample("B13","missed_difference",trial,"measured_filesystem",ns(start),json!({"L":step,"t":16,"record_reads":reads,"retained_bytes":difference_bytes,"paired_generation_ns":generation_ns,"paired_two_mode_publication_ns":publication_ns,"source_share_required":true}))?;
                let a = last_snapshot.as_ref().unwrap();
                let start = Instant::now();
                let (snapshot, stats) =
                    recover(a, sk, &pks, 2, &state.public, &mut VectorCache::default())?;
                ensure!(snapshot == state.share(1), "snapshot current");
                r.sample("B13","missed_snapshot",trial,"measured_filesystem",ns(start),json!({"L":step,"t":16,"record_reads":stats.records_read,"latest_retained_bytes":a.bytes()?,"source_share_required":false,"committee_online":false}))?;
            }
        }
        // A missing intermediate edge prevents difference recovery; the latest absolute checkpoint still works.
        for id in 1..=3 {
            fs::remove_file(chain[3].0.dir.join(format!("record-{id}.bin")))?;
        }
        let blocked = recover(
            &chain[3].0,
            sk,
            &pks,
            2,
            &chain[3].1,
            &mut VectorCache::default(),
        )
        .is_err();
        let snapshot = recover(
            last_snapshot.as_ref().unwrap(),
            sk,
            &pks,
            2,
            &state.public,
            &mut VectorCache::default(),
        )?;
        r.check(
            "B18",
            "intermediate_gap_latest_snapshot",
            blocked && snapshot.0 == state.share(1),
            json!({"L":32,"missing_epoch":4,"source_share_lost_snapshot_succeeds":true}),
        )?;
    }
    Ok(())
}
fn budget_sweep(c: &Config, r: &mut Recorder) -> Result<()> {
    for style in ["identical", "overlap", "disjoint"] {
        let path = r.dir.join(format!("abort-sweep/{style}"));
        let ledger = Ledger::create(
            &path,
            Policy {
                source: hash(&[style.as_bytes()]),
                source_t: 16,
                delta: 1,
                incoming: [1, 2].into(),
                rho_out: 12,
            },
        )?;
        for trial in 0..16usize {
            let recipients = match style {
                "identical" => [3, 4],
                "overlap" => [3, 4 + trial as u64],
                _ => [3 + 2 * trial as u64, 4 + 2 * trial as u64],
            };
            let req = Request {
                old_root: ledger.root()?,
                nonce: trial as u64 + 1,
                recipients: recipients.into(),
                target: hash(&[&trial.to_le_bytes()]),
                target_t: 16,
                target_rho: 2,
                eligible: 16,
                mode: Mode::Difference,
            };
            let start = Instant::now();
            let accepted = ledger.reserve(req).is_ok();
            let elapsed = ns(start);
            let reopen = Instant::now();
            let entries = Ledger::open(&path)?.entries()?;
            let recovery = ns(reopen);
            r.sample("B10",style,trial,"measured_durable_io",elapsed,json!({"accepted":accepted,"abort_count":trial,"reserved_union":entries.last().map(|e|e.reserved.len()).unwrap_or(0),"disk_bytes":fs::metadata(path.join("log.bin")).map(|m|m.len()).unwrap_or(0),"restart_scan_ns":recovery,"policy_exhaustion_is_secret_reconstruction":false}))?;
        }
    }
    for &offline in &[0usize, 1, 100, 330, 495, 991, 992, 1000, 2048] {
        let source_ok = 32 + offline < 1024;
        let target_ok = 32 + offline < 1024;
        r.sample("B10","threshold_1024_admission",offline,"derived_formula",0,json!({"t":1024,"delta":32,"offline":offline,"rho_out_target":0,"eligible":1024,"accepted":source_ok&&target_ok,"classification":if source_ok&&target_ok{"admissible"}else{"expected_rejection"},"runtime_ns":Value::Null}))?;
    }
    let _ = c;
    Ok(())
}
fn committee_sweep(c: &Config, r: &mut Recorder) -> Result<()> {
    if !c.thresholds.contains(&1024) {
        return Ok(());
    }
    for (n, k, f) in [(4, 2, 1), (7, 3, 2), (10, 4, 3)] {
        for trial in 0..c.repeats {
            let mut random = rng(c.seed, "committee-sweep", (n * 1000 + trial) as u64);
            let src = init(Params { n, k, f, t: 1024 }, 0, &mut random)?;
            let start = Instant::now();
            let ids: Vec<_> = (1..=n as u64).collect();
            let partials: Vec<_> = src.rows.iter().map(|p| eval(p, Fr::ONE)).collect();
            ensure!(
                batch_verify(b"issuance", &ids, &partials, &src.vectors, Fr::ONE),
                "committee batch"
            );
            let share = combine(
                &ids.iter()
                    .zip(&partials)
                    .take(k)
                    .map(|(i, p)| (*i, *p))
                    .collect::<Vec<_>>(),
            )?;
            ensure!(
                share.commitment() == eval_commit(&src.public, Fr::ONE),
                "final share verify"
            );
            r.sample(
                "B02",
                "issuance_committee_1024",
                trial,
                "measured_component",
                ns(start),
                json!({"t":1024,"n":n,"k":k,"f":f,"authorization":false,"network":false}),
            )?;
        }
    }
    Ok(())
}
fn participant_crashes(c: &Config, r: &mut Recorder) -> Result<()> {
    let mut random = rng(c.seed, "participant-crash", 0);
    let src = init(
        Params {
            n: 4,
            k: 2,
            f: 1,
            t: 8,
        },
        0,
        &mut random,
    )?;
    let dst = generate(&src, 8, &mut random)?;
    let participant = Participant {
        id: 1,
        epoch: 0,
        share: src.share(1),
        staged: None,
        applied: BTreeSet::new(),
    };
    let staged = Staged {
        nonce: 19,
        target: 1,
        token: dst.share(1).minus(src.share(1)),
        target_public: dst.public.clone(),
    };
    let dir = r.dir.join("participant-crashes");
    fs::create_dir_all(&dir)?;
    let input = dir.join("input.bin");
    fs::write(&input, enc(&(participant, staged)))?;
    for phase in ["stage", "apply", "abort"] {
        let output = dir.join(format!("{phase}.bin"));
        let start = Instant::now();
        let status = Command::new(std::env::current_exe()?)
            .arg("crash-participant")
            .arg("--input")
            .arg(&input)
            .arg("--output")
            .arg(&output)
            .arg("--phase")
            .arg(phase)
            .status()?;
        let mut recovered = Participant::load(&output)?;
        ensure!(status.code() == Some(73), "crash exit");
        let pass = match phase {
            "stage" => recovered.share == src.share(1) && recovered.staged.is_some(),
            "apply" => {
                recovered.share == dst.share(1)
                    && recovered.staged.is_none()
                    && !recovered.apply(19, 1, &output)?
            }
            _ => recovered.share == src.share(1) && recovered.staged.is_none(),
        };
        r.sample("B11",&format!("crash_after_{phase}"),0,"measured_process_crash",ns(start),json!({"pass":pass,"exit_code":73,"epoch":recovered.epoch,"staged":recovered.staged.is_some(),"exposure_material":if phase=="stage"{"old source pair + staged difference token"}else if phase=="apply"{"new target pair; old/staged application fields removed"}else{"source pair; staged token removed"}}))?;
        ensure!(pass, "participant restart invariant");
    }
    Ok(())
}
fn transitions(c: &Config, r: &mut Recorder) -> Result<()> {
    let cases = if c.thresholds.contains(&1024) {
        vec![
            (16, 16),
            (16, 64),
            (64, 16),
            (3, 2),
            (256, 1024),
            (1024, 256),
        ]
    } else {
        vec![(3, 2), (8, 16), (16, 8)]
    };
    for (source_t, target_t) in cases {
        for trial in 0..c.distributed_repeats {
            let mut random = rng(
                c.seed,
                "threshold-transition",
                (source_t * 10000 + target_t * 10 + trial) as u64,
            );
            let src = init(
                Params {
                    n: 4,
                    k: 2,
                    f: 1,
                    t: source_t,
                },
                0,
                &mut random,
            )?;
            let start = Instant::now();
            let dst = generate(&src, target_t, &mut random)?;
            let generation = ns(start);
            let delta = delta(&src.public, &dst.public);
            let mut shares = Vec::new();
            let start = Instant::now();
            for id in 1..=target_t as u64 + 1 {
                let token = dst.share(id).minus(src.share(id));
                ensure!(
                    token.commitment() == eval_commit(&delta, Fr::from(id)),
                    "zero padding token"
                );
                let updated = src.share(id).plus(token);
                ensure!(updated == dst.share(id), "direct issuance mismatch");
                shares.push((id, updated));
            }
            let updates = ns(start);
            shares[0].1.v += Fr::ONE;
            shares.push(shares[1]);
            let start = Instant::now();
            let secret = reconstruct(&dst.public, &shares)?;
            ensure!(
                secret.commitment() == src.public[0],
                "threshold reconstruction with bad and duplicate share"
            );
            r.sample("B03","transition_with_bad_and_duplicate_shares",trial,"measured_component",ns(start),json!({"source_t":source_t,"target_t":target_t,"generation_ns":generation,"updates_ns":updates,"provided_shares":shares.len(),"valid_unique_used":target_t,"constant_preserved":true}))?;
        }
    }
    Ok(())
}
