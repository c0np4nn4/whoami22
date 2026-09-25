use super::*;
use crate::{crypto::*, ledger::*, protocol::*, storage::*};
use std::{collections::BTreeMap, hint::black_box};

fn isolate(ids: &[u64], parts: &[Pair], vectors: &[Vec<Point>], out: &mut Vec<u64>) {
    if batch_verify(b"issuance-v1", ids, parts, vectors, Fr::ONE) {
        return;
    }
    if ids.len() == 1 {
        out.push(ids[0]);
        return;
    }
    let mid = ids.len() / 2;
    isolate(&ids[..mid], &parts[..mid], &vectors[..mid], out);
    isolate(&ids[mid..], &parts[mid..], &vectors[mid..], out);
}
pub fn run(c: &Config, r: &mut Recorder) -> Result<()> {
    for trial in 0..c.warmup + c.repeats {
        let mut random = rng(c.seed, "crypto", trial as u64);
        let sk = nonzero(&mut random);
        let pk = sk * g();
        let m = Pair::sample(&mut random);
        let ad = enc(&("benchmark", trial as u64, 1u64));
        let start = Instant::now();
        let ct = encrypt(&ad, 1, pk, m, &mut random);
        let encrypt_ns = ns(start);
        let start = Instant::now();
        ensure!(black_box(pop_ok(&ad, &ct)), "valid PoP");
        let pop_ns = ns(start);
        let start = Instant::now();
        ensure!(decrypt(&ad, 1, sk, &ct)? == m, "decrypt");
        let decrypt_ns = ns(start);
        let start = Instant::now();
        let dp = decryption_proof(&ad, sk, &ct, &mut random)?;
        let prove_ns = ns(start);
        let start = Instant::now();
        ensure!(from_proof(&ad, 1, pk, &ct, &dp)? == m, "decryption proof");
        let verify_ns = ns(start);
        if trial >= c.warmup {
            for (case, elapsed) in [
                ("encrypt_with_pop", encrypt_ns),
                ("verify_pop", pop_ns),
                ("decrypt_with_pop", decrypt_ns),
                ("decryption_prove_with_pop", prove_ns),
                ("decryption_verify_with_pop", verify_ns),
            ] {
                r.sample(
                    "B01",
                    case,
                    trial - c.warmup,
                    "measured_component",
                    elapsed,
                    json!({"cipher_bytes":enc(&ct).len(),"proof_bytes":enc(&dp).len()}),
                )?;
            }
        }
    }
    for &t in &c.thresholds {
        eprintln!("core threshold {t}");
        for trial in 0..c.repeats {
            let mut random = rng(c.seed, "core-fixture", (t * 1000 + trial) as u64);
            let src = init(
                Params {
                    n: 5,
                    k: 2,
                    f: 1,
                    t,
                },
                0,
                &mut random,
            )?;
            // Init is a separate owner operation. Refresh below executes actual local VSS contributions.
            let start = Instant::now();
            let dst = generate(&src, t, &mut random)?;
            let generation_ns = ns(start);
            r.sample(
                "B04",
                "local_vss_reference",
                trial,
                "measured_component",
                generation_ns,
                json!({"t":t,"n":5,"k":2,"f":1,"network":false}),
            )?;
            let ids: Vec<_> = (1..=5).collect();
            let parts: Vec<_> = src.rows.iter().map(|p| eval(p, Fr::ONE)).collect();
            let start = Instant::now();
            ensure!(
                batch_verify(b"issuance-v1", &ids, &parts, &src.vectors, Fr::ONE),
                "batch"
            );
            r.sample(
                "B02",
                "batch",
                trial,
                "measured_component",
                ns(start),
                json!({"t":t,"dealers":5}),
            )?;
            let start = Instant::now();
            ensure!(
                parts
                    .iter()
                    .zip(&src.vectors)
                    .all(|(p, v)| p.commitment() == eval_commit(v, Fr::ONE)),
                "individual"
            );
            r.sample(
                "B02",
                "individual",
                trial,
                "measured_component",
                ns(start),
                json!({"t":t,"dealers":5}),
            )?;
            let mut bad = parts.clone();
            bad[0].v += Fr::ONE;
            bad[1].v += Fr::ONE;
            let start = Instant::now();
            let mut found = Vec::new();
            isolate(&ids, &bad, &src.vectors, &mut found);
            ensure!(found == vec![1, 2], "batch localization");
            r.sample(
                "B02",
                "recursive_isolation",
                trial,
                "measured_component",
                ns(start),
                json!({"t":t,"identified":found}),
            )?;
            let sk = nonzero(&mut random);
            let keys: Vec<_> = (0..5).map(|_| nonzero(&mut random)).collect();
            let pks: Vec<_> = keys.iter().map(|s| s * g()).collect();
            let vectors: BTreeMap<_, _> = (0..5)
                .map(|j| {
                    (
                        (j + 1) as u64,
                        (src.vectors[j].clone(), dst.vectors[j].clone()),
                    )
                })
                .collect();
            for case in [
                "happy",
                "one_inconsistent",
                "bad_and_missing",
                "k_only",
                "snapshot",
                "source_vector_missing",
                "record_missing_all",
            ] {
                // Four records were anchored at finalization; returning participants may read fewer.
                let mode = if case == "snapshot" {
                    Mode::Snapshot
                } else {
                    Mode::Difference
                };
                let start = Instant::now();
                let records: Vec<_> = (0..4)
                    .map(|j| {
                        make_record(
                            &src,
                            &dst,
                            j,
                            1,
                            100 + trial as u64,
                            mode,
                            sk * g(),
                            keys[j],
                            if (case == "one_inconsistent"
                                || case == "bad_and_missing"
                                || case == "source_vector_missing")
                                && j == 0
                            {
                                Fr::ONE
                            } else {
                                Fr::ZERO
                            },
                            &mut random,
                        )
                    })
                    .collect();
                let publication_compute_ns = ns(start);
                let path = r.dir.join(format!("archives/t{t}-{trial}-{case}"));
                let a = Archive::write(&path, &records, &vectors)?;
                if case == "bad_and_missing" {
                    fs::remove_file(path.join("record-2.bin"))?;
                }
                if case == "k_only" {
                    for id in [3, 4] {
                        fs::remove_file(path.join(format!("record-{id}.bin")))?;
                    }
                }
                if case == "record_missing_all" {
                    for id in 1..=4 {
                        fs::remove_file(path.join(format!("record-{id}.bin")))?;
                    }
                }
                if case == "source_vector_missing" {
                    fs::remove_file(path.join("vectors-1.bin"))?;
                }
                let expected = if mode == Mode::Difference {
                    delta(&src.public, &dst.public)
                } else {
                    dst.public.clone()
                };
                for warm in [false, true] {
                    if warm && ["source_vector_missing", "record_missing_all"].contains(&case) {
                        continue;
                    }
                    let mut cache = VectorCache::default();
                    if warm {
                        cache.preload(&a)?;
                    }
                    let start = Instant::now();
                    let result = recover(&a, sk, &pks, 2, &expected, &mut cache);
                    let elapsed = ns(start);
                    let success = result.is_ok();
                    ensure!(
                        success != ["source_vector_missing", "record_missing_all"].contains(&case),
                        "unexpected recovery outcome {case}"
                    );
                    let details = match result {
                        Ok((token, stats)) => {
                            let updated = if mode == Mode::Difference {
                                src.share(1).plus(token)
                            } else {
                                token
                            };
                            ensure!(updated == dst.share(1), "wrong recovered share");
                            ensure!(stats.records_read <= 3, "k+f read bound");
                            json!({"stats":stats})
                        }
                        Err(e) => {
                            json!({"error":e.to_string(),"fallback":"interactive_reissuance_required"})
                        }
                    };
                    r.sample(if case=="snapshot"{"B13"}else if case.contains("missing"){"B18"}else{"B07"},case,trial,"measured_filesystem",elapsed,json!({"t":t,"n":5,"k":2,"f":1,"margin":1,"cache":if warm{"warm"}else{"cold"},"os_page_cache":"uncontrolled; cold means application vector cache","success":success,"publication_compute_ns":publication_compute_ns,"raw_record_bytes":enc(&records[0]).len(),"archive_bytes":a.bytes()?,"details":details}))?;
                }
                if case == "k_only" {
                    r.check(
                        "B06",
                        "return_gate_below_publication_quorum",
                        true,
                        json!({"t":t,"available":2,"publication_quorum":4,"return_gate":2}),
                    )?;
                }
            }
            let target_sizes = if trial == 0 {
                vec![(t / 2).max(2), t, t + 1]
            } else {
                vec![t]
            };
            for tt in target_sizes {
                let changed = if tt == t {
                    dst.clone()
                } else {
                    generate(&src, tt, &mut random)?
                };
                let token = changed.share(1).minus(src.share(1));
                let start = Instant::now();
                let updated = src.share(1).plus(token);
                ensure!(
                    updated.commitment() == eval_commit(&changed.public, Fr::ONE),
                    "apply verification"
                );
                r.sample(
                    "B03",
                    "apply_update",
                    trial,
                    "measured_component",
                    ns(start),
                    json!({"source_t":t,"target_t":tt,"zero_padding":t!=tt}),
                )?;
                if trial < c.distributed_repeats {
                    let shares: Vec<_> =
                        (1..=tt as u64).map(|id| (id, changed.share(id))).collect();
                    let start = Instant::now();
                    let secret = reconstruct(&changed.public, &shares)?;
                    ensure!(secret.commitment() == src.public[0], "reconstruct secret");
                    r.sample("B03","reconstruct",trial,"measured_component",ns(start),json!({"source_t":t,"target_t":tt,"shares":tt,"repeats_for_expensive_path":c.distributed_repeats}))?;
                }
            }
            // Interactive re-issuance costs all dealer partials, authentication, batch verification and interpolation.
            let start = Instant::now();
            let returned: Vec<_> = dst.rows.iter().map(|v| eval(v, Fr::ONE)).collect();
            let sigs: Vec<_> = returned
                .iter()
                .enumerate()
                .map(|(i, p)| sign(keys[i], &enc(&(1u64, trial, p)), &mut random))
                .collect();
            ensure!(
                sigs.iter().enumerate().all(|(i, s)| verify_sig(
                    pks[i],
                    &enc(&(1u64, trial, &returned[i])),
                    s
                )),
                "reissue authentication"
            );
            ensure!(
                batch_verify(b"reissue", &ids, &returned, &dst.vectors, Fr::ONE),
                "reissue batch"
            );
            ensure!(
                combine(&[(1, returned[0]), (2, returned[1])])? == dst.share(1),
                "reissue"
            );
            r.sample("B13","interactive_reissuance_local",trial,"measured_component",ns(start),json!({"t":t,"committee_online":true,"network":false,"source_share_required":false}))?;
            monitor(r, trial, t, &src, &dst)?;
        }
    }
    cancellation(c, r)?;
    ledger_and_registry(c, r)?;
    load(c, r)?;
    super::extended::run(c, r)?;
    super::load::run(c, r)?;
    Ok(())
}
fn monitor(r: &mut Recorder, trial: usize, t: usize, src: &Epoch, dst: &Epoch) -> Result<()> {
    use curve25519_dalek::traits::VartimeMultiscalarMul;
    let vectors: Vec<_> = src
        .vectors
        .iter()
        .zip(&dst.vectors)
        .map(|(a, b)| delta(a, b))
        .collect();
    let mut points: Vec<_> = vectors.iter().map(|v| eval_commit(v, Fr::ONE)).collect();
    points[0] += g();
    fn inspect(v: &[Vec<Point>], e: &[Point], offset: usize, found: &mut Vec<usize>) {
        let tr = enc(&(v, e));
        let mut sc = Vec::new();
        let mut bs = Vec::new();
        for (i, (p, vs)) in e.iter().zip(v).enumerate() {
            let w = hs(&[b"monitor", &tr, &(i as u64).to_le_bytes()]);
            sc.push(w);
            bs.push(*p);
            for b in vs {
                sc.push(-w);
                bs.push(*b);
            }
        }
        let good = Point::vartime_multiscalar_mul(sc, bs) == Pair::zero().commitment();
        if good {
            return;
        }
        if e.len() == 1 {
            found.push(offset);
            return;
        }
        let m = e.len() / 2;
        inspect(&v[..m], &e[..m], offset, found);
        inspect(&v[m..], &e[m..], offset + m, found);
    }
    let start = Instant::now();
    let mut found = Vec::new();
    inspect(&vectors, &points, 0, &mut found);
    ensure!(found == vec![0], "monitor isolate");
    r.sample("B21","keyless_batch_binary_isolation",trial,"measured_component",ns(start),json!({"t":t,"families":5,"download_bytes":enc(&vectors).len()+enc(&points).len(),"identified":found,"plaintext_monitor":false}))?;
    Ok(())
}
fn cancellation(c: &Config, r: &mut Recorder) -> Result<()> {
    let mut random = rng(c.seed, "cancel", 0);
    let src = init(
        Params {
            n: 7,
            k: 3,
            f: 2,
            t: 8,
        },
        0,
        &mut random,
    )?;
    let dst = generate(&src, 8, &mut random)?;
    let sk = nonzero(&mut random);
    let keys: Vec<_> = (0..7).map(|_| nonzero(&mut random)).collect();
    let pks: Vec<_> = keys.iter().map(|s| s * g()).collect();
    let records: Vec<_> = (0..5)
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
                if j < 2 { Fr::ONE } else { Fr::ZERO },
                &mut random,
            )
        })
        .collect();
    let vs = (0..7)
        .map(|j| {
            (
                (j + 1) as u64,
                (src.vectors[j].clone(), dst.vectors[j].clone()),
            )
        })
        .collect();
    let a = Archive::write(&r.dir.join("cancellation"), &records, &vs)?;
    let (p, stats) = recover(
        &a,
        sk,
        &pks,
        3,
        &delta(&src.public, &dst.public),
        &mut VectorCache::default(),
    )?;
    r.check(
        "B08",
        "weights_3_minus3_1",
        src.share(1).plus(p) == dst.share(1)
            && stats.localizations == 0
            && stats.individually_validated == 0,
        json!(stats),
    )?;
    Ok(())
}

fn ledger_and_registry(c: &Config, r: &mut Recorder) -> Result<()> {
    for trial in 0..c.repeats {
        let path = r.dir.join(format!("ledger/{trial}"));
        let ledger = Ledger::create(
            &path,
            Policy {
                source: hash(&[&trial.to_le_bytes()]),
                source_t: 8,
                delta: 1,
                incoming: [1, 2].into(),
                rho_out: 4,
            },
        )?;
        for (nonce, ids, accepted) in [
            (1, vec![3, 4], true),
            (2, vec![5, 6], true),
            (3, vec![7], false),
            (4, vec![3, 4], true),
        ] {
            let request = Request {
                old_root: ledger.root()?,
                nonce,
                recipients: ids.into_iter().collect(),
                target: hash(&[&nonce.to_le_bytes()]),
                target_t: 16,
                target_rho: 4,
                eligible: 16,
                mode: Mode::Difference,
            };
            let start = Instant::now();
            let result = ledger.reserve(request.clone());
            let elapsed = ns(start);
            ensure!(result.is_ok() == accepted, "budget boundary");
            r.sample("B10",if accepted{"reserve_abort_retained"}else{"budget_rejection"},trial,"measured_durable_io",elapsed,json!({"nonce":nonce,"accepted":accepted,"reserved":ledger.entries()?.last().map(|e|e.reserved.len()),"source_t":8,"delta":1}))?;
            if let Ok(e) = result {
                ensure!(
                    ledger.reserve(request)?.new_root == e.new_root,
                    "idempotency"
                );
            }
        }
        let request = Request {
            old_root: ledger.root()?,
            nonce: 50,
            recipients: [3].into(),
            target: [50; 32],
            target_t: 16,
            target_rho: 4,
            eligible: 16,
            mode: Mode::Difference,
        };
        let mut other = request.clone();
        other.nonce = 51;
        other.target = [51; 32];
        let start = Instant::now();
        let successes = std::thread::scope(|scope| {
            let a = ledger.clone();
            let b = ledger.clone();
            let one = scope.spawn(move || a.reserve(request).is_ok());
            let two = scope.spawn(move || b.reserve(other).is_ok());
            usize::from(one.join().unwrap()) + usize::from(two.join().unwrap())
        });
        ensure!(successes == 1, "CAS must choose one winner");
        r.sample("B09","concurrent_cas",trial,"measured_durable_io",ns(start),json!({"writers":2,"successes":successes,"consensus":"local flock only; chain ordering measured separately"}))?;
        if trial == 0 {
            let req = Request {
                old_root: ledger.root()?,
                nonce: 60,
                recipients: [3].into(),
                target: [60; 32],
                target_t: 16,
                target_rho: 4,
                eligible: 16,
                mode: Mode::Difference,
            };
            let f = path.join("request.bin");
            fs::write(&f, enc(&req))?;
            let status = Command::new(std::env::current_exe()?)
                .args(["crash-reserve", "--ledger"])
                .arg(&path)
                .arg("--request")
                .arg(f)
                .status()?;
            let reopened = Ledger::open(&path)?;
            r.check("B09","process_exit_after_fsync",status.code()==Some(73)&&reopened.entries()?.last().unwrap().request.nonce==60,json!({"exit":status.code(),"acknowledged_log_survived":true,"unacknowledged_torn_write":"fail_closed"}))?;
            let mut truncated = fs::read(path.join("log.bin"))?;
            truncated.pop();
            fs::write(path.join("log.bin"), truncated)?;
            r.check(
                "B09",
                "torn_tail_fails_closed",
                reopened.entries().is_err(),
                json!({}),
            )?;
        }
    }
    let mut random = rng(c.seed, "registry", 0);
    let authority = nonzero(&mut random);
    let mut registry = Registry::default();
    for id in 1..=*c.populations.iter().max().unwrap_or(&16) as u64 {
        let reg = Registration {
            id,
            pk: nonzero(&mut random) * g(),
            epoch: 0,
            activation: id,
            deadline: 100,
            status: RegistryStatus::Pending,
        };
        let sig = sign(
            authority,
            &enc(&(reg.id, reg.pk, reg.epoch, reg.activation, reg.deadline)),
            &mut random,
        );
        let start = Instant::now();
        registry.enroll(reg, &sig, authority * g())?;
        durable_write(&r.dir.join("registry.bin"), &enc(&registry))?;
        registry.complete(id, id)?;
        if c.populations.contains(&(id as usize)) {
            r.sample(
                "B11",
                "authorized_registry_growth",
                id as usize,
                "measured_durable_io",
                ns(start),
                json!({"N":id,"registry_bytes":enc(&registry).len(),"includes_authorization":true}),
            )?;
        }
    }
    registry.begin_recovery(1)?;
    r.check(
        "B11",
        "pending_recovery_blocks_finalization",
        !registry.can_finalize(0),
        json!({}),
    )?;
    registry.complete(1, 1)?;
    r.check(
        "B11",
        "recovery_completion_unblocks",
        registry.can_finalize(0),
        json!({}),
    )?;
    let pending = Registration {
        id: 99999,
        pk: nonzero(&mut random) * g(),
        epoch: 1,
        activation: 99,
        deadline: 100,
        status: RegistryStatus::Pending,
    };
    let sig = sign(
        authority,
        &enc(&(
            pending.id,
            pending.pk,
            pending.epoch,
            pending.activation,
            pending.deadline,
        )),
        &mut random,
    );
    registry.enroll(pending, &sig, authority * g())?;
    registry.expire(101);
    r.check(
        "B11",
        "expiry_completion_race",
        registry.complete(99999, 99).is_err() && registry.can_finalize(1),
        json!({}),
    )?;
    Ok(())
}
fn load(c: &Config, r: &mut Recorder) -> Result<()> {
    let t = 16;
    let mut random = rng(c.seed, "load", 0);
    let src = init(
        Params {
            n: 4,
            k: 2,
            f: 1,
            t,
        },
        0,
        &mut random,
    )?;
    for &population in &c.populations {
        for &concurrency in &c.concurrency {
            for trial in 0..c.distributed_repeats {
                let jobs = population.min(64);
                let started = Instant::now();
                let results = std::thread::scope(|scope| {
                    let mut handles = Vec::new();
                    for worker in 0..concurrency {
                        let src = &src;
                        handles.push(scope.spawn(move || {
                            let mut out = Vec::new();
                            for job in (worker..jobs).step_by(concurrency) {
                                let start = Instant::now();
                                let id = (job + 1) as u64;
                                let partials: Vec<_> =
                                    src.rows.iter().map(|v| eval(v, Fr::from(id))).collect();
                                assert!(batch_verify(
                                    b"load",
                                    &[1, 2, 3, 4],
                                    &partials,
                                    &src.vectors,
                                    Fr::from(id)
                                ));
                                out.push((job, ns(start)));
                            }
                            out
                        }));
                    }
                    handles
                        .into_iter()
                        .flat_map(|h| h.join().unwrap())
                        .collect::<Vec<_>>()
                });
                let wall = ns(started);
                r.sample("B20","issuance_burst_local",trial,"measured_load",wall,json!({"t":t,"N":population,"requests":jobs,"concurrency":concurrency,"throughput_per_s":jobs as f64*1e9/wall as f64,"request_latency_ns":results,"queue_policy":"static closed-loop workers","population_note":"registered population label; at most 64 issuing clients per trial","network":false}))?;
            }
        }
    }
    Ok(())
}
