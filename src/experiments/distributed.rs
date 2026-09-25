use super::*;
use crate::{
    chain::{self, Arg},
    crypto::*,
    ledger::*,
    network::*,
    protocol::*,
    storage::*,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn run(c: &Config, r: &mut Recorder) -> Result<()> {
    let mut chain = chain::Devnet::start(&r.dir.join("lifecycle-chain"))?;
    for &t in &c.distributed_thresholds {
        for trial in 0..c.distributed_repeats {
            eprintln!("distributed lifecycle t={t} trial={trial}");
            let total = Instant::now();
            let mut random = rng(c.seed, "lifecycle", (t * 100 + trial) as u64);
            let p = Params {
                n: 4,
                k: 2,
                f: 1,
                t,
            };
            let src = init(p, 0, &mut random)?;
            let cluster = Cluster::start(
                &r.dir.join(format!("nodes/{t}-{trial}")),
                &src,
                c.seed,
                "honest",
                0,
                0,
            )?;
            let cluster_setup_ns = ns(total);
            let mut clients = Vec::new();
            let mut client_keys = Vec::new();
            let mut registry = Registry::default();
            let enroll_start = Instant::now();
            for id in 1..=t as u64 {
                let sk = nonzero(&mut random);
                let pk = sk * g();
                let reg = Registration {
                    id,
                    pk,
                    epoch: 0,
                    activation: id,
                    deadline: 100,
                    status: RegistryStatus::Pending,
                };
                let sig = sign(
                    cluster.authority_sk,
                    &enc(&(reg.id, reg.pk, reg.epoch, reg.activation, reg.deadline)),
                    &mut random,
                );
                registry.enroll(reg, &sig, cluster.authority_sk * g())?;
                let authorization = sign(cluster.authority_sk, &enc(&(id, pk, 0u64)), &mut random);
                let replies = cluster.all(Rpc::Enroll {
                    recipient: id,
                    pk,
                    authorization,
                })?;
                let records: Vec<Record> = replies
                    .iter()
                    .map(|b| bincode::deserialize(b))
                    .collect::<std::result::Result<_, _>>()?;
                let partials: Vec<_> = records
                    .iter()
                    .zip(&cluster.configs[0].signing_pks)
                    .map(|(rec, pk)| admit(rec, *pk, sk))
                    .collect::<Result<_>>()?;
                ensure!(
                    batch_verify(
                        b"enroll",
                        &[1, 2, 3, 4],
                        &partials,
                        &src.vectors,
                        Fr::from(id)
                    ),
                    "enrollment batch"
                );
                let share = combine(&[(1, partials[0]), (2, partials[1])])?;
                ensure!(share == src.share(id), "enrollment share");
                let participant = Participant {
                    id,
                    epoch: 0,
                    share,
                    staged: None,
                    applied: BTreeSet::new(),
                };
                participant.save(&cluster.dir.join(format!("client-{id}.bin")))?;
                clients.push(participant);
                client_keys.push(sk);
                registry.complete(id, id)?;
            }
            durable_write(&cluster.dir.join("registry.bin"), &enc(&registry))?;
            let enrollment_ns = ns(enroll_start);
            let live_start = Instant::now();
            let nonce = (t * 1000 + trial + 1) as u64;
            for id in 1..t as u64 {
                let proof = sign(
                    client_keys[id as usize - 1],
                    &enc(&("heartbeat", id, nonce, src.digest())),
                    &mut random,
                );
                cluster.all(Rpc::Heartbeat {
                    recipient: id,
                    nonce,
                    proof,
                })?;
            }
            let liveness_ns = ns(live_start);
            let policy = Policy {
                source: src.digest(),
                source_t: t,
                delta: 1,
                incoming: BTreeSet::new(),
                rho_out: 1,
            };
            let reference =
                Ledger::create(&cluster.dir.join("coordinator-ledger"), policy.clone())?;
            let mut request = Request {
                old_root: reference.root()?,
                nonce,
                recipients: [t as u64].into(),
                target: [0; 32],
                target_t: t,
                target_rho: 1,
                eligible: t,
                mode: Mode::Difference,
            };
            target_check(&request, policy.delta)?;
            let before_generation: Vec<NodeStats> = cluster
                .all(Rpc::Stats)?
                .iter()
                .map(|b| bincode::deserialize(b))
                .collect::<std::result::Result<_, _>>()?;
            let gen_start = Instant::now();
            let (vectors, phases) = cluster.generation(nonce, t)?;
            let generation_ns = ns(gen_start);
            let after_generation: Vec<NodeStats> = cluster
                .all(Rpc::Stats)?
                .iter()
                .map(|b| bincode::deserialize(b))
                .collect::<std::result::Result<_, _>>()?;
            let generation_stats = stats_delta(&before_generation, &after_generation);
            let public = public_from_vectors(p, &vectors)?;
            ensure!(public[0] == src.public[0], "distributed constant");
            let target = Epoch {
                params: p,
                epoch: 1,
                rows: Vec::new(),
                vectors: vectors.clone(),
                public: public.clone(),
            };
            request.target = target.digest();
            let pre_release = cluster.all(Rpc::Issue {
                recipient: t as u64,
                pk: client_keys[t - 1] * g(),
                mode: Mode::Difference,
                source: src.digest(),
                target: target.digest(),
            });
            ensure!(pre_release.is_err(), "token released before reservation");
            let reserve_start = Instant::now();
            let entry = reference.reserve(request.clone())?;
            let digest = hash(&[&enc(&(policy.source, &entry))]);
            let to = chain.ledger.clone();
            let init = chain::calldata(
                "initialize(bytes32,bytes32,uint256,uint256,uint256,uint256[])",
                &[
                    Arg::Word(policy.source),
                    Arg::Word(request.old_root),
                    Arg::Word(chain::word(t as u64)),
                    Arg::Word(chain::word(1)),
                    Arg::Word(chain::word(1)),
                    Arg::Words(vec![]),
                ],
            );
            let receipt = chain.send(Some(&to), init, 0, 0, "lifecycle-ledger-init")?;
            ensure!(chain::hex_u64(&receipt["status"])? == 1, "chain init");
            let args = vec![
                Arg::Word(policy.source),
                Arg::Word(request.old_root),
                Arg::Word(entry.new_root),
                Arg::Word(digest),
                Arg::Word(chain::word(nonce)),
                Arg::Word(chain::word(t as u64)),
                Arg::Word(chain::word(1)),
                Arg::Word(chain::word(t as u64)),
                Arg::Words(vec![chain::word(t as u64)]),
                Arg::Word(chain::word(1)),
            ];
            let receipt=chain.send(Some(&to),chain::calldata("reserve(bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint256,uint256,uint256[],bool)",&args),0,0,"lifecycle-reserve")?;
            ensure!(chain::hex_u64(&receipt["status"])? == 1, "chain reserve");
            let replies = cluster.all(Rpc::Reserve {
                request,
                policy,
                chain: Some((chain.url.clone(), to, digest)),
            })?;
            let signed: Vec<(Entry, Signature)> = replies
                .iter()
                .map(|b| bincode::deserialize(b))
                .collect::<std::result::Result<_, _>>()?;
            ensure!(
                signed.iter().all(|(e, _)| enc(e) == enc(&entry)),
                "ledger agreement"
            );
            let certificate = Certificate {
                digest,
                signatures: signed
                    .into_iter()
                    .enumerate()
                    .map(|(j, (_, s))| ((j + 1) as u64, s))
                    .collect(),
            };
            ensure!(
                verify_certificate(&certificate, &cluster.configs[0].reservation_pks, 3),
                "certificate"
            );
            cluster.all(Rpc::Release {
                entry: entry.clone(),
                certificate: certificate.clone(),
            })?;
            let reservation_ns = ns(reserve_start);
            let release_start = Instant::now();
            let mut offline_records = Vec::new();
            for id in 1..=t as u64 {
                let replies = cluster.all(Rpc::Issue {
                    recipient: id,
                    pk: client_keys[id as usize - 1] * g(),
                    mode: Mode::Difference,
                    source: src.digest(),
                    target: target.digest(),
                })?;
                let records: Vec<Record> = replies
                    .iter()
                    .map(|b| bincode::deserialize(b))
                    .collect::<std::result::Result<_, _>>()?;
                if id == t as u64 {
                    offline_records = records[..3].to_vec();
                    continue;
                }
                let parts: Vec<_> = records
                    .iter()
                    .take(2)
                    .enumerate()
                    .map(|(j, rec)| {
                        Ok((
                            (j + 1) as u64,
                            admit(
                                rec,
                                cluster.configs[0].signing_pks[j],
                                client_keys[id as usize - 1],
                            )?,
                        ))
                    })
                    .collect::<Result<_>>()?;
                let token = combine(&parts)?;
                clients[id as usize - 1].stage(
                    Staged {
                        nonce,
                        target: 1,
                        token,
                        target_public: public.clone(),
                    },
                    &cluster.dir.join(format!("client-{id}.bin")),
                )?;
            }
            let archive_vectors = (0..4)
                .map(|j| ((j + 1) as u64, (src.vectors[j].clone(), vectors[j].clone())))
                .collect::<BTreeMap<_, _>>();
            let archive = Archive::write(
                &cluster.dir.join("archive"),
                &offline_records,
                &archive_vectors,
            )?;
            let release_stage_ns = ns(release_start);
            let anchor_start = Instant::now();
            let payload = enc(&(&offline_records, &certificate));
            let bundle = chain::blob_bundle(archive.meta.root, &payload)?;
            let call = chain::calldata(
                "anchorBlob(bytes32,bytes32,bytes32,uint256,uint256)",
                &[
                    Arg::Word(archive.meta.root),
                    Arg::Word(src.digest()),
                    Arg::Word(target.digest()),
                    Arg::Word(chain::word(t as u64)),
                    Arg::Word(chain::word(t as u64)),
                ],
            );
            let receipt = chain.blob_send(call, &bundle, "lifecycle-publication")?;
            ensure!(chain::hex_u64(&receipt["status"])? == 1, "publication");
            let finalization_ns = ns(anchor_start);
            durable_write(
                &cluster.dir.join("committed.bin"),
                &enc(&(nonce, target.digest(), archive.meta.root)),
            )?;
            cluster.all(Rpc::Commit {
                nonce,
                target: target.digest(),
            })?;
            let apply_start = Instant::now();
            for id in 1..t as u64 {
                let path = cluster.dir.join(format!("client-{id}.bin"));
                let mut participant = Participant::load(&path)?;
                ensure!(participant.apply(nonce, 1, &path)?, "first apply");
                ensure!(!participant.apply(nonce, 1, &path)?, "double apply");
                clients[id as usize - 1] = participant;
            }
            let apply_ns = ns(apply_start);
            // Warm and cold TCP/TLS recovery read authenticated archive bytes from a dealer endpoint.
            let first = &cluster.configs[0];
            let archive_dir = first.dir.join("archive");
            fs::create_dir_all(&archive_dir)?;
            for item in fs::read_dir(&archive.dir)? {
                let item = item?;
                fs::copy(item.path(), archive_dir.join(item.file_name()))?;
            }
            let catch_start = Instant::now();
            let (token, stats) = recover_with(
                &archive,
                client_keys[t - 1],
                &first.signing_pks,
                2,
                &delta(&src.public, &public),
                &mut VectorCache::default(),
                |path| {
                    let file = path.file_name().unwrap().to_string_lossy().to_string();
                    let reply = call_port(&first.tls, 0, first.port, &Rpc::Fetch { file }, 0)?;
                    Ok(bincode::deserialize(&reply)?)
                },
            )?;
            let catchup_ns = ns(catch_start);
            clients[t - 1].share = clients[t - 1].share.plus(token);
            clients[t - 1].epoch = 1;
            let reconstruct_start = Instant::now();
            let secret = reconstruct(
                &public,
                &clients.iter().map(|p| (p.id, p.share)).collect::<Vec<_>>(),
            )?;
            ensure!(secret.commitment() == src.public[0], "end-to-end secret");
            let reconstruct_ns = ns(reconstruct_start);
            let node_stats: Vec<NodeStats> = cluster
                .all(Rpc::Stats)?
                .iter()
                .map(|b| bincode::deserialize(b))
                .collect::<std::result::Result<_, _>>()?;
            let wall = ns(total);
            let pks = first.signing_pks.clone();
            let archive_owned = archive.clone();
            let rootdir = cluster.dir.clone();
            drop(cluster);
            let read_start = Instant::now();
            let (again, stopped_stats) = recover(
                &archive_owned,
                client_keys[t - 1],
                &pks,
                2,
                &delta(&src.public, &public),
                &mut VectorCache::default(),
            )?;
            ensure!(again == token, "stopped dealer recovery");
            r.sample(
                "B20",
                "dealer_stopped_archive_catchup",
                trial,
                "measured_filesystem",
                ns(read_start),
                json!({"t":t,"stats":stopped_stats,"dealer_online":false}),
            )?;
            r.sample("B04","distributed_generation",trial,"measured_tls_processes",generation_ns,json!({"t":t,"n":4,"k":2,"f":1,"phases":phases,"nodes":generation_stats,"entropy":"OsRng independent per dealer","logical_commitment_bytes":32*4*t*2,"logical_pair_bytes_including_self":64*4*4*t,"self_delivery_included":true,"rounds":3,"broadcast":"signed synchronous echo/ready, all processes responsive"}))?;
            r.sample("B05","lifecycle",trial,"measured_tls_devnet",wall,json!({"t":t,"N":t,"offline":1,"cluster_setup_ns":cluster_setup_ns,"enrollment_ns":enrollment_ns,"liveness_ns":liveness_ns,"generation_ns":generation_ns,"reservation_ns":reservation_ns,"release_stage_ns":release_stage_ns,"publication_inclusion_ns":finalization_ns,"apply_ns":apply_ns,"catchup_ns":catchup_ns,"reconstruct_ns":reconstruct_ns,"catchup_stats":stats,"publication_gas":chain::hex_u64(&receipt["gasUsed"])?,"publication_blob_gas":receipt["blobGasUsed"],"node_stats":node_stats,"directory":rootdir,"chain_finality":"immediate Anvil inclusion, not CL finality","contract_crypto_suite":"publication anchor only; Ristretto admission off-chain"}))?;
            // Reclassification and retry are policy tests; they do not silently release another public token.
            let mut ack_missing = entry.request.clone();
            ack_missing.old_root = reference.root()?;
            ack_missing.nonce += 1;
            ack_missing.recipients.insert(1);
            r.check(
                "B11",
                "ack_withheld_budget_abort",
                reference.reserve(ack_missing).is_err(),
                json!({"rho_out":1,"existing_offline":t,"newly_unresponsive":1}),
            )?;
        }
    }
    // Real VSS faults exercise the public complaint path, including a malicious constant.
    for fault in [
        "bad_share",
        "bad_constant",
        "spurious",
        "omission",
        "equivocation",
    ] {
        let mut random = rng(c.seed, "generation-fault", 0);
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
        let cluster = Cluster::start(
            &r.dir.join(format!("fault-nodes/{fault}")),
            &src,
            c.seed,
            fault,
            1,
            0,
        )?;
        let start = Instant::now();
        let (v, phases) = cluster.generation(1, 8)?;
        let public = public_from_vectors(src.params, &v)?;
        ensure!(public[0] == src.public[0], "fault refresh constant");
        let node_stats: Vec<NodeStats> = cluster
            .all(Rpc::Stats)?
            .iter()
            .map(|b| bincode::deserialize(b))
            .collect::<std::result::Result<_, _>>()?;
        r.sample(
            "B04",
            fault,
            0,
            "measured_tls_processes",
            ns(start),
            json!({"t":8,"phases":phases,"nodes":node_stats}),
        )?;
    }
    for &t in c.thresholds.iter().filter(|t| **t >= 256) {
        for trial in 0..c.distributed_repeats {
            eprintln!("distributed generation t={t} trial={trial}");
            let mut random = rng(
                c.seed,
                "distributed-generation-sweep",
                (t * 100 + trial) as u64,
            );
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
            let cluster = Cluster::start(
                &r.dir.join(format!("generation-sweep/{t}-{trial}")),
                &src,
                c.seed,
                "honest",
                0,
                0,
            )?;
            let start = Instant::now();
            let (vectors, phases) = cluster.generation(1, t)?;
            let generation_ns = ns(start);
            let check = Instant::now();
            let public = public_from_vectors(src.params, &vectors)?;
            ensure!(public[0] == src.public[0], "sweep constant");
            let consistency_ns = ns(check);
            let stats: Vec<NodeStats> = cluster
                .all(Rpc::Stats)?
                .iter()
                .map(|b| bincode::deserialize(b))
                .collect::<std::result::Result<_, _>>()?;
            r.sample("B04","distributed_generation",trial,"measured_tls_processes",generation_ns,json!({"t":t,"n":4,"k":2,"f":1,"phases":phases,"commitment_consistency_ns":consistency_ns,"nodes":stats,"logical_commitment_bytes":32*4*t*2,"logical_pair_bytes_including_self":64*4*4*t,"self_delivery_included":true,"entropy":"OsRng independent per dealer","rounds":3,"broadcast":"signed synchronous echo/ready, all processes responsive"}))?;
        }
    }
    Ok(())
}
fn stats_delta(before: &[NodeStats], after: &[NodeStats]) -> Vec<NodeStats> {
    before
        .iter()
        .zip(after)
        .map(|(a, b)| NodeStats {
            sent: b.sent - a.sent,
            received: b.received - a.received,
            transport_sent: b.transport_sent - a.transport_sent,
            transport_received: b.transport_received - a.transport_received,
            requests: b.requests - a.requests,
            complaints: b.complaints,
            qualified: b.qualified,
            compute_ns: b.compute_ns - a.compute_ns,
            peak_rss_bytes: b.peak_rss_bytes,
            source_erased: b.source_erased,
            cpu_user_ns: b.cpu_user_ns - a.cpu_user_ns,
            cpu_system_ns: b.cpu_system_ns - a.cpu_system_ns,
            tls_handshakes: b.tls_handshakes - a.tls_handshakes,
            tls_handshake_ns: b.tls_handshake_ns - a.tls_handshake_ns,
        })
        .collect()
}
