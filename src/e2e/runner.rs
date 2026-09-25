use super::{
    core::*,
    dispute,
    issuance::{active_participants, Completion, RegistrationProof, ACTIVATE_ABI, REGISTER_ABI},
    model::*,
    wire::*,
};
use crate::chain::{self, keccak, word, Arg, Devnet, Word};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub name: String,
    pub repeats: usize,
    /// Explicit [dealer count, sharing threshold, protocol fault bound].
    /// The fault bound is independent of actual injected faults.
    pub committees: Vec<[usize; 3]>,
    pub thresholds: Vec<usize>,
    pub populations: Vec<usize>,
    /// Participants 1..=offline_participants miss transitions 1 and 2.
    #[serde(default = "default_offline_participants")]
    pub offline_participants: usize,
    #[serde(default = "default_participant_corruption_budget")]
    pub participant_corruption_budget: usize,
    #[serde(default = "default_outgoing_recipient_budget")]
    pub outgoing_recipient_budget: usize,
    #[serde(default = "default_catchup_concurrency")]
    pub catchup_concurrency: usize,
    #[serde(default)]
    pub fault_scenarios: bool,
    pub timeout_ms: u64,
    #[serde(default = "default_liveness_timeout_ms")]
    /// Response budget per participant, excluding time queued for a probe worker.
    pub liveness_timeout_ms: u64,
    #[serde(default = "default_generation_round_seconds")]
    pub generation_round_seconds: u64,
    #[serde(default)]
    pub dealer_omission: bool,
}
fn default_offline_participants() -> usize {
    1
}
fn default_participant_corruption_budget() -> usize {
    1
}
fn default_outgoing_recipient_budget() -> usize {
    2
}
fn default_catchup_concurrency() -> usize {
    16
}
fn default_liveness_timeout_ms() -> u64 {
    2000
}
fn default_generation_round_seconds() -> u64 {
    120
}
/// Validate P1/P2 without replacing the configured fault bound.
pub fn committee_parameters([n, k, f]: [usize; 3]) -> Result<[usize; 3]> {
    ensure!(
        n > 0 && k > 0 && k <= n,
        "committee requires 1 <= k_D <= n_D"
    );
    ensure!(f < k, "committee requires f_D < k_D (P1)");
    ensure!(
        f <= (n - k) / 2,
        "committee requires k_D + 2*f_D <= n_D (P2)"
    );
    Ok([n, k, f])
}
impl Config {
    pub fn load(p: &Path) -> Result<Self> {
        let c: Self = toml::from_str(
            &fs::read_to_string(p)
                .with_context(|| format!("read benchmark config: {}", p.display()))?,
        )?;
        c.validate()?;
        Ok(c)
    }
    fn validate(&self) -> Result<()> {
        let c = self;
        ensure!(
            c.repeats > 0
                && c.liveness_timeout_ms > 0
                && c.generation_round_seconds > 0
                && !c.committees.is_empty()
                && c.thresholds.len() == c.populations.len()
                && c.thresholds.len() >= 4,
            "E2E config"
        );
        ensure!(
            !c.dealer_omission || c.fault_scenarios,
            "dealer omission belongs only to explicit fault validation"
        );
        for committee in &c.committees {
            let [n, k, f] = committee_parameters(*committee)?;
            Params {
                n,
                k,
                f,
                t: c.thresholds[0],
            }
            .check()?;
        }
        for (i, (&t, &n)) in c.thresholds.iter().zip(&c.populations).enumerate() {
            ensure!(
                t >= 8 && n >= t && (i == 0 || n >= c.populations[i - 1]),
                "eligible/growing population"
            );
        }
        ensure!(
            c.offline_participants > 0 && c.offline_participants <= c.populations[0],
            "offline_participants must identify a nonempty subset of the initial population"
        );
        ensure!(
            c.catchup_concurrency > 0,
            "catchup_concurrency must be positive"
        );
        ensure!(
            !c.fault_scenarios || c.offline_participants == 1,
            "the separate fault fixture requires offline_participants=1"
        );
        ensure!(
            c.offline_participants <= c.outgoing_recipient_budget,
            "offline participants exceed the cumulative outgoing recipient budget"
        );
        for epoch in 1..c.thresholds.len() {
            let outgoing = if epoch <= 2 {
                c.offline_participants
            } else {
                0
            };
            // The same IDs miss both transitions. Incoming and outgoing
            // exposure sets overlap completely at source epoch 1.
            let source_union = if epoch <= 3 {
                c.offline_participants
            } else {
                0
            };
            let source_exposure = c
                .participant_corruption_budget
                .checked_add(source_union)
                .context("source exposure overflow")?;
            let target_exposure = c
                .participant_corruption_budget
                .checked_add(outgoing)
                .and_then(|x| x.checked_add(c.outgoing_recipient_budget))
                .context("target exposure overflow")?;
            ensure!(source_exposure < c.thresholds[epoch - 1],
                "transition {epoch}: source bound fails: delta + |incoming union outgoing| = {source_exposure} must be < {}", c.thresholds[epoch - 1]);
            ensure!(target_exposure < c.thresholds[epoch],
                "transition {epoch}: target bound fails: delta + offline + outgoing budget = {target_exposure} must be < {}", c.thresholds[epoch]);
        }
        ensure!(
            c.populations[1] - c.offline_participants >= c.thresholds[1],
            "epoch 1 reconstruction requires at least t online participants"
        );
        Ok(())
    }
}
pub struct Samples {
    pub path: PathBuf,
    pub run: String,
    pub committee: [usize; 3],
    pub trial: usize,
    pub scenario: String,
}
impl Samples {
    pub fn add(
        &self,
        metric: &str,
        epoch: u64,
        t: usize,
        n: usize,
        ns: u64,
        data: Value,
    ) -> Result<()> {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(
            f,
            "{}",
            json!({"schema_version":2,"run":self.run,"committee":[self.committee[0],self.committee[1]],"protocol_fault_bound":self.committee[2],"trial":self.trial,"scenario":self.scenario,"metric":metric,"epoch":epoch,"t":t,"N":n,"duration_ns":if ns==0{None}else{Some(ns)},"evidence_kind":if ns==0{"invariant"}else{"measurement"},"data":data,"suite":SUITE,"execution_mode":"local_processes","chain_condition":"anvil_inclusion","status":"passed"})
        )?;
        Ok(())
    }
}
pub fn elapsed(t: Instant) -> u64 {
    t.elapsed().as_nanos() as u64
}
pub struct Cluster {
    pub cfg: NodeConfig,
    pub configs: BTreeMap<u64, PathBuf>,
    pub children: BTreeMap<u64, Child>,
    pub dir: PathBuf,
}
impl Drop for Cluster {
    fn drop(&mut self) {
        for child in self.children.values_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Cluster {
    fn new(dir: &Path, c: &Config, committee: [usize; 3], d: &Devnet) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let mut roles = vec![
            (8001, "owner".to_owned()),
            (9001, "archive".to_owned()),
            (9002, "archive".to_owned()),
        ];
        for id in 1..=committee[0] as u64 {
            roles.push((id, "dealer".into()))
        }
        for id in 1..=*c.populations.last().unwrap() as u64 {
            roles.push((1000 + id, "participant".into()))
        }
        let mut peers = Vec::new();
        let mut listeners = Vec::new();
        for (id, role) in roles {
            let listener = TcpListener::bind(("127.0.0.1", 0)).with_context(|| {
                format!(
                    "reserve port for {role} {id}; {} peer sockets already open",
                    listeners.len()
                )
            })?;
            peers.push(Peer {
                id,
                role,
                port: listener.local_addr()?.port(),
            });
            listeners.push(listener);
        }
        let tls = dir.join("pki");
        let mut ids = vec![0usize];
        ids.extend(peers.iter().map(|p| p.id as usize));
        crate::network::tls_material_ids(&tls, &ids)?;
        let cfg = NodeConfig {
            run: dir
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into(),
            id: 0,
            role: "runner".into(),
            port: 0,
            dir: dir.to_owned(),
            tls: tls.clone(),
            peers: peers.clone(),
            rpc: d.url.clone(),
            contract: d.verifier.clone(),
            n: committee[0],
            k: committee[1],
            f: committee[2],
            participant_corruption_budget: c.participant_corruption_budget,
            outgoing_recipient_budget: c.outgoing_recipient_budget,
            timeout_ms: c.timeout_ms,
        };
        let mut cluster = Self {
            cfg,
            configs: BTreeMap::new(),
            children: BTreeMap::new(),
            dir: dir.to_owned(),
        };
        for peer in peers {
            let mut config = cluster.cfg.clone();
            config.id = peer.id;
            config.role = peer.role.clone();
            config.port = peer.port;
            config.dir = dir.join(format!("{}-{}", peer.role, peer.id));
            fs::create_dir_all(&config.dir)?;
            let private_tls = config.dir.join("tls");
            fs::create_dir_all(&private_tls)?;
            fs::copy(tls.join("ca.der"), private_tls.join("ca.der"))?;
            for id in &ids {
                fs::copy(
                    tls.join(format!("{id}.cert")),
                    private_tls.join(format!("{id}.cert")),
                )?;
            }
            fs::copy(
                tls.join(format!("{}.key", peer.id)),
                private_tls.join(format!("{}.key", peer.id)),
            )?;
            fs::remove_file(tls.join(format!("{}.key", peer.id)))?;
            config.tls = private_tls;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config.dir, fs::Permissions::from_mode(0o700))?;
            let path = config.dir.join("node.json");
            fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
            cluster.configs.insert(peer.id, path);
        }
        drop(listeners);
        let ready = cluster
            .cfg
            .peers
            .iter()
            .filter(|p| p.role != "participant")
            .map(|p| p.id)
            .collect::<Vec<_>>();
        for id in ready {
            cluster.start(id)?;
        }
        Ok(cluster)
    }
    pub fn start(&mut self, id: u64) -> Result<()> {
        ensure!(!self.children.contains_key(&id), "process already running");
        let path = &self.configs[&id];
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.parent().unwrap().join("stderr.log"))?;
        let mut cmd = Command::new(std::env::current_exe()?);
        cmd.args(["e2e-node", "--config"])
            .arg(path)
            .stdout(Stdio::null())
            .stderr(log);
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let pid = child.id();
        self.children.insert(id, child);
        let _: bool = wait_call(&self.cfg, id, "ping", &())?;
        self.process_event("start", id, pid)?;
        Ok(())
    }
    fn process_event(&self, action: &str, id: u64, pid: u32) -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("process_events.jsonl"))?;
        writeln!(
            file,
            "{}",
            json!({"action":action,"id":id,"role":self.cfg.role(id)?,"pid":pid})
        )?;
        Ok(())
    }
    pub fn stop(&mut self, id: u64) -> Result<()> {
        if let Some(mut child) = self.children.remove(&id) {
            let pid = child.id();
            if let Ok(stats) = call_json(&self.cfg, id, "status", &()) {
                let mut f = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.dir.join("instance_metrics.jsonl"))?;
                writeln!(f, "{}", json!({"node":id,"stats":stats}))?;
            }
            child.kill()?;
            child.wait()?;
            self.process_event("stop", id, pid)?;
        }
        Ok(())
    }
}
pub fn parallel<A: Serialize + Sync, B: serde::de::DeserializeOwned + Send>(
    cfg: &NodeConfig,
    ids: &[u64],
    op: &str,
    a: &A,
) -> Result<Vec<B>> {
    // Bound control RPCs so participant growth does not create unbounded OS threads.
    let mut out = Vec::new();
    for batch in ids.chunks(16) {
        let result: Result<Vec<B>> = std::thread::scope(|scope| {
            let tasks = batch
                .iter()
                .map(|id| scope.spawn(move || call(cfg, *id, op, a)))
                .collect::<Vec<_>>();
            tasks
                .into_iter()
                .map(|h| h.join().expect("RPC thread"))
                .collect()
        });
        out.extend(result?);
    }
    Ok(out)
}
fn parallel_results<A: Serialize + Sync, B: serde::de::DeserializeOwned + Send>(
    cfg: &NodeConfig,
    ids: &[u64],
    op: &str,
    a: &A,
) -> Vec<(u64, Result<B>)> {
    let mut out = Vec::new();
    for batch in ids.chunks(16) {
        out.extend(std::thread::scope(|scope| {
            batch
                .iter()
                .map(|id| (*id, scope.spawn(move || call(cfg, *id, op, a))))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|(id, handle)| (id, handle.join().expect("RPC thread")))
                .collect::<Vec<_>>()
        }));
    }
    out
}

/// Probe every canonical participant with its own response deadline. The full
/// registry sweep can take longer than one deadline; local scheduling is timed
/// as part of liveness but never counts as a participant's failure to respond.
fn classify_liveness(
    cfg: &NodeConfig,
    nonce: u64,
    timeout_ms: u64,
) -> Result<(Vec<u64>, Vec<u64>)> {
    let eligible = active_participants(cfg)?;
    let ids = eligible.iter().map(|id| 1000 + id).collect::<Vec<_>>();
    let (online, offline) =
        super::liveness::classify(&ids, Duration::from_millis(timeout_ms), |id, remaining| {
            let mut probe = cfg.clone();
            probe.timeout_ms = remaining.as_millis().max(1) as u64;
            matches!(call::<_, bool>(&probe, id, "live", &nonce), Ok(true))
        });
    Ok((online, offline.into_iter().map(|id| id - 1000).collect()))
}

pub fn tx(
    d: &mut Devnet,
    sig: &str,
    args: Vec<Arg>,
    from: usize,
    value: u64,
    label: &str,
) -> Result<Value> {
    let r = d.transact(sig, args, from, value, label)?;
    ensure!(
        chain::hex_u64(&r["status"])? == 1,
        "transaction {label} reverted: {r}"
    );
    Ok(r)
}
fn deploy(d: &mut Devnet) -> Result<()> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("contract-out/E2EVess.sol/E2EVess.json");
    let artifact: Value = serde_json::from_slice(&fs::read(p)?)?;
    let rc = d.send(
        None,
        chain::unhex(
            artifact["bytecode"]["object"]
                .as_str()
                .context("contract bytecode")?,
        )?,
        0,
        0,
        "deploy-E2EVess",
    )?;
    ensure!(chain::hex_u64(&rc["status"])? == 1, "E2E deployment");
    d.verifier = rc["contractAddress"].as_str().context("address")?.into();
    let artifact: Value = serde_json::from_slice(&fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("contract-out/E2EPublication.sol/E2EPublication.json"),
    )?)?;
    let mut code = chain::unhex(
        artifact["bytecode"]["object"]
            .as_str()
            .context("publication bytecode")?,
    )?;
    code.extend(chain::address(&d.verifier)?);
    let rc = d.send(None, code, 0, 0, "deploy-E2EPublication")?;
    ensure!(
        chain::hex_u64(&rc["status"])? == 1,
        "publication store deployment"
    );
    let store = chain::address(
        rc["contractAddress"]
            .as_str()
            .context("publication address")?,
    )?;
    tx(
        d,
        "setPublicationStore(address)",
        vec![Arg::Word(store)],
        0,
        0,
        "bind-publication-store",
    )?;
    Ok(())
}
fn wa(n: u64) -> Arg {
    Arg::Word(word(n))
}
fn metas(c: &Cluster) -> Result<Vec<Meta>> {
    parallel(
        &c.cfg,
        &(1..=c.cfg.n as u64).collect::<Vec<_>>(),
        "meta",
        &(),
    )
}
fn reconstruct_checked(c: &Cluster, n: usize, public: &State, expected: Word) -> Result<Value> {
    let mut result = call_json(&c.cfg, 8001, "reconstruct", &(n, public))?;
    ensure!(
        result["secret_digest"] == hex::encode(expected),
        "original secret digest mismatch"
    );
    result["secret_matches_owner"] = json!(true);
    Ok(result)
}
fn join(
    c: &mut Cluster,
    d: &mut Devnet,
    old: usize,
    new: usize,
    fault_validation: bool,
) -> Result<()> {
    if new == old {
        return Ok(());
    }
    let started = Instant::now();
    let count = new - old;
    eprintln!(
        "Issuance: starting {count} participants (IDs {}..={new})",
        old + 1
    );
    for id in old + 1..=new {
        c.start(1000 + id as u64)?;
        let proof: RegistrationProof = call(&c.cfg, 1000 + id as u64, "registration_proof", &())?;
        tx(d, REGISTER_ABI, proof.args(), 0, 0, "register-participant")?;
        if (id - old).is_multiple_of(32) || id == new {
            eprintln!(
                "Issuance registration: {}/{count} ({:.1}s elapsed)",
                id - old,
                started.elapsed().as_secs_f64()
            );
        }
    }
    let ids = (old + 1..=new).map(|i| 1000 + i as u64).collect::<Vec<_>>();
    eprintln!("Issuance: collecting and verifying dealer partials for {count} participants");
    let completions: Vec<Completion> = parallel(&c.cfg, &ids, "enroll", &())?;
    eprintln!("Issuance: partials verified; confirming {count} activations on chain");
    for (index, completion) in completions.into_iter().enumerate() {
        let participant = 1000 + completion.activation.id;
        let pending = call_json(&c.cfg, participant, "status", &())?;
        ensure!(
            pending["has_share"] == false && pending["pending_enrollment"] == true,
            "pending enrollment retains only partials"
        );
        if fault_validation {
            let premature: Result<bool> = call(
                &c.cfg,
                participant,
                "complete_enrollment",
                &completion.activation.alpha,
            );
            ensure!(
                premature.is_err(),
                "pending activation cannot install a share"
            );
        }
        tx(
            d,
            ACTIVATE_ABI,
            completion.args(),
            0,
            0,
            "activate-participant",
        )?;
        let installed: bool = call(
            &c.cfg,
            participant,
            "complete_enrollment",
            &completion.activation.alpha,
        )?;
        ensure!(installed, "canonical issuance installation");
        if (index + 1).is_multiple_of(16) || index + 1 == count {
            eprintln!(
                "Issuance installed: {}/{count} ({:.1}s elapsed)",
                index + 1,
                started.elapsed().as_secs_f64()
            );
        }
        if fault_validation {
            let duplicate: bool = call(
                &c.cfg,
                participant,
                "complete_enrollment",
                &completion.activation.alpha,
            )?;
            ensure!(!duplicate, "issuance installation must be idempotent");
        }
    }
    Ok(())
}
fn generation(c: &Cluster, d: &mut Devnet, req: &Generation) -> Result<State> {
    tx(
        d,
        "openGeneration(uint256)",
        vec![wa(req.nonce)],
        0,
        0,
        "open-generation-round",
    )?;
    let ids = (1..=c.cfg.n as u64).collect::<Vec<_>>();
    let started = parallel_results::<_, bool>(&c.cfg, &ids, "generate", req);
    for (id, result) in &started {
        if let Err(error) = result {
            eprintln!(
                "Generation {} dealer {} did not start: {error:#}",
                req.nonce, id
            );
        }
    }
    ensure!(
        started
            .iter()
            .filter(|(_, result)| matches!(result, Ok(true)))
            .count()
            >= c.cfg.n - c.cfg.f,
        "generation start quorum"
    );
    let mut targets: BTreeMap<Word, Vec<State>> = BTreeMap::new();
    for (id, _) in started.into_iter().filter(|(_, result)| result.is_ok()) {
        if let Ok(s) = wait_call::<_, State>(&c.cfg, id, "target_state", &req.nonce) {
            targets.entry(s.id()).or_default().push(s);
        }
    }
    targets
        .into_values()
        .find(|states| states.len() >= c.cfg.n - c.cfg.f)
        .and_then(|mut states| states.pop())
        .context("target agreement quorum")
}
/// A failed attempt still owns private candidate material. A reservation that
/// reached the chain must be canonically aborted; a failed compare-and-set
/// leaves no chain Attempt and is abandoned locally without touching the log.
fn cleanup_failed_attempt(
    c: &Cluster,
    d: &mut Devnet,
    source: Word,
    nonce: u64,
    participants: &[u64],
) -> Result<()> {
    let published = publication(&c.cfg, nonce)?;
    ensure!(published.len() == 6, "failed-attempt publication status");
    let before = query_word(&c.cfg, "releaseRoot(bytes32)", &[Arg::Word(source)])?;
    let ids = (1..=c.cfg.n as u64).collect::<Vec<_>>();
    let mut cleanup_cfg = c.cfg.clone();
    cleanup_cfg.timeout_ms = cleanup_cfg
        .timeout_ms
        .saturating_mul(4)
        .saturating_add(10000);
    let cleaned = if published[5] == word(0) {
        parallel_results::<_, bool>(&cleanup_cfg, &ids, "abandon_candidate", &(source, nonce))
    } else {
        ensure!(
            published[3] == source && published[5] != word(3),
            "cannot clean up a committed or unrelated attempt"
        );
        if published[5] != word(4) {
            tx(
                d,
                "abortEpoch(uint256)",
                vec![wa(nonce)],
                0,
                0,
                "abort-failed-attempt",
            )?;
        }
        let results = parallel_results::<_, bool>(&cleanup_cfg, &ids, "abort", &nonce);
        // Offline participants retain only their source share. Reachable staged
        // participants must discard their candidate token after canonical abort.
        let participants = parallel_results::<_, bool>(&cleanup_cfg, participants, "abort", &nonce);
        ensure!(
            participants.iter().all(|(_, result)| result.is_ok()),
            "failed-attempt participant cleanup incomplete"
        );
        results
    };
    ensure!(
        cleaned.iter().filter(|(_, result)| result.is_ok()).count() >= c.cfg.n - c.cfg.f,
        "failed-attempt dealer cleanup quorum incomplete"
    );
    ensure!(
        query_word(&c.cfg, "releaseRoot(bytes32)", &[Arg::Word(source)])? == before,
        "cleanup must retain the release ledger"
    );
    Ok(())
}
fn prepare(
    c: &Cluster,
    d: &mut Devnet,
    nonce: u64,
    n: usize,
    offline: Vec<u64>,
) -> Result<(Plan, Certificate)> {
    let ids = (1..=c.cfg.n as u64).collect::<Vec<_>>();
    let keys = current_dealer_metas(&c.cfg)?;
    let prepared =
        parallel_results::<_, (Plan, Sig)>(&c.cfg, &ids, "reserve_intent", &(nonce, n, offline));
    let mut groups: BTreeMap<Vec<u8>, Vec<(u64, Plan, Sig)>> = BTreeMap::new();
    for (id, result) in prepared {
        if let Ok((plan, signature)) = result {
            if verify(keys[id as usize - 1].reservation, plan.digest, &signature) {
                groups
                    .entry(enc(&plan))
                    .or_default()
                    .push((id, plan, signature));
            }
        }
    }
    let prepared = groups
        .into_values()
        .find(|group| group.len() >= c.cfg.n - c.cfg.f)
        .context("reservation agreement quorum")?;
    let plan = prepared[0].1.clone();
    let mut sigs = Vec::new();
    for (id, _, s) in &prepared {
        sigs.extend(sig_words(*id, s))
    }
    tx(
        d,
        "reserve(bytes32,bytes32,uint256,uint256,uint256,bytes32,uint256[],uint256[])",
        vec![
            Arg::Word(plan.source.id),
            Arg::Word(plan.target.id),
            wa(nonce),
            wa(plan.target.params.t as u64),
            wa(n as u64),
            Arg::Word(plan.old_root),
            Arg::Words(plan.offline.iter().map(|i| word(*i)).collect()),
            Arg::Words(sigs),
        ],
        0,
        0,
        "reservation-CAS",
    )?;
    let signatures = parallel_results::<_, Sig>(&c.cfg, &ids, "certify", &plan)
        .into_iter()
        .filter_map(|(id, result)| result.ok().map(|s| (id, s)))
        .filter(|(id, s)| verify(keys[*id as usize - 1].reservation, plan.digest, s))
        .collect();
    let cert = Certificate {
        digest: plan.digest,
        signatures,
    };
    ensure!(
        certificate_ok(&cert, &keys, c.cfg.n - c.cfg.f),
        "durable reservation certificate quorum"
    );
    let released = parallel_results::<_, bool>(&c.cfg, &ids, "release", &cert);
    ensure!(
        released
            .iter()
            .filter(|(_, r)| matches!(r, Ok(true)))
            .count()
            >= c.cfg.n - c.cfg.f,
        "certified release quorum"
    );
    Ok((plan, cert))
}
fn publication_bundle(
    c: &Cluster,
    source: &State,
    target: &State,
    plan: &Plan,
    certificate: Certificate,
) -> Result<Bundle> {
    let mut records = Vec::new();
    let keys = current_dealer_metas(&c.cfg)?;
    for i in &plan.offline {
        let before = records.len();
        for j in 1..=c.cfg.n as u64 {
            let checked = (|| -> Result<Record> {
                let record: Record = call(&c.cfg, j, "issue", &(*i, plan.nonce, false))?;
                context(&record, &plan.source, &plan.target, plan.nonce, false)?;
                ensure!(
                    record.dealer() == j as usize
                        && record.id() == *i
                        && record.key_epoch() == keys[j as usize - 1].key_epoch,
                    "publication identity"
                );
                signed_record(&record, keys[j as usize - 1].pk)?;
                Ok(record)
            })();
            if let Ok(record) = checked {
                records.push(record);
            }
        }
        ensure!(
            records.len() - before >= c.cfg.n - c.cfg.f,
            "signed publication quorum"
        );
    }
    let manifest = Manifest {
        source: Header::from(source),
        target: Header::from(target),
        nonce: plan.nonce,
        offline: plan.offline.clone(),
        keys,
        record_ids: records
            .iter()
            .map(|r: &Record| (r.dealer() as u64, r.id(), r.hash()))
            .collect(),
        record_root: record_tree(&records, source, target).root(),
        reservation: plan.digest,
    };
    let b = Bundle {
        manifest,
        records,
        source: source.clone(),
        target: target.clone(),
        certificate,
    };
    b.validate()?;
    Ok(b)
}
fn publish(c: &Cluster, d: &mut Devnet, b: &Bundle, dir: &Path) -> Result<chain::FieldPublication> {
    let bytes = enc(b);
    let _: Vec<Word> = parallel(&c.cfg, &archives(&c.cfg), "put", b)?;
    let publication = chain::FieldPublication::new(b.manifest.record_root, &bytes)?;
    fs::create_dir_all(dir)?;
    fs::write(dir.join(format!("{}.bundle", b.manifest.nonce)), &bytes)?;
    let mut batches = Vec::new();
    let mut fragments = Vec::new();
    for (batch, blobs) in publication
        .blobs
        .chunks(chain::BLOBS_PER_TRANSACTION)
        .enumerate()
    {
        let offset = batch * chain::BLOBS_PER_TRANSACTION;
        let data = chain::calldata(
            "publish(uint256,bytes32,bytes32,bytes32[],uint256,uint256,bytes)",
            &[
                wa(b.manifest.nonce),
                Arg::Word(b.manifest.record_root),
                Arg::Word(b.manifest.id()),
                Arg::Words(b.manifest.target.roots.clone()),
                wa(bytes.len() as u64),
                wa(offset as u64),
                Arg::Bytes(
                    blobs
                        .iter()
                        .flat_map(|blob| blob.point_proofs[0].clone())
                        .collect(),
                ),
            ],
        );
        let rc = d.blobs_send(
            data,
            &blobs.iter().collect::<Vec<_>>(),
            "lifecycle-blob-publication",
        )?;
        ensure!(
            chain::hex_u64(&rc["status"])? == 1,
            "blob batch publication"
        );
        batches.push(
            json!({"offset":offset,"count":blobs.len(),"transaction_hash":rc["transactionHash"]}),
        );
        for (i, blob) in blobs.iter().enumerate() {
            let file = format!("{}.{}.blob", b.manifest.nonce, offset + i);
            fs::write(dir.join(&file), &blob.bytes)?;
            fragments.push(json!({"file":file,"versioned_hash":chain::hhex(&blob.versioned)}));
        }
    }
    fs::write(
        dir.join(format!("{}.publication.json", b.manifest.nonce)),
        serde_json::to_vec_pretty(&json!({"schema":1,"payload_bytes":bytes.len(),
            "root":chain::hhex(&b.manifest.record_root),"fragments":fragments,"batches":batches}))?,
    )?;
    Ok(publication)
}
fn rotate(c: &Cluster, d: &mut Devnet) -> Result<()> {
    for j in 1..=c.cfg.n as u64 {
        let m: Meta = call(&c.cfg, j, "rotate", &())?;
        let p = words(m.pk);
        let r = words(m.reservation);
        tx(
            d,
            "rotate(uint256,uint256,uint256,uint256,uint256,uint256)",
            vec![
                wa(j),
                wa(m.key_epoch),
                Arg::Word(p[0]),
                Arg::Word(p[1]),
                Arg::Word(r[0]),
                Arg::Word(r[1]),
            ],
            0,
            0,
            "rotate-record-and-reservation-key",
        )?;
    }
    Ok(())
}
/// Recover independent recipients concurrently, but apply each recipient's
/// missed transitions in canonical order. Write samples only on the runner
/// thread so JSONL append operations cannot interleave.
fn catchup_participants(
    c: &Cluster,
    history: &[(Bundle, chain::FieldPublication)],
    recipients: &[u64],
    concurrency: usize,
    samples: &Samples,
    population: usize,
) -> Result<()> {
    let next = AtomicUsize::new(0);
    let final_target = &history.last().context("missing catch-up history")?.0.target;
    let mut recovered = std::thread::scope(|scope| -> Result<Vec<_>> {
        let workers = (0..concurrency.min(recipients.len()))
            .map(|_| {
                let next = &next;
                scope.spawn(move || -> Result<Vec<_>> {
                    let mut completed = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&recipient) = recipients.get(index) else { break };
                        let start = Instant::now();
                        let mut steps = Vec::new();
                        for (bundle, _) in history {
                            let step = Instant::now();
                            let result: ReturnResult = call(&c.cfg, 1000 + recipient,
                                "recover", &bundle.manifest.id())
                                .with_context(|| format!("participant {recipient} catch-up epoch {}", bundle.target.epoch))?;
                            ensure!(result.ok && result.bad.is_empty() && result.localized == 0,
                                "participant {recipient}: unexpected catch-up failure or malformed record");
                            steps.push((elapsed(step), result));
                        }
                        let header: Header = call(&c.cfg, 1000 + recipient, "header", &())?;
                        let status = call_json(&c.cfg, 1000 + recipient, "status", &())?;
                        ensure!(header.id == final_target.id()
                            && header.epoch == final_target.epoch
                            && header.params.t == final_target.params.t
                            && status["has_share"] == true,
                            "participant {recipient}: catch-up did not install the final target share");
                        completed.push((recipient, elapsed(start), steps));
                    }
                    Ok(completed)
                })
            }).collect::<Vec<_>>();
        let mut all = Vec::new();
        for worker in workers {
            all.extend(
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("catch-up worker panicked"))??,
            );
        }
        Ok(all)
    })?;
    recovered.sort_by_key(|(recipient, _, _)| *recipient);
    let completed_epochs = history
        .iter()
        .map(|(b, _)| b.target.epoch)
        .collect::<Vec<_>>();
    for (recipient, total_ns, steps) in recovered {
        let records_read = steps.iter().map(|(_, result)| result.read).sum::<usize>();
        for ((bundle, _), (duration_ns, result)) in history.iter().zip(steps) {
            samples.add("offline_catchup", bundle.target.epoch, bundle.target.params.t,
                population, duration_ns,
                json!({"recipient":recipient,"records_read":result.read,"localized":result.localized,
                    "vector_fetches":result.vector_fetches,"bytes":result.bytes,
                    "dealers_running":c.cfg.n,"archive_replicas_running":archives(&c.cfg).len(),
                    "historical_key_epoch":bundle.manifest.keys[0].key_epoch,"nonce":bundle.manifest.nonce}))?;
        }
        samples.add(
            "participant_catchup",
            final_target.epoch,
            final_target.params.t,
            population,
            total_ns,
            json!({"recipient":recipient,"missed_epochs":history.len(),
                "records_read":records_read,"completed_epochs":completed_epochs,
                "target_epoch":final_target.epoch,"includes_final_state_verification":true}),
        )?;
    }
    Ok(())
}

fn trial(
    config: &Config,
    committee: [usize; 3],
    trial: usize,
    faults: bool,
    out: &Path,
) -> Result<()> {
    let dir = out.join(format!(
        "n{}-{}-trial{:03}",
        committee[0],
        if faults { "faults" } else { "baseline" },
        trial
    ));
    fs::create_dir_all(&dir)?;
    let samples = Samples {
        path: out.join("samples.jsonl"),
        run: dir.file_name().unwrap().to_string_lossy().into(),
        committee,
        trial,
        scenario: if faults {
            "integrated_faults"
        } else {
            "baseline"
        }
        .into(),
    };
    let cold = Instant::now();
    let mut d = Devnet::start_empty_with_accounts(
        &dir.join("chain"),
        committee[0]
            .checked_add(3)
            .context("Anvil account count overflow")?,
    )?;
    deploy(&mut d)?;
    let mut c = Cluster::new(&dir.join("nodes"), config, committee, &d)?;
    samples.add(
        "deployment_and_process_setup",
        0,
        config.thresholds[0],
        config.populations[0],
        elapsed(cold),
        json!({"contract":d.verifier,"anvil_pid":d.child.id()}),
    )?;
    let whole = Instant::now();
    let setup = Instant::now();
    let p = Params {
        n: committee[0],
        k: committee[1],
        f: committee[2],
        t: config.thresholds[0],
    };
    let meta = metas(&c)?;
    tx(
        &mut d,
        "configureGeneration(uint256,uint256,uint256,uint256)",
        vec![
            wa(p.n as u64),
            wa(p.k as u64),
            wa(p.f as u64),
            wa(config.generation_round_seconds),
        ],
        0,
        0,
        "configure-generation-broadcast",
    )?;
    tx(
        &mut d,
        "configureReleasePolicy(uint256,uint256)",
        vec![
            wa(config.participant_corruption_budget as u64),
            wa(config.outgoing_recipient_budget as u64),
        ],
        0,
        0,
        "configure-release-policy",
    )?;
    let owner_account = chain::address(&d.accounts[committee[0] + 2])?;
    tx(
        &mut d,
        "setGenerationOwner(address)",
        vec![Arg::Word(owner_account)],
        0,
        0,
        "configure-generation-owner",
    )?;
    for m in &meta {
        let pk = words(m.pk);
        let account = chain::address(&d.accounts[m.id as usize])?;
        tx(
            &mut d,
            "register(uint256,uint256,uint256,uint256,address)",
            vec![
                wa(m.id),
                wa(m.key_epoch),
                Arg::Word(pk[0]),
                Arg::Word(pk[1]),
                Arg::Word(account),
            ],
            0,
            0,
            "dealer-account",
        )?;
    }
    tx(
        &mut d,
        "openGeneration(uint256)",
        vec![wa(0)],
        0,
        0,
        "open-initial-generation",
    )?;
    let (mut source, secret_digest): (State, Word) = call(&c.cfg, 8001, "owner_init", &p)?;
    fs::write(
        dir.join("correctness_oracle.json"),
        serde_json::to_vec_pretty(
            &json!({"secret_pair_digest":hex::encode(secret_digest),"retains_secret":false}),
        )?,
    )?;
    let keys = meta
        .iter()
        .flat_map(|m| [words(m.pk), words(m.reservation)].concat())
        .collect();
    tx(
        &mut d,
        "bootstrap(bytes32,uint256,uint256,uint256,uint256,uint256,uint256[],bytes32[])",
        vec![
            Arg::Word(source.id()),
            wa(0),
            wa(p.t as u64),
            wa(p.n as u64),
            wa(p.k as u64),
            wa(p.f as u64),
            Arg::Words(keys),
            Arg::Words((1..=p.n).map(|j| source.root(j)).collect()),
        ],
        0,
        0,
        "bootstrap-state",
    )?;
    if faults {
        let _: bool = call(&c.cfg, 1, "set_fault", &"invalid_partial".to_owned())?;
    }
    join(&mut c, &mut d, 0, config.populations[0], faults)?;
    if faults {
        let _: bool = call(&c.cfg, 1, "set_fault", &String::new())?;
        samples.add(
            "issuance_invalid_partial_replaced",
            0,
            p.t,
            config.populations[0],
            0,
            json!({"dealer":1,"all_initial_participants_issued":true}),
        )?;
    }
    samples.add(
        "bootstrap_and_initial_issuance",
        0,
        p.t,
        config.populations[0],
        elapsed(setup),
        json!({"participants":config.populations[0]}),
    )?;
    let initial = reconstruct_checked(&c, config.populations[0], &source, secret_digest)?;
    samples.add(
        "initial_secret_check",
        0,
        p.t,
        config.populations[0],
        0,
        initial,
    )?;
    if faults {
        let _: bool = call(&c.cfg, 1001, "set_fault", &"invalid_share".to_owned())?;
        c.stop(1002)?;
        let checked = reconstruct_checked(&c, config.populations[0], &source, secret_digest)?;
        samples.add(
            "reconstruct_invalid_and_missing_share",
            0,
            p.t,
            config.populations[0],
            0,
            checked,
        )?;
        c.start(1002)?;
        let _: bool = call(&c.cfg, 1001, "set_fault", &String::new())?;
    }
    let mut previous_n = config.populations[0];
    let mut nonce = 1u64;
    let mut history: Vec<(Bundle, chain::FieldPublication)> = Vec::new();
    let ids = (1..=p.n as u64).collect::<Vec<_>>();
    let offline_recipients = (1..=config.offline_participants as u64).collect::<Vec<_>>();
    let lifecycle_result = (|| -> Result<()> {
        for epoch in 1..config.thresholds.len() {
            let t = config.thresholds[epoch];
            let n = config.populations[epoch];
            eprintln!(
                "E2E n={} trial={} faults={} epoch={} t={} N={}",
                p.n, trial, faults, epoch, t, n
            );
            let epoch_start = Instant::now();
            let start = Instant::now();
            join(&mut c, &mut d, previous_n, n, faults)?;
            samples.add(
                "growth_issuance",
                epoch as u64,
                t,
                n,
                elapsed(start),
                json!({"new_participants":n-previous_n,"source_t":source.params.t}),
            )?;
            previous_n = n;
            if faults && config.dealer_omission && epoch == 3 {
                c.stop(p.n as u64)?;
                samples.add(
                    "dealer_omission_started",
                    epoch as u64,
                    t,
                    n,
                    0,
                    json!({"dealer":p.n,"stays_offline_through_generation_and_finalization":true}),
                )?;
            }
            if epoch == 1 {
                for recipient in &offline_recipients {
                    c.stop(1000 + recipient)?;
                }
            }
            let start = Instant::now();
            let (mut online, offline) =
                classify_liveness(&c.cfg, nonce, config.liveness_timeout_ms)?;
            samples.add(
                "liveness",
                epoch as u64,
                t,
                n,
                elapsed(start),
                json!({"offline":offline,"eligible":n,"probed":online.len()+offline.len(),"deadline_ms":config.liveness_timeout_ms,"deadline_scope":"per_participant","probe_concurrency":super::liveness::WORKERS,"classification":"full_registry_per_participant_deadline_probe"}),
            )?;
            eprintln!(
                "Liveness: {}/{} online, {} offline; {}ms response deadline per participant ({:.2}s total)",
                online.len(), n, offline.len(), config.liveness_timeout_ms, start.elapsed().as_secs_f64()
            );
            if !faults {
                // Validate the measured set, never supply it to the classifier.
                let expected_offline = if epoch <= 2 {
                    offline_recipients.clone()
                } else {
                    vec![]
                };
                ensure!(
                    offline == expected_offline,
                    "normal lifecycle liveness mismatch: expected offline {:?}, measured {:?}; all {} participants probed with individual {}ms deadlines",
                    expected_offline, offline, online.len() + offline.len(), config.liveness_timeout_ms
                );
            }
            let repeats = if faults && epoch == 1 { 2 } else { 1 };
            for attempt in 0..repeats {
                let abort = faults && epoch == 1 && attempt == 0;
                let fault = if faults && !abort && epoch == 1 {
                    "inconsistent"
                } else if faults && epoch == 2 {
                    "bad_plaintext"
                } else if faults && epoch == 3 && !config.dealer_omission {
                    "direct_inconsistent"
                } else {
                    ""
                };
                if faults {
                    let _: bool = call(&c.cfg, 1, "set_fault", &fault.to_owned())?;
                }
                let refresh = Instant::now();
                let start = Instant::now();
                let generated = generation(
                    &c,
                    &mut d,
                    &Generation {
                        nonce,
                        t,
                        eligible: n,
                        offline: offline.clone(),
                        bad_share: faults && epoch == 1,
                    },
                );
                let target =
                    match generated {
                        Ok(target) => target,
                        Err(error) => {
                            let cleanup =
                                cleanup_failed_attempt(&c, &mut d, source.id(), nonce, &online);
                            return Err(error.context(match cleanup {
                        Ok(()) => "generation failed; candidate erased and release ledger retained"
                            .to_owned(),
                        Err(e) => format!("generation failed; cleanup also failed: {e:#}"),
                    }));
                        }
                    };
                samples.add(
                    "generation",
                    epoch as u64,
                    t,
                    n,
                    elapsed(start),
                    json!({"nonce":nonce,"aborted_attempt":abort}),
                )?;
                let start = Instant::now();
                if faults {
                    let forbidden: Result<Record> = call(&c.cfg, 1, "issue", &(1u64, nonce, false));
                    ensure!(forbidden.is_err(), "release before certificate must reject");
                }
                let (mut plan, mut cert) = match prepare(&c, &mut d, nonce, n, offline.clone()) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let cleanup =
                            cleanup_failed_attempt(&c, &mut d, source.id(), nonce, &online);
                        return Err(error.context(match cleanup {
                            Ok(()) => {
                                "reservation failed; candidate erased and release ledger retained"
                                    .to_owned()
                            }
                            Err(e) => format!("reservation failed; cleanup also failed: {e:#}"),
                        }));
                    }
                };
                if faults {
                    let mut wrong = plan.clone();
                    wrong.digest[0] ^= 1;
                    let rejected: Result<Sig> = call(&c.cfg, 1, "certify", &wrong);
                    ensure!(rejected.is_err(), "mismatched reservation must reject");
                    samples.add(
                        "authorization_negative_checks",
                        epoch as u64,
                        t,
                        n,
                        0,
                        json!({"no_token_before_certificate":true,"exact_tuple_binding":true}),
                    )?;
                }

                samples.add(
                    "reservation_and_certificate",
                    epoch as u64,
                    t,
                    n,
                    elapsed(start),
                    json!({"nonce":nonce,"digest":hex::encode(plan.digest)}),
                )?;
                let start = Instant::now();
                if faults && epoch == 3 {
                    let _: bool = call(&c.cfg, 1002, "set_fault", &"withhold_ack".to_owned())?;
                }
                let stages = parallel_results::<_, Ack>(&c.cfg, &online, "stage", &plan);
                let reclassified = stages
                    .iter()
                    .filter_map(|(id, r)| r.is_err().then_some(*id - 1000))
                    .collect::<Vec<_>>();
                ensure!(
                    faults || reclassified.is_empty(),
                    "unexpected online participant failure in normal lifecycle"
                );
                if !reclassified.is_empty() {
                    let mut extended = plan.offline.clone();
                    extended.extend(&reclassified);
                    extended.sort_unstable();
                    extended.dedup();
                    match prepare(&c, &mut d, nonce, n, extended) {
                        Ok((new_plan, new_cert)) => {
                            plan = new_plan;
                            cert = new_cert;
                        }
                        Err(error) => {
                            tx(
                                &mut d,
                                "abortEpoch(uint256)",
                                vec![wa(nonce)],
                                0,
                                0,
                                "abort-reclassification-budget",
                            )?;
                            let _: Vec<bool> = parallel(&c.cfg, &ids, "abort", &nonce)?;
                            let _ = parallel_results::<_, bool>(&c.cfg, &online, "abort", &nonce);
                            return Err(error.context("reclassification guard failed; candidate aborted with reservations retained"));
                        }
                    }
                    online.retain(|id| !reclassified.contains(&(*id - 1000)));
                    samples.add("online_reclassified_public", epoch as u64, t, n, 0,
                    json!({"nonce":nonce,"recipients":reclassified,"reservation":hex::encode(plan.digest),"same_candidate":true}))?;
                }
                samples.add(
                    "direct_delivery_stage",
                    epoch as u64,
                    t,
                    n,
                    elapsed(start),
                    json!({"nonce":nonce,"online":online.len()}),
                )?;
                let start = Instant::now();
                if faults && epoch == 3 {
                    let _: bool = call(&c.cfg, 1, "set_fault", &"bad_pop".to_owned())?;
                }
                let bundle = publication_bundle(&c, &source, &target, &plan, cert)?;
                let blob = publish(&c, &mut d, &bundle, &dir.join("public"))?;
                samples.add("archive_blob_publication",epoch as u64,t,n,elapsed(start),json!({"nonce":nonce,"records":bundle.records.len(),"payload_bytes":enc(&bundle).len(),"physical_blob_bytes":blob.physical_bytes(),"blob_count":blob.blobs.len(),"publication_transactions":blob.blobs.len().div_ceil(chain::BLOBS_PER_TRANSACTION),"metadata":hex::encode(bundle.manifest.id())}))?;
                if faults {
                    let premature: Result<bool> = call(&c.cfg, 1, "install", &bundle.manifest.id());
                    ensure!(
                        premature.is_err(),
                        "apply before canonical commit must reject"
                    );
                }
                if abort {
                    tx(
                        &mut d,
                        "abortEpoch(uint256)",
                        vec![wa(nonce)],
                        0,
                        0,
                        "abort-after-publication",
                    )?;
                    let _: Vec<bool> = parallel(&c.cfg, &ids, "abort", &nonce)?;
                    let _: Vec<bool> = parallel(&c.cfg, &online, "abort", &nonce)?;
                    samples.add("published_attempt_abort",epoch as u64,t,n,elapsed(refresh),json!({"nonce":nonce,"reservation_retained":query_word(&c.cfg,"releaseRoot(bytes32)",&[Arg::Word(source.id())])?==plan.next_root}))?;
                    nonce += 1;
                    continue;
                }
                if faults && epoch == 1 {
                    let start = Instant::now();
                    c.stop(2)?;
                    c.stop(1002)?;
                    c.start(2)?;
                    c.start(1002)?;
                    samples.add(
                        "crash_restart_before_commit",
                        epoch as u64,
                        t,
                        n,
                        elapsed(start),
                        json!({"dealer":2,"participant":2}),
                    )?;
                }
                let start = Instant::now();
                let keys = current_dealer_metas(&c.cfg)?;
                let votes =
                    parallel_results::<_, Sig>(&c.cfg, &ids, "commit_vote", &bundle.manifest.id())
                        .into_iter()
                        .filter_map(|(id, result)| result.ok().map(|s| (id, s)))
                        .filter(|(id, s)| {
                            verify(
                                keys[*id as usize - 1].pk,
                                bundle.manifest.commit_message(),
                                s,
                            )
                        })
                        .collect::<Vec<_>>();
                ensure!(votes.len() >= p.n - p.f, "valid finalization vote quorum");
                let sigs = votes
                    .into_iter()
                    .flat_map(|(id, s)| sig_words(id, &s))
                    .collect();
                tx(
                    &mut d,
                    "commitEpoch(uint256,uint256[])",
                    vec![wa(nonce), Arg::Words(sigs)],
                    0,
                    0,
                    "canonical-epoch-commit",
                )?;
                let installs =
                    parallel_results::<_, bool>(&c.cfg, &ids, "install", &bundle.manifest.id());
                ensure!(
                    installs
                        .iter()
                        .filter(|(_, result)| matches!(result, Ok(true)))
                        .count()
                        >= p.n - p.f,
                    "dealer target installation quorum"
                );
                let _: Vec<bool> = parallel(&c.cfg, &online, "install", &bundle.manifest.id())?;
                if faults {
                    let duplicate: bool =
                        call(&c.cfg, online[0], "install", &bundle.manifest.id())?;
                    ensure!(!duplicate, "duplicate apply must be idempotent");
                }
                for id in &reclassified {
                    let _: bool = call(&c.cfg, 1000 + id, "set_fault", &String::new())?;
                    let result: ReturnResult =
                        call(&c.cfg, 1000 + id, "recover", &bundle.manifest.id())?;
                    ensure!(result.ok, "reclassified recipient recovery");
                    if !result.bad.is_empty() {
                        dispute::execute(&c, &mut d, &bundle, blob.anchor(), &result, &samples, n)?;
                    }
                }
                samples.add(
                    "commit_and_apply",
                    epoch as u64,
                    t,
                    n,
                    elapsed(start),
                    json!({"nonce":nonce,"exactly_once":true}),
                )?;
                samples.add("refresh",epoch as u64,t,n,elapsed(refresh),json!({"nonce":nonce,"includes_growth_issuance":false,"source_t":source.params.t,"offline":offline.len()}))?;
                history.push((bundle, blob));
                source = target;
                nonce += 1;
            }
            if epoch == 1 {
                let start = Instant::now();
                rotate(&c, &mut d)?;
                samples.add(
                    "authentication_key_rotation",
                    epoch as u64,
                    t,
                    n,
                    elapsed(start),
                    json!({"dealers":p.n}),
                )?;
            }
            if epoch == 2 && !faults {
                let start = Instant::now();
                for recipient in &offline_recipients {
                    c.start(1000 + recipient)?;
                }
                let concurrency = config.catchup_concurrency.min(offline_recipients.len());
                catchup_participants(&c, &history, &offline_recipients, concurrency, &samples, n)?;
                samples.add("offline_return_and_catchup", epoch as u64, t, n, elapsed(start),
                    json!({"missed_epochs":history.len(),"participant_count":offline_recipients.len(),
                        "participants":offline_recipients,"concurrency":concurrency,
                        "includes_process_restart":true}))?;
            }
            if epoch == 2 && faults {
                let start = Instant::now();
                c.start(1001)?;
                let first = &history[0].0;
                if faults {
                    let hidden = (0..first.records.len())
                        .filter(|i| *i == 0 || *i >= p.k)
                        .collect::<Vec<_>>();
                    let _: Vec<bool> = parallel(
                        &c.cfg,
                        &archives(&c.cfg),
                        "hide",
                        &(first.manifest.id(), hidden),
                    )?;
                    let result: ReturnResult = call(&c.cfg, 1001, "recover", &first.manifest.id())?;
                    ensure!(!result.ok, "k-1 recovery must not succeed");
                    dispute::availability(&c, &mut d, first, p.k, &samples, n, true)?;
                    samples.add(
                        "insufficient_records_rejected",
                        epoch as u64,
                        t,
                        n,
                        elapsed(start),
                        json!({"valid_available":p.k-1,"read":result.read}),
                    )?;
                    let _: Vec<bool> = parallel(
                        &c.cfg,
                        &archives(&c.cfg),
                        "hide",
                        &(first.manifest.id(), Vec::<usize>::new()),
                    )?;
                }
                if faults {
                    for id in &ids {
                        c.stop(*id)?;
                    }
                    c.stop(9001)?;
                }
                for (bundle, blob) in &history {
                    let ret = Instant::now();
                    let result: ReturnResult =
                        call(&c.cfg, 1001, "recover", &bundle.manifest.id())?;
                    ensure!(result.ok, "offline catch-up");
                    ensure!(
                        faults || (result.bad.is_empty() && result.localized == 0),
                        "unexpected malformed record in normal lifecycle"
                    );
                    samples.add("offline_catchup",bundle.target.epoch,bundle.target.params.t,n,elapsed(ret),json!({"records_read":result.read,"localized":result.localized,"vector_fetches":result.vector_fetches,"bytes":result.bytes,"dealers_running":ids.iter().filter(|id|c.children.contains_key(id)).count(),"archive_replicas_running":archives(&c.cfg).iter().filter(|id|c.children.contains_key(id)).count(),"historical_key_epoch":bundle.manifest.keys[0].key_epoch,"nonce":bundle.manifest.nonce}))?;
                    if !result.bad.is_empty() {
                        for id in &ids {
                            c.start(*id)?;
                        }
                        dispute::execute(&c, &mut d, bundle, blob.anchor(), &result, &samples, n)?;
                        for id in &ids {
                            c.stop(*id)?;
                        }
                    }
                }
                if faults {
                    for id in &ids {
                        c.start(*id)?;
                    }
                    c.start(9001)?;
                }
                samples.add(
                    if faults {
                        "offline_maintenance_window"
                    } else {
                        "offline_return_and_catchup"
                    },
                    epoch as u64,
                    t,
                    n,
                    elapsed(start),
                    json!({"missed_epochs":2}),
                )?;
            }
            let recon = Instant::now();
            let verified = reconstruct_checked(&c, n, &source, secret_digest)?;
            samples.add("reconstruct", epoch as u64, t, n, elapsed(recon), verified)?;
            samples.add(
                "epoch_with_growth",
                epoch as u64,
                t,
                n,
                elapsed(epoch_start),
                json!({"includes_maintenance_and_disputes":faults,"includes_offline_catchup":epoch==2,"offline":offline.len()}),
            )?;
        }
        if faults {
            let start = Instant::now();
            let id = *config.populations.last().unwrap() as u64;
            let _: bool = call(&c.cfg, 1000 + id, "prepare_recovery", &())?;
            tx(
                &mut d,
                "beginRecovery(uint256)",
                vec![wa(id)],
                0,
                0,
                "authorized-reissuance",
            )?;
            let completion: Completion = call(&c.cfg, 1000 + id, "enroll", &())?;
            tx(
                &mut d,
                ACTIVATE_ABI,
                completion.args(),
                0,
                0,
                "reissuance-activation",
            )?;
            let installed: bool = call(
                &c.cfg,
                1000 + id,
                "complete_enrollment",
                &completion.activation.alpha,
            )?;
            ensure!(installed, "current-epoch reissuance installation");
            samples.add(
                "authorized_current_epoch_reissuance",
                source.epoch,
                source.params.t,
                previous_n,
                elapsed(start),
                json!({"recipient":id}),
            )?;
        }
        let recon = Instant::now();
        let verified = reconstruct_checked(&c, previous_n, &source, secret_digest)?;
        samples.add(
            "final_reconstruct",
            source.epoch,
            source.params.t,
            previous_n,
            elapsed(recon),
            verified,
        )?;
        samples.add("lifecycle",source.epoch,source.params.t,previous_n,elapsed(whole),json!({"initial_N":config.populations[0],"population_schedule":config.populations,"threshold_schedule":config.thresholds,"committed_transitions":history.len(),"includes_bootstrap_and_issuance":true,"excludes_chain_deployment":true,"same_suite_contract":true}))?;
        let mut status = Vec::new();
        for peer in &c.cfg.peers {
            if c.children.contains_key(&peer.id) {
                let v: Value = call_json(&c.cfg, peer.id, "status", &())?;
                status.push(json!({"id":peer.id,"role":peer.role,"stats":v}));
            }
        }
        fs::write(
            dir.join("node_metrics.json"),
            serde_json::to_vec_pretty(&status)?,
        )?;
        fs::write(
            dir.join("completion.json"),
            serde_json::to_vec_pretty(
                &json!({"passed":true,"suite":SUITE,"contract":d.verifier,"epochs":history.len(),"original_secret_reconstructed":true,"faults":faults}),
            )?,
        )?;
        Ok(())
    })();
    if let Err(error) = lifecycle_result {
        // The attempt may have failed after certification/publication, or after
        // the commit transaction succeeded but local application failed. Never
        // turn the latter into an abort of an already canonical target.
        let publication_state = publication(&c.cfg, nonce);
        if publication_state
            .as_ref()
            .is_ok_and(|p| p.len() == 6 && p[5] == word(3))
        {
            return Err(
                error.context("lifecycle failed after canonical commit; committed state retained")
            );
        }
        if let Err(status_error) = publication_state {
            return Err(error.context(format!(
                "lifecycle failed; canonical attempt lookup prevents cleanup: {status_error:#}"
            )));
        }
        let participants = c
            .children
            .keys()
            .copied()
            .filter(|id| matches!(c.cfg.role(*id), Ok("participant")))
            .collect::<Vec<_>>();
        let cleanup = cleanup_failed_attempt(&c, &mut d, source.id(), nonce, &participants);
        return Err(error.context(match cleanup {
            Ok(()) => "lifecycle failed; uncommitted candidate erased and release ledger retained"
                .to_owned(),
            Err(cleanup_error) => {
                format!("lifecycle failed; cleanup also failed: {cleanup_error:#}")
            }
        }));
    }
    Ok(())
}
pub fn run(config: &Path, out: &Path) -> Result<()> {
    let c = Config::load(config)?;
    ensure!(!out.exists(), "output exists; choose a new directory");
    let resources = super::resources::prepare_file_limit(&c)?;
    fs::create_dir_all(out)?;
    fs::write(
        out.join("resource_limits.json"),
        serde_json::to_vec_pretty(&resources)?,
    )?;
    fs::copy(config, out.join("config.toml"))?;
    let total = Instant::now();
    record_tool_versions(out)?;
    let protocol_fault_bounds = c
        .committees
        .iter()
        .map(|committee| {
            let [n, k, f] = committee_parameters(*committee)?;
            Ok(json!({"n_D":n,"k_D":k,"f_D":f}))
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest = json!({"suite":SUITE,"chain":"Anvil Prague","execution_gas_policy":chain::E2E_GAS_POLICY,"chain_condition":"inclusion; no consensus finality","network":"localhost mTLS 1.3, fresh connections","implementation":if c.fault_scenarios { "main-lifecycle-v2-fault-validation" } else { "main-lifecycle-v2-normal" },"workload":if c.fault_scenarios { "explicit_fault_validation" } else { "normal_lifecycle_with_participant_catchup" },"fault_injection_enabled":c.fault_scenarios,"protocol_fault_bounds":protocol_fault_bounds,"source_snapshot":false,"publication_encoding":"field-root-ordered-blobs-v1","max_blobs_per_transaction":chain::BLOBS_PER_TRANSACTION,"executable_keccak256":hex::encode(keccak(&fs::read(std::env::current_exe()?)?)),"generation_broadcast":"Anvil immutable public transcript; costs included","policy":{"delta":c.participant_corruption_budget,"outgoing_recipient_budget":c.outgoing_recipient_budget},"catchup_timing":{"participant":"sequential recover calls and final state check; excludes worker queue and restart","group":"process restart through all recipient recoveries and sample persistence"},"participants":"one OS process per participant; growing registry","rust":Command::new("rustc").arg("--version").output().ok().map(|x|String::from_utf8_lossy(&x.stdout).to_string()),"cpu":fs::read_to_string("/proc/cpuinfo").unwrap_or_default(),"config":c});
    fs::write(
        out.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    for committee in &c.committees {
        let parameters = committee_parameters(*committee)?;
        for trial_id in 0..c.repeats {
            if let Err(e) = trial(&c, parameters, trial_id, false, out) {
                fs::write(
                    out.join("failure.json"),
                    serde_json::to_vec_pretty(
                        &json!({"committee":committee,"trial":trial_id,"error":format!("{e:#}")}),
                    )?,
                )?;
                return Err(e);
            }
        }
        if c.fault_scenarios {
            if let Err(e) = trial(&c, parameters, 0, true, out) {
                fs::write(
                    out.join("failure.json"),
                    serde_json::to_vec_pretty(
                        &json!({"committee":committee,"trial":0,"scenario":"integrated_faults","error":format!("{e:#}")}),
                    )?,
                )?;
                return Err(e);
            }
        }
    }
    fs::write(
        out.join("completion.json"),
        serde_json::to_vec_pretty(
            &json!({"completed":true,"elapsed_seconds":total.elapsed().as_secs_f64(),"baseline_trials":c.repeats*c.committees.len(),"fault_trials":if c.fault_scenarios{c.committees.len()}else{0}}),
        )?,
    )?;
    super::report::write(out, &out.join("e2e_result.tex"))?;
    Ok(())
}

fn record_tool_versions(out: &Path) -> Result<()> {
    let versions = ["rustc", "cargo", "anvil", "forge"]
        .iter()
        .map(|tool| {
            let text = Command::new(tool)
                .arg("--version")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            ((*tool).to_owned(), text)
        })
        .collect::<BTreeMap<_, _>>();
    fs::write(
        out.join("tool_versions.json"),
        serde_json::to_vec_pretty(&versions)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn explicit_fault_bounds_are_preserved_and_validated() {
        assert_eq!(committee_parameters([4, 2, 0]).unwrap(), [4, 2, 0]);
        assert_eq!(committee_parameters([7, 3, 1]).unwrap(), [7, 3, 1]);
        for n in 1..=7 {
            for k in 1..=n {
                for f in 0..=n {
                    let result = committee_parameters([n, k, f]);
                    assert_eq!(result.is_ok(), f < k && 2 * f + k <= n);
                    if let Ok(parameters) = result {
                        assert_eq!(parameters, [n, k, f]);
                    }
                }
            }
        }
        for invalid in [[0, 0, 0], [4, 0, 0], [4, 5, 0], [4, 2, usize::MAX]] {
            assert!(committee_parameters(invalid).is_err());
        }
    }

    #[test]
    fn normal_profile_has_explicit_bounds_and_no_faults() {
        let config = Config::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("configs/e2e-conformance.toml"),
        )
        .unwrap();
        for committee in &config.committees {
            assert_eq!(committee_parameters(*committee).unwrap(), *committee);
        }
        assert!(!config.fault_scenarios && !config.dealer_omission);
    }

    #[test]
    fn committee_input_requires_an_explicit_fault_bound() {
        let raw = include_str!("../../configs/e2e-smoke.toml");
        let config: Config = toml::from_str(raw).unwrap();
        assert_eq!(config.committees, vec![[4, 2, 1]]);
        assert!(toml::from_str::<Config>(&raw.replace("[4, 2, 1]", "[4, 2]")).is_err());
    }

    #[test]
    fn legacy_profiles_keep_one_offline_participant() {
        let config: Config = toml::from_str(include_str!("../../configs/e2e-smoke.toml")).unwrap();
        config.validate().unwrap();
        assert_eq!(config.offline_participants, 1);
        assert_eq!(config.participant_corruption_budget, 1);
        assert_eq!(config.outgoing_recipient_budget, 2);
    }

    #[test]
    fn repeated_recipients_are_a_union_and_bounds_are_strict() {
        let mut config: Config =
            toml::from_str(include_str!("../../configs/e2e-multi-catchup-smoke.toml")).unwrap();
        // At the middle transition the same 16 IDs occur in both sets.
        // The final transition has no outgoing recipients but still charges
        // the previous incoming set at its source.
        config.thresholds = vec![18, 34, 34, 18];
        config.validate().unwrap();
        config.thresholds[0] = 17;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("source bound"));
        config.thresholds[0] = 18;
        config.thresholds[1] = 33;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("target bound"));
        config.thresholds[1] = 34;
        config.outgoing_recipient_budget = 15;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("outgoing recipient budget"));
        config.outgoing_recipient_budget = 16;
        config.participant_corruption_budget = usize::MAX;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("overflow"));
    }

    #[test]
    fn catchup_profile_requires_available_reconstruction_and_positive_workers() {
        let mut config: Config =
            toml::from_str(include_str!("../../configs/e2e-multi-catchup-smoke.toml")).unwrap();
        config.validate().unwrap();
        config.thresholds[1] = 49;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("online participants"));
        config.thresholds[1] = 48;
        config.catchup_concurrency = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("catchup_concurrency"));
        config.catchup_concurrency = 16;
        config.offline_participants = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("nonempty subset"));
    }
}
