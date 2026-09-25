//! Independent dealer processes with mTLS and synchronous signed echo/ready rounds.
use crate::{crypto::*, ledger::*, protocol::*};
use anyhow::{ensure, Context, Result};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub id: usize,
    pub params: Params,
    pub seed: u64,
    pub signing_sk: Fr,
    pub reservation_sk: Fr,
    pub port: u16,
    pub peers: Vec<u16>,
    pub dir: PathBuf,
    pub tls: PathBuf,
    pub source_row: Vec<Pair>,
    pub source_vectors: Vec<Vec<Point>>,
    pub source_digest: Hash,
    pub source_epoch: u64,
    pub authority: Point,
    pub signing_pks: Vec<Point>,
    pub reservation_pks: Vec<Point>,
    pub faulty: usize,
    pub fault: String,
    pub delay_ms: u64,
}
pub fn signing_key(seed: u64, id: usize, reservation: bool) -> Fr {
    nonzero(&mut rng(
        seed,
        if reservation {
            "reservation-key"
        } else {
            "record-key"
        },
        id as u64,
    ))
}
pub fn tls_material(dir: &Path, n: usize) -> Result<()> {
    tls_material_ids(dir, &(0..=n).collect::<Vec<_>>())
}
pub fn tls_material_ids(dir: &Path, ids: &[usize]) -> Result<()> {
    fs::create_dir_all(dir)?;
    let mut params = CertificateParams::new(vec!["vess-ca".into()])?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate()?)?;
    fs::write(dir.join("ca.der"), ca.der())?;
    for &id in ids {
        let key = KeyPair::generate()?;
        let mut p = CertificateParams::new(vec!["localhost".into()])?;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let cert = p.signed_by(&key, &ca)?;
        fs::write(dir.join(format!("{id}.cert")), cert.der())?;
        fs::write(dir.join(format!("{id}.key")), key.serialize_der())?;
    }
    Ok(())
}
fn credentials(
    dir: &Path,
    id: usize,
) -> Result<(
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    RootCertStore,
)> {
    let cert = CertificateDer::from(fs::read(dir.join(format!("{id}.cert")))?);
    let key = PrivatePkcs8KeyDer::from(fs::read(dir.join(format!("{id}.key")))?);
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(fs::read(dir.join("ca.der"))?))?;
    Ok((vec![cert], key.into(), roots))
}
pub(crate) fn client_config(dir: &Path, id: usize) -> Result<Arc<ClientConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key, roots) = credentials(dir, id)?;
    let mut c = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(cert, key)?;
    c.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(c))
}
pub(crate) fn server_config(dir: &Path, id: usize) -> Result<Arc<ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key, roots) = credentials(dir, id)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    Ok(Arc::new(
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert, key)?,
    ))
}
pub(crate) fn write_frame<S: Write>(s: &mut S, v: &[u8]) -> Result<()> {
    s.write_all(&(v.len() as u64).to_be_bytes())?;
    s.write_all(v)?;
    s.flush()?;
    Ok(())
}
pub(crate) fn read_frame<S: Read>(s: &mut S) -> Result<Vec<u8>> {
    let mut len = [0; 8];
    s.read_exact(&mut len)?;
    let len = u64::from_be_bytes(len) as usize;
    ensure!(len < 256 * 1024 * 1024, "frame limit");
    let mut v = vec![0; len];
    s.read_exact(&mut v)?;
    Ok(v)
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    pub sender: usize,
    pub payload: T,
    pub sig: Signature,
}
fn signed<T: Serialize>(cfg: &NodeConfig, payload: T) -> Signed<T> {
    let mut r = rand::rngs::OsRng;
    let sig = sign(cfg.signing_sk, &enc(&payload), &mut r);
    Signed {
        sender: cfg.id,
        payload,
        sig,
    }
}
fn checked<T: Serialize>(cfg: &NodeConfig, v: &Signed<T>, id: usize) -> bool {
    v.sender == id && verify_sig(cfg.signing_pks[id - 1], &enc(&v.payload), &v.sig)
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub nonce: u64,
    pub commitments: Vec<Vec<Point>>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Echo {
    pub nonce: u64,
    pub proposals: BTreeMap<usize, Signed<Proposal>>,
    pub complaints: BTreeSet<usize>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Ready {
    pub nonce: u64,
    pub qualified: Vec<usize>,
    pub transcript: Hash,
}
#[derive(Clone, Serialize, Deserialize)]
pub enum Rpc {
    Enroll {
        recipient: u64,
        pk: Point,
        authorization: Signature,
    },
    Heartbeat {
        recipient: u64,
        nonce: u64,
        proof: Signature,
    },
    Answer {
        complaint: Signed<Echo>,
    },
    Ping,
    Prepare {
        nonce: u64,
        target_t: usize,
    },
    GetProposal,
    GetShare {
        recipient: usize,
        nonce: u64,
        proof: Signature,
    },
    Collect,
    Echo,
    Resolve,
    GetReady,
    Finish,
    Vector,
    Reserve {
        request: Request,
        policy: Policy,
        chain: Option<(String, String, Hash)>,
    },
    Release {
        entry: Entry,
        certificate: Certificate,
    },
    Commit {
        nonce: u64,
        target: Hash,
    },
    Issue {
        recipient: u64,
        pk: Point,
        mode: Mode,
        source: Hash,
        target: Hash,
    },
    Stats,
    Shutdown,
    Fetch {
        file: String,
    },
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    pub bytes: Vec<u8>,
    pub error: String,
}
impl Reply {
    fn value<T: Serialize>(v: &T) -> Self {
        Self {
            ok: true,
            bytes: enc(v),
            error: String::new(),
        }
    }
}
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct NodeStats {
    pub sent: u64,
    pub received: u64,
    pub transport_sent: u64,
    pub transport_received: u64,
    pub requests: u64,
    pub complaints: usize,
    pub qualified: usize,
    pub compute_ns: u64,
    pub peak_rss_bytes: u64,
    pub source_erased: bool,
    pub cpu_user_ns: u64,
    pub cpu_system_ns: u64,
    pub tls_handshakes: u64,
    pub tls_handshake_ns: u64,
}
pub struct NodeState {
    cfg: NodeConfig,
    enrolled: BTreeMap<u64, Point>,
    release_target: Option<Hash>,
    contribution: Option<Contribution>,
    nonce: u64,
    target_t: usize,
    proposals: BTreeMap<usize, Signed<Proposal>>,
    shares: BTreeMap<usize, Vec<Pair>>,
    echo: Option<Signed<Echo>>,
    ready: Option<Signed<Ready>>,
    target_row: Option<Vec<Pair>>,
    release: Option<Certificate>,
    stats: NodeStats,
}
fn call_cfg(cfg: &NodeConfig, id: usize, req: &Rpc) -> Result<Vec<u8>> {
    call_port(&cfg.tls, cfg.id, cfg.peers[id - 1], req, cfg.delay_ms)
}
static TLS_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static TLS_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static WIRE_SENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static WIRE_RECV: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
struct Counted(TcpStream);
impl Read for Counted {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.read(b)?;
        WIRE_RECV.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }
}
impl Write for Counted {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.0.write(b)?;
        WIRE_SENT.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
pub fn call_port(
    tls: &Path,
    identity: usize,
    port: u16,
    req: &Rpc,
    delay_ms: u64,
) -> Result<Vec<u8>> {
    let socket = TcpStream::connect(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(Duration::from_secs(120)))?;
    socket.set_write_timeout(Some(Duration::from_secs(120)))?;
    socket.set_nodelay(true)?;
    let conn = ClientConnection::new(
        client_config(tls, identity)?,
        ServerName::try_from("localhost")?,
    )?;
    let mut stream = StreamOwned::new(conn, Counted(socket));
    let handshake = Instant::now();
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    TLS_NS.fetch_add(
        handshake.elapsed().as_nanos() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    TLS_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if delay_ms > 0 {
        std::thread::sleep(Duration::from_millis(delay_ms));
    }
    write_frame(&mut stream, &enc(req))?;
    let rep: Reply = bincode::deserialize(&read_frame(&mut stream)?)?;
    ensure!(rep.ok, "remote: {}", rep.error);
    Ok(rep.bytes)
}
fn phase(state: &Arc<Mutex<NodeState>>, resolve: bool) -> Result<()> {
    let (cfg, nonce, target_t) = {
        let s = state.lock().unwrap();
        (s.cfg.clone(), s.nonce, s.target_t)
    };
    let p = Params {
        t: target_t,
        ..cfg.params
    };
    let start = Instant::now();
    let mut sent = 0;
    let mut received = 0;
    if !resolve {
        let mut proposals = BTreeMap::new();
        let mut shares = BTreeMap::new();
        let mut complaints = BTreeSet::new();
        for id in 1..=p.n {
            let req = Rpc::GetProposal;
            let bytes = call_cfg(&cfg, id, &req)?;
            sent += enc(&req).len() as u64;
            received += bytes.len() as u64;
            let prop: Signed<Proposal> = bincode::deserialize(&bytes)?;
            ensure!(
                checked(&cfg, &prop, id) && prop.payload.nonce == nonce,
                "proposal authentication"
            );
            let mut r = rand::rngs::OsRng;
            let proof = sign(cfg.signing_sk, &enc(&(nonce, cfg.id)), &mut r);
            let req = Rpc::GetShare {
                recipient: cfg.id,
                nonce,
                proof,
            };
            let bytes = call_cfg(&cfg, id, &req).unwrap_or_else(|_| enc(&Vec::<Pair>::new()));
            sent += enc(&req).len() as u64;
            received += bytes.len() as u64;
            let parts: Vec<Pair> = bincode::deserialize(&bytes)?;
            if !verify_contribution(
                &prop.payload.commitments,
                &parts,
                cfg.id as u64,
                cfg.source_vectors[id - 1][0],
                p,
            ) {
                complaints.insert(id);
            }
            proposals.insert(id, prop);
            shares.insert(id, parts);
        }
        if cfg.fault == "spurious" && cfg.id <= cfg.faulty {
            complaints.insert(p.n);
        }
        let echo = signed(
            &cfg,
            Echo {
                nonce,
                proposals: proposals.clone(),
                complaints: complaints.clone(),
            },
        );
        let mut s = state.lock().unwrap();
        s.proposals = proposals;
        s.shares = shares;
        s.stats.complaints = complaints.len();
        s.echo = Some(echo);
    } else {
        let mut echoes = Vec::new();
        for id in 1..=p.n {
            let req = Rpc::Echo;
            let bytes = call_cfg(&cfg, id, &req)?;
            sent += enc(&req).len() as u64;
            received += bytes.len() as u64;
            let e: Signed<Echo> = bincode::deserialize(&bytes)?;
            ensure!(
                checked(&cfg, &e, id) && e.payload.nonce == nonce,
                "echo authentication"
            );
            echoes.push(e);
        }
        let mut qualified = Vec::new();
        let mut canonical = BTreeMap::new();
        let mut local = state.lock().unwrap().shares.clone();
        for id in 1..=p.n {
            let mut votes: BTreeMap<Hash, (usize, Signed<Proposal>)> = BTreeMap::new();
            for e in &echoes {
                if let Some(prop) = e.payload.proposals.get(&id) {
                    if checked(&cfg, prop, id) && prop.payload.nonce == nonce {
                        let key = hash(&[&enc(&prop.payload)]);
                        let v = votes.entry(key).or_insert((0, prop.clone()));
                        v.0 += 1;
                    }
                }
            }
            let Some((_, prop)) = votes.into_values().find(|(n, _)| *n >= p.n - p.f) else {
                continue;
            };
            let c = &prop.payload.commitments;
            if c.len() != p.t
                || c.iter().any(|v| v.len() != p.k)
                || c[0][0] != cfg.source_vectors[id - 1][0]
            {
                continue;
            }
            let mut accepted = true;
            for echo in &echoes {
                if echo.payload.complaints.contains(&id) {
                    // A signed request from the complainant makes this an explicitly public answer.
                    let req = Rpc::Answer {
                        complaint: echo.clone(),
                    };
                    let bytes = match call_cfg(&cfg, id, &req) {
                        Ok(b) => b,
                        Err(_) => {
                            accepted = false;
                            break;
                        }
                    };
                    sent += enc(&req).len() as u64;
                    received += bytes.len() as u64;
                    let ans: Signed<(u64, usize, Vec<Pair>)> = bincode::deserialize(&bytes)?;
                    if !checked(&cfg, &ans, id)
                        || ans.payload.0 != nonce
                        || ans.payload.1 != echo.sender
                        || !verify_contribution(
                            c,
                            &ans.payload.2,
                            echo.sender as u64,
                            cfg.source_vectors[id - 1][0],
                            p,
                        )
                    {
                        accepted = false;
                        break;
                    }
                    if echo.sender == cfg.id {
                        local.insert(id, ans.payload.2);
                    }
                }
            }
            if accepted {
                qualified.push(id);
                canonical.insert(id, prop);
            }
        }
        ensure!(
            qualified.len() >= p.n - p.f,
            "generation qualified-set shortage"
        );
        let transcript = hash(&[&enc(&echoes), &enc(&qualified)]);
        let ready = signed(
            &cfg,
            Ready {
                nonce,
                qualified,
                transcript,
            },
        );
        let mut s = state.lock().unwrap();
        s.shares = local;
        s.proposals = canonical;
        s.ready = Some(ready);
    }
    let mut s = state.lock().unwrap();
    s.stats.sent += sent;
    s.stats.received += received;
    s.stats.compute_ns += start.elapsed().as_nanos() as u64;
    Ok(())
}
fn dispatch(state: &Arc<Mutex<NodeState>>, req: Rpc) -> Result<Reply> {
    if matches!(req, Rpc::Collect | Rpc::Resolve) {
        phase(state, matches!(req, Rpc::Resolve))?;
        return Ok(Reply::value(&true));
    }
    if matches!(req, Rpc::Finish) {
        let (cfg, ready, parts) = {
            let s = state.lock().unwrap();
            (
                s.cfg.clone(),
                s.ready.clone().context("not ready")?,
                s.shares.clone(),
            )
        };
        let mut agreement = 0;
        for id in 1..=cfg.params.n {
            let bytes = call_cfg(&cfg, id, &Rpc::GetReady)?;
            let r: Signed<Ready> = bincode::deserialize(&bytes)?;
            if checked(&cfg, &r, id) && enc(&r.payload) == enc(&ready.payload) {
                agreement += 1;
            }
        }
        ensure!(agreement >= cfg.params.n - cfg.params.f, "ready quorum");
        let mut s = state.lock().unwrap();
        let p = Params {
            t: s.target_t,
            ..cfg.params
        };
        let q: Vec<_> = ready
            .payload
            .qualified
            .iter()
            .map(|id| (*id as u64, parts[id].clone()))
            .collect();
        let row = aggregate_contributions(p, &q)?;
        durable_write(&cfg.dir.join("target.bin"), &enc(&row))?;
        s.target_row = Some(row);
        s.stats.qualified = q.len();
        use zeroize::Zeroize;
        if let Some(mut c) = s.contribution.take() {
            for v in &mut c.to {
                v.zeroize();
            }
        }
        for v in s.shares.values_mut() {
            v.zeroize();
        }
        s.shares.clear();
        return Ok(Reply::value(&true));
    }
    let mut s = state.lock().unwrap();
    s.stats.requests += 1;
    match req {
        Rpc::Enroll {
            recipient,
            pk,
            authorization,
        } => {
            ensure!(
                recipient > 0
                    && verify_sig(
                        s.cfg.authority,
                        &enc(&(recipient, pk, s.cfg.source_epoch)),
                        &authorization
                    ),
                "enrollment authorization"
            );
            if let Some(old) = s.enrolled.get(&recipient) {
                ensure!(*old == pk, "enrollment key conflict");
            }
            s.enrolled.insert(recipient, pk);
            let pair = eval(&s.cfg.source_row, Fr::from(recipient));
            let ad = Ad {
                version: 1,
                source_epoch: s.cfg.source_epoch,
                target_epoch: s.cfg.source_epoch,
                nonce: recipient,
                mode: Mode::Snapshot,
                dealer: s.cfg.id as u64,
                recipient,
                key_epoch: 0,
                source: s.cfg.source_digest,
                target: s.cfg.source_digest,
                vector_digest: hash(&[&enc(&s.cfg.source_vectors[s.cfg.id - 1])]),
                e: pair.commitment(),
            };
            let rec = record(ad, pair, pk, s.cfg.signing_sk, &mut rand::rngs::OsRng);
            Ok(Reply::value(&rec))
        }
        Rpc::Heartbeat {
            recipient,
            nonce,
            proof,
        } => {
            let pk = s.enrolled.get(&recipient).context("not enrolled")?;
            ensure!(
                verify_sig(
                    *pk,
                    &enc(&("heartbeat", recipient, nonce, s.cfg.source_digest)),
                    &proof
                ),
                "heartbeat authentication"
            );
            Ok(Reply::value(&true))
        }
        Rpc::Ping => Ok(Reply::value(&s.cfg.id)),
        Rpc::Prepare { nonce, target_t } => {
            let p = Params {
                t: target_t,
                ..s.cfg.params
            };
            p.check()?;
            let mut r = rand::rngs::OsRng;
            let c = contribute(s.cfg.source_row[0], p, &mut r);
            s.contribution = Some(c);
            s.nonce = nonce;
            s.target_t = target_t;
            s.release = None;
            s.target_row = None;
            s.echo = None;
            s.ready = None;
            Ok(Reply::value(&true))
        }
        Rpc::GetProposal => {
            let mut c = s
                .contribution
                .as_ref()
                .context("not prepared")?
                .commitments
                .clone();
            if s.cfg.fault == "bad_constant" && s.cfg.id <= s.cfg.faulty {
                c[0][0] += g();
            }
            if s.cfg.fault == "equivocation" && s.cfg.id <= s.cfg.faulty {
                c[1][0] += Fr::from(s.stats.requests % 2 + 1) * g();
            }
            Ok(Reply::value(&signed(
                &s.cfg,
                Proposal {
                    nonce: s.nonce,
                    commitments: c,
                },
            )))
        }
        Rpc::GetShare {
            recipient,
            nonce,
            proof,
        } => {
            ensure!(
                !(s.cfg.fault == "omission" && s.cfg.id <= s.cfg.faulty),
                "withheld share"
            );
            ensure!(
                recipient > 0 && recipient <= s.cfg.params.n && nonce == s.nonce,
                "share request context"
            );
            ensure!(
                verify_sig(
                    s.cfg.signing_pks[recipient - 1],
                    &enc(&(nonce, recipient)),
                    &proof
                ),
                "share request signature"
            );
            let mut v = s.contribution.as_ref().context("not prepared")?.to[recipient - 1].clone();
            if s.cfg.fault == "bad_share" && s.cfg.id <= s.cfg.faulty {
                v[0].v += Fr::ONE;
            }
            Ok(Reply::value(&v))
        }
        Rpc::Echo => Ok(Reply::value(s.echo.as_ref().context("no echo")?)),
        Rpc::GetReady => Ok(Reply::value(s.ready.as_ref().context("no ready")?)),
        Rpc::Vector => Ok(Reply::value(
            &s.target_row
                .as_ref()
                .context("no target")?
                .iter()
                .map(|p| p.commitment())
                .collect::<Vec<_>>(),
        )),
        Rpc::Reserve {
            request,
            policy,
            chain,
        } => {
            ensure!(
                request.nonce == s.nonce && policy.source == s.cfg.source_digest,
                "reservation state"
            );
            if let Some((rpc, address, digest)) = chain {
                ensure!(
                    crate::chain::allowed(&rpc, &address, digest)?,
                    "reservation not chain ordered"
                );
            }
            let l = Ledger::create(&s.cfg.dir.join("ledger"), policy.clone())?;
            let entry = l.reserve(request)?;
            let digest = hash(&[&enc(&(policy.source, &entry))]);
            let sig = lock_and_sign(
                &s.cfg.dir.join("locks"),
                policy.source,
                entry.version,
                digest,
                s.cfg.reservation_sk,
            )?;
            Ok(Reply::value(&(entry, sig)))
        }
        Rpc::Release { entry, certificate } => {
            let expected = hash(&[&enc(&(s.cfg.source_digest, &entry))]);
            ensure!(
                certificate.digest == expected
                    && entry.request.nonce == s.nonce
                    && verify_certificate(
                        &certificate,
                        &s.cfg.reservation_pks,
                        s.cfg.params.n - s.cfg.params.f
                    ),
                "release certificate"
            );
            let l = Ledger::open(&s.cfg.dir.join("ledger"))?;
            ensure!(l.root()? == entry.new_root, "release log state");
            s.release_target = Some(entry.request.target);
            s.release = Some(certificate);
            Ok(Reply::value(&true))
        }
        Rpc::Commit { nonce, target } => {
            ensure!(
                nonce == s.nonce && s.release_target == Some(target) && s.release.is_some(),
                "commit context"
            );
            use zeroize::Zeroize;
            s.cfg.source_row.zeroize();
            s.release = None;
            s.stats.source_erased = s.cfg.source_row.iter().all(|p| *p == Pair::zero());
            durable_write(&s.cfg.dir.join("config.json"), &serde_json::to_vec(&s.cfg)?)?;
            Ok(Reply::value(&s.stats.source_erased))
        }
        Rpc::Issue {
            recipient,
            pk,
            mode,
            source,
            target,
        } => {
            ensure!(
                source == s.cfg.source_digest && s.release_target == Some(target),
                "state binding"
            );
            ensure!(s.release.is_some(), "no public token before certificate");
            let row = s.target_row.as_ref().context("no target")?;
            let mut pair = eval(row, Fr::from(recipient));
            if mode == Mode::Difference {
                pair = pair.minus(eval(&s.cfg.source_row, Fr::from(recipient)));
            }
            let tgt: Vec<_> = row.iter().map(|p| p.commitment()).collect();
            let v = if mode == Mode::Difference {
                delta(&s.cfg.source_vectors[s.cfg.id - 1], &tgt)
            } else {
                tgt
            };
            let ad = Ad {
                version: 1,
                source_epoch: s.cfg.source_epoch,
                target_epoch: s.cfg.source_epoch + 1,
                nonce: s.nonce,
                mode,
                dealer: s.cfg.id as u64,
                recipient,
                key_epoch: 0,
                source,
                target,
                vector_digest: hash(&[&enc(&v)]),
                e: pair.commitment(),
            };
            let mut r = rand::rngs::OsRng;
            let rec = record(ad, pair, pk, s.cfg.signing_sk, &mut r);
            Ok(Reply::value(&rec))
        }
        Rpc::Stats => {
            s.stats.tls_handshakes = TLS_COUNT.load(std::sync::atomic::Ordering::Relaxed);
            s.stats.tls_handshake_ns = TLS_NS.load(std::sync::atomic::Ordering::Relaxed);
            s.stats.transport_sent = WIRE_SENT.load(std::sync::atomic::Ordering::Relaxed);
            s.stats.transport_received = WIRE_RECV.load(std::sync::atomic::Ordering::Relaxed);
            let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
            if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0 {
                let usage = unsafe { usage.assume_init() };
                s.stats.peak_rss_bytes = usage.ru_maxrss as u64 * 1024;
                s.stats.cpu_user_ns = usage.ru_utime.tv_sec as u64 * 1_000_000_000
                    + usage.ru_utime.tv_usec as u64 * 1000;
                s.stats.cpu_system_ns = usage.ru_stime.tv_sec as u64 * 1_000_000_000
                    + usage.ru_stime.tv_usec as u64 * 1000;
            }
            Ok(Reply::value(&s.stats))
        }
        Rpc::Answer { complaint } => {
            ensure!(
                !(s.cfg.fault == "omission" && s.cfg.id <= s.cfg.faulty),
                "withheld answer"
            );
            let id = complaint.sender;
            ensure!(
                id > 0
                    && id <= s.cfg.params.n
                    && checked(&s.cfg, &complaint, id)
                    && complaint.payload.nonce == s.nonce
                    && complaint.payload.complaints.contains(&s.cfg.id),
                "authenticated complaint required"
            );
            let c = s.contribution.as_ref().context("no contribution")?;
            Ok(Reply::value(&signed(
                &s.cfg,
                (s.nonce, id, c.to[id - 1].clone()),
            )))
        }
        Rpc::Fetch { file } => {
            ensure!(
                !file.contains('/') && !file.contains("..") && !file.starts_with("answer-"),
                "path"
            );
            let bytes = fs::read(s.cfg.dir.join("archive").join(file))?;
            Ok(Reply::value(&bytes))
        }
        Rpc::Shutdown => {
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                std::process::exit(0);
            });
            Ok(Reply::value(&true))
        }
        _ => anyhow::bail!("unexpected phase"),
    }
}
pub fn serve(path: &Path) -> Result<()> {
    let cfg: NodeConfig = serde_json::from_slice(&fs::read(path)?)?;
    let server = server_config(&cfg.tls, cfg.id)?;
    let listener = TcpListener::bind(("127.0.0.1", cfg.port))?;
    let state = Arc::new(Mutex::new(NodeState {
        cfg,
        enrolled: BTreeMap::new(),
        release_target: None,
        contribution: None,
        nonce: 0,
        target_t: 0,
        proposals: BTreeMap::new(),
        shares: BTreeMap::new(),
        echo: None,
        ready: None,
        target_row: None,
        release: None,
        stats: NodeStats::default(),
    }));
    for socket in listener.incoming() {
        let socket = socket?;
        let state = Arc::clone(&state);
        let server = Arc::clone(&server);
        std::thread::spawn(move || {
            let run = || -> Result<()> {
                socket.set_read_timeout(Some(Duration::from_secs(120)))?;
                socket.set_nodelay(true)?;
                let conn = ServerConnection::new(server)?;
                let mut stream = StreamOwned::new(conn, Counted(socket));
                let handshake = Instant::now();
                while stream.conn.is_handshaking() {
                    stream.conn.complete_io(&mut stream.sock)?;
                }
                TLS_NS.fetch_add(
                    handshake.elapsed().as_nanos() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                TLS_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let bytes = read_frame(&mut stream)?;
                let req: Rpc = bincode::deserialize(&bytes)?;
                let rep = match dispatch(&state, req) {
                    Ok(v) => v,
                    Err(e) => Reply {
                        ok: false,
                        bytes: Vec::new(),
                        error: e.to_string(),
                    },
                };
                write_frame(&mut stream, &enc(&rep))?;
                Ok(())
            };
            if let Err(e) = run() {
                eprintln!("node connection: {e}");
            }
        });
    }
    Ok(())
}
pub type GenerationResult = (Vec<Vec<Point>>, Vec<(String, u64)>);
pub struct Cluster {
    pub children: Vec<Child>,
    pub configs: Vec<NodeConfig>,
    pub dir: PathBuf,
    pub authority_sk: Fr,
}
impl Drop for Cluster {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Cluster {
    pub fn start(
        dir: &Path,
        source: &Epoch,
        seed: u64,
        fault: &str,
        faulty: usize,
        delay_ms: u64,
    ) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let tls = dir.join("tls");
        tls_material(&tls, source.params.n)?;
        let mut listeners = Vec::new();
        for _ in 0..source.params.n {
            listeners.push(TcpListener::bind(("127.0.0.1", 0))?);
        }
        let ports: Vec<_> = listeners
            .iter()
            .map(|l| l.local_addr().unwrap().port())
            .collect();
        drop(listeners);
        let keys: Vec<_> = (0..source.params.n)
            .map(|_| nonzero(&mut rand::rngs::OsRng))
            .collect();
        let rkeys: Vec<_> = (0..source.params.n)
            .map(|_| nonzero(&mut rand::rngs::OsRng))
            .collect();
        let pks = keys.iter().map(|s| s * g()).collect::<Vec<_>>();
        let rpks = rkeys.iter().map(|s| s * g()).collect::<Vec<_>>();
        let authority_sk = nonzero(&mut rand::rngs::OsRng);
        let mut cluster = Self {
            children: Vec::new(),
            configs: Vec::new(),
            dir: dir.to_owned(),
            authority_sk,
        };
        for id in 1..=source.params.n {
            let node_dir = dir.join(format!("dealer-{id}"));
            fs::create_dir_all(&node_dir)?;
            let cfg = NodeConfig {
                id,
                params: source.params,
                seed,
                signing_sk: keys[id - 1],
                reservation_sk: rkeys[id - 1],
                port: ports[id - 1],
                peers: ports.clone(),
                dir: node_dir.clone(),
                tls: tls.clone(),
                source_row: source.rows[id - 1].clone(),
                source_vectors: source.vectors.clone(),
                source_digest: source.digest(),
                source_epoch: source.epoch,
                authority: authority_sk * g(),
                signing_pks: pks.clone(),
                reservation_pks: rpks.clone(),
                faulty,
                fault: fault.into(),
                delay_ms,
            };
            let path = node_dir.join("config.json");
            fs::write(&path, serde_json::to_vec(&cfg)?)?;
            let log = fs::File::create(node_dir.join("node.log"))?;
            let child = Command::new(std::env::current_exe()?)
                .arg("node")
                .arg("--config")
                .arg(&path)
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()?;
            cluster.children.push(child);
            cluster.configs.push(cfg);
        }
        for cfg in &cluster.configs {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if call_port(&tls, 0, cfg.port, &Rpc::Ping, 0).is_ok() {
                    break;
                }
                ensure!(Instant::now() < deadline, "dealer startup failed");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Ok(cluster)
    }
    pub fn all(&self, req: Rpc) -> Result<Vec<Vec<u8>>> {
        std::thread::scope(|scope| {
            let jobs: Vec<_> = self
                .configs
                .iter()
                .map(|c| {
                    let r = req.clone();
                    scope.spawn(move || call_port(&c.tls, 0, c.port, &r, c.delay_ms))
                })
                .collect();
            jobs.into_iter()
                .map(|j| j.join().expect("RPC worker panic"))
                .collect()
        })
    }
    pub fn generation(&self, nonce: u64, target_t: usize) -> Result<GenerationResult> {
        let mut phases = Vec::new();
        for (name, cmd) in [
            ("prepare", Rpc::Prepare { nonce, target_t }),
            ("distribution_echo", Rpc::Collect),
            ("complaint_resolution", Rpc::Resolve),
            ("ready_aggregation", Rpc::Finish),
        ] {
            let start = Instant::now();
            self.all(cmd)?;
            phases.push((name.into(), start.elapsed().as_nanos() as u64));
        }
        let vectors = self
            .all(Rpc::Vector)?
            .iter()
            .map(|b| Ok(bincode::deserialize(b)?))
            .collect::<Result<Vec<_>>>()?;
        Ok((vectors, phases))
    }
}
