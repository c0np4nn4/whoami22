use super::{core::*, issuance::*, model::*, wire::*};
use crate::chain::{keccak, word, Arg, Word};
use anyhow::{bail, ensure, Context, Result};
use halo2curves::ff::Field;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    sync::{Arc, Condvar, Mutex},
    time::Instant,
};
#[derive(Clone, Serialize, Deserialize)]
struct Candidate {
    request: Generation,
    row: Vec<Pair>,
    state: Option<State>,
}
#[derive(Clone, Serialize, Deserialize)]
struct InitialSeed {
    params: Params,
    commitments: Vec<Point>,
    share: Pair,
}
impl Drop for InitialSeed {
    fn drop(&mut self) {
        self.share.erase();
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Answers {
    nonce: u64,
    pairs: Vec<(u64, Vec<Pair>)>,
    signature: Sig,
}
#[derive(Clone, Serialize, Deserialize)]
struct GenerationVector {
    nonce: u64,
    epoch: u64,
    commitments: Vec<Point>,
    signature: Sig,
}
#[derive(Clone, Serialize, Deserialize)]
struct PendingEnrollment {
    completion: Completion,
    header: Header,
    partials: Vec<BatchPartial>,
    rejected: Vec<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Disk {
    sk: Scalar,
    rsk: Scalar,
    key_epoch: u64,
    source: Option<State>,
    row: Vec<Pair>,
    initial: Option<InitialSeed>,
    generation_attempt: Option<u64>,
    candidate: Option<Candidate>,
    plan: Option<Plan>,
    certificate: Option<Certificate>,
    reservations: BTreeMap<(u64, Word), Word>,
    header: Option<Header>,
    share: Option<Pair>,
    staged: Option<Staged>,
    pending_enrollment: Option<PendingEnrollment>,
    completed_enrollment: Option<Completion>,
    applied: BTreeSet<u64>,
    fault: String,
}
impl Disk {
    fn new() -> Self {
        Self {
            sk: nonzero(),
            rsk: nonzero(),
            key_epoch: 0,
            source: None,
            row: vec![],
            initial: None,
            generation_attempt: None,
            candidate: None,
            plan: None,
            certificate: None,
            reservations: BTreeMap::new(),
            header: None,
            share: None,
            staged: None,
            pending_enrollment: None,
            completed_enrollment: None,
            applied: BTreeSet::new(),
            fault: String::new(),
        }
    }
    fn begin_enrollment(&mut self) {
        if let Some(old) = &mut self.share {
            old.erase();
        }
        self.share = None;
        self.header = None;
        self.staged = None;
        self.pending_enrollment = None;
    }
    fn finish_enrollment(
        &mut self,
        activation: &Activation,
        status: u64,
    ) -> Result<Option<PendingEnrollment>> {
        if status == 3 {
            self.pending_enrollment = None;
        }
        ensure!(status == 2, "registry has not issued this activation");
        if self
            .completed_enrollment
            .as_ref()
            .is_some_and(|c| enc(&c.activation) == enc(activation))
        {
            return Ok(None);
        }
        let pending = self
            .pending_enrollment
            .as_ref()
            .context("no saved enrollment partials")?;
        ensure!(
            enc(&pending.completion.activation) == enc(activation)
                && pending.header.id == activation.state
                && pending.header.epoch == activation.epoch
                && g() * self.sk == activation.pk,
            "issued activation does not match saved partials"
        );
        ensure!(
            pending.partials.len() >= pending.header.params.k,
            "insufficient saved enrollment partials"
        );
        let inputs = zeroize::Zeroizing::new(
            pending
                .partials
                .iter()
                .map(|p| (p.dealer, p.partial))
                .collect::<Vec<_>>(),
        );
        let share = zeroize::Zeroizing::new(combine(&inputs)?);
        ensure!(
            share.commit() == peval(&pending.header.public, Scalar::from(activation.id)),
            "issued share Verify"
        );
        self.share = Some(*share);
        self.header = Some(pending.header.clone());
        self.completed_enrollment = Some(pending.completion.clone());
        Ok(self.pending_enrollment.take())
    }
    fn abandon_unreserved(&mut self, nonce: u64, memory: &mut Option<GenMemory>) -> Result<bool> {
        ensure!(
            self.generation_attempt.is_none_or(|n| n == nonce)
                && self
                    .candidate
                    .as_ref()
                    .is_none_or(|c| c.request.nonce == nonce)
                && self.plan.as_ref().is_none_or(|p| p.nonce == nonce)
                && memory.as_ref().is_none_or(|m| m.request.nonce == nonce),
            "abandon cannot erase another attempt or generation thread"
        );
        ensure!(
            self.certificate.is_none() && self.reservations.keys().all(|(n, _)| *n != nonce),
            "abandon forbidden after durable release certification"
        );
        let had_candidate = self.generation_attempt.is_some()
            || self.candidate.is_some()
            || self.plan.is_some()
            || memory.is_some();
        self.generation_attempt = None;
        if let Some(c) = self.candidate.as_mut() {
            for pair in &mut c.row {
                pair.erase();
            }
        }
        self.candidate = None;
        self.plan = None;
        *memory = None;
        Ok(had_candidate)
    }
}
impl Drop for Disk {
    fn drop(&mut self) {
        for pair in &mut self.row {
            pair.erase();
        }
        if let Some(share) = &mut self.share {
            share.erase();
        }
        if let Some(initial) = &mut self.initial {
            initial.share.erase();
        }
        if let Some(candidate) = &mut self.candidate {
            for pair in &mut candidate.row {
                pair.erase();
            }
        }
        unsafe {
            std::ptr::write_volatile(&mut self.sk, Scalar::ZERO);
            std::ptr::write_volatile(&mut self.rsk, Scalar::ZERO);
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
struct GenMemory {
    request: Generation,
    contribution: Contribution,
    error: Option<String>,
}
impl Drop for GenMemory {
    fn drop(&mut self) {
        for row in &mut self.contribution.shares {
            for pair in row {
                pair.erase();
            }
        }
    }
}
struct GenerationWorker {
    node: Arc<Node>,
    nonce: u64,
}
impl Drop for GenerationWorker {
    fn drop(&mut self) {
        {
            let mut memory = self.node.generation.lock().unwrap();
            if memory
                .as_ref()
                .is_some_and(|m| m.request.nonce == self.nonce)
            {
                *memory = None;
            }
        }
        self.node
            .generation_workers
            .lock()
            .unwrap()
            .remove(&self.nonce);
        self.node.generation_finished.notify_all();
    }
}
pub struct Node {
    cfg: NodeConfig,
    disk: Mutex<Disk>,
    generation: Mutex<Option<GenMemory>>,
    generation_workers: Mutex<BTreeSet<u64>>,
    generation_finished: Condvar,
    started: Instant,
    event_lock: Mutex<()>,
}
impl Node {
    fn save(&self, d: &Disk) -> Result<()> {
        let bytes = zeroize::Zeroizing::new(enc(d));
        crate::ledger::durable_write(&self.cfg.dir.join("private.bin"), &bytes)
    }
    fn event(&self, kind: &str, body: serde_json::Value) -> Result<()> {
        let _g = self.event_lock.lock().unwrap();
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.cfg.dir.join("events.jsonl"))?;
        writeln!(
            f,
            "{}",
            json!({"run":self.cfg.run,"node":self.cfg.id,"role":self.cfg.role,"pid":std::process::id(),"local_ns":self.started.elapsed().as_nanos(),"kind":kind,"data":body})
        )?;
        Ok(())
    }
    fn meta(&self) -> Meta {
        let d = self.disk.lock().unwrap();
        Meta {
            id: self.cfg.id,
            pk: g() * d.sk,
            reservation: g() * d.rsk,
            key_epoch: d.key_epoch,
        }
    }
    fn admin(&self, from: u64) -> Result<()> {
        ensure!(from == 0, "controller identity");
        Ok(())
    }
    fn source(&self) -> Result<State> {
        self.disk
            .lock()
            .unwrap()
            .source
            .clone()
            .context("not initialized")
    }
    fn candidate(&self) -> Result<State> {
        self.disk
            .lock()
            .unwrap()
            .candidate
            .as_ref()
            .and_then(|c| c.state.clone())
            .context("generation not ready")
    }
    fn plan(&self) -> Result<Plan> {
        self.disk
            .lock()
            .unwrap()
            .plan
            .clone()
            .context("no reservation plan")
    }
    fn check_release_policy(&self) -> Result<()> {
        ensure!(
            query_word(&self.cfg, "participantCorruptionBudget()", &[])?
                == word(self.cfg.participant_corruption_budget as u64)
                && query_word(&self.cfg, "outgoingRecipientBudget()", &[])?
                    == word(self.cfg.outgoing_recipient_budget as u64),
            "configured release policy must match the chain policy"
        );
        Ok(())
    }
    fn generate(self: Arc<Self>, req: Generation) -> Result<()> {
        use super::generation as board;
        let mut initial = {
            let d = self.disk.lock().unwrap();
            ensure!(
                d.generation_attempt == Some(req.nonce),
                "generation cancelled before sampling"
            );
            d.initial.clone()
        };
        let (src, row0, sk) = {
            let d = self.disk.lock().unwrap();
            let src = if let Some(seed) = &initial {
                let vectors = (1..=seed.params.n)
                    .map(|j| {
                        let mut row = vec![Pair::zero().commit(); seed.params.t];
                        row[0] = peval(&seed.commitments, Scalar::from(j as u64));
                        row
                    })
                    .collect();
                state(0, seed.params, vectors)?
            } else {
                d.source.clone().context("generation source")?
            };
            let constant = initial
                .as_ref()
                .map(|s| s.share)
                .unwrap_or_else(|| d.row[0]);
            (src, constant, d.sk)
        };
        let mut row0 = zeroize::Zeroizing::new(row0);
        if initial.is_none() {
            ensure!(
                current(&self.cfg)? == src.id(),
                "generation source not canonical"
            );
            ensure!(
                self.cfg.target_budget_allows(req.offline.len(), req.t) && req.eligible >= req.t,
                "pre-generation target guard"
            );
        }
        let p = Params {
            t: req.t,
            ..src.params
        };
        p.check()?;
        let contribution = if initial.is_some() {
            contribute_initial(p)
        } else {
            contribute(*row0, p)
        };
        let proposal = Proposal {
            nonce: req.nonce,
            source: src.id(),
            commitments: contribution.commitments.clone(),
            sig: sign(
                sk,
                digest(&(req.nonce, src.id(), &contribution.commitments)),
            ),
        };
        {
            let d = self.disk.lock().unwrap();
            ensure!(
                d.generation_attempt == Some(req.nonce),
                "generation abandoned before private sampling publication"
            );
            *self.generation.lock().unwrap() = Some(GenMemory {
                request: req.clone(),
                contribution,
                error: None,
            });
        }
        let keys = board::signing_keys(&self.cfg)?;
        self.generation_broadcast(req.nonce, 0, &proposal)?;
        let proposed: Vec<(u64, Proposal)> = self.generation_snapshot(req.nonce, 0)?;
        let proposals = proposed
            .into_iter()
            .filter(|(id, v)| {
                v.nonce == req.nonce
                    && v.source == src.id()
                    && v.commitments.len() == p.t
                    && v.commitments.iter().all(|c| c.len() == p.k)
                    && v.commitments[0][0]
                        == if initial.is_some() {
                            Pair::zero().commit()
                        } else {
                            src.vectors[*id as usize - 1][0]
                        }
                    && verify(
                        keys[*id as usize - 1],
                        digest(&(req.nonce, v.source, &v.commitments)),
                        &v.sig,
                    )
            })
            .collect::<Vec<_>>();
        ensure!(proposals.len() >= p.n - p.f, "valid VSS proposal quorum");
        let mut shares: BTreeMap<u64, zeroize::Zeroizing<Vec<Pair>>> = BTreeMap::new();
        let mut complaints = Vec::new();
        for (id, proposal) in &proposals {
            let expected = if initial.is_some() {
                Pair::zero().commit()
            } else {
                src.vectors[*id as usize - 1][0]
            };
            ensure!(
                self.disk.lock().unwrap().generation_attempt == Some(req.nonce),
                "private delivery cancelled"
            );
            match call::<_, Vec<Pair>>(&self.cfg, *id, "subshare", &req.nonce) {
                Ok(value) => {
                    let value = zeroize::Zeroizing::new(value);
                    if verify_share(&proposal.commitments, &value, self.cfg.id, expected, p) {
                        shares.insert(*id, value);
                    } else {
                        complaints.push(*id);
                    }
                }
                Err(_) => complaints.push(*id),
            }
        }
        let hashes = proposals
            .iter()
            .map(|(id, v)| (*id, digest(&v.commitments)))
            .collect::<Vec<_>>();
        let echo = Echo {
            nonce: req.nonce,
            proposals: hashes.clone(),
            complaints: complaints.clone(),
            sig: sign(sk, digest(&(req.nonce, &hashes, &complaints))),
        };
        self.generation_broadcast(req.nonce, 1, &echo)?;
        let echoes: Vec<(u64, Echo)> = self.generation_snapshot(req.nonce, 1)?;
        let echoes = echoes
            .into_iter()
            .filter(|(id, e)| {
                e.nonce == req.nonce
                    && e.proposals == hashes
                    && e.complaints
                        .iter()
                        .all(|j| proposals.iter().any(|(id, _)| id == j))
                    && e.complaints.iter().copied().collect::<BTreeSet<_>>().len()
                        == e.complaints.len()
                    && verify(
                        keys[*id as usize - 1],
                        digest(&(e.nonce, &e.proposals, &e.complaints)),
                        &e.sig,
                    )
            })
            .collect::<Vec<_>>();
        ensure!(
            echoes.len() >= p.n - p.f,
            "valid complaint broadcast quorum"
        );
        // The frozen public complaints determine exactly which coordinates an
        // honest contributor may reveal. No controller can ask for other shares.
        let pairs = {
            let m = self.generation.lock().unwrap();
            let m = m.as_ref().context("VSS memory")?;
            ensure!(m.request.nonce == req.nonce, "generation ownership changed");
            echoes
                .iter()
                .filter(|(_, e)| e.complaints.contains(&self.cfg.id))
                .map(|(who, _)| (*who, m.contribution.shares[*who as usize - 1].clone()))
                .collect::<Vec<_>>()
        };
        let answers = Answers {
            nonce: req.nonce,
            signature: sign(sk, digest(&(req.nonce, &pairs))),
            pairs,
        };
        self.generation_broadcast(req.nonce, 2, &answers)?;
        let answers: Vec<(u64, Answers)> = self.generation_snapshot(req.nonce, 2)?;
        let answers = answers
            .into_iter()
            .filter(|(id, a)| {
                a.nonce == req.nonce
                    && verify(
                        keys[*id as usize - 1],
                        digest(&(a.nonce, &a.pairs)),
                        &a.signature,
                    )
                    && a.pairs
                        .iter()
                        .map(|(who, _)| *who)
                        .collect::<BTreeSet<_>>()
                        .len()
                        == a.pairs.len()
            })
            .collect::<BTreeMap<_, _>>();
        let mut qualified = Vec::new();
        for (id, proposal) in &proposals {
            let expected = if initial.is_some() {
                Pair::zero().commit()
            } else {
                src.vectors[*id as usize - 1][0]
            };
            let mut good = true;
            for (who, e) in &echoes {
                if !e.complaints.contains(id) {
                    continue;
                }
                let answer = answers
                    .get(id)
                    .and_then(|a| a.pairs.iter().find(|(j, _)| j == who));
                if let Some((_, value)) = answer
                    .filter(|(_, v)| verify_share(&proposal.commitments, v, *who, expected, p))
                {
                    if *who == self.cfg.id {
                        shares.insert(*id, zeroize::Zeroizing::new(value.clone()));
                    }
                    self.event(
                        "complaint_answer",
                        json!({"nonce":req.nonce,"contributor":id,"recipient":who}),
                    )?;
                } else {
                    good = false;
                    break;
                }
            }
            if good {
                qualified.push(*id);
            }
        }
        ensure!(qualified.len() >= p.n - p.f, "JRSS qualified-set quorum");
        let mut row = zeroize::Zeroizing::new(aggregate(
            p,
            qualified
                .iter()
                .map(|id| {
                    Ok((
                        *id,
                        shares
                            .get(id)
                            .context("qualified private subshare")?
                            .to_vec(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        )?);
        if initial.is_some() {
            row[0] = *row0;
        }
        row0.erase();
        // Compute the expected public polynomial from the agreed transcript.
        // This validates each signed output vector independently, so a bad or
        // missing lowest-index dealer cannot poison the canonical family.
        let weights = weights(&qualified[..p.k], Scalar::ZERO)?;
        let vectors = (1..=p.n)
            .map(|j| {
                (0..p.t)
                    .map(|ell| {
                        if ell == 0 && initial.is_some() {
                            return src.vectors[j - 1][0];
                        }
                        qualified
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| ell != 0 || *i < p.k)
                            .fold(Pair::zero().commit(), |acc, (i, id)| {
                                let prop = &proposals.iter().find(|(d, _)| d == id).unwrap().1;
                                let value = peval(&prop.commitments[ell], Scalar::from(j as u64));
                                acc + value * if ell == 0 { weights[i] } else { Scalar::ONE }
                            })
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        ensure!(
            row.iter().map(|v| v.commit()).collect::<Vec<_>>() == vectors[self.cfg.id as usize - 1],
            "local VSS output consistency"
        );
        let epoch = if initial.is_some() { 0 } else { src.epoch + 1 };
        let commitments = vectors[self.cfg.id as usize - 1].clone();
        let vector = GenerationVector {
            nonce: req.nonce,
            epoch,
            signature: sign(
                sk,
                digest(&("VESS-GENERATION-VECTOR-v1", req.nonce, epoch, &commitments)),
            ),
            commitments,
        };
        self.generation_broadcast(req.nonce, 3, &vector)?;
        let signed: Vec<(u64, GenerationVector)> = self.generation_snapshot(req.nonce, 3)?;
        let accepted = signed
            .iter()
            .filter(|(id, v)| {
                v.nonce == req.nonce
                    && v.epoch == epoch
                    && v.commitments == vectors[*id as usize - 1]
                    && verify(
                        keys[*id as usize - 1],
                        digest(&(
                            "VESS-GENERATION-VECTOR-v1",
                            v.nonce,
                            v.epoch,
                            &v.commitments,
                        )),
                        &v.signature,
                    )
            })
            .count();
        ensure!(
            accepted >= p.n - p.f,
            "signed target commitment record quorum"
        );
        let target = state(epoch, p, vectors)?;
        ensure!(target.public[0] == src.public[0], "secret preserved");
        {
            let mut d = self.disk.lock().unwrap();
            ensure!(
                d.generation_attempt == Some(req.nonce),
                "generation abandoned before output installation"
            );
            d.candidate = Some(Candidate {
                request: req.clone(),
                row: row.to_vec(),
                state: Some(target.clone()),
            });
            self.save(&d)?;
        }
        // Every party signing an output vector has consumed its input shares.
        // Public answers remain on chain; all private invocation material ends
        // at this subprotocol completion boundary.
        for values in shares.values_mut() {
            for pair in values.iter_mut() {
                pair.erase();
            }
        }
        if let Some(seed) = initial.as_mut() {
            seed.share.erase();
        }
        {
            let mut memory = self.generation.lock().unwrap();
            if memory
                .as_ref()
                .is_some_and(|m| m.request.nonce == req.nonce)
            {
                *memory = None;
            }
        }
        self.event("generation_ready",json!({"nonce":req.nonce,"initial":initial.is_some(),"target":hex::encode(target.id()),"qualified":qualified,"accepted_vectors":accepted,"complaints":complaints.len(),"broadcast":"immutable_anvil_bulletin_board"}))?;
        Ok(())
    }
    fn generation_broadcast<T: Serialize>(
        &self,
        nonce: u64,
        phase: u64,
        payload: &T,
    ) -> Result<()> {
        let d = self.disk.lock().unwrap();
        ensure!(
            d.generation_attempt == Some(nonce),
            "generation abandoned before broadcast"
        );
        super::generation::publish(&self.cfg, nonce, phase, payload)
    }
    fn generation_snapshot<T: serde::de::DeserializeOwned>(
        &self,
        nonce: u64,
        phase: u64,
    ) -> Result<Vec<(u64, T)>> {
        super::generation::snapshot_while(&self.cfg, nonce, phase, || {
            self.disk.lock().unwrap().generation_attempt == Some(nonce)
        })
    }
    fn wait_generation_stopped(&self, nonce: u64) -> Result<()> {
        let mut workers = self.generation_workers.lock().unwrap();
        while workers.contains(&nonce) {
            workers = self.generation_finished.wait(workers).unwrap();
        }
        Ok(())
    }
    fn issue(&self, from: u64, id: u64, nonce: u64, snapshot: bool) -> Result<Record> {
        let d = self.disk.lock().unwrap();
        let src = d.source.as_ref().context("source")?;
        let pk = participant_pk(&self.cfg, id)?;
        if snapshot {
            ensure!(d.fault != "omit_partial", "injected issuance omission");
            let activation = Activation::load(&self.cfg, id)?;
            ensure!(
                from == 1000 + id
                    && activation.state == src.id()
                    && activation.alpha == word(nonce)
                    && activation.pk == pk,
                "issuance authorization"
            );
            let p = zeroize::Zeroizing::new(eval(&d.row, Scalar::from(id)));
            return Ok(record(
                src,
                src,
                self.cfg.id as usize,
                id,
                nonce,
                d.key_epoch,
                pk,
                d.sk,
                *p,
                true,
                if d.fault == "invalid_partial" {
                    "bad_plaintext"
                } else {
                    ""
                },
            ));
        }
        let plan = d.plan.as_ref().context("no plan")?;
        let certificate = d
            .certificate
            .as_ref()
            .context("no token before certificate")?;
        ensure!(
            plan.nonce == nonce && certificate.digest == plan.digest,
            "release context"
        );
        ensure!(
            from == 1000 + id || (from == 0 && plan.offline.contains(&id)),
            "token recipient authorization"
        );
        let c = d.candidate.as_ref().context("candidate")?;
        let target = c.state.as_ref().context("target")?;
        let pair = zeroize::Zeroizing::new(
            eval(&c.row, Scalar::from(id)).minus(eval(&d.row, Scalar::from(id))),
        );
        let fault = if d.fault == "direct_inconsistent" && !plan.offline.contains(&id) {
            "inconsistent"
        } else if plan.offline.contains(&id) {
            d.fault.as_str()
        } else {
            ""
        };
        let mut rec = record(
            src,
            target,
            self.cfg.id as usize,
            id,
            nonce,
            d.key_epoch,
            pk,
            d.sk,
            *pair,
            false,
            fault,
        );
        if fault == "bad_pop" {
            rec.words[18] = sw(sf(rec.words[18])? + Scalar::ONE);
            let signature = sign(d.sk, keccak(&rec.words[..22].concat()));
            rec.words[22..24].copy_from_slice(&words(signature.r));
            rec.words[24] = sw(signature.s);
        }
        self.event("token_release",json!({"nonce":nonce,"recipient":id,"digest":hex::encode(plan.digest),"record":hex::encode(rec.hash()),"public":plan.offline.contains(&id),"fault":fault}))?;
        Ok(rec)
    }
    fn partial_join(&self, from: u64, id: u64) -> Result<PartialJoin> {
        let activation = Activation::load(&self.cfg, id)?;
        let nonce = u64::from_be_bytes(activation.alpha[24..].try_into()?);
        let rec = self.issue(from, id, nonce, true)?;
        let d = self.disk.lock().unwrap();
        let src = d.source.as_ref().context("source")?;
        ensure!(
            src.id() == activation.state,
            "activation changed during issuance"
        );
        let evaluation = peval(&src.vectors[self.cfg.id as usize - 1], Scalar::from(id));
        let attestation = Attestation::new(&activation, self.cfg.id, d.key_epoch, evaluation, d.sk);
        Ok(PartialJoin {
            record: rec,
            attestation,
        })
    }
    fn enroll(&self) -> Result<Completion> {
        let id = self.cfg.id - 1000;
        let (activation, status) = Activation::observe(&self.cfg, id)?;
        {
            let mut d = self.disk.lock().unwrap();
            if status == 3
                || d.pending_enrollment
                    .as_ref()
                    .is_some_and(|p| enc(&p.completion.activation) != enc(&activation))
            {
                d.pending_enrollment = None;
                self.save(&d)?;
            }
            ensure!(
                status == 1 || status == 2,
                "activation is neither pending nor issued"
            );
            if let Some(pending) = &d.pending_enrollment {
                return Ok(pending.completion.clone());
            }
            if status == 2 {
                return d
                    .completed_enrollment
                    .as_ref()
                    .filter(|c| enc(&c.activation) == enc(&activation))
                    .cloned()
                    .context("issued activation has no recoverable local enrollment");
            }
            // Main.tex's pending-enrollment rule applies equally to a fresh
            // registration and dealer re-issuance during recovery.
            d.begin_enrollment();
            self.save(&d)?;
        }
        ensure!(
            activation.state == current(&self.cfg)?,
            "pending enrollment state"
        );
        let src = state_from_available(&self.cfg)?;
        let header = Header::from(&src);
        ensure!(
            activation.state == header.id && activation.epoch == header.epoch,
            "issuance canonical state"
        );
        let sk = self.disk.lock().unwrap().sk;
        ensure!(
            participant_pk(&self.cfg, id)? == g() * sk,
            "registry binding"
        );
        let mut accepted: Vec<(BatchPartial, Attestation)> = Vec::with_capacity(src.params.n);
        let mut rejected = Vec::new();
        let nonce = u64::from_be_bytes(activation.alpha[24..].try_into()?);
        for j in 1..=src.params.n as u64 {
            let response = (|| -> Result<(BatchPartial, Attestation)> {
                let response: PartialJoin = call(&self.cfg, j, "partial_join", &id)?;
                let (key_epoch, pk) = dealer_key(&self.cfg, j)?;
                let rec = response.record;
                let att = response.attestation;
                context(&rec, &header, &header, nonce, true)?;
                ensure!(
                    rec.dealer() as u64 == j
                        && att.dealer == j
                        && rec.key_epoch() == key_epoch
                        && att.key_epoch == key_epoch
                        && att.verify(&activation, pk),
                    "issuance attestation signature/context"
                );
                let vector = src.vectors[j as usize - 1].clone();
                ensure!(
                    att.evaluation == peval(&vector, Scalar::from(id))
                        && rec.e()? == att.evaluation,
                    "scalar-free attestation evaluation"
                );
                let partial = decrypt_for_batch(&rec, pk, sk)?;
                Ok((
                    BatchPartial {
                        dealer: j,
                        partial,
                        attestation: enc(&att),
                        vector,
                    },
                    att,
                ))
            })();
            match response {
                Ok(p) => accepted.push(p),
                Err(_) => {
                    rejected.push(j);
                    continue;
                }
            }
            if accepted.len() >= src.params.k {
                let batch = accepted.iter().map(|p| p.0.clone()).collect::<Vec<_>>();
                let (valid, bad) =
                    verified_partials(header.id, activation.alpha, header.epoch, id, &batch)?;
                rejected.extend(bad);
                accepted.retain(|p| valid.contains(&p.0.dealer));
                if accepted.len() >= src.params.k {
                    break;
                }
            }
        }
        ensure!(
            accepted.len() >= src.params.k,
            "fewer than k valid issuance partials"
        );
        accepted.sort_by_key(|p| p.0.dealer);
        accepted.truncate(src.params.k);
        let completion = Completion {
            activation,
            attestations: accepted.iter().map(|p| p.1.clone()).collect(),
            vectors: accepted.iter().map(|p| p.0.vector.clone()).collect(),
        };
        {
            let mut d = self.disk.lock().unwrap();
            ensure!(
                d.share.is_none(),
                "pending enrollment must not contain a share"
            );
            d.pending_enrollment = Some(PendingEnrollment {
                completion: completion.clone(),
                header: header.clone(),
                partials: accepted.into_iter().map(|p| p.0).collect(),
                rejected: rejected.clone(),
            });
            self.save(&d)?;
        }
        self.event(
            "enrollment_partials_verified",
            json!({"epoch":header.epoch,"state":hex::encode(header.id),"recipient":id,
                "activation":hex::encode(completion.activation.alpha),"dealers":completion.attestations.iter().map(|p|p.dealer).collect::<Vec<_>>(),"rejected":rejected,
                "verification":"canonical-transcript-fiat-shamir-msm"}),
        )?;
        Ok(completion)
    }
    fn complete_enrollment(&self, alpha: Word) -> Result<bool> {
        let id = self.cfg.id - 1000;
        let (activation, status) = Activation::observe(&self.cfg, id)?;
        ensure!(activation.alpha == alpha, "stale completion activation");
        let mut d = self.disk.lock().unwrap();
        let completed = d.finish_enrollment(&activation, status);
        // Expiration also durably erases the unusable saved partials.
        self.save(&d)?;
        if let Some(pending) = completed? {
            self.event("issued", json!({"epoch":activation.epoch,"state":hex::encode(activation.state),
                "recipient":id,"activation":hex::encode(alpha),
                "dealers":pending.partials.iter().map(|p|p.dealer).collect::<Vec<_>>(),"rejected":pending.rejected,
                "registry_status":"issued","verification":"canonical-transcript-fiat-shamir-msm"}))?;
            return Ok(true);
        }
        Ok(false)
    }
    fn stage(&self, plan: Plan) -> Result<Ack> {
        let d = self.disk.lock().unwrap().clone();
        ensure!(
            d.fault != "withhold_ack",
            "injected missing staging acknowledgment"
        );
        let id = self.cfg.id - 1000;
        let header = d.header.as_ref().context("not issued")?;
        ensure!(
            header.id == plan.source.id && !plan.offline.contains(&id),
            "stage source/classification"
        );
        ensure!(
            current(&self.cfg)? == plan.source.id
                && query_word(
                    &self.cfg,
                    "reservation(uint256)",
                    &[Arg::Word(word(plan.nonce))]
                )? == plan.digest,
            "stage canonical reservation"
        );
        // Obtain public vectors whose complete state digests match the reservation.
        // No private dealer state is used to check a direct partial.
        let mut public_states = None;
        for j in 1..=plan.target.params.n as u64 {
            let states = (|| -> Result<(State, State)> {
                let source: State = call(&self.cfg, j, "state", &())?;
                let target: State = call(&self.cfg, j, "target_state", &plan.nonce)?;
                ensure!(
                    enc(&Header::from(&source)) == enc(&plan.source)
                        && enc(&Header::from(&target)) == enc(&plan.target),
                    "direct partial vector anchors"
                );
                Ok((source, target))
            })();
            if let Ok(states) = states {
                public_states = Some(states);
                break;
            }
        }
        let (source_state, target_state) =
            public_states.context("anchored direct vectors unavailable")?;
        let mut parts = zeroize::Zeroizing::new(Vec::new());
        let mut rejected = Vec::new();
        for j in 1..=plan.target.params.n as u64 {
            let checked = (|| -> Result<Pair> {
                let rec: Record = call(&self.cfg, j, "issue", &(id, plan.nonce, false))?;
                context(&rec, &plan.source, &plan.target, plan.nonce, false)?;
                ensure!(
                    rec.dealer() == j as usize && rec.id() == id,
                    "direct sender/recipient"
                );
                let key = current_dealer_meta(&self.cfg, j)?;
                ensure!(rec.key_epoch() == key.key_epoch, "record key epoch");
                let partial = zeroize::Zeroizing::new(decrypt(&rec, key.pk, d.sk)?);
                ensure!(
                    partial.commit()
                        == peval(
                            &delta(
                                &source_state.vectors[j as usize - 1],
                                &target_state.vectors[j as usize - 1]
                            ),
                            Scalar::from(id)
                        ),
                    "direct partial dealer commitment"
                );
                Ok(*partial)
            })();
            if let Ok(partial) = checked {
                parts.push((j, partial));
                if parts.len() == plan.target.params.k {
                    break;
                }
            } else {
                rejected.push(j);
            }
        }
        ensure!(
            parts.len() >= plan.target.params.k,
            "insufficient valid direct partials"
        );
        let token = zeroize::Zeroizing::new(combine(&parts[..plan.target.params.k])?);
        ensure!(
            token.commit()
                == peval(
                    &delta(&header.public, &plan.target.public),
                    Scalar::from(id)
                ),
            "direct token Verify"
        );
        ensure!(
            d.share.context("share")?.plus(*token).commit()
                == peval(&plan.target.public, Scalar::from(id)),
            "target share Verify"
        );
        {
            let mut d = self.disk.lock().unwrap();
            d.staged = Some(Staged {
                nonce: plan.nonce,
                token: *token,
                target: plan.target.clone(),
            });
            self.save(&d)?;
        }
        self.event(
            "durable_stage_ack",
            json!({"nonce":plan.nonce,"target":hex::encode(plan.target.id),"valid_dealers":parts.iter().map(|(id,_)|*id).collect::<Vec<_>>(),"rejected_dealers":rejected}),
        )?;
        Ok(Ack {
            id,
            nonce: plan.nonce,
            target: plan.target.id,
            signature: sign(d.sk, ack_message(id, plan.nonce, plan.target.id)),
        })
    }
    fn recover(&self, mid: Word) -> Result<ReturnResult> {
        let m: Manifest = fetch_verified(&self.cfg, "manifest", &mid, |m: &Manifest| {
            ensure!(m.id() == mid, "manifest digest");
            check_publication(&self.cfg, m, true)
        })?;
        let id = self.cfg.id - 1000;
        let snapshot = self.disk.lock().unwrap().clone();
        let mut result = ReturnResult {
            ok: false,
            read: 0,
            localized: 0,
            bytes: enc(&m).len(),
            bad: vec![],
            proofs: vec![],
            vector_fetches: 0,
        };
        if snapshot.applied.contains(&m.nonce)
            && snapshot
                .header
                .as_ref()
                .is_some_and(|h| h.id == m.target.id)
        {
            result.ok = true;
            return Ok(result);
        }
        ensure!(
            enc(snapshot.header.as_ref().context("header")?) == enc(&m.source)
                && m.offline.contains(&id),
            "return source and recipient classification"
        );
        let mut selected = Vec::new();
        let mut checked = BTreeSet::new();
        let expected = peval(&delta(&m.source.public, &m.target.public), Scalar::from(id));
        // A log's storage order need not be dealer order. Use the canonical
        // smallest available distinct dealer identities for each aggregate.
        let mut candidates = m
            .record_ids
            .iter()
            .enumerate()
            .filter(|(_, (_, recipient, _))| *recipient == id)
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(_, (dealer, _, _))| *dealer);
        for (index, (j, _, rhash)) in candidates {
            let key = &m.keys[*j as usize - 1];
            let fetched: Result<RecordProof> =
                fetch_verified(&self.cfg, "record", &(mid, index), |p: &RecordProof| {
                    ensure!(
                        p.index == index
                            && p.record.hash() == *rhash
                            && crate::chain::field_member(
                                m.record_root,
                                record_leaf(index, *rhash),
                                index,
                                &p.proof
                            ),
                        "record membership"
                    );
                    context(&p.record, &m.source, &m.target, m.nonce, false)?;
                    ensure!(
                        p.record.dealer() as u64 == *j
                            && p.record.id() == id
                            && p.record.key_epoch() == key.key_epoch,
                        "anchored dealer/recipient/key binding"
                    );
                    ensure!(
                        point(&p.record.words[12..])? == g() * snapshot.sk,
                        "record recipient key"
                    );
                    Ok(())
                });
            let Ok(p) = fetched else { continue };
            result.read += 1;
            result.bytes += enc(&p).len();
            let rec = p.record;
            // A correctly signed, anchored malformed epk proof is itself
            // publicly verifiable dealer misconduct. No decryption witness
            // exists or is required for this branch.
            if signed_record(&rec, key.pk).is_err() {
                continue;
            }
            if !pop_ok(&rec).unwrap_or(false) {
                result.proofs.push(Vec::new());
                result.bad.push(rec);
                continue;
            }
            let part = match decrypt(&rec, key.pk, snapshot.sk) {
                Ok(v) => v,
                Err(_) => {
                    if authenticated(&rec, key.pk).is_ok() {
                        if let Ok(proof) = decryption_proof(&rec, snapshot.sk) {
                            result.proofs.push(proof);
                            result.bad.push(rec);
                        }
                    }
                    continue;
                }
            };
            selected.push((*j, zeroize::Zeroizing::new(part), rec));
            if selected.len() >= m.target.params.k {
                let parts = zeroize::Zeroizing::new(
                    selected
                        .iter()
                        .map(|(j, p, _)| (*j, **p))
                        .collect::<Vec<_>>(),
                );
                let token = zeroize::Zeroizing::new(combine(&parts[..m.target.params.k])?);
                if token.commit() == expected {
                    let share =
                        zeroize::Zeroizing::new(snapshot.share.context("old share")?.plus(*token));
                    ensure!(
                        share.commit() == peval(&m.target.public, Scalar::from(id)),
                        "return final Verify"
                    );
                    let mut d = self.disk.lock().unwrap();
                    ensure!(
                        d.header.as_ref().is_some_and(|h| h.id == m.source.id),
                        "return state unchanged while fetching"
                    );
                    if let Some(old) = &mut d.share {
                        old.erase();
                    }
                    d.share = Some(*share);
                    d.header = Some(m.target.clone());
                    d.staged = None;
                    d.applied.insert(m.nonce);
                    self.save(&d)?;
                    result.ok = true;
                    self.event("catchup_applied",json!({"nonce":m.nonce,"target":hex::encode(m.target.id),"records":result.read,"localized":result.localized,"vector_fetches":result.vector_fetches}))?;
                    return Ok(result);
                }
                let mut keep = Vec::new();
                for (j, p, rec) in selected.drain(..) {
                    if checked.contains(&j) {
                        keep.push((j, p, rec));
                        continue;
                    }
                    let fetched: Result<(Vec<Point>, Vec<Point>)> = fetch_verified(
                        &self.cfg,
                        "vectors",
                        &(mid, j),
                        |vectors: &(Vec<Point>, Vec<Point>)| {
                            ensure!(
                                vectors.0.len() == m.source.params.t
                                    && vectors.1.len() == m.target.params.t
                                    && vector_tree(&vectors.0).root()
                                        == m.source.roots[j as usize - 1]
                                    && vector_tree(&vectors.1).root()
                                        == m.target.roots[j as usize - 1],
                                "vector anchors"
                            );
                            Ok(())
                        },
                    );
                    let Ok(vectors) = fetched else { continue };
                    result.bytes += enc(&vectors).len();
                    result.vector_fetches += 1;
                    if p.commit() != peval(&delta(&vectors.0, &vectors.1), Scalar::from(id)) {
                        result.localized += 1;
                        result.proofs.push(Vec::new());
                        result.bad.push(rec);
                    } else {
                        checked.insert(j);
                        keep.push((j, p, rec));
                    }
                }
                selected = keep;
            }
        }
        self.event(
            "catchup_insufficient",
            json!({"nonce":m.nonce,"valid":selected.len()}),
        )?;
        Ok(result)
    }
    fn dispatch(self: &Arc<Self>, from: u64, op: &str, b: &[u8]) -> Result<Vec<u8>> {
        match op {
            "ping" => Ok(enc(&true)),
            "meta" => Ok(enc(&self.meta())),
            "registration_proof" => {
                self.admin(from)?;
                ensure!(
                    self.cfg.role == "participant",
                    "participant registration role"
                );
                let sk = self.disk.lock().unwrap().sk;
                Ok(enc(&RegistrationProof::new(
                    current(&self.cfg)?,
                    self.cfg.id - 1000,
                    sk,
                )))
            }
            "state" => Ok(enc(&self.source()?)),
            "header" => Ok(enc(&self
                .disk
                .lock()
                .unwrap()
                .header
                .clone()
                .context("participant header")?)),
            "status" => {
                let d = self.disk.lock().unwrap();
                let mut v = stats();
                v["epoch"] = json!(d
                    .source
                    .as_ref()
                    .map(|s| s.epoch)
                    .or(d.header.as_ref().map(|h| h.epoch)));
                v["applied"] = json!(d.applied.len());
                v["reservations"] = json!(d.reservations.len());
                v["key_epoch"] = json!(d.key_epoch);
                v["has_share"] = json!(d.share.is_some());
                v["pending_enrollment"] = json!(d.pending_enrollment.is_some());
                let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
                unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
                v["peak_rss_bytes"] = json!(usage.ru_maxrss * 1024);
                v["cpu_ns"] = json!(
                    (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1_000_000_000
                        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) * 1000
                );
                Ok(enc(&v.to_string()))
            }
            "owner_init" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "owner", "owner role");
                let p: Params = decode(b)?;
                ensure!(
                    self.cfg.participant_corruption_budget < p.t,
                    "initial threshold must exceed the participant corruption budget"
                );
                self.check_release_policy()?;
                ensure!(
                    self.disk.lock().unwrap().source.is_none(),
                    "owner cannot reinitialize"
                );
                // Synthetic benchmark input s is supplied to one constant-term
                // VSS. r0 is sampled independently inside this ShareInit call.
                let mut secret = Pair {
                    v: random(),
                    r: random(),
                };
                let encoded_secret = zeroize::Zeroizing::new(enc(&secret));
                let oracle = keccak(&encoded_secret);
                drop(encoded_secret);
                let (commitments, mut shares) = initial_constant(p, secret)?;
                secret.erase();
                super::generation::publish_initial(&self.cfg, p, &commitments)?;
                let mut seeded = Vec::new();
                for (j, share) in shares.iter_mut().enumerate() {
                    if call::<_, bool>(
                        &self.cfg,
                        j as u64 + 1,
                        "bootstrap",
                        &InitialSeed {
                            params: p,
                            commitments: commitments.clone(),
                            share: *share,
                        },
                    )
                    .unwrap_or(false)
                    {
                        seeded.push(j as u64 + 1);
                    }
                    share.erase();
                }
                shares.clear();
                ensure!(seeded.len() >= p.n - p.f, "owner VSS delivery quorum");
                // No owner input, sharing polynomial, or secret pair is stored
                // on disk or retained while dealers generate higher coefficients.
                let started = seeded
                    .into_iter()
                    .filter(|id| {
                        call::<_, bool>(&self.cfg, *id, "generate_initial", &()).unwrap_or(false)
                    })
                    .collect::<Vec<_>>();
                ensure!(
                    started.len() >= p.n - p.f,
                    "initial generation participant quorum"
                );
                let mut outputs: BTreeMap<Word, (State, Vec<u64>)> = BTreeMap::new();
                let mut waiting = self.cfg.clone();
                waiting.timeout_ms = waiting.timeout_ms.saturating_mul(10).saturating_add(10000);
                for id in started {
                    let Ok(target) = wait_call::<_, State>(&waiting, id, "target_state", &0u64)
                    else {
                        continue;
                    };
                    if target.epoch != 0
                        || enc(&target.params) != enc(&p)
                        || target.public.first() != commitments.first()
                    {
                        continue;
                    }
                    let Ok(checked) = state(0, p, target.vectors.clone()) else {
                        continue;
                    };
                    if checked.id() != target.id() {
                        continue;
                    }
                    outputs
                        .entry(target.id())
                        .or_insert_with(|| (target, Vec::new()))
                        .1
                        .push(id);
                }
                let (state, ready) = outputs
                    .into_values()
                    .find(|(_, ids)| ids.len() >= p.n - p.f)
                    .context("initial state agreement quorum")?;
                let installed = ready
                    .iter()
                    .filter(|id| {
                        call::<_, bool>(&self.cfg, **id, "install_initial", &state.id())
                            .unwrap_or(false)
                    })
                    .count();
                ensure!(installed >= p.n - p.f, "initial install quorum");
                {
                    let mut d = self.disk.lock().unwrap();
                    d.source = Some(state.clone());
                    self.save(&d)?;
                }
                self.event("bootstrap",json!({"state":hex::encode(state.id()),"n":p.n,"t":p.t,
                    "owner_vss_invocations":1,"dealer_jrss_invocations":p.n*(p.t-1),"owner_inputs_erased":true}))?;
                // The controller retains only this one-way digest as an external
                // equality oracle. It is not part of any live protocol state.
                Ok(enc(&(state, oracle)))
            }
            "bootstrap" => {
                ensure!(
                    self.cfg.role == "dealer" && self.cfg.role(from)? == "owner",
                    "bootstrap authority"
                );
                let seed: InitialSeed = decode(b)?;
                seed.params.check()?;
                ensure!(
                    self.cfg.participant_corruption_budget < seed.params.t,
                    "initial dealer release policy"
                );
                let (canonical_params, canonical_commitments) =
                    super::generation::initial(&self.cfg)?;
                ensure!(
                    enc(&canonical_params) == enc(&seed.params)
                        && canonical_commitments == seed.commitments,
                    "canonical owner VSS broadcast"
                );
                ensure!(
                    seed.params.n == self.cfg.n
                        && seed.params.k == self.cfg.k
                        && seed.params.f == self.cfg.f
                        && seed.commitments.len() == seed.params.k
                        && seed.share.commit()
                            == peval(&seed.commitments, Scalar::from(self.cfg.id)),
                    "owner constant Pedersen VSS"
                );
                let mut d = self.disk.lock().unwrap();
                ensure!(
                    d.source.is_none() && d.initial.is_none(),
                    "owner cannot reinitialize"
                );
                d.initial = Some(seed);
                self.save(&d)?;
                Ok(enc(&true))
            }
            "generate_initial" => {
                ensure!(
                    self.cfg.role == "dealer" && self.cfg.role(from)? == "owner",
                    "initial generation authority"
                );
                let p = self
                    .disk
                    .lock()
                    .unwrap()
                    .initial
                    .as_ref()
                    .context("constant VSS pending")?
                    .params;
                ensure!(
                    self.generation.lock().unwrap().is_none(),
                    "initial generation already running"
                );
                {
                    let mut d = self.disk.lock().unwrap();
                    ensure!(
                        d.generation_attempt.is_none(),
                        "initial generation ownership"
                    );
                    d.generation_attempt = Some(0);
                    self.save(&d)?;
                    self.generation_workers.lock().unwrap().insert(0);
                }
                let node = self.clone();
                let req = Generation {
                    nonce: 0,
                    t: p.t,
                    eligible: 0,
                    offline: vec![],
                    bad_share: false,
                };
                std::thread::spawn(move || {
                    let _finished = GenerationWorker {
                        node: node.clone(),
                        nonce: 0,
                    };
                    if let Err(e) = node.clone().generate(req) {
                        let msg = format!("{e:#}");
                        let _ = node.event("generation_failed", json!({"error":msg}));
                        if let Some(m) = node
                            .generation
                            .lock()
                            .unwrap()
                            .as_mut()
                            .filter(|m| m.request.nonce == 0)
                        {
                            m.error = Some(msg);
                        }
                    }
                });
                Ok(enc(&true))
            }
            "install_initial" => {
                ensure!(
                    self.cfg.role == "dealer" && self.cfg.role(from)? == "owner",
                    "initial install authority"
                );
                let id: Word = decode(b)?;
                let mut d = self.disk.lock().unwrap();
                ensure!(
                    d.source.is_none() && d.initial.is_some(),
                    "initial install once"
                );
                let candidate = d.candidate.take().context("initial candidate")?;
                let target = candidate.state.context("initial target")?;
                ensure!(
                    candidate.request.nonce == 0 && target.epoch == 0 && target.id() == id,
                    "initial target binding"
                );
                if let Some(seed) = d.initial.as_mut() {
                    seed.share.erase();
                }
                d.initial = None;
                d.generation_attempt = None;
                d.row = candidate.row;
                d.source = Some(target);
                self.save(&d)?;
                drop(d);
                self.wait_generation_stopped(0)?;
                Ok(enc(&true))
            }
            "generate" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "dealer", "dealer role");
                let req: Generation = decode(b)?;
                let source = self.source()?;
                ensure!(
                    req.eligible >= req.t && self.cfg.target_budget_allows(req.offline.len(), req.t),
                    "precheck before generation: eligible={}, target_t={}, offline={}, corruption_budget={}, outgoing_budget={}; require eligible >= target_t, offline <= outgoing_budget, and corruption_budget + offline + outgoing_budget < target_t",
                    req.eligible, req.t, req.offline.len(), self.cfg.participant_corruption_budget, self.cfg.outgoing_recipient_budget
                );
                self.check_release_policy()?;
                ensure!(current(&self.cfg)? == source.id(), "canonical source");
                ensure!(
                    query_word(&self.cfg, "population()", &[])? == word(req.eligible as u64)
                        && query_word(&self.cfg, "pendingParticipants()", &[])? == word(0),
                    "pre-generation actual eligibility and pending issuance"
                );
                ensure!(
                    req.offline.iter().copied().collect::<BTreeSet<_>>().len() == req.offline.len(),
                    "distinct offline identifiers"
                );
                for id in &req.offline {
                    ensure!(
                        *id > 0
                            && self.cfg.role(1000 + id)? == "participant"
                            && query_word(
                                &self.cfg,
                                "activeParticipant(uint256)",
                                &[Arg::Word(word(*id))]
                            )? == word(1),
                        "registered offline recipient"
                    );
                }
                {
                    let mut d = self.disk.lock().unwrap();
                    ensure!(
                        d.candidate.is_none() && d.generation_attempt.is_none(),
                        "candidate exists"
                    );
                    d.generation_attempt = Some(req.nonce);
                    self.save(&d)?;
                    self.generation_workers.lock().unwrap().insert(req.nonce);
                }
                let node = self.clone();
                let nonce = req.nonce;
                std::thread::spawn(move || {
                    let _finished = GenerationWorker {
                        node: node.clone(),
                        nonce,
                    };
                    if let Err(e) = node.clone().generate(req) {
                        let msg = format!("{e:#}");
                        let _ = node.event("generation_failed", json!({"error":msg}));
                        if let Some(m) = node
                            .generation
                            .lock()
                            .unwrap()
                            .as_mut()
                            .filter(|m| m.request.nonce == nonce)
                        {
                            m.error = Some(msg)
                        }
                    }
                });
                Ok(enc(&true))
            }
            "subshare" => {
                ensure!(self.cfg.role(from)? == "dealer", "private share recipient");
                let nonce: u64 = decode(b)?;
                let mem = self.generation.lock().unwrap();
                let m = mem.as_ref().context("generation pending")?;
                ensure!(m.request.nonce == nonce, "nonce");
                let mut shares =
                    zeroize::Zeroizing::new(m.contribution.shares[from as usize - 1].clone());
                if m.request.bad_share && self.cfg.id == 1 {
                    shares[0].v += Scalar::ONE
                }
                Ok(enc(&*shares))
            }
            "target_state" => {
                let nonce: u64 = decode(b)?;
                let d = self.disk.lock().unwrap();
                let c = d.candidate.as_ref().context("generation not ready")?;
                ensure!(c.request.nonce == nonce, "nonce");
                let target = c.state.clone().context("generation not ready")?;
                drop(d);
                self.wait_generation_stopped(nonce)?;
                Ok(enc(&target))
            }
            "reserve_intent" => {
                self.admin(from)?;
                let (nonce, eligible, offline): (u64, usize, Vec<u64>) = decode(b)?;
                let source = self.source()?;
                let target = self.candidate()?;
                ensure!(
                    current(&self.cfg)? == source.id()
                        && eligible >= target.params.t
                        && self
                            .cfg
                            .target_budget_allows(offline.len(), target.params.t),
                    "reservation guards"
                );
                let old = query_word(&self.cfg, "releaseRoot(bytes32)", &[Arg::Word(source.id())])?;
                let plan = Plan::new(
                    nonce,
                    Header::from(&source),
                    Header::from(&target),
                    eligible,
                    offline,
                    old,
                );
                let mut d = self.disk.lock().unwrap();
                ensure!(
                    d.candidate.as_ref().unwrap().request.nonce == nonce,
                    "candidate nonce"
                );
                if let Some(previous) = &d.plan {
                    ensure!(
                        previous.nonce == nonce
                            && previous.source.id == plan.source.id
                            && previous.target.id == plan.target.id
                            && previous.offline.iter().all(|id| plan.offline.contains(id)),
                        "reservation extension must preserve prior recipients and target"
                    );
                }
                d.plan = Some(plan.clone());
                d.certificate = None;
                self.save(&d)?;
                Ok(enc(&(plan.clone(), sign(d.rsk, plan.digest))))
            }
            "certify" => {
                self.admin(from)?;
                let p: Plan = decode(b)?;
                let mut d = self.disk.lock().unwrap();
                ensure!(
                    enc(d.plan.as_ref().context("plan")?) == enc(&p),
                    "exact reservation tuple"
                );
                ensure!(
                    p.eligible >= p.target.params.t
                        && self
                            .cfg
                            .target_budget_allows(p.offline.len(), p.target.params.t),
                    "certification release policy"
                );
                ensure!(
                    query_word(
                        &self.cfg,
                        "reservation(uint256)",
                        &[Arg::Word(word(p.nonce))]
                    )? == p.digest,
                    "chain reservation binding"
                );
                if let Some(old) = d.reservations.get(&(p.nonce, p.old_root)) {
                    ensure!(*old == p.digest, "durable signing lock")
                }
                d.reservations.insert((p.nonce, p.old_root), p.digest);
                self.save(&d)?;
                let s = sign(d.rsk, p.digest);
                self.event(
                    "certificate_signed",
                    json!({"nonce":p.nonce,"digest":hex::encode(p.digest)}),
                )?;
                Ok(enc(&s))
            }
            "release" => {
                self.admin(from)?;
                let c: Certificate = decode(b)?;
                let metas = current_dealer_metas(&self.cfg)?;
                let mut d = self.disk.lock().unwrap();
                let p = d.plan.as_ref().context("plan")?;
                ensure!(
                    c.digest == p.digest
                        && d.reservations.get(&(p.nonce, p.old_root)) == Some(&c.digest)
                        && certificate_ok(&c, &metas, self.cfg.n - self.cfg.f),
                    "release certificate"
                );
                d.certificate = Some(c);
                self.save(&d)?;
                Ok(enc(&true))
            }
            "issue" => {
                ensure!(self.cfg.role == "dealer", "dealer issuance");
                let (id, nonce, snapshot): (u64, u64, bool) = decode(b)?;
                Ok(enc(&self.issue(from, id, nonce, snapshot)?))
            }
            "partial_join" => {
                ensure!(self.cfg.role == "dealer", "dealer issuance");
                Ok(enc(&self.partial_join(from, decode(b)?)?))
            }
            "heartbeat" => {
                let (id, nonce, sig): (u64, u64, Sig) = decode(b)?;
                ensure!(
                    from == 1000 + id
                        && verify(
                            participant_pk(&self.cfg, id)?,
                            keccak(&[b"LIVE".as_slice(), &word(id), &word(nonce)].concat()),
                            &sig
                        ),
                    "liveness authentication"
                );
                Ok(enc(&true))
            }
            "live" => {
                self.admin(from)?;
                let nonce: u64 = decode(b)?;
                let id = self.cfg.id - 1000;
                let sk = self.disk.lock().unwrap().sk;
                let sig = sign(
                    sk,
                    keccak(&[b"LIVE".as_slice(), &word(id), &word(nonce)].concat()),
                );
                let acknowledged = (1..=self.cfg.n as u64)
                    .filter(|j| {
                        matches!(
                            call::<_, bool>(&self.cfg, *j, "heartbeat", &(id, nonce, sig.clone())),
                            Ok(true)
                        )
                    })
                    .count();
                ensure!(
                    acknowledged >= self.cfg.n - self.cfg.f,
                    "liveness committee quorum"
                );
                Ok(enc(&true))
            }
            "enroll" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "participant", "participant role");
                Ok(enc(&self.enroll()?))
            }
            "prepare_recovery" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "participant", "participant role");
                // Erase before requesting the on-chain recover-pending state,
                // so that no registry-pending interval exposes an old share.
                let mut d = self.disk.lock().unwrap();
                d.begin_enrollment();
                self.save(&d)?;
                Ok(enc(&true))
            }
            "complete_enrollment" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "participant", "participant role");
                Ok(enc(&self.complete_enrollment(decode(b)?)?))
            }
            "da_authorization" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "participant", "participant role");
                let (nonce, dealer, challenger): (u64, u64, [u8; 20]) = decode(b)?;
                ensure!(dealer > 0 && dealer <= self.cfg.n as u64, "DA dealer");
                let chain_id = crate::chain::hex_u64(&crate::chain::rpc(
                    &self.cfg.rpc,
                    "eth_chainId",
                    json!([]),
                )?)?;
                let contract = crate::chain::address(&self.cfg.contract)?;
                let message = da_authorization_message(
                    chain_id,
                    contract[12..].try_into()?,
                    nonce,
                    dealer,
                    self.cfg.id - 1000,
                    challenger,
                );
                Ok(enc(&sign(self.disk.lock().unwrap().sk, message)))
            }
            "stage" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "participant", "participant role");
                Ok(enc(&self.stage(decode(b)?)?))
            }
            "ack" => {
                ensure!(self.cfg.role(from)? == "dealer" || from == 0, "ACK reader");
                let nonce: u64 = decode(b)?;
                let d = self.disk.lock().unwrap();
                let s = d.staged.as_ref().context("no durable stage")?;
                ensure!(s.nonce == nonce, "stage nonce");
                let id = self.cfg.id - 1000;
                Ok(enc(&Ack {
                    id,
                    nonce,
                    target: s.target.id,
                    signature: sign(d.sk, ack_message(id, nonce, s.target.id)),
                }))
            }
            "commit_vote" => {
                self.admin(from)?;
                let mid: Word = decode(b)?;
                let bundle: Bundle = fetch_verified(&self.cfg, "bundle", &mid, |b: &Bundle| {
                    ensure!(b.manifest.id() == mid, "commit manifest digest");
                    b.validate()
                })?;
                let m = &bundle.manifest;
                ensure!(
                    m.id() == mid
                        && m.source.id == self.source()?.id()
                        && m.target.id == self.candidate()?.id(),
                    "vote state"
                );
                check_publication(&self.cfg, m, false)?;
                check_reservation_keys(&self.cfg, m)?;
                ensure!(
                    query_word(&self.cfg, "pendingParticipants()", &[])? == word(0),
                    "no pending source activation at finalization"
                );
                let p = self.plan()?;
                ensure!(
                    p.nonce == m.nonce && p.digest == m.reservation && p.offline == m.offline,
                    "vote reservation"
                );
                for id in &p.offline {
                    let mut seen = BTreeSet::new();
                    let recipient_pk = participant_pk(&self.cfg, *id)?;
                    for r in &bundle.records {
                        if r.id() == *id {
                            context(r, &m.source, &m.target, m.nonce, false)?;
                            let key = &m.keys[r.dealer() - 1];
                            ensure!(r.key_epoch() == key.key_epoch, "publication key epoch");
                            signed_record(r, key.pk)?;
                            ensure!(
                                point(&r.words[12..])? == recipient_pk,
                                "published recipient registry binding"
                            );
                            ensure!(seen.insert(r.dealer()), "duplicate dealer publication");
                        }
                    }
                    ensure!(seen.len() >= self.cfg.n - self.cfg.f, "publication quorum");
                }
                let eligible = active_participants(&self.cfg)?;
                ensure!(
                    eligible.len() == p.eligible
                        && p.offline.iter().all(|id| eligible.contains(id)),
                    "finalization recipient set"
                );
                for id in eligible {
                    if p.offline.contains(&id) {
                        continue;
                    }
                    let ack: Ack = call(&self.cfg, 1000 + id, "ack", &p.nonce)?;
                    ensure!(
                        ack.id == id
                            && ack.nonce == p.nonce
                            && ack.target == p.target.id
                            && verify(
                                participant_pk(&self.cfg, id)?,
                                ack_message(id, p.nonce, p.target.id),
                                &ack.signature
                            ),
                        "durable stage ACK"
                    );
                }
                let sig = sign(self.disk.lock().unwrap().sk, m.commit_message());
                self.event("commit_vote",json!({"nonce":p.nonce,"target":hex::encode(p.target.id),"metadata":hex::encode(mid)}))?;
                Ok(enc(&sig))
            }
            "install" => {
                self.admin(from)?;
                let mid: Word = decode(b)?;
                let m: Manifest = fetch(&self.cfg, "manifest", &mid)?;
                ensure!(m.id() == mid, "manifest hash");
                check_publication(&self.cfg, &m, true)?;
                ensure!(committed(&self.cfg, m.target.id)?, "canonical commit");
                let mut d = self.disk.lock().unwrap();
                if self.cfg.role == "dealer" {
                    if d.source.as_ref().is_some_and(|s| s.id() == m.target.id) {
                        return Ok(enc(&false));
                    }
                    ensure!(
                        d.source.as_ref().is_some_and(|s| s.id() == m.source.id)
                            && current(&self.cfg)? == m.target.id,
                        "dealer install source/order"
                    );
                    let c = d.candidate.as_ref().context("candidate")?;
                    let target = c.state.as_ref().context("candidate target")?;
                    ensure!(
                        target.id() == m.target.id
                            && c.request.nonce == m.nonce
                            && d.generation_attempt == Some(m.nonce),
                        "install target"
                    );
                    let c = d.candidate.take().unwrap();
                    let target = c.state.unwrap();
                    for pair in &mut d.row {
                        pair.erase();
                    }
                    d.row = c.row;
                    d.source = Some(target);
                    d.generation_attempt = None;
                    d.plan = None;
                    d.certificate = None;
                    *self.generation.lock().unwrap() = None;
                } else {
                    ensure!(self.cfg.role == "participant", "apply role");
                    if d.applied.contains(&m.nonce) {
                        return Ok(enc(&false));
                    }
                    ensure!(
                        d.header.as_ref().is_some_and(|h| enc(h) == enc(&m.source)),
                        "apply source state/order"
                    );
                    let s = d.staged.as_ref().context("staged token")?;
                    ensure!(
                        s.nonce == m.nonce && enc(&s.target) == enc(&m.target),
                        "apply target"
                    );
                    let share = d.share.context("source share")?.plus(s.token);
                    ensure!(
                        share.commit() == peval(&m.target.public, Scalar::from(self.cfg.id - 1000)),
                        "apply Verify"
                    );
                    d.staged = None;
                    if let Some(old) = &mut d.share {
                        old.erase();
                    }
                    d.share = Some(share);
                    d.header = Some(m.target.clone());
                    d.applied.insert(m.nonce);
                }
                self.save(&d)?;
                drop(d);
                if self.cfg.role == "dealer" {
                    self.wait_generation_stopped(m.nonce)?;
                }
                self.event("commit_applied",json!({"nonce":m.nonce,"epoch":m.target.epoch,"target":hex::encode(m.target.id)}))?;
                Ok(enc(&true))
            }
            "abandon_candidate" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "dealer", "candidate owner role");
                let (source, nonce): (Word, u64) = decode(b)?;
                let published = publication(&self.cfg, nonce)?;
                ensure!(
                    published.len() == 6
                        && published[5] == word(0)
                        && query_word(
                            &self.cfg,
                            "reservation(uint256)",
                            &[Arg::Word(word(nonce))]
                        )? == word(0),
                    "only an unreserved attempt may be abandoned locally"
                );
                ensure!(current(&self.cfg)? == source, "abandon canonical source");
                let mut d = self.disk.lock().unwrap();
                ensure!(
                    d.source.as_ref().is_some_and(|s| s.id() == source),
                    "abandon source owner"
                );
                let mut memory = self.generation.lock().unwrap();
                // Clear ownership before dropping shared private material. A
                // delayed generation thread must check this owner before it
                // can install memory or persist any candidate state.
                let had_candidate = d.abandon_unreserved(nonce, &mut memory)?;
                self.save(&d)?;
                let retained = d.reservations.len();
                drop(memory);
                drop(d);
                self.wait_generation_stopped(nonce)?;
                self.event(
                    "candidate_abandoned",
                    json!({"nonce":nonce,"source":hex::encode(source),
                    "reserved_entries_retained":retained,"had_candidate":had_candidate}),
                )?;
                Ok(enc(&had_candidate))
            }
            "abort" => {
                self.admin(from)?;
                let nonce: u64 = decode(b)?;
                let p = publication(&self.cfg, nonce)?;
                ensure!(p.len() == 6 && p[5] == word(4), "canonical abort");
                let mut d = self.disk.lock().unwrap();
                ensure!(
                    d.generation_attempt.is_none_or(|n| n == nonce)
                        && d.candidate
                            .as_ref()
                            .is_none_or(|c| c.request.nonce == nonce)
                        && d.plan.as_ref().is_none_or(|p| p.nonce == nonce)
                        && d.staged.as_ref().is_none_or(|s| s.nonce == nonce),
                    "abort cannot erase another attempt"
                );
                if let Some(c) = d.candidate.as_mut() {
                    for pair in &mut c.row {
                        pair.erase();
                    }
                }
                d.candidate = None;
                d.generation_attempt = None;
                d.plan = None;
                d.certificate = None;
                d.staged = None;
                *self.generation.lock().unwrap() = None;
                self.save(&d)?;
                let retained = d.reservations.len();
                drop(d);
                if self.cfg.role == "dealer" {
                    self.wait_generation_stopped(nonce)?;
                }
                self.event(
                    "aborted",
                    json!({"nonce":nonce,"reserved_entries":retained}),
                )?;
                Ok(enc(&true))
            }
            "recover" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "participant", "participant role");
                Ok(enc(&self.recover(decode(b)?)?))
            }
            "share" => {
                ensure!(
                    self.cfg.role(from)? == "owner" && self.cfg.role == "participant",
                    "reconstruction recipient"
                );
                let target: Word = decode(b)?;
                let d = self.disk.lock().unwrap();
                ensure!(
                    d.header.as_ref().context("not issued")?.id == target,
                    "reconstruction epoch"
                );
                let mut share = zeroize::Zeroizing::new(d.share.context("share")?);
                if d.fault == "invalid_share" {
                    share.v += Scalar::ONE;
                }
                Ok(enc(&(d.header.clone().unwrap(), *share)))
            }
            "reconstruct" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "owner", "collector role");
                let (n, public): (usize, State) = decode(b)?;
                let target = current(&self.cfg)?;
                ensure!(public.id() == target, "canonical reconstruction state");
                let rebuilt = state(public.epoch, public.params, public.vectors.clone())?;
                ensure!(
                    rebuilt.id() == target,
                    "valid reconstruction commitment record"
                );
                let expected_header = Header::from(&public);
                let mut shares = zeroize::Zeroizing::new(Vec::new());
                for id in 1..=n as u64 {
                    if let Ok((h, p)) =
                        call::<_, (Header, Pair)>(&self.cfg, 1000 + id, "share", &target)
                    {
                        let p = zeroize::Zeroizing::new(p);
                        if enc(&h) != enc(&expected_header)
                            || p.commit() != peval(&public.public, Scalar::from(id))
                        {
                            self.event(
                                "reconstruction_share_rejected",
                                json!({"recipient":id,"state":hex::encode(target)}),
                            )?;
                            continue;
                        }
                        shares.push((id, *p));
                        if shares.len() >= public.params.t {
                            break;
                        }
                    }
                }
                let mut secret = reconstruct(&public, &shares)?;
                let secret_digest = digest(&secret);
                secret.erase();
                shares.iter_mut().for_each(|(_, p)| p.erase());
                self.event(
                    "secret_reconstructed",
                    json!({"epoch":public.epoch,"shares":shares.len(),"commitment_verified":true,"secret_digest":hex::encode(secret_digest)}),
                )?;
                Ok(enc(
                    &json!({"epoch":public.epoch,"shares":shares.len(),"threshold":public.params.t,"secret_digest":hex::encode(secret_digest),"public_constant":words(public.public[0])}).to_string(),
                ))
            }
            "dispute_trace" => {
                self.admin(from)?;
                let (mid, record_hash): (Word, Word) = decode(b)?;
                let bundle: Bundle = fetch(&self.cfg, "bundle", &mid)?;
                bundle.validate()?;
                check_publication(&self.cfg, &bundle.manifest, true)?;
                let r = bundle
                    .records
                    .iter()
                    .find(|r| r.hash() == record_hash)
                    .context("disputed record")?;
                let j = r.dealer();
                let dv = delta(&bundle.source.vectors[j - 1], &bundle.target.vectors[j - 1]);
                let mut points = vec![Point::default()];
                let mut power = Scalar::ONE;
                for p in dv {
                    points.push(*points.last().unwrap() + p * power);
                    power *= Scalar::from(r.id());
                }
                if self.cfg.role == "dealer" {
                    ensure!(self.cfg.id == j as u64, "defending dealer");
                    *points.last_mut().unwrap() = r.e()?;
                } else {
                    ensure!(
                        self.cfg.role == "participant" && self.cfg.id == 1000 + r.id(),
                        "challenging participant"
                    );
                }
                self.event("dispute_trace",json!({"nonce":bundle.manifest.nonce,"record":hex::encode(record_hash),"points":points.len()}))?;
                Ok(enc(&points))
            }
            "set_fault" => {
                self.admin(from)?;
                let fault: String = decode(b)?;
                ensure!(
                    (self.cfg.role == "dealer" && self.cfg.id == 1)
                        || self.cfg.role == "participant",
                    "configured fault role"
                );
                ensure!(
                    fault.is_empty()
                        || (self.cfg.role == "participant"
                            && matches!(fault.as_str(), "withhold_ack" | "invalid_share"))
                        || (self.cfg.role == "dealer"
                            && matches!(
                                fault.as_str(),
                                "inconsistent"
                                    | "bad_plaintext"
                                    | "bad_pop"
                                    | "invalid_partial"
                                    | "omit_partial"
                                    | "direct_inconsistent"
                            )),
                    "fault type for role"
                );
                let mut d = self.disk.lock().unwrap();
                d.fault = fault.clone();
                self.save(&d)?;
                self.event("fault_injected", json!({"fault":fault}))?;
                Ok(enc(&true))
            }
            "rotate" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "dealer", "dealer role");
                {
                    let mut d = self.disk.lock().unwrap();
                    ensure!(d.candidate.is_none(), "rotate between attempts");
                    d.sk = nonzero();
                    d.rsk = nonzero();
                    d.key_epoch += 1;
                    self.save(&d)?;
                }
                Ok(enc(&self.meta()))
            }
            "put" => {
                ensure!(
                    self.cfg.role == "archive" && (from == 0 || self.cfg.role(from)? == "dealer"),
                    "archive writer"
                );
                let bundle: Bundle = decode(b)?;
                bundle.validate()?;
                let id = bundle.manifest.id();
                crate::ledger::durable_write(
                    &self.cfg.dir.join(format!("{}.bundle", hex::encode(id))),
                    b,
                )?;
                self.event(
                    "archive_put",
                    json!({"metadata":hex::encode(id),"bytes":b.len()}),
                )?;
                Ok(enc(&id))
            }
            "bundle" | "manifest" => {
                ensure!(self.cfg.role == "archive", "archive role");
                let mid: Word = decode(b)?;
                let bytes = fs::read(self.cfg.dir.join(format!("{}.bundle", hex::encode(mid))))?;
                if op == "bundle" {
                    Ok(bytes)
                } else {
                    let bundle: Bundle = decode(&bytes)?;
                    Ok(enc(&bundle.manifest))
                }
            }
            "record" => {
                ensure!(self.cfg.role == "archive", "archive role");
                let (mid, index): (Word, usize) = decode(b)?;
                let hidden = self.cfg.dir.join(format!("{}.hidden", hex::encode(mid)));
                if hidden.exists() {
                    let ids: Vec<usize> = decode(&fs::read(hidden)?)?;
                    ensure!(!ids.contains(&index), "record unavailable");
                }
                let bundle: Bundle = decode(&fs::read(
                    self.cfg.dir.join(format!("{}.bundle", hex::encode(mid))),
                )?)?;
                let record = bundle.records.get(index).context("record index")?.clone();
                let value = RecordProof {
                    record,
                    index,
                    proof: bundle.tree().proof(index),
                };
                self.event(
                    "archive_record_read",
                    json!({"metadata":hex::encode(mid),"index":index,"bytes":enc(&value).len()}),
                )?;
                Ok(enc(&value))
            }
            "vectors" => {
                ensure!(self.cfg.role == "archive", "archive role");
                let (mid, j): (Word, u64) = decode(b)?;
                let bundle: Bundle = decode(&fs::read(
                    self.cfg.dir.join(format!("{}.bundle", hex::encode(mid))),
                )?)?;
                ensure!(j > 0 && j <= self.cfg.n as u64, "vector index");
                self.event(
                    "archive_vector_read",
                    json!({"metadata":hex::encode(mid),"dealer":j}),
                )?;
                Ok(enc(&(
                    bundle.source.vectors[j as usize - 1].clone(),
                    bundle.target.vectors[j as usize - 1].clone(),
                )))
            }
            "hide" => {
                self.admin(from)?;
                ensure!(self.cfg.role == "archive", "archive role");
                let (mid, ids): (Word, Vec<usize>) = decode(b)?;
                crate::ledger::durable_write(
                    &self.cfg.dir.join(format!("{}.hidden", hex::encode(mid))),
                    &enc(&ids),
                )?;
                self.event(
                    "archive_records_hidden",
                    json!({"manifest":hex::encode(mid),"indices":ids}),
                )?;
                Ok(enc(&true))
            }
            _ => bail!("unsupported role operation {op}"),
        }
    }
}
pub fn serve_node(path: &std::path::Path) -> Result<()> {
    let cfg: NodeConfig = serde_json::from_slice(&fs::read(path)?)?;
    fs::create_dir_all(&cfg.dir)?;
    let private = cfg.dir.join("private.bin");
    let disk = if private.exists() {
        let bytes = zeroize::Zeroizing::new(fs::read(&private)?);
        decode(&bytes)?
    } else {
        Disk::new()
    };
    let node = Arc::new(Node {
        cfg: cfg.clone(),
        disk: Mutex::new(disk),
        generation: Mutex::new(None),
        generation_workers: Mutex::new(BTreeSet::new()),
        generation_finished: Condvar::new(),
        started: Instant::now(),
        event_lock: Mutex::new(()),
    });
    node.save(&node.disk.lock().unwrap())?;
    node.event("process_started", json!({"suite":SUITE}))?;
    serve(cfg, Arc::new(move |from, op, b| node.dispatch(from, op, b)))
}

#[cfg(test)]
mod enrollment_state_tests {
    use super::*;

    fn pending() -> (Disk, Activation) {
        let params = Params {
            n: 4,
            k: 2,
            f: 1,
            t: 4,
        };
        let (state, rows) = init(params).unwrap();
        let mut disk = Disk::new();
        let activation = Activation {
            alpha: word(10),
            state: state.id(),
            epoch: state.epoch,
            id: 3,
            pk: g() * disk.sk,
        };
        let partials = rows
            .iter()
            .take(params.k)
            .enumerate()
            .map(|(j, row)| BatchPartial {
                dealer: j as u64 + 1,
                partial: eval(row, Scalar::from(activation.id)),
                attestation: vec![],
                vector: state.vectors[j].clone(),
            })
            .collect();
        disk.pending_enrollment = Some(PendingEnrollment {
            completion: Completion {
                activation: activation.clone(),
                attestations: vec![],
                vectors: vec![],
            },
            header: Header::from(&state),
            partials,
            rejected: vec![],
        });
        (disk, activation)
    }

    #[test]
    fn pending_activation_has_no_share_even_after_restart() {
        let (mut disk, activation) = pending();
        assert!(disk.finish_enrollment(&activation, 1).is_err());
        assert!(disk.share.is_none() && disk.header.is_none());
        let serialized = zeroize::Zeroizing::new(enc(&disk));
        let mut restarted: Disk = decode(&serialized).unwrap();
        assert!(restarted.share.is_none() && restarted.header.is_none());
        assert!(restarted
            .finish_enrollment(&activation, 2)
            .unwrap()
            .is_some());
        assert!(restarted.pending_enrollment.is_none());
        assert_eq!(
            restarted.share.unwrap().commit(),
            peval(
                &restarted.header.as_ref().unwrap().public,
                Scalar::from(activation.id)
            )
        );
        let installed = zeroize::Zeroizing::new(enc(&restarted));
        assert!(restarted
            .finish_enrollment(&activation, 2)
            .unwrap()
            .is_none());
        assert_eq!(enc(&restarted), *installed);
    }

    #[test]
    fn expired_or_mismatched_activation_cannot_install_a_share() {
        let (mut disk, activation) = pending();
        let mut other = activation.clone();
        other.alpha = word(11);
        assert!(disk.finish_enrollment(&other, 2).is_err());
        assert!(disk.share.is_none() && disk.pending_enrollment.is_some());
        assert!(disk.finish_enrollment(&activation, 3).is_err());
        assert!(disk.share.is_none() && disk.pending_enrollment.is_none());
        assert!(disk.finish_enrollment(&activation, 2).is_err());
    }

    #[test]
    fn corrupted_saved_partials_are_not_installed_after_registry_completion() {
        let (mut disk, activation) = pending();
        disk.pending_enrollment.as_mut().unwrap().partials[0]
            .partial
            .v += Scalar::ONE;
        assert!(disk.finish_enrollment(&activation, 2).is_err());
        assert!(disk.share.is_none() && disk.pending_enrollment.is_some());
    }

    #[test]
    fn recovery_enrollment_erases_previous_share_and_staging_before_partial_collection() {
        let (mut disk, activation) = pending();
        disk.finish_enrollment(&activation, 2).unwrap();
        assert!(disk.share.is_some());
        disk.begin_enrollment();
        assert!(disk.share.is_none() && disk.header.is_none() && disk.staged.is_none());
    }
}

#[cfg(test)]
mod generation_worker_tests {
    use super::*;
    fn fixture() -> Arc<Node> {
        Arc::new(Node {
            cfg: NodeConfig {
                run: "worker-test".into(),
                id: 1,
                role: "dealer".into(),
                port: 0,
                dir: Default::default(),
                tls: Default::default(),
                peers: vec![],
                rpc: String::new(),
                contract: String::new(),
                n: 4,
                k: 2,
                f: 1,
                participant_corruption_budget: 1,
                outgoing_recipient_budget: 2,
                timeout_ms: 100,
            },
            disk: Mutex::new(Disk::new()),
            generation: Mutex::new(None),
            generation_workers: Mutex::new([7].into_iter().collect()),
            generation_finished: Condvar::new(),
            started: Instant::now(),
            event_lock: Mutex::new(()),
        })
    }
    #[test]
    fn completion_wait_does_not_acknowledge_a_live_generation_worker() {
        let node = fixture();
        let finished = GenerationWorker {
            node: node.clone(),
            nonce: 7,
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = node.clone();
        let thread = std::thread::spawn(move || {
            worker.wait_generation_stopped(7).unwrap();
            tx.send(()).unwrap();
        });
        assert!(matches!(
            rx.recv_timeout(std::time::Duration::from_millis(30)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(finished);
        rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        thread.join().unwrap();
        node.wait_generation_stopped(999).unwrap();
    }
    #[test]
    fn stale_worker_completion_preserves_a_new_attempts_private_memory() {
        let node = fixture();
        node.generation_workers.lock().unwrap().insert(8);
        *node.generation.lock().unwrap() = Some(GenMemory {
            request: Generation {
                nonce: 8,
                t: 4,
                eligible: 4,
                offline: vec![],
                bad_share: false,
            },
            contribution: Contribution {
                commitments: vec![],
                shares: vec![vec![Pair::random()]],
            },
            error: None,
        });
        drop(GenerationWorker {
            node: node.clone(),
            nonce: 7,
        });
        assert_eq!(
            node.generation
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .request
                .nonce,
            8
        );
        assert!(node.generation_workers.lock().unwrap().contains(&8));
        node.wait_generation_stopped(7).unwrap();
    }
}

#[cfg(test)]
mod abandonment_tests {
    use super::*;

    fn pending(nonce: u64) -> (Disk, Option<GenMemory>) {
        let request = Generation {
            nonce,
            t: 8,
            eligible: 12,
            offline: vec![1],
            bad_share: false,
        };
        let mut d = Disk::new();
        d.generation_attempt = Some(nonce);
        d.row = vec![Pair::random()];
        d.candidate = Some(Candidate {
            request: request.clone(),
            row: vec![Pair::random()],
            state: None,
        });
        d.reservations.insert((nonce - 1, word(9)), word(10));
        let memory = GenMemory {
            request,
            contribution: Contribution {
                commitments: vec![],
                shares: vec![vec![Pair::random()]],
            },
            error: None,
        };
        (d, Some(memory))
    }

    #[test]
    fn abandonment_erases_candidate_and_revokes_generation_ownership_but_preserves_source_and_ledger(
    ) {
        let (mut d, mut memory) = pending(7);
        let source = enc(&d.row);
        let ledger = d.reservations.clone();
        assert!(d.abandon_unreserved(7, &mut memory).unwrap());
        assert!(d.generation_attempt.is_none() && d.candidate.is_none() && memory.is_none());
        assert_eq!(enc(&d.row), source);
        assert_eq!(d.reservations, ledger);
        let restored: Disk = decode(&enc(&d)).unwrap();
        assert!(restored.generation_attempt.is_none() && restored.candidate.is_none());
        assert_eq!(restored.reservations, ledger);
        assert!(!d.abandon_unreserved(7, &mut memory).unwrap());
    }

    #[test]
    fn stale_abandonment_cannot_erase_newer_candidate_or_thread() {
        let (mut d, mut memory) = pending(8);
        let before = enc(&d);
        assert!(d.abandon_unreserved(7, &mut memory).is_err());
        assert_eq!(enc(&d), before);
        assert_eq!(memory.as_ref().unwrap().request.nonce, 8);
    }

    #[test]
    fn certified_attempt_requires_canonical_abort_instead_of_local_abandonment() {
        let (mut d, mut memory) = pending(7);
        d.reservations.insert((7, word(11)), word(12));
        assert!(d.abandon_unreserved(7, &mut memory).is_err());
        assert!(d.candidate.is_some() && memory.is_some());
        d.reservations.remove(&(7, word(11)));
        d.certificate = Some(Certificate {
            digest: word(12),
            signatures: vec![],
        });
        assert!(d.abandon_unreserved(7, &mut memory).is_err());
        assert!(d.candidate.is_some() && memory.is_some());
    }
}
