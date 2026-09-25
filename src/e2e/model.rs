use super::{core::*, wire::*};
use crate::chain::{self, keccak, word, Arg, Word};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
#[derive(Clone, Serialize, Deserialize)]
pub struct Meta {
    pub id: u64,
    pub pk: Point,
    pub reservation: Point,
    pub key_epoch: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Header {
    pub id: Word,
    pub epoch: u64,
    pub params: Params,
    pub public: Vec<Point>,
    pub roots: Vec<Word>,
}
impl From<&State> for Header {
    fn from(s: &State) -> Self {
        Self {
            id: s.id(),
            epoch: s.epoch,
            params: s.params,
            public: s.public.clone(),
            roots: (1..=s.params.n).map(|j| s.root(j)).collect(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Bootstrap {
    pub state: State,
    pub row: Vec<Pair>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub nonce: u64,
    pub source: Word,
    pub commitments: Vec<Vec<Point>>,
    pub sig: Sig,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Echo {
    pub nonce: u64,
    pub proposals: Vec<(u64, Word)>,
    pub complaints: Vec<u64>,
    pub sig: Sig,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Generation {
    pub nonce: u64,
    pub t: usize,
    pub eligible: usize,
    pub offline: Vec<u64>,
    pub bad_share: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Plan {
    pub nonce: u64,
    pub source: Header,
    pub target: Header,
    pub eligible: usize,
    pub offline: Vec<u64>,
    pub old_root: Word,
    pub next_root: Word,
    pub digest: Word,
}
impl Plan {
    pub fn new(
        nonce: u64,
        source: Header,
        target: Header,
        eligible: usize,
        offline: Vec<u64>,
        old_root: Word,
    ) -> Self {
        let oh = keccak(
            &offline
                .iter()
                .map(|i| word(*i))
                .collect::<Vec<_>>()
                .concat(),
        );
        let next_root = keccak(&[old_root, oh, word(nonce), target.id].concat());
        let d = keccak(
            &[
                b"RESERVE".as_slice(),
                &source.id,
                &target.id,
                &word(nonce),
                &word(target.params.t as u64),
                &word(eligible as u64),
                &old_root,
                &next_root,
                &oh,
            ]
            .concat(),
        );
        Self {
            nonce,
            source,
            target,
            eligible,
            offline,
            old_root,
            next_root,
            digest: d,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub digest: Word,
    pub signatures: Vec<(u64, Sig)>,
}
pub fn certificate_ok(c: &Certificate, keys: &[Meta], k: usize) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    c.signatures.len() >= k
        && c.signatures.iter().all(|(id, s)| {
            seen.insert(*id)
                && keys
                    .iter()
                    .find(|m| m.id == *id)
                    .is_some_and(|m| verify(m.reservation, c.digest, s))
        })
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Ack {
    pub id: u64,
    pub nonce: u64,
    pub target: Word,
    pub signature: Sig,
}
pub fn ack_message(id: u64, nonce: u64, target: Word) -> Word {
    keccak(&[b"STAGE".as_slice(), &word(id), &word(nonce), &target].concat())
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub source: Header,
    pub target: Header,
    pub nonce: u64,
    pub offline: Vec<u64>,
    pub keys: Vec<Meta>,
    pub record_ids: Vec<(u64, u64, Word)>,
    pub record_root: Word,
    pub reservation: Word,
}
impl Manifest {
    /// Structural checks do not trust an archive's claimed signer identities.
    /// Their canonical chain bindings are checked by `check_publication`.
    pub fn validate_layout(&self) -> Result<()> {
        let p = self.target.params;
        self.source.params.check()?;
        p.check()?;
        ensure!(
            self.nonce > 0
                && self.target.epoch == self.source.epoch + 1
                && self.source.params.n == p.n
                && self.source.params.k == p.k
                && self.source.params.f == p.f
                && self.source.public.len() == self.source.params.t
                && self.target.public.len() == p.t
                && self.source.roots.len() == p.n
                && self.target.roots.len() == p.n
                && self.source.public[0] == self.target.public[0],
            "manifest epoch, committee and preserved constant"
        );
        ensure!(
            self.keys.len() == p.n
                && self.keys.iter().enumerate().all(|(i, k)| {
                    k.id == i as u64 + 1
                        && k.pk != Point::default()
                        && k.reservation != Point::default()
                }),
            "canonical manifest dealer keys"
        );
        let offline = self.offline.iter().copied().collect::<BTreeSet<_>>();
        ensure!(
            offline.len() == self.offline.len() && !offline.contains(&0),
            "unique public recipients"
        );
        let mut seen = BTreeSet::new();
        ensure!(
            self.record_ids.iter().all(|(j, i, _)| {
                *j > 0 && *j <= p.n as u64 && offline.contains(i) && seen.insert((*j, *i))
            }),
            "distinct dealer/recipient publication records"
        );
        Ok(())
    }
    pub fn id(&self) -> Word {
        digest(self)
    }
    pub fn commit_message(&self) -> Word {
        keccak(
            &[
                b"COMMIT".as_slice(),
                &self.source.id,
                &self.target.id,
                &word(self.nonce),
                &self.record_root,
                &self.id(),
            ]
            .concat(),
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub manifest: Manifest,
    pub records: Vec<Record>,
    pub source: State,
    pub target: State,
    pub certificate: Certificate,
}
impl Bundle {
    pub fn tree(&self) -> chain::bn::Tree {
        record_tree(&self.records, &self.source, &self.target)
    }
    /// Outer inclusion of a coefficient-vector root; its inner coefficient
    /// opening remains the ordinary indexed Keccak Merkle proof.
    pub fn vector_root_index(&self, dealer: usize, source: bool) -> usize {
        assert!(dealer > 0 && dealer <= self.source.params.n);
        self.records.len() + if source { 0 } else { self.source.params.n } + dealer - 1
    }
    pub fn vector_root_proof(&self, dealer: usize, source: bool) -> Vec<Word> {
        self.tree().proof(self.vector_root_index(dealer, source))
    }
    pub fn validate(&self) -> Result<()> {
        let m = &self.manifest;
        ensure!(
            self.records.iter().all(|r| r.words.len() == 25),
            "publication record shape"
        );
        m.validate_layout()?;
        for s in [&self.source, &self.target] {
            let checked = state(s.epoch, s.params, s.vectors.clone())?;
            ensure!(
                checked.id() == s.id(),
                "accepted coefficient commitment record"
            );
        }
        ensure!(
            m.source.id == self.source.id() && m.target.id == self.target.id(),
            "bundle state"
        );
        ensure!(
            enc(&m.source) == enc(&Header::from(&self.source))
                && enc(&m.target) == enc(&Header::from(&self.target)),
            "header binding"
        );
        ensure!(
            self.tree().root() == m.record_root
                && m.record_ids
                    == self
                        .records
                        .iter()
                        .map(|r| (r.dealer() as u64, r.id(), r.hash()))
                        .collect::<Vec<_>>(),
            "record root"
        );
        ensure!(
            self.certificate.digest == m.reservation
                && certificate_ok(
                    &self.certificate,
                    &m.keys,
                    m.target.params.n - m.target.params.f
                ),
            "certificate"
        );
        for r in &self.records {
            context(r, &m.source, &m.target, m.nonce, false)?;
            let key = &m.keys[r.dealer() - 1];
            ensure!(
                r.key_epoch() == key.key_epoch,
                "publication record key epoch"
            );
            let dv = delta(
                &self.source.vectors[r.dealer() - 1],
                &self.target.vectors[r.dealer() - 1],
            );
            ensure!(
                r.words[9]
                    == keccak(
                        &dv.iter()
                            .flat_map(|p| words(*p))
                            .collect::<Vec<_>>()
                            .concat()
                    ),
                "associated delta vector digest"
            );
            signed_record(r, key.pk)?;
        }
        Ok(())
    }
}
pub fn record_leaf(index: usize, record_hash: Word) -> Word {
    chain::field_hash(
        &[
            b"VESS-RECORD-v1".as_slice(),
            &word(index as u64),
            &record_hash,
        ]
        .concat(),
    )
}
pub fn vector_root_leaf(state: Word, dealer: usize, root: Word) -> Word {
    chain::field_hash(
        &[
            b"VESS-VECTOR-v1".as_slice(),
            &state,
            &word(dealer as u64),
            &root,
        ]
        .concat(),
    )
}
pub fn record_tree(records: &[Record], source: &State, target: &State) -> chain::bn::Tree {
    let mut leaves = records
        .iter()
        .enumerate()
        .map(|(i, r)| record_leaf(i, r.hash()))
        .collect::<Vec<_>>();
    for s in [source, target] {
        leaves.extend((1..=s.params.n).map(|j| vector_root_leaf(s.id(), j, s.root(j))));
    }
    chain::bn::Tree::new_field(leaves)
}
#[derive(Clone, Serialize, Deserialize)]
pub struct RecordProof {
    pub index: usize,
    pub record: Record,
    pub proof: Vec<Word>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Staged {
    pub nonce: u64,
    pub token: Pair,
    pub target: Header,
}
impl Drop for Staged {
    fn drop(&mut self) {
        self.token.erase();
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ReturnResult {
    pub ok: bool,
    pub read: usize,
    pub localized: usize,
    pub bytes: usize,
    pub bad: Vec<Record>,
    pub proofs: Vec<Vec<Word>>,
    pub vector_fetches: usize,
}
pub fn query(cfg: &NodeConfig, sig: &str, args: &[Arg]) -> Result<Vec<u8>> {
    let data = chain::calldata(sig, args);
    let v = chain::rpc(
        &cfg.rpc,
        "eth_call",
        json!([{"to":cfg.contract,"data":chain::hhex(&data)},"latest"]),
    )?;
    chain::unhex(v.as_str().context("eth_call")?)
}
pub fn query_word(cfg: &NodeConfig, sig: &str, args: &[Arg]) -> Result<Word> {
    query(cfg, sig, args)?
        .get(..32)
        .context("word response")?
        .try_into()
        .map_err(Into::into)
}
pub fn participant_pk(cfg: &NodeConfig, id: u64) -> Result<Point> {
    let b = query(cfg, "participantKeys(uint256)", &[Arg::Word(word(id))])?;
    ensure!(b.len() == 64, "registry key");
    let p = point(&[b[..32].try_into()?, b[32..].try_into()?])?;
    ensure!(words(p) != [[0; 32]; 2], "unregistered participant");
    Ok(p)
}
fn query_point(cfg: &NodeConfig, sig: &str, args: &[Arg]) -> Result<Point> {
    let b = query(cfg, sig, args)?;
    ensure!(b.len() == 64, "public key response");
    let p = point(&[b[..32].try_into()?, b[32..].try_into()?])?;
    ensure!(p != Point::default(), "registered nonidentity key");
    Ok(p)
}
fn query_u64(cfg: &NodeConfig, sig: &str, args: &[Arg]) -> Result<u64> {
    let w = query_word(cfg, sig, args)?;
    ensure!(w[..24] == [0; 24], "u64 chain value");
    Ok(u64::from_be_bytes(w[24..].try_into()?))
}
pub fn current_dealer_meta(cfg: &NodeConfig, id: u64) -> Result<Meta> {
    ensure!(id > 0 && id <= cfg.n as u64, "dealer identity");
    let key_epoch = query_u64(cfg, "keyEpoch(uint256)", &[Arg::Word(word(id))])?;
    Ok(Meta {
        id,
        key_epoch,
        pk: query_point(
            cfg,
            "dealerKeys(uint256,uint256)",
            &[Arg::Word(word(id)), Arg::Word(word(key_epoch))],
        )?,
        reservation: query_point(cfg, "reservationKeys(uint256)", &[Arg::Word(word(id))])?,
    })
}
pub fn current_dealer_metas(cfg: &NodeConfig) -> Result<Vec<Meta>> {
    (1..=cfg.n as u64)
        .map(|id| current_dealer_meta(cfg, id))
        .collect()
}
pub fn check_reservation_keys(cfg: &NodeConfig, m: &Manifest) -> Result<()> {
    for key in &m.keys {
        ensure!(
            current_dealer_meta(cfg, key.id)?.reservation == key.reservation,
            "canonical reservation verification key"
        );
    }
    Ok(())
}
pub fn current(cfg: &NodeConfig) -> Result<Word> {
    query_word(cfg, "currentState()", &[])
}
pub fn committed(cfg: &NodeConfig, id: Word) -> Result<bool> {
    Ok(query_word(cfg, "committed(bytes32)", &[Arg::Word(id)])? == word(1))
}
pub fn publication(cfg: &NodeConfig, nonce: u64) -> Result<Vec<Word>> {
    Ok(
        query(cfg, "publication(uint256)", &[Arg::Word(word(nonce))])?
            .as_chunks::<32>()
            .0
            .to_vec(),
    )
}
pub fn check_publication(cfg: &NodeConfig, m: &Manifest, commit: bool) -> Result<()> {
    m.validate_layout()?;
    let a = publication(cfg, m.nonce)?;
    ensure!(
        a.len() == 6
            && a[0] == m.record_root
            && a[1] == m.id()
            && a[3] == m.source.id
            && a[4] == m.target.id,
        "canonical manifest"
    );
    ensure!(
        a[5] == word(if commit { 3 } else { 2 }),
        "publication status"
    );
    for header in [&m.source, &m.target] {
        let args = [Arg::Word(header.id)];
        ensure!(
            query_word(cfg, "coefficientRootDigest(bytes32)", &args)?
                == keccak(&header.roots.concat())
                && query_word(cfg, "stateT(bytes32)", &args)? == word(header.params.t as u64)
                && query_word(cfg, "stateEpoch(bytes32)", &args)? == word(header.epoch),
            "canonical coefficient roots and epoch header"
        );
    }
    for key in &m.keys {
        let epoch = query_u64(
            cfg,
            "publicationKeyEpoch(uint256,uint256)",
            &[Arg::Word(word(m.nonce)), Arg::Word(word(key.id))],
        )?;
        ensure!(epoch == key.key_epoch, "canonical historical key epoch");
        ensure!(
            query_point(
                cfg,
                "dealerKeys(uint256,uint256)",
                &[Arg::Word(word(key.id)), Arg::Word(word(epoch))]
            )? == key.pk,
            "canonical historical dealer key"
        );
    }
    Ok(())
}
pub fn context(r: &Record, src: &Header, tgt: &Header, nonce: u64, snapshot: bool) -> Result<()> {
    ensure!(r.words.len() == 25, "record size");
    let j = r.dealer();
    ensure!(
        j > 0
            && j <= tgt.params.n
            && r.words[0] == word(j as u64)
            && r.id() > 0
            && r.words[1] == word(r.id())
            && r.words[4] == word(r.key_epoch())
            && src.roots.len() >= j
            && tgt.roots.len() >= j
            && r.words[2] == word(nonce)
            && r.words[3] == word(u64::from(snapshot))
            && r.words[5] == word(src.epoch)
            && r.words[6] == word(tgt.epoch)
            && r.words[7] == src.roots[j - 1]
            && r.words[8] == tgt.roots[j - 1],
        "record context"
    );
    Ok(())
}
/// Publication requires a valid dealer signature; malformed encryption is
/// handled by recovery/complaints, and is not silently excluded at commit.
pub fn signed_record(r: &Record, pk: Point) -> Result<()> {
    ensure!(r.words.len() == 25, "record size");
    ensure!(
        verify(
            pk,
            keccak(&r.words[..22].concat()),
            &Sig {
                r: point(&r.words[22..])?,
                s: sf(r.words[24])?,
            }
        ),
        "publication record signature"
    );
    Ok(())
}
pub fn archives(cfg: &NodeConfig) -> Vec<u64> {
    cfg.peers
        .iter()
        .filter(|p| p.role == "archive")
        .map(|p| p.id)
        .collect()
}
pub fn fetch<A: Serialize, B: serde::de::DeserializeOwned>(
    cfg: &NodeConfig,
    op: &str,
    args: &A,
) -> Result<B> {
    fetch_verified(cfg, op, args, |_| Ok(()))
}
pub fn fetch_verified<A: Serialize, B: serde::de::DeserializeOwned>(
    cfg: &NodeConfig,
    op: &str,
    args: &A,
    validate: impl Fn(&B) -> Result<()>,
) -> Result<B> {
    let mut error = None;
    for id in archives(cfg) {
        match call(cfg, id, op, args).and_then(|v| {
            validate(&v)?;
            Ok(v)
        }) {
            Ok(v) => return Ok(v),
            Err(e) => error = Some(e),
        }
    }
    Err(error.context("no archive")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(fault: &str) -> Bundle {
        let make = |epoch, t| {
            let p = Params {
                n: 4,
                k: 2,
                f: 1,
                t,
            };
            let rows = (1..=p.n)
                .map(|j| {
                    (0..t)
                        .map(|l| Pair {
                            v: Scalar::from(
                                if l == 0 { 7 } else { epoch * 100 + l as u64 } + 3 * j as u64,
                            ),
                            r: Scalar::from(
                                if l == 0 { 11 } else { epoch * 200 + l as u64 } + 5 * j as u64,
                            ),
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let s = state(
                epoch,
                p,
                rows.iter()
                    .map(|row| row.iter().map(|p| p.commit()).collect())
                    .collect(),
            )
            .unwrap();
            (s, rows)
        };
        let (source, source_rows) = make(0, 4);
        let (target, target_rows) = make(1, 5);
        let private = (0..4).map(|_| (nonzero(), nonzero())).collect::<Vec<_>>();
        let keys = private
            .iter()
            .enumerate()
            .map(|(j, (sk, rsk))| Meta {
                id: j as u64 + 1,
                pk: g() * sk,
                reservation: g() * rsk,
                key_epoch: 0,
            })
            .collect::<Vec<_>>();
        let recipient = nonzero();
        let records = (1..=4)
            .map(|j| {
                record(
                    &source,
                    &target,
                    j,
                    1,
                    1,
                    0,
                    g() * recipient,
                    private[j - 1].0,
                    eval(&target_rows[j - 1], Scalar::from(1))
                        .minus(eval(&source_rows[j - 1], Scalar::from(1))),
                    false,
                    if j == 1 { fault } else { "" },
                )
            })
            .collect::<Vec<_>>();
        let plan = Plan::new(
            1,
            Header::from(&source),
            Header::from(&target),
            5,
            vec![1],
            [0; 32],
        );
        let manifest = Manifest {
            source: Header::from(&source),
            target: Header::from(&target),
            nonce: 1,
            offline: vec![1],
            keys,
            record_ids: records
                .iter()
                .map(|r| (r.dealer() as u64, r.id(), r.hash()))
                .collect(),
            record_root: record_tree(&records, &source, &target).root(),
            reservation: plan.digest,
        };
        let certificate = Certificate {
            digest: plan.digest,
            signatures: private
                .iter()
                .enumerate()
                .map(|(j, (_, sk))| (j as u64 + 1, sign(*sk, plan.digest)))
                .collect(),
        };
        Bundle {
            manifest,
            records,
            source,
            target,
            certificate,
        }
    }

    fn reindex(b: &mut Bundle) {
        b.manifest.record_ids = b
            .records
            .iter()
            .map(|r| (r.dealer() as u64, r.id(), r.hash()))
            .collect();
        b.manifest.record_root = b.tree().root();
    }

    #[test]
    fn public_log_keeps_signed_faults_for_return_and_dispute() {
        for fault in ["", "inconsistent", "bad_plaintext"] {
            fixture(fault).validate().unwrap();
        }
    }

    #[test]
    fn outer_blob_tree_authenticates_records_and_both_coefficient_states() {
        let b = fixture("");
        let tree = b.tree();
        for (i, record) in b.records.iter().enumerate() {
            assert!(chain::field_member(
                tree.root(),
                record_leaf(i, record.hash()),
                i,
                &tree.proof(i)
            ));
            assert!(!chain::field_member(
                tree.root(),
                record_leaf(i + 1, record.hash()),
                i,
                &tree.proof(i)
            ));
        }
        for (source, state) in [(true, &b.source), (false, &b.target)] {
            for dealer in 1..=state.params.n {
                let index = b.vector_root_index(dealer, source);
                let path = b.vector_root_proof(dealer, source);
                let root = state.root(dealer);
                assert!(chain::field_member(
                    tree.root(),
                    vector_root_leaf(state.id(), dealer, root),
                    index,
                    &path
                ));
                assert!(!chain::field_member(
                    tree.root(),
                    vector_root_leaf(state.id(), dealer + 1, root),
                    index,
                    &path
                ));
                assert!(!chain::field_member(
                    tree.root(),
                    vector_root_leaf([0; 32], dealer, root),
                    index,
                    &path
                ));
                let inner = vector_tree(&state.vectors[dealer - 1]);
                for ell in 0..state.params.t {
                    assert!(member(
                        root,
                        leaf(ell, state.vectors[dealer - 1][ell]),
                        ell,
                        &inner.proof(ell)
                    ));
                }
            }
        }
        assert_eq!(tree.len, b.records.len() + 2 * b.source.params.n);
        assert_eq!(tree.root()[0], 0);
    }

    #[test]
    fn publication_rejects_duplicate_dealer_recipient_even_with_new_root() {
        let mut b = fixture("");
        b.records.push(b.records[0].clone());
        reindex(&mut b);
        assert!(b.validate().is_err());
    }

    #[test]
    fn publication_requires_registered_key_order_and_signed_records() {
        let mut b = fixture("");
        b.manifest.keys.swap(0, 1);
        assert!(b.validate().is_err());
        let mut b = fixture("");
        b.records[0].words[21] = word(123);
        reindex(&mut b);
        assert!(b.validate().is_err());
    }

    #[test]
    fn publication_recomputes_public_commitments_from_dealer_vectors() {
        let mut b = fixture("");
        b.source.public[1] += g();
        b.manifest.source = Header::from(&b.source);
        assert!(b.validate().is_err());
        let mut b = fixture("");
        b.target.vectors[3][1] += g();
        b.manifest.target = Header::from(&b.target);
        assert!(b.validate().is_err());
    }

    #[test]
    fn malformed_record_context_is_rejected_without_indexing_panic() {
        let b = fixture("");
        assert!(context(
            &Record { words: vec![] },
            &b.manifest.source,
            &b.manifest.target,
            1,
            false
        )
        .is_err());
        let mut r = b.records[0].clone();
        r.words[0][0] = 1;
        assert!(context(&r, &b.manifest.source, &b.manifest.target, 1, false).is_err());
    }
}
