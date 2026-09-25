//! Paper registry attestations and transcript-bound PartialJoin batch verification.
use super::{core::*, model::*, wire::*};
use crate::chain::{keccak, word, Arg, Word};
use anyhow::{ensure, Result};
use halo2curves::{
    ff::Field,
    group::{Curve, Group},
    msm::msm_serial,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Serialize, Deserialize)]
pub struct RegistrationProof {
    pub id: u64,
    pub state: Word,
    pub pk: Point,
    pub signature: Sig,
}
impl RegistrationProof {
    pub fn message(state: Word, id: u64, pk: Point) -> Word {
        keccak(
            &[
                b"VESS-REGISTER-v1".as_slice(),
                &state,
                &word(id),
                &words(pk).concat(),
            ]
            .concat(),
        )
    }
    pub fn new(state: Word, id: u64, sk: Scalar) -> Self {
        let pk = g() * sk;
        Self {
            id,
            state,
            pk,
            signature: sign(sk, Self::message(state, id, pk)),
        }
    }
    pub fn args(&self) -> Vec<Arg> {
        vec![
            Arg::Word(word(self.id)),
            Arg::Word(self.state),
            Arg::Word(words(self.pk)[0]),
            Arg::Word(words(self.pk)[1]),
            Arg::Word(words(self.signature.r)[0]),
            Arg::Word(words(self.signature.r)[1]),
            Arg::Word(sw(self.signature.s)),
        ]
    }
}
pub const REGISTER_ABI: &str =
    "registerParticipant(uint256,bytes32,uint256,uint256,uint256,uint256,uint256)";

/// Registry membership rather than 1..population: pending/expired activations
/// and recovery can leave holes in identifier space. Return canonical ID order.
pub fn active_participants(cfg: &NodeConfig) -> Result<Vec<u64>> {
    let response = query(cfg, "eligibleParticipants()", &[])?;
    ensure!(
        response.len() >= 64 && response.len() % 32 == 0,
        "eligible response length"
    );
    ensure!(response[..32] == word(32), "eligible ABI offset");
    let n = u64::from_be_bytes(response[56..64].try_into()?) as usize;
    ensure!(response.len() == 64 + 32 * n, "eligible ABI array");
    let mut ids = Vec::with_capacity(n);
    for w in response[64..].as_chunks::<32>().0 {
        ensure!(w[..24] == [0; 24], "participant identifier overflow");
        ids.push(u64::from_be_bytes(w[24..].try_into()?));
    }
    ids.sort_unstable();
    ensure!(
        ids.iter().all(|id| *id > 0) && ids.windows(2).all(|p| p[0] != p[1]),
        "eligible identifiers"
    );
    Ok(ids)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Activation {
    pub alpha: Word,
    pub state: Word,
    pub epoch: u64,
    pub id: u64,
    pub pk: Point,
}
impl Activation {
    /// Observe the registry before consuming saved enrollment partials. An
    /// issued activation may belong to an earlier epoch after a client crash.
    pub fn observe(cfg: &NodeConfig, id: u64) -> Result<(Self, u64)> {
        let value = query(cfg, "activation(uint256)", &[Arg::Word(word(id))])?;
        ensure!(value.len() == 192, "activation response");
        let w = value.as_chunks::<32>().0.to_vec();
        ensure!(w[2][..24] == [0; 24], "activation status overflow");
        let status = u64::from_be_bytes(w[2][24..].try_into()?);
        Ok((
            Self {
                alpha: w[0],
                state: w[1],
                epoch: u64::from_be_bytes(w[3][24..].try_into()?),
                id,
                pk: point(&w[4..6])?,
            },
            status,
        ))
    }
    pub fn load(cfg: &NodeConfig, id: u64) -> Result<Self> {
        let (activation, status) = Self::observe(cfg, id)?;
        ensure!(status == 1, "activation is not pending");
        ensure!(
            activation.state == current(cfg)?,
            "activation epoch is no longer current"
        );
        Ok(activation)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub dealer: u64,
    pub key_epoch: u64,
    pub evaluation: Point,
    pub signature: Sig,
}
impl Attestation {
    pub fn message(a: &Activation, dealer: u64, key_epoch: u64, evaluation: Point) -> Word {
        keccak(
            &[
                b"VESS-ISSUANCE-v1".as_slice(),
                &a.alpha,
                &a.state,
                &word(a.epoch),
                &word(a.id),
                &words(a.pk).concat(),
                &word(dealer),
                &word(key_epoch),
                &words(evaluation).concat(),
            ]
            .concat(),
        )
    }
    pub fn new(a: &Activation, dealer: u64, key_epoch: u64, evaluation: Point, sk: Scalar) -> Self {
        Self {
            dealer,
            key_epoch,
            evaluation,
            signature: sign(sk, Self::message(a, dealer, key_epoch, evaluation)),
        }
    }
    pub fn verify(&self, a: &Activation, pk: Point) -> bool {
        verify(
            pk,
            Self::message(a, self.dealer, self.key_epoch, self.evaluation),
            &self.signature,
        )
    }
    pub fn words(&self) -> Vec<Word> {
        vec![
            word(self.dealer),
            word(self.key_epoch),
            words(self.evaluation)[0],
            words(self.evaluation)[1],
            words(self.signature.r)[0],
            words(self.signature.r)[1],
            sw(self.signature.s),
        ]
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PartialJoin {
    pub record: Record,
    pub attestation: Attestation,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Completion {
    pub activation: Activation,
    pub attestations: Vec<Attestation>,
    pub vectors: Vec<Vec<Point>>,
}
impl Completion {
    pub fn args(&self) -> Vec<Arg> {
        vec![
            Arg::Word(word(self.activation.id)),
            Arg::Word(self.activation.state),
            Arg::Words(
                self.attestations
                    .iter()
                    .flat_map(Attestation::words)
                    .collect(),
            ),
            Arg::Words(
                self.vectors
                    .iter()
                    .flatten()
                    .flat_map(|p| words(*p))
                    .collect(),
            ),
        ]
    }
}
pub const ACTIVATE_ABI: &str = "activate(uint256,bytes32,uint256[],uint256[])";

pub fn da_authorization_message(
    chain_id: u64,
    contract: [u8; 20],
    nonce: u64,
    dealer: u64,
    recipient: u64,
    challenger: [u8; 20],
) -> Word {
    keccak(
        &[
            b"VESS-DA-v1".as_slice(),
            &word(chain_id),
            &contract,
            &word(nonce),
            &word(dealer),
            &word(recipient),
            &challenger,
        ]
        .concat(),
    )
}

/// Authentication/decryption only: the Pedersen relation is checked by the
/// transcript-bound batch, rather than paying for k individual opening checks.
pub fn decrypt_for_batch(r: &Record, pk: Point, sk: Scalar) -> Result<Pair> {
    authenticated(r, pk)?;
    ensure!(point(&r.words[12..])? == g() * sk, "recipient binding");
    let shared = point(&r.words[14..])? * sk;
    let ctx = zeroize::Zeroizing::new(
        [
            r.words[1],
            r.words[12],
            r.words[13],
            r.words[14],
            r.words[15],
            words(shared)[0],
            words(shared)[1],
        ]
        .concat(),
    );
    Ok(Pair {
        v: sf(r.words[20])? - hs(&[b"derive-key-0", &r.ad(), &ctx]),
        r: sf(r.words[21])? - hs(&[b"derive-key-1", &r.ad(), &ctx]),
    })
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BatchPartial {
    pub dealer: u64,
    pub partial: Pair,
    /// Complete authenticated attestation (or update record) in the transcript.
    pub attestation: Vec<u8>,
    pub vector: Vec<Point>,
}
impl Drop for BatchPartial {
    fn drop(&mut self) {
        self.partial.erase();
    }
}
struct BatchScalars(Vec<Scalar>);
impl std::ops::Deref for BatchScalars {
    type Target = Vec<Scalar>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for BatchScalars {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for BatchScalars {
    fn drop(&mut self) {
        for scalar in &mut self.0 {
            // Scalar is an external field type without Zeroize. Volatile writes
            // plus the compiler fence provide the same application-level wipe;
            // ZERO is a valid representation of this type.
            unsafe {
                std::ptr::write_volatile(scalar, Scalar::ZERO);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn transcript(public: Word, alpha: Word, epoch: u64, id: u64, p: &[BatchPartial]) -> Word {
    // Fixed-width public context + bincode's length-prefixed canonical dealer
    // order binds every decrypted scalar and every commitment before H is used.
    let encoded = zeroize::Zeroizing::new(enc(&(
        b"VESS-BATCH-TRANSCRIPT-v1".as_slice(),
        public,
        alpha,
        epoch,
        id,
        p,
    )));
    keccak(&encoded)
}
#[cfg(test)]
fn challenge(
    public: Word,
    alpha: Word,
    epoch: u64,
    id: u64,
    p: &[BatchPartial],
    dealer: u64,
) -> Scalar {
    hs(&[
        b"BATCH",
        &alpha,
        &word(epoch),
        &word(id),
        &transcript(public, alpha, epoch, id, p),
        &word(dealer),
    ])
}
fn check(public: Word, alpha: Word, epoch: u64, id: u64, p: &[BatchPartial]) -> bool {
    if p.is_empty() {
        return true;
    }
    let tr = transcript(public, alpha, epoch, id, p);
    let mut bases = vec![g().to_affine(), h().to_affine()];
    // Reserve before private sums are written: reallocation must not leave a
    // freed copy of the first two (secret) MSM coefficients behind.
    let mut scalars = BatchScalars(Vec::with_capacity(
        2 + p.iter().map(|p| p.vector.len()).sum::<usize>(),
    ));
    scalars.extend([Scalar::ZERO, Scalar::ZERO]);
    for part in p {
        let eta = hs(&[
            b"BATCH",
            &alpha,
            &word(epoch),
            &word(id),
            &tr,
            &word(part.dealer),
        ]);
        scalars[0] += eta * part.partial.v;
        scalars[1] += eta * part.partial.r;
        let mut power = Scalar::ONE;
        for c in &part.vector {
            bases.push(c.to_affine());
            scalars.push(-eta * power);
            power *= Scalar::from(id);
        }
    }
    let mut residual = Point::identity();
    msm_serial(&scalars, &bases, &mut residual);
    bool::from(residual.is_identity())
}
/// Returns canonical valid/invalid dealer sets; failed batches are recursively
/// split with a fresh transcript for each subset, exactly as Appendix batch.
pub fn verified_partials(
    public: Word,
    alpha: Word,
    epoch: u64,
    id: u64,
    partials: &[BatchPartial],
) -> Result<(Vec<u64>, Vec<u64>)> {
    ensure!(id > 0 && !partials.is_empty(), "empty batch/recipient");
    let mut canonical = partials.to_vec();
    canonical.sort_by_key(|p| p.dealer);
    let mut seen = BTreeSet::new();
    ensure!(
        canonical
            .iter()
            .all(|p| p.dealer > 0 && seen.insert(p.dealer) && !p.vector.is_empty()),
        "duplicate dealer/empty vector"
    );
    fn split(
        public: Word,
        alpha: Word,
        epoch: u64,
        id: u64,
        p: &[BatchPartial],
        valid: &mut Vec<u64>,
        bad: &mut Vec<u64>,
    ) {
        if check(public, alpha, epoch, id, p) {
            valid.extend(p.iter().map(|p| p.dealer));
        } else if p.len() == 1 {
            bad.push(p[0].dealer);
        } else {
            let mid = p.len() / 2;
            split(public, alpha, epoch, id, &p[..mid], valid, bad);
            split(public, alpha, epoch, id, &p[mid..], valid, bad);
        }
    }
    let (mut valid, mut bad) = (Vec::new(), Vec::new());
    split(public, alpha, epoch, id, &canonical, &mut valid, &mut bad);
    Ok((valid, bad))
}

/// Dealer keys come from the canonical registry, not a potentially unavailable
/// dealer RPC. Historical epoch is explicit for replay protection.
pub fn dealer_key(cfg: &NodeConfig, dealer: u64) -> Result<(u64, Point)> {
    let e = query_word(cfg, "keyEpoch(uint256)", &[Arg::Word(word(dealer))])?;
    let epoch = u64::from_be_bytes(e[24..].try_into()?);
    let p = query(
        cfg,
        "dealerKeys(uint256,uint256)",
        &[Arg::Word(word(dealer)), Arg::Word(e)],
    )?;
    ensure!(p.len() == 64, "dealer key response");
    Ok((epoch, point(&[p[..32].try_into()?, p[32..].try_into()?])?))
}

pub fn state_from_available(cfg: &NodeConfig) -> Result<State> {
    let canonical = current(cfg)?;
    for j in 1..=cfg.n as u64 {
        let candidate: Result<State> = call(cfg, j, "state", &());
        if let Ok(s) = candidate {
            if s.id() == canonical {
                return Ok(s);
            }
        }
    }
    anyhow::bail!("no dealer supplies the canonical public epoch state")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn batch() -> Vec<BatchPartial> {
        (1..=4)
            .map(|dealer| {
                let v = (0..4).map(|_| Pair::random()).collect::<Vec<_>>();
                BatchPartial {
                    dealer,
                    partial: eval(&v, Scalar::from(9)),
                    attestation: vec![dealer as u8],
                    vector: v.iter().map(|x| x.commit()).collect(),
                }
            })
            .collect()
    }
    #[test]
    fn detects_cancelling_partials_and_recursively_isolates_them() {
        let mut p = batch();
        assert_eq!(
            verified_partials(word(1), word(2), 3, 9, &p).unwrap().0,
            vec![1, 2, 3, 4]
        );
        // Even errors cancelling with the previously observed weights fail:
        // changing a plaintext changes the transcript and therefore the weights.
        let e0 = challenge(word(1), word(2), 3, 9, &p, 1);
        let e1 = challenge(word(1), word(2), 3, 9, &p, 2);
        p[0].partial.v += Scalar::ONE;
        p[1].partial.v -= e0 * Option::<Scalar>::from(e1.invert()).unwrap();
        let (valid, bad) = verified_partials(word(1), word(2), 3, 9, &p).unwrap();
        assert_eq!(valid, vec![3, 4]);
        assert_eq!(bad, vec![1, 2]);
    }
    #[test]
    fn transcript_binds_context_scalars_and_attestation() {
        let mut p = batch();
        let old = transcript(word(1), word(2), 3, 9, &p);
        assert_ne!(old, transcript(word(8), word(2), 3, 9, &p));
        assert_ne!(old, transcript(word(1), word(8), 3, 9, &p));
        assert_ne!(old, transcript(word(1), word(2), 8, 9, &p));
        p[0].partial.r += Scalar::ONE;
        assert_ne!(old, transcript(word(1), word(2), 3, 9, &p));
        p[0].partial.r -= Scalar::ONE;
        p[0].attestation.push(0);
        assert_ne!(old, transcript(word(1), word(2), 3, 9, &p));
    }
    #[test]
    fn rejects_duplicates_and_accepts_canonical_permutation() {
        let mut p = batch();
        p.reverse();
        assert_eq!(
            verified_partials(word(1), word(2), 3, 9, &p).unwrap().0,
            vec![1, 2, 3, 4]
        );
        p.push(p[0].clone());
        assert!(verified_partials(word(1), word(2), 3, 9, &p).is_err());
    }
    #[test]
    fn attestation_is_scalar_free_and_rejects_replay() {
        let sk = nonzero();
        let mut a = Activation {
            alpha: word(1),
            state: word(2),
            epoch: 3,
            id: 9,
            pk: g() * nonzero(),
        };
        let att = Attestation::new(&a, 1, 0, g() * nonzero(), sk);
        assert!(att.verify(&a, g() * sk));
        a.alpha = word(2);
        assert!(!att.verify(&a, g() * sk));
    }
}
