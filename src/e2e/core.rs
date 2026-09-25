//! One BN254 suite from VSS to the EVM verifier; secret multiplication uses halo2curves.
use crate::chain::{bn::Tree, keccak, word, Word};
use anyhow::{bail, ensure, Context, Result};
use halo2curves::{
    bn256::{Fq, Fr, G1Affine, G1},
    ff::{Field, FromUniformBytes, PrimeField},
    group::{Curve, Group},
    CurveAffine,
};
use serde::{Deserialize, Serialize};
pub type Scalar = Fr;
pub type Point = G1;
pub const SUITE: &str = "bn254-halo2curves-0.10-mega-keccak-merkle248-v2";
pub fn enc<T: Serialize>(v: &T) -> Vec<u8> {
    bincode::serialize(v).expect("serialize")
}
pub fn digest<T: Serialize>(v: &T) -> Word {
    keccak(&enc(v))
}
pub fn random() -> Fr {
    Fr::random(rand::rngs::OsRng)
}
pub fn nonzero() -> Fr {
    loop {
        let s = random();
        if s != Fr::ZERO {
            return s;
        }
    }
}
pub fn g() -> G1 {
    G1::generator()
}
pub fn scalar(w: Word) -> Fr {
    let mut b = [0; 64];
    for i in 0..32 {
        b[i] = w[31 - i];
    }
    Fr::from_uniform_bytes(&b)
}
pub fn sw(s: Fr) -> Word {
    let mut b: Word = s.to_repr().into();
    b.reverse();
    b
}
pub fn sf(w: Word) -> Result<Fr> {
    let mut b = w;
    b.reverse();
    Option::<Fr>::from(Fr::from_repr(b.into())).context("noncanonical scalar")
}
pub fn hs(parts: &[&[u8]]) -> Fr {
    scalar(keccak(&parts.concat()))
}
pub fn words(p: G1) -> [Word; 2] {
    let a = p.to_affine();
    let c = Option::from(a.coordinates());
    if let Some(c) = c {
        let c: halo2curves::Coordinates<G1Affine> = c;
        let mut x: Word = c.x().to_repr().into();
        let mut y: Word = c.y().to_repr().into();
        x.reverse();
        y.reverse();
        [x, y]
    } else {
        [[0; 32]; 2]
    }
}
pub fn point(w: &[Word]) -> Result<G1> {
    ensure!(w.len() >= 2, "point length");
    if w[0] == [0; 32] && w[1] == [0; 32] {
        return Ok(G1::identity());
    }
    let mut x = w[0];
    let mut y = w[1];
    x.reverse();
    y.reverse();
    let x = Option::<Fq>::from(Fq::from_repr(x.into())).context("point x")?;
    let y = Option::<Fq>::from(Fq::from_repr(y.into())).context("point y")?;
    Ok(G1::from(
        Option::<G1Affine>::from(G1Affine::from_xy(x, y)).context("off curve")?,
    ))
}
pub fn hash_point(seed: Word) -> G1 {
    let mut b = [0; 64];
    for i in 0..32 {
        b[i] = seed[31 - i]
    }
    let mut x = Fq::from_uniform_bytes(&b);
    loop {
        if let Some(mut y) = Option::<Fq>::from((x * x * x + Fq::from(3)).sqrt()) {
            if y.to_repr()[0] & 1 == 1 {
                y = -y
            }
            return G1::from(Option::<G1Affine>::from(G1Affine::from_xy(x, y)).expect("curve"));
        }
        x += Fq::ONE
    }
}
pub fn h() -> G1 {
    static H: std::sync::OnceLock<G1> = std::sync::OnceLock::new();
    *H.get_or_init(|| hash_point(keccak(b"VESS-BN-H-v1")))
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pair {
    pub v: Fr,
    pub r: Fr,
}
impl Default for Pair {
    fn default() -> Self {
        Self::zero()
    }
}
impl zeroize::DefaultIsZeroes for Pair {}
impl Pair {
    /// Volatile application-level erasure; OS snapshots/backups remain an
    /// explicit environmental assumption of the paper's corruption model.
    pub fn erase(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
    pub fn zero() -> Self {
        Self {
            v: Fr::ZERO,
            r: Fr::ZERO,
        }
    }
    pub fn random() -> Self {
        Self {
            v: random(),
            r: random(),
        }
    }
    pub fn plus(self, b: Self) -> Self {
        Self {
            v: self.v + b.v,
            r: self.r + b.r,
        }
    }
    pub fn minus(self, b: Self) -> Self {
        Self {
            v: self.v - b.v,
            r: self.r - b.r,
        }
    }
    pub fn scale(self, s: Fr) -> Self {
        Self {
            v: self.v * s,
            r: self.r * s,
        }
    }
    pub fn commit(self) -> G1 {
        g() * self.v + h() * self.r
    }
}
pub fn eval(v: &[Pair], x: Fr) -> Pair {
    v.iter()
        .rev()
        .fold(Pair::zero(), |a, b| a.scale(x).plus(*b))
}
pub fn peval(v: &[G1], x: Fr) -> G1 {
    v.iter().rev().fold(G1::identity(), |a, b| a * x + b)
}
pub fn weights(ids: &[u64], x: Fr) -> Result<Vec<Fr>> {
    ensure!(!ids.is_empty(), "empty interpolation");
    let mut seen = std::collections::BTreeSet::new();
    for i in ids {
        ensure!(*i > 0 && seen.insert(*i), "duplicate coordinate")
    }
    Ok(ids
        .iter()
        .map(|i| {
            let mut a = Fr::ONE;
            let mut b = Fr::ONE;
            for j in ids {
                if i != j {
                    a *= x - Fr::from(*j);
                    b *= Fr::from(*i) - Fr::from(*j)
                }
            }
            a * Option::<Fr>::from(b.invert()).unwrap()
        })
        .collect())
}
pub fn combine(v: &[(u64, Pair)]) -> Result<Pair> {
    let w = weights(&v.iter().map(|p| p.0).collect::<Vec<_>>(), Fr::ZERO)?;
    Ok(v.iter()
        .zip(w)
        .fold(Pair::zero(), |a, ((_, p), w)| a.plus(p.scale(w))))
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Params {
    pub n: usize,
    pub k: usize,
    pub f: usize,
    pub t: usize,
}
impl Params {
    pub fn check(self) -> Result<()> {
        ensure!(
            self.k > self.f && self.n >= 2 * self.f + self.k && self.t >= 4,
            "thresholds"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct State {
    pub epoch: u64,
    pub params: Params,
    pub vectors: Vec<Vec<G1>>,
    pub public: Vec<G1>,
}
impl State {
    pub fn id(&self) -> Word {
        digest(self)
    }
    pub fn root(&self, j: usize) -> Word {
        vector_tree(&self.vectors[j - 1]).root()
    }
}
pub fn state(epoch: u64, p: Params, vectors: Vec<Vec<G1>>) -> Result<State> {
    p.check()?;
    ensure!(
        vectors.len() == p.n && vectors.iter().all(|v| v.len() == p.t),
        "vectors"
    );
    let ids = (1..=p.k as u64).collect::<Vec<_>>();
    for (j, v) in vectors.iter().enumerate().skip(p.k) {
        let w = weights(&ids, Fr::from(j as u64 + 1))?;
        for (i, c) in v.iter().enumerate() {
            let actual = (0..p.k).fold(G1::identity(), |a, u| a + vectors[u][i] * w[u]);
            ensure!(actual == *c, "dealer polynomial eq:record")
        }
    }
    let w = weights(&ids, Fr::ZERO)?;
    let public = (0..p.t)
        .map(|i| (0..p.k).fold(G1::identity(), |a, u| a + vectors[u][i] * w[u]))
        .collect();
    Ok(State {
        epoch,
        params: p,
        vectors,
        public,
    })
}
/// Owner's single Pedersen VSS invocation for (s, r0). No higher epoch
/// coefficients are generated here: those belong to dealer JRSS invocations.
pub fn initial_constant(p: Params, mut secret: Pair) -> Result<(Vec<G1>, Vec<Pair>)> {
    p.check()?;
    let mut poly = (0..p.k).map(|_| Pair::random()).collect::<Vec<_>>();
    poly[0] = secret;
    secret.erase();
    let commitments = poly.iter().map(|v| v.commit()).collect();
    let shares = (1..=p.n).map(|j| eval(&poly, Fr::from(j as u64))).collect();
    for pair in &mut poly {
        pair.erase();
    }
    Ok((commitments, shares))
}

/// In-memory fixture only. The live protocol invokes these dealer contributions
/// in separate dealer processes, after the owner has erased its constant VSS.
#[cfg(test)]
pub fn init(p: Params) -> Result<(State, Vec<Vec<Pair>>)> {
    let (_, constants) = initial_constant(p, Pair::random())?;
    let contributions = (0..p.n).map(|_| contribute_initial(p)).collect::<Vec<_>>();
    let rows = (0..p.n)
        .map(|j| {
            let mut row = aggregate(
                p,
                contributions
                    .iter()
                    .enumerate()
                    .map(|(i, c)| (i as u64 + 1, c.shares[j].clone()))
                    .collect(),
            )?;
            row[0] = constants[j];
            Ok(row)
        })
        .collect::<Result<Vec<_>>>()?;
    let s = state(
        0,
        p,
        rows.iter()
            .map(|r| r.iter().map(|p| p.commit()).collect())
            .collect(),
    )?;
    Ok((s, rows))
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Contribution {
    pub commitments: Vec<Vec<G1>>,
    pub shares: Vec<Vec<Pair>>,
}
impl Drop for Contribution {
    fn drop(&mut self) {
        for row in &mut self.shares {
            for pair in row {
                pair.erase();
            }
        }
    }
}
pub fn contribute(source: Pair, p: Params) -> Contribution {
    contribute_inner(Some(source), p)
}

/// ShareInit calls JRSS only for coefficient indices 1..t. The zero slot is a
/// wire-layout sentinel; it is not a VSS invocation and contributes no constant.
pub fn contribute_initial(p: Params) -> Contribution {
    contribute_inner(None, p)
}

fn contribute_inner(mut source: Option<Pair>, p: Params) -> Contribution {
    let mut c = Contribution {
        commitments: vec![],
        shares: vec![vec![]; p.n],
    };
    for i in 0..p.t {
        if i == 0 && source.is_none() {
            c.commitments.push(vec![G1::identity(); p.k]);
            for shares in &mut c.shares {
                shares.push(Pair::zero());
            }
            continue;
        }
        let mut poly = (0..p.k).map(|_| Pair::random()).collect::<Vec<_>>();
        if i == 0 {
            poly[0] = source.expect("transition source")
        }
        c.commitments
            .push(poly.iter().map(|a| a.commit()).collect());
        for j in 0..p.n {
            c.shares[j].push(eval(&poly, Fr::from(j as u64 + 1)))
        }
        for pair in &mut poly {
            pair.erase();
        }
    }
    if let Some(pair) = source.as_mut() {
        pair.erase();
    }
    c
}
pub fn verify_share(c: &[Vec<G1>], v: &[Pair], j: u64, source: G1, p: Params) -> bool {
    c.len() == p.t
        && v.len() == p.t
        && c.iter().all(|v| v.len() == p.k)
        && c[0][0] == source
        && v.iter()
            .zip(c)
            .all(|(v, c)| v.commit() == peval(c, Fr::from(j)))
}
pub fn aggregate(p: Params, mut q: Vec<(u64, Vec<Pair>)>) -> Result<Vec<Pair>> {
    ensure!(q.len() >= p.n - p.f, "qualification quorum");
    q.sort_by_key(|v| v.0);
    ensure!(
        q.iter()
            .all(|(id, row)| *id > 0 && *id <= p.n as u64 && row.len() == p.t)
            && q.windows(2).all(|w| w[0].0 != w[1].0),
        "qualified dealer identities and rows"
    );
    let mut row = vec![combine(
        &q[..p.k].iter().map(|(j, v)| (*j, v[0])).collect::<Vec<_>>(),
    )?];
    for i in 1..p.t {
        row.push(q.iter().fold(Pair::zero(), |a, (_, v)| a.plus(v[i])))
    }
    for (_, values) in &mut q {
        for pair in values {
            pair.erase();
        }
    }
    Ok(row)
}
pub fn delta(a: &[G1], b: &[G1]) -> Vec<G1> {
    (0..a.len().max(b.len()))
        .map(|i| b.get(i).copied().unwrap_or_default() - a.get(i).copied().unwrap_or_default())
        .collect()
}
pub fn leaf(i: usize, p: G1) -> Word {
    keccak(&[word(i as u64).to_vec(), words(p).concat()].concat())
}
pub fn vector_tree(v: &[G1]) -> Tree {
    Tree::new(v.iter().enumerate().map(|(i, p)| leaf(i, *p)).collect())
}
pub fn member(root: Word, mut leaf: Word, mut i: usize, path: &[Word]) -> bool {
    for p in path {
        leaf = if i.is_multiple_of(2) {
            keccak(&[leaf, *p].concat())
        } else {
            keccak(&[*p, leaf].concat())
        };
        i /= 2
    }
    i == 0 && leaf == root
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Sig {
    pub r: G1,
    pub s: Fr,
}
pub fn sign(sk: Fr, msg: Word) -> Sig {
    let w = nonzero();
    let r = g() * w;
    let c = hs(&[
        b"BN-SIG-v1",
        &words(g() * sk).concat(),
        &words(r).concat(),
        &msg,
    ]);
    Sig { r, s: w + c * sk }
}
pub fn verify(pk: G1, msg: Word, s: &Sig) -> bool {
    if bool::from(pk.is_identity()) || bool::from(s.r.is_identity()) {
        return false;
    }
    let c = hs(&[
        b"BN-SIG-v1",
        &words(pk).concat(),
        &words(s.r).concat(),
        &msg,
    ]);
    g() * s.s == s.r + pk * c
}
pub fn sig_words(id: u64, s: &Sig) -> Vec<Word> {
    vec![word(id), words(s.r)[0], words(s.r)[1], sw(s.s)]
}
pub fn proof(sk: Fr, b: G1, p: G1, q: G1, ctx: Word) -> [Word; 2] {
    let w = nonzero();
    let all = [words(b), words(p), words(q), words(g() * w), words(b * w)]
        .concat()
        .concat();
    let c = hs(&[b"BN-DLEQ-v1", &ctx, &all]);
    [sw(c), sw(w + c * sk)]
}
pub fn check_proof(b: G1, p: G1, q: G1, ctx: Word, c: Fr, s: Fr) -> bool {
    if [b, p, q].iter().any(|a| bool::from(a.is_identity())) {
        return false;
    }
    let all = [
        words(b),
        words(p),
        words(q),
        words(g() * s - p * c),
        words(b * s - q * c),
    ]
    .concat()
    .concat();
    hs(&[b"BN-DLEQ-v1", &ctx, &all]) == c
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub words: Vec<Word>,
}
impl Record {
    pub fn hash(&self) -> Word {
        keccak(&self.words.concat())
    }
    pub fn id(&self) -> u64 {
        u64::from_be_bytes(self.words[1][24..].try_into().unwrap())
    }
    pub fn dealer(&self) -> usize {
        u64::from_be_bytes(self.words[0][24..].try_into().unwrap()) as usize
    }
    pub fn key_epoch(&self) -> u64 {
        u64::from_be_bytes(self.words[4][24..].try_into().unwrap())
    }
    pub fn e(&self) -> Result<G1> {
        point(&self.words[10..])
    }
    pub fn ad(&self) -> Word {
        keccak(&self.words[..14].concat())
    }
}
#[allow(clippy::too_many_arguments)]
pub fn record(
    src: &State,
    tgt: &State,
    j: usize,
    id: u64,
    nonce: u64,
    key_epoch: u64,
    pk: G1,
    sk: Fr,
    mut m: Pair,
    snapshot: bool,
    fault: &str,
) -> Record {
    if fault == "inconsistent" {
        m.v += Fr::ONE
    }
    let dv = if snapshot {
        tgt.vectors[j - 1].clone()
    } else {
        delta(&src.vectors[j - 1], &tgt.vectors[j - 1])
    };
    let mut r = vec![
        word(j as u64),
        word(id),
        word(nonce),
        word(u64::from(snapshot)),
        word(key_epoch),
        word(src.epoch),
        word(tgt.epoch),
        src.root(j),
        tgt.root(j),
        keccak(
            &dv.iter()
                .flat_map(|p| words(*p))
                .collect::<Vec<_>>()
                .concat(),
        ),
    ];
    r.extend(words(m.commit()));
    r.extend(words(pk));
    let ad = keccak(&r.concat());
    let mut k = nonzero();
    let ep = g() * k;
    let hp = hash_point(keccak(
        &[b"epk-pop".as_slice(), &ad, &words(ep).concat()].concat(),
    ));
    let ep2 = hp * k;
    r.extend(words(ep));
    r.extend(words(ep2));
    r.extend(proof(k, hp, ep, ep2, ad));
    let shared = pk * k;
    let ctx = zeroize::Zeroizing::new(
        [word(id)]
            .into_iter()
            .chain(words(pk))
            .chain(words(ep))
            .chain(words(shared))
            .collect::<Vec<_>>()
            .concat(),
    );
    if fault == "bad_plaintext" {
        m.v += Fr::ONE
    }
    r.push(sw(m.v + hs(&[b"derive-key-0", &ad, &ctx])));
    r.push(sw(m.r + hs(&[b"derive-key-1", &ad, &ctx])));
    let sig = sign(sk, keccak(&r.concat()));
    r.extend(words(sig.r));
    r.push(sw(sig.s));
    m.erase();
    // Fr has no Zeroize implementation. Volatile overwrite follows the same
    // application-level erasure boundary as Pair::erase.
    unsafe {
        std::ptr::write_volatile(&mut k, Fr::ZERO);
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    Record { words: r }
}
pub fn pop_ok(r: &Record) -> Result<bool> {
    ensure!(r.words.len() == 25, "record size");
    let ep = point(&r.words[14..])?;
    let hp = hash_point(keccak(
        &[b"epk-pop".as_slice(), &r.ad(), &words(ep).concat()].concat(),
    ));
    Ok(check_proof(
        hp,
        ep,
        point(&r.words[16..])?,
        r.ad(),
        sf(r.words[18])?,
        sf(r.words[19])?,
    ))
}
pub fn authenticated(r: &Record, pk: G1) -> Result<()> {
    ensure!(r.words.len() == 25, "record size");
    ensure!(
        verify(
            pk,
            keccak(&r.words[..22].concat()),
            &Sig {
                r: point(&r.words[22..])?,
                s: sf(r.words[24])?
            }
        ),
        "record signature"
    );
    ensure!(pop_ok(r)?, "record PoP");
    Ok(())
}
pub fn decrypt(r: &Record, pk: G1, sk: Fr) -> Result<Pair> {
    authenticated(r, pk)?;
    ensure!(point(&r.words[12..])? == g() * sk, "recipient binding");
    let shared = point(&r.words[14..])? * sk;
    let ctx = [
        r.words[1],
        r.words[12],
        r.words[13],
        r.words[14],
        r.words[15],
        words(shared)[0],
        words(shared)[1],
    ]
    .concat();
    let p = Pair {
        v: sf(r.words[20])? - hs(&[b"derive-key-0", &r.ad(), &ctx]),
        r: sf(r.words[21])? - hs(&[b"derive-key-1", &r.ad(), &ctx]),
    };
    ensure!(p.commit() == r.e()?, "plaintext opening");
    Ok(p)
}
pub fn decryption_proof(r: &Record, sk: Fr) -> Result<Vec<Word>> {
    ensure!(
        point(&r.words[12..])? == g() * sk,
        "decryption proof recipient"
    );
    ensure!(pop_ok(r)?, "PoP before proof");
    let ep = point(&r.words[14..])?;
    let shared = ep * sk;
    let ctx = keccak(
        &[
            b"DEC".as_slice(),
            &r.ad(),
            &words(ep).concat(),
            &r.words[20..22].concat(),
        ]
        .concat(),
    );
    let mut p = words(shared).to_vec();
    p.extend(proof(sk, ep, g() * sk, shared, ctx));
    Ok(p)
}
pub fn reconstruct(s: &State, shares: &[(u64, Pair)]) -> Result<Pair> {
    let mut seen = std::collections::BTreeSet::new();
    let v = shares
        .iter()
        .filter(|(i, p)| *i > 0 && p.commit() == peval(&s.public, Fr::from(*i)) && seen.insert(*i))
        .take(s.params.t)
        .copied()
        .collect::<Vec<_>>();
    ensure!(v.len() == s.params.t, "reconstruction threshold");
    let result = combine(&v)?;
    ensure!(result.commit() == s.public[0], "secret commitment");
    Ok(result)
}
pub fn decode<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T> {
    Ok(bincode::deserialize(b)?)
}
pub fn require(v: bool, msg: &str) -> Result<()> {
    if !v {
        bail!("{msg}")
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_record_and_transition() {
        let p = Params {
            n: 4,
            k: 2,
            f: 1,
            t: 4,
        };
        let (s, rows) = init(p).unwrap();
        let keys = (0..p.n).map(|_| nonzero()).collect::<Vec<_>>();
        let sk = nonzero();
        let m = eval(&rows[0], Fr::from(1));
        let r = record(&s, &s, 1, 1, 1, 0, g() * sk, keys[0], m, true, "");
        assert_eq!(decrypt(&r, g() * keys[0], sk).unwrap(), m);
        let mut bad = r.clone();
        bad.words[20] = sw(sf(bad.words[20]).unwrap() + Fr::ONE);
        assert!(decrypt(&bad, g() * keys[0], sk).is_err());
        let contributions = rows.iter().map(|r| contribute(r[0], p)).collect::<Vec<_>>();
        let rows2 = (0..p.n)
            .map(|j| {
                aggregate(
                    p,
                    contributions
                        .iter()
                        .enumerate()
                        .map(|(i, c)| (i as u64 + 1, c.shares[j].clone()))
                        .collect(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let t = state(
            1,
            p,
            rows2
                .iter()
                .map(|r| r.iter().map(|a| a.commit()).collect())
                .collect(),
        )
        .unwrap();
        assert_eq!(s.public[0], t.public[0]);
        let shares = (1..=4)
            .map(|i| {
                (
                    i,
                    combine(
                        &(0..2)
                            .map(|j| (j as u64 + 1, eval(&rows2[j], Fr::from(i))))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(reconstruct(&t, &shares).unwrap().commit(), s.public[0]);
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    #[test]
    fn share_init_owner_vss_and_independent_jrss_with_one_omission() {
        let p = Params {
            n: 4,
            k: 2,
            f: 1,
            t: 8,
        };
        let secret = Pair {
            v: Fr::from(42),
            r: random(),
        };
        let (constant, shares) = initial_constant(p, secret).unwrap();
        assert_eq!(constant[0], secret.commit());
        for (j, value) in shares.iter().enumerate() {
            assert_eq!(value.commit(), peval(&constant, Fr::from(j as u64 + 1)));
        }
        // Dealer 1 is absent. Exactly n-f independent contributors remain;
        // their JRSS invocations never reshare or alter the owner constant.
        let contributions = (2..=4)
            .map(|id| (id, contribute_initial(p)))
            .collect::<Vec<_>>();
        for (_, c) in &contributions {
            assert!(c.commitments[0].iter().all(|v| *v == G1::identity()));
            assert!(c.shares.iter().all(|row| row[0] == Pair::zero()));
        }
        let rows = (0..p.n)
            .map(|j| {
                let mut row = aggregate(
                    p,
                    contributions
                        .iter()
                        .map(|(id, c)| (*id, c.shares[j].clone()))
                        .collect(),
                )
                .unwrap();
                row[0] = shares[j];
                row
            })
            .collect::<Vec<_>>();
        let state = state(
            0,
            p,
            rows.iter()
                .map(|r| r.iter().map(|x| x.commit()).collect())
                .collect(),
        )
        .unwrap();
        assert_eq!(state.public[0], secret.commit());
        for ell in 1..p.t {
            assert_eq!(
                state.public[ell],
                contributions
                    .iter()
                    .fold(G1::identity(), |a, (_, c)| a + c.commitments[ell][0])
            );
        }
        let participant_shares = (1..=p.t as u64)
            .map(|id| {
                (
                    id,
                    combine(&[
                        (2, eval(&rows[1], Fr::from(id))),
                        (4, eval(&rows[3], Fr::from(id))),
                    ])
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(reconstruct(&state, &participant_shares).unwrap(), secret);
    }
    #[test]
    fn qualification_rejects_duplicate_and_out_of_committee_identities() {
        let p = Params {
            n: 4,
            k: 2,
            f: 1,
            t: 4,
        };
        let row = vec![Pair::zero(); p.t];
        assert!(aggregate(
            p,
            vec![(1, row.clone()), (1, row.clone()), (2, row.clone())]
        )
        .is_err());
        assert!(aggregate(
            p,
            vec![(1, row.clone()), (2, row.clone()), (5, row.clone())]
        )
        .is_err());
        assert!(aggregate(p, vec![(1, row.clone()), (2, row)]).is_err());
    }
    #[test]
    fn reject_noncanonical_and_wrong_recipient_proof() {
        assert!(sf([255; 32]).is_err());
        assert!(point(&[[0; 32], crate::chain::word(1)]).is_err());
        let (state, rows) = init(Params {
            n: 4,
            k: 2,
            f: 1,
            t: 4,
        })
        .unwrap();
        let sk = nonzero();
        let dealer = nonzero();
        let m = eval(&rows[0], Fr::from(1));
        let rec = record(&state, &state, 1, 1, 7, 0, g() * sk, dealer, m, true, "");
        assert!(decryption_proof(&rec, sk + Fr::ONE).is_err());
        assert!(decryption_proof(&rec, sk).is_ok());
    }
    #[test]
    fn distinguish_plaintext_fault_and_consistency_fault() {
        let (state, rows) = init(Params {
            n: 4,
            k: 2,
            f: 1,
            t: 4,
        })
        .unwrap();
        let sk = nonzero();
        let dealer = nonzero();
        let m = eval(&rows[0], Fr::from(1));
        let plain = record(
            &state,
            &state,
            1,
            1,
            7,
            0,
            g() * sk,
            dealer,
            m,
            true,
            "bad_plaintext",
        );
        assert!(authenticated(&plain, g() * dealer).is_ok());
        assert!(decrypt(&plain, g() * dealer, sk).is_err());
        let inconsistent = record(
            &state,
            &state,
            1,
            1,
            7,
            0,
            g() * sk,
            dealer,
            m,
            true,
            "inconsistent",
        );
        let value = decrypt(&inconsistent, g() * dealer, sk).unwrap();
        assert_ne!(value.commit(), peval(&state.vectors[0], Fr::from(1)));
        let mut bad_pop = plain;
        bad_pop.words[18] = sw(sf(bad_pop.words[18]).unwrap() + Fr::ONE);
        assert!(decryption_proof(&bad_pop, sk).is_err());
    }
}
