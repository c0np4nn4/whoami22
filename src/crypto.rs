//! Ristretto255 / SHA-512 MEGa-DH reference suite. Independent research implementation.
use anyhow::{ensure, Result};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul},
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

pub type Point = RistrettoPoint;
pub type Fr = Scalar;
pub type Hash = [u8; 32];
pub const SUITE: &str = "ristretto255-sha512-schnorr-mega-v1";

pub fn hash(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}
pub fn wide(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}
pub fn hs(parts: &[&[u8]]) -> Fr {
    Fr::from_bytes_mod_order_wide(&wide(parts))
}
pub fn hg(parts: &[&[u8]]) -> Point {
    Point::from_uniform_bytes(&wide(parts))
}
pub fn rng(seed: u64, domain: &str, id: u64) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(hash(&[
        b"VESS-BENCH-RNG",
        &seed.to_le_bytes(),
        domain.as_bytes(),
        &id.to_le_bytes(),
    ]))
}
pub fn g() -> Point {
    RISTRETTO_BASEPOINT_POINT
}
pub fn h() -> Point {
    static H: std::sync::OnceLock<Point> = std::sync::OnceLock::new();
    *H.get_or_init(|| hg(&[b"VESS-PEDERSEN-H-v1"]))
}
pub fn enc<T: Serialize>(x: &T) -> Vec<u8> {
    bincode::serialize(x).expect("serializable protocol value")
}
pub fn random<R: RngCore + CryptoRng>(r: &mut R) -> Fr {
    Fr::random(r)
}
pub fn nonzero<R: RngCore + CryptoRng>(r: &mut R) -> Fr {
    loop {
        let x = random(r);
        if x != Fr::ZERO {
            return x;
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct Pair {
    pub v: Fr,
    pub r: Fr,
}
impl Pair {
    pub fn zero() -> Self {
        Self {
            v: Fr::ZERO,
            r: Fr::ZERO,
        }
    }
    pub fn sample<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            v: random(rng),
            r: random(rng),
        }
    }
    pub fn plus(self, x: Self) -> Self {
        Self {
            v: self.v + x.v,
            r: self.r + x.r,
        }
    }
    pub fn minus(self, x: Self) -> Self {
        Self {
            v: self.v - x.v,
            r: self.r - x.r,
        }
    }
    pub fn scale(self, x: Fr) -> Self {
        Self {
            v: self.v * x,
            r: self.r * x,
        }
    }
    pub fn commitment(self) -> Point {
        self.v * g() + self.r * h()
    }
}
pub fn eval(poly: &[Pair], x: Fr) -> Pair {
    poly.iter()
        .rev()
        .fold(Pair::zero(), |v, a| v.scale(x).plus(*a))
}
pub fn powers(x: Fr, n: usize) -> Vec<Fr> {
    let mut a = Fr::ONE;
    (0..n)
        .map(|_| {
            let out = a;
            a *= x;
            out
        })
        .collect()
}
/// Variable-time is used only for public verification scalars and public points.
pub fn eval_commit(c: &[Point], x: Fr) -> Point {
    Point::vartime_multiscalar_mul(powers(x, c.len()), c)
}
pub fn weights(ids: &[u64], at: Fr) -> Result<Vec<Fr>> {
    ensure!(!ids.is_empty(), "empty interpolation set");
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        ensure!(*id != 0 && seen.insert(*id), "zero/duplicate coordinate");
    }
    Ok(ids
        .iter()
        .map(|j| {
            let x = Fr::from(*j);
            let mut a = Fr::ONE;
            let mut b = Fr::ONE;
            for k in ids {
                if j != k {
                    let y = Fr::from(*k);
                    a *= at - y;
                    b *= x - y;
                }
            }
            a * b.invert()
        })
        .collect())
}
pub fn combine(parts: &[(u64, Pair)]) -> Result<Pair> {
    let ids: Vec<_> = parts.iter().map(|p| p.0).collect();
    Ok(parts
        .iter()
        .zip(weights(&ids, Fr::ZERO)?)
        .fold(Pair::zero(), |v, ((_, p), w)| v.plus(p.scale(w))))
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    pub r: Point,
    pub s: Fr,
}
pub fn sign<R: RngCore + CryptoRng>(sk: Fr, msg: &[u8], rng: &mut R) -> Signature {
    let mut nonce = nonzero(rng);
    let public = sk * g();
    let r = nonce * g();
    let c = hs(&[b"VESS-SIGN-v1", &enc(&public), &enc(&r), msg]);
    let s = nonce + c * sk;
    nonce.zeroize();
    Signature { r, s }
}
pub fn verify_sig(pk: Point, msg: &[u8], sig: &Signature) -> bool {
    if pk == Point::identity() || sig.r == Point::identity() {
        return false;
    }
    let c = hs(&[b"VESS-SIGN-v1", &enc(&pk), &enc(&sig.r), msg]);
    sig.s * g() == sig.r + c * pk
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dleq {
    pub c: Fr,
    pub s: Fr,
}
pub fn prove<R: RngCore + CryptoRng>(
    sk: Fr,
    b1: Point,
    b2: Point,
    p1: Point,
    p2: Point,
    context: &[u8],
    rng: &mut R,
) -> Dleq {
    let mut w = nonzero(rng);
    let a = w * b1;
    let b = w * b2;
    let c = hs(&[b"VESS-DLEQ-v1", context, &enc(&(b1, b2, p1, p2, a, b))]);
    let s = w + c * sk;
    w.zeroize();
    Dleq { c, s }
}
pub fn verify_proof(b1: Point, b2: Point, p1: Point, p2: Point, context: &[u8], p: &Dleq) -> bool {
    if [b1, b2, p1, p2].contains(&Point::identity()) {
        return false;
    }
    let a = p.s * b1 - p.c * p1;
    let b = p.s * b2 - p.c * p2;
    hs(&[b"VESS-DLEQ-v1", context, &enc(&(b1, b2, p1, p2, a, b))]) == p.c
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cipher {
    pub v: Point,
    pub vp: Point,
    pub pop: Dleq,
    pub c: Pair,
}
fn pop_base(ad: &[u8], v: Point) -> Point {
    hg(&[b"epk-pop", ad, &enc(&v)])
}
fn key(ad: &[u8], id: u64, pk: Point, v: Point, shared: Point) -> Pair {
    let ctx = enc(&(id, pk, v, shared));
    Pair {
        v: hs(&[b"derive-key-0", ad, &ctx]),
        r: hs(&[b"derive-key-1", ad, &ctx]),
    }
}
pub fn encrypt<R: RngCore + CryptoRng>(
    ad: &[u8],
    id: u64,
    pk: Point,
    m: Pair,
    rng: &mut R,
) -> Cipher {
    let mut k = nonzero(rng);
    let v = k * g();
    let b = pop_base(ad, v);
    let vp = k * b;
    let pop = prove(k, g(), b, v, vp, ad, rng);
    let c = m.plus(key(ad, id, pk, v, k * pk));
    k.zeroize();
    Cipher { v, vp, pop, c }
}
pub fn pop_ok(ad: &[u8], ct: &Cipher) -> bool {
    verify_proof(g(), pop_base(ad, ct.v), ct.v, ct.vp, ad, &ct.pop)
}
pub fn decrypt(ad: &[u8], id: u64, sk: Fr, ct: &Cipher) -> Result<Pair> {
    ensure!(pop_ok(ad, ct), "invalid PoP");
    Ok(ct.c.minus(key(ad, id, sk * g(), ct.v, sk * ct.v)))
}
#[derive(Clone, Serialize, Deserialize)]
pub struct DecryptionProof {
    pub shared: Point,
    pub proof: Dleq,
}
pub fn decryption_proof<R: RngCore + CryptoRng>(
    ad: &[u8],
    sk: Fr,
    ct: &Cipher,
    rng: &mut R,
) -> Result<DecryptionProof> {
    ensure!(pop_ok(ad, ct), "refuse disclosure before valid PoP");
    let shared = sk * ct.v;
    Ok(DecryptionProof {
        shared,
        proof: prove(
            sk,
            g(),
            ct.v,
            sk * g(),
            shared,
            &enc(&(b"DEC", ad, ct)),
            rng,
        ),
    })
}
pub fn from_proof(
    ad: &[u8],
    id: u64,
    pk: Point,
    ct: &Cipher,
    proof: &DecryptionProof,
) -> Result<Pair> {
    ensure!(pop_ok(ad, ct), "invalid PoP");
    ensure!(
        verify_proof(
            g(),
            ct.v,
            pk,
            proof.shared,
            &enc(&(b"DEC", ad, ct)),
            &proof.proof
        ),
        "invalid decryption proof"
    );
    Ok(ct.c.minus(key(ad, id, pk, ct.v, proof.shared)))
}
/// Random challenges bind every partial and public commitment before evaluation.
pub fn batch_verify(
    context: &[u8],
    ids: &[u64],
    partials: &[Pair],
    vectors: &[Vec<Point>],
    at: Fr,
) -> bool {
    if ids.len() != partials.len() || ids.len() != vectors.len() || ids.is_empty() {
        return false;
    }
    if weights(ids, Fr::ZERO).is_err() {
        return false;
    }
    let tr = enc(&(context, ids, partials, vectors, at));
    let mut sum = Pair::zero();
    let mut bases = Vec::new();
    let mut scalars = Vec::new();
    for (idx, ((id, p), c)) in ids.iter().zip(partials).zip(vectors).enumerate() {
        let eta = hs(&[
            b"BATCH",
            &tr,
            &id.to_le_bytes(),
            &(idx as u64).to_le_bytes(),
        ]);
        sum = sum.plus(p.scale(eta));
        for (pow, base) in powers(at, c.len()).into_iter().zip(c) {
            scalars.push(pow * eta);
            bases.push(*base);
        }
    }
    sum.commitment() == Point::vartime_multiscalar_mul(scalars, bases)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mega_proofs_context_and_bad_opening() {
        let mut r = rng(9, "test", 0);
        let sk = nonzero(&mut r);
        let m = Pair::sample(&mut r);
        let ct = encrypt(b"a", 7, sk * g(), m, &mut r);
        assert_eq!(decrypt(b"a", 7, sk, &ct).unwrap(), m);
        assert!(decrypt(b"b", 7, sk, &ct).is_err());
        let dp = decryption_proof(b"a", sk, &ct, &mut r).unwrap();
        assert_eq!(from_proof(b"a", 7, sk * g(), &ct, &dp).unwrap(), m);
        let mut bad = ct.clone();
        bad.pop.s += Fr::ONE;
        assert!(decryption_proof(b"a", sk, &bad, &mut r).is_err());
        let mut modified = ct.clone();
        modified.c.v += Fr::ONE;
        assert_ne!(
            decrypt(b"a", 7, sk, &modified).unwrap().commitment(),
            m.commitment()
        );
    }
    #[test]
    fn interpolation_and_encoding() {
        let mut r = rng(4, "interpolate", 0);
        for k in 2..8 {
            let p: Vec<_> = (0..k).map(|_| Pair::sample(&mut r)).collect();
            let parts: Vec<_> = (1..=k as u64).map(|i| (i, eval(&p, Fr::from(i)))).collect();
            assert_eq!(combine(&parts).unwrap(), p[0]);
        }
        assert!(weights(&[1, 1], Fr::ZERO).is_err());
        assert!(bincode::deserialize::<Fr>(&[255; 32]).is_err());
        assert!(bincode::deserialize::<Point>(&[255; 32]).is_err());
        assert_eq!(enc(&g()).len(), 32);
    }
}
