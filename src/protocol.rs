use crate::crypto::*;
use anyhow::{ensure, Result};
use curve25519_dalek::traits::Identity;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

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
            self.k > self.f && self.n >= 2 * self.f + self.k && self.t >= 2,
            "invalid dealer/participant thresholds"
        );
        Ok(())
    }
    pub fn margin(self) -> usize {
        self.n - 2 * self.f - self.k
    }
}
/// Full rows exist only in reference fixtures, not in the distributed node coordinator.
#[derive(Clone, Serialize, Deserialize)]
pub struct Epoch {
    pub params: Params,
    pub epoch: u64,
    pub rows: Vec<Vec<Pair>>,
    pub vectors: Vec<Vec<Point>>,
    pub public: Vec<Point>,
}
impl Epoch {
    pub fn from_rows(params: Params, epoch: u64, rows: Vec<Vec<Pair>>) -> Result<Self> {
        params.check()?;
        ensure!(
            rows.len() == params.n && rows.iter().all(|r| r.len() == params.t),
            "row dimensions"
        );
        let vectors: Vec<Vec<_>> = rows
            .iter()
            .map(|r| r.iter().map(|p| p.commitment()).collect())
            .collect();
        let public = public_from_vectors(params, &vectors)?;
        Ok(Self {
            params,
            epoch,
            rows,
            vectors,
            public,
        })
    }
    pub fn digest(&self) -> Hash {
        hash(&[b"STATE", &enc(&(self.params, self.epoch, &self.public))])
    }
    pub fn share(&self, i: u64) -> Pair {
        let parts: Vec<_> = (0..self.params.k)
            .map(|j| ((j + 1) as u64, eval(&self.rows[j], Fr::from(i))))
            .collect();
        combine(&parts).expect("valid dealer coordinates")
    }
}
pub fn public_from_vectors(p: Params, c: &[Vec<Point>]) -> Result<Vec<Point>> {
    ensure!(
        c.len() == p.n && c.iter().all(|x| x.len() == p.t),
        "commitment dimensions"
    );
    let ids: Vec<_> = (1..=p.k as u64).collect();
    let ws = weights(&ids, Fr::ZERO)?;
    // eq:record at every published dealer coordinate, including non-selected dealers.
    for (j, row) in c.iter().enumerate().skip(p.k) {
        let wj = weights(&ids, Fr::from((j + 1) as u64))?;
        for (l, claimed) in row.iter().enumerate() {
            let actual: Point = (0..p.k).map(|u| wj[u] * c[u][l]).sum();
            ensure!(
                *claimed == actual,
                "inconsistent dealer commitment polynomial"
            );
        }
    }
    Ok((0..p.t)
        .map(|l| (0..p.k).map(|j| ws[j] * c[j][l]).sum())
        .collect())
}
pub fn init<R: RngCore + CryptoRng>(p: Params, epoch: u64, rng: &mut R) -> Result<Epoch> {
    p.check()?;
    let mut rows = vec![vec![Pair::zero(); p.t]; p.n];
    for l in 0..p.t {
        let poly: Vec<_> = (0..p.k).map(|_| Pair::sample(rng)).collect();
        for (j, row) in rows.iter_mut().enumerate() {
            row[l] = eval(&poly, Fr::from((j + 1) as u64));
        }
    }
    Epoch::from_rows(p, epoch, rows)
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Contribution {
    pub commitments: Vec<Vec<Point>>,
    pub to: Vec<Vec<Pair>>,
}
pub fn contribute<R: RngCore + CryptoRng>(
    source_constant: Pair,
    p: Params,
    rng: &mut R,
) -> Contribution {
    let mut commitments = Vec::with_capacity(p.t);
    let mut to = vec![Vec::with_capacity(p.t); p.n];
    for l in 0..p.t {
        let mut poly: Vec<_> = (0..p.k).map(|_| Pair::sample(rng)).collect();
        if l == 0 {
            poly[0] = source_constant;
        }
        commitments.push(poly.iter().map(|p| p.commitment()).collect());
        for (j, parts) in to.iter_mut().enumerate() {
            parts.push(eval(&poly, Fr::from((j + 1) as u64)));
        }
        use zeroize::Zeroize;
        poly.zeroize();
    }
    Contribution { commitments, to }
}
pub fn verify_contribution(
    c: &[Vec<Point>],
    parts: &[Pair],
    recipient: u64,
    constant: Point,
    p: Params,
) -> bool {
    c.len() == p.t
        && parts.len() == p.t
        && c.iter().all(|v| v.len() == p.k)
        && c[0][0] == constant
        && c.iter()
            .zip(parts)
            .all(|(v, p)| eval_commit(v, Fr::from(recipient)) == p.commitment())
}
pub fn aggregate_contributions(p: Params, qualified: &[(u64, Vec<Pair>)]) -> Result<Vec<Pair>> {
    ensure!(
        qualified.len() >= p.n - p.f,
        "insufficient JRSS qualified set"
    );
    let mut q = qualified.to_vec();
    q.sort_by_key(|v| v.0);
    let base: Vec<_> = q[..p.k].iter().map(|(id, v)| (*id, v[0])).collect();
    let mut row = vec![combine(&base)?];
    for l in 1..p.t {
        row.push(q.iter().fold(Pair::zero(), |v, (_, r)| v.plus(r[l])));
    }
    Ok(row)
}
pub fn generate<R: RngCore + CryptoRng>(
    source: &Epoch,
    target_t: usize,
    rng: &mut R,
) -> Result<Epoch> {
    let p = Params {
        t: target_t,
        ..source.params
    };
    p.check()?;
    let contributions: Vec<_> = source
        .rows
        .iter()
        .map(|r| contribute(r[0], p, rng))
        .collect();
    let mut rows = Vec::new();
    for j in 0..p.n {
        let mut qualified = Vec::new();
        for (d, c) in contributions.iter().enumerate() {
            ensure!(
                verify_contribution(
                    &c.commitments,
                    &c.to[j],
                    (j + 1) as u64,
                    source.vectors[d][0],
                    p
                ),
                "VSS verification"
            );
            qualified.push(((d + 1) as u64, c.to[j].clone()));
        }
        rows.push(aggregate_contributions(p, &qualified)?);
    }
    let e = Epoch::from_rows(p, source.epoch + 1, rows)?;
    ensure!(e.public[0] == source.public[0], "constant not preserved");
    Ok(e)
}
pub fn delta(source: &[Point], target: &[Point]) -> Vec<Point> {
    (0..source.len().max(target.len()))
        .map(|l| {
            target.get(l).copied().unwrap_or(Point::identity())
                - source.get(l).copied().unwrap_or(Point::identity())
        })
        .collect()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Difference,
    Snapshot,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Ad {
    pub version: u8,
    pub source_epoch: u64,
    pub target_epoch: u64,
    pub nonce: u64,
    pub mode: Mode,
    pub dealer: u64,
    pub recipient: u64,
    pub key_epoch: u64,
    pub source: Hash,
    pub target: Hash,
    pub vector_digest: Hash,
    pub e: Point,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub ad: Ad,
    pub cipher: Cipher,
    pub signature: Signature,
}
pub fn record<R: RngCore + CryptoRng>(
    mut ad: Ad,
    m: Pair,
    recipient_pk: Point,
    sign_sk: Fr,
    rng: &mut R,
) -> Record {
    ad.e = m.commitment();
    let cipher = encrypt(&enc(&ad), ad.recipient, recipient_pk, m, rng);
    let signature = sign(sign_sk, &enc(&(&ad, &cipher)), rng);
    Record {
        ad,
        cipher,
        signature,
    }
}
pub fn admit(rec: &Record, sign_pk: Point, recipient_sk: Fr) -> Result<Pair> {
    ensure!(
        verify_sig(sign_pk, &enc(&(&rec.ad, &rec.cipher)), &rec.signature),
        "signature"
    );
    let p = decrypt(&enc(&rec.ad), rec.ad.recipient, recipient_sk, &rec.cipher)?;
    ensure!(p.commitment() == rec.ad.e, "plaintext opening");
    Ok(p)
}
// Fixture constructor mirrors the record context and explicit injected error.
#[allow(clippy::too_many_arguments)]
pub fn make_record<R: RngCore + CryptoRng>(
    source: &Epoch,
    target: &Epoch,
    j: usize,
    i: u64,
    nonce: u64,
    mode: Mode,
    recipient_pk: Point,
    sign_sk: Fr,
    shift: Fr,
    rng: &mut R,
) -> Record {
    let mut pair = eval(&target.rows[j], Fr::from(i));
    if mode == Mode::Difference {
        pair = pair.minus(eval(&source.rows[j], Fr::from(i)));
    }
    pair.v += shift;
    let v = if mode == Mode::Difference {
        delta(&source.vectors[j], &target.vectors[j])
    } else {
        target.vectors[j].clone()
    };
    let ad = Ad {
        version: 1,
        source_epoch: source.epoch,
        target_epoch: target.epoch,
        nonce,
        mode,
        dealer: (j + 1) as u64,
        recipient: i,
        key_epoch: 0,
        source: source.digest(),
        target: target.digest(),
        vector_digest: hash(&[&enc(&v)]),
        e: Point::identity(),
    };
    record(ad, pair, recipient_pk, sign_sk, rng)
}
pub fn reconstruct(public: &[Point], shares: &[(u64, Pair)]) -> Result<Pair> {
    let mut valid = std::collections::BTreeMap::new();
    for (i, p) in shares {
        if *i != 0 && p.commitment() == eval_commit(public, Fr::from(*i)) {
            valid.entry(*i).or_insert(*p);
        }
    }
    ensure!(valid.len() >= public.len(), "too few valid unique shares");
    combine(&valid.into_iter().take(public.len()).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generation_and_threshold_changes() {
        let mut r = rng(7, "test", 0);
        let a = init(
            Params {
                n: 4,
                k: 2,
                f: 1,
                t: 3,
            },
            0,
            &mut r,
        )
        .unwrap();
        for t in [2, 3, 8] {
            let b = generate(&a, t, &mut r).unwrap();
            assert_eq!(a.public[0], b.public[0]);
            let mut shares = Vec::new();
            for i in 1..=t as u64 {
                let old = a.share(i);
                let new = b.share(i);
                let token = new.minus(old);
                assert_eq!(
                    token.commitment(),
                    eval_commit(&delta(&a.public, &b.public), Fr::from(i))
                );
                shares.push((i, new));
            }
            assert_eq!(
                reconstruct(&b.public, &shares).unwrap().commitment(),
                a.public[0]
            );
        }
    }
}
