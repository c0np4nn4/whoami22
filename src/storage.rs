use crate::{crypto::*, protocol::*};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub index: usize,
    pub count: usize,
    pub siblings: Vec<Hash>,
}
pub struct Merkle {
    layers: Vec<Vec<Hash>>,
    count: usize,
}
impl Merkle {
    pub fn new(values: &[Vec<u8>]) -> Self {
        assert!(!values.is_empty());
        let count = values.len();
        let size = count.next_power_of_two();
        let mut first: Vec<_> = values
            .iter()
            .enumerate()
            .map(|(i, v)| hash(&[b"leaf", &(i as u64).to_le_bytes(), v]))
            .collect();
        first.resize(size, hash(&[b"padding"]));
        let mut layers = vec![first];
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            layers.push(
                prev.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|v| hash(&[b"node", &v[0], &v[1]]))
                    .collect(),
            );
        }
        Self { layers, count }
    }
    pub fn root(&self) -> Hash {
        hash(&[
            b"root",
            &(self.count as u64).to_le_bytes(),
            &self.layers.last().unwrap()[0],
        ])
    }
    pub fn proof(&self, index: usize) -> MerkleProof {
        assert!(index < self.count);
        let mut idx = index;
        let mut siblings = Vec::new();
        for l in &self.layers[..self.layers.len() - 1] {
            siblings.push(l[idx ^ 1]);
            idx /= 2;
        }
        MerkleProof {
            index,
            count: self.count,
            siblings,
        }
    }
}
pub fn merkle_verify(root: Hash, value: &[u8], p: &MerkleProof) -> bool {
    if p.count == 0
        || p.index >= p.count
        || p.siblings.len() != p.count.next_power_of_two().trailing_zeros() as usize
    {
        return false;
    }
    let mut h = hash(&[b"leaf", &(p.index as u64).to_le_bytes(), value]);
    let mut i = p.index;
    for s in &p.siblings {
        h = if i.is_multiple_of(2) {
            hash(&[b"node", &h, s])
        } else {
            hash(&[b"node", s, &h])
        };
        i /= 2;
    }
    hash(&[b"root", &(p.count as u64).to_le_bytes(), &h]) == root
}
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredRecord {
    pub record: Record,
    pub proof: MerkleProof,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ArchiveMeta {
    pub root: Hash,
    pub source: Hash,
    pub target: Hash,
    pub nonce: u64,
    pub recipient: u64,
    pub mode: Mode,
    pub record_ids: Vec<u64>,
    pub vector_hashes: BTreeMap<u64, Hash>,
}
#[derive(Clone)]
pub struct Archive {
    pub dir: PathBuf,
    pub meta: ArchiveMeta,
}
impl Archive {
    pub fn write(
        dir: &Path,
        records: &[Record],
        vectors: &BTreeMap<u64, (Vec<Point>, Vec<Point>)>,
    ) -> Result<Self> {
        ensure!(!records.is_empty(), "empty archive");
        fs::create_dir_all(dir)?;
        let blobs: Vec<_> = records.iter().map(enc).collect();
        let tree = Merkle::new(&blobs);
        let a = &records[0].ad;
        let mut hashes = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for (idx, rec) in records.iter().enumerate() {
            ensure!(ids.insert(rec.ad.dealer), "duplicate dealer record");
            ensure!(
                rec.ad.source == a.source
                    && rec.ad.target == a.target
                    && rec.ad.nonce == a.nonce
                    && rec.ad.mode == a.mode
                    && rec.ad.recipient == a.recipient,
                "mixed archive context"
            );
            fs::write(
                dir.join(format!("record-{}.bin", rec.ad.dealer)),
                enc(&StoredRecord {
                    record: rec.clone(),
                    proof: tree.proof(idx),
                }),
            )?;
        }
        for (j, v) in vectors {
            let bytes = enc(v);
            hashes.insert(*j, hash(&[&bytes]));
            fs::write(dir.join(format!("vectors-{j}.bin")), bytes)?;
        }
        let meta = ArchiveMeta {
            root: tree.root(),
            source: a.source,
            target: a.target,
            nonce: a.nonce,
            recipient: a.recipient,
            mode: a.mode,
            record_ids: ids.into_iter().collect(),
            vector_hashes: hashes,
        };
        fs::write(dir.join("meta.bin"), enc(&meta))?;
        Ok(Self {
            dir: dir.to_owned(),
            meta,
        })
    }
    pub fn open(dir: &Path) -> Result<Self> {
        let meta = bincode::deserialize(&fs::read(dir.join("meta.bin"))?)?;
        Ok(Self {
            dir: dir.to_owned(),
            meta,
        })
    }
    pub fn bytes(&self) -> Result<u64> {
        Ok(fs::read_dir(&self.dir)?
            .filter_map(|x| x.ok())
            .map(|x| x.metadata().map(|m| m.len()).unwrap_or(0))
            .sum())
    }
}
#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct RecoveryStats {
    pub records_read: usize,
    pub fetch_attempts: usize,
    pub missing: usize,
    pub discarded: usize,
    pub bytes: u64,
    pub vector_bytes: u64,
    pub localizations: usize,
    pub admitted: usize,
    pub aggregate_ns: u64,
    pub localization_ns: u64,
    pub individually_validated: usize,
}
#[derive(Default)]
pub struct VectorCache {
    pub vectors: BTreeMap<u64, (Vec<Point>, Vec<Point>)>,
}
impl VectorCache {
    pub fn preload(&mut self, a: &Archive) -> Result<()> {
        for j in &a.meta.record_ids {
            let b = fs::read(a.dir.join(format!("vectors-{j}.bin")))?;
            ensure!(
                hash(&[&b]) == a.meta.vector_hashes[j],
                "vector authentication"
            );
            self.vectors.insert(*j, bincode::deserialize(&b)?);
        }
        Ok(())
    }
}
pub fn recover(
    a: &Archive,
    sk: Fr,
    sign_pks: &[Point],
    k: usize,
    expected: &[Point],
    cache: &mut VectorCache,
) -> Result<(Pair, RecoveryStats)> {
    recover_with(a, sk, sign_pks, k, expected, cache, |path| {
        Ok(fs::read(path)?)
    })
}
pub fn recover_with<F: FnMut(&Path) -> Result<Vec<u8>>>(
    a: &Archive,
    sk: Fr,
    sign_pks: &[Point],
    k: usize,
    expected: &[Point],
    cache: &mut VectorCache,
    mut fetch: F,
) -> Result<(Pair, RecoveryStats)> {
    let mut stats = RecoveryStats::default();
    let mut selected: Vec<(u64, Pair, Record)> = Vec::new();
    let mut checked = BTreeSet::new();
    let mut localizing = false;
    for id in &a.meta.record_ids {
        stats.fetch_attempts += 1;
        let bytes = match fetch(&a.dir.join(format!("record-{id}.bin"))) {
            Ok(b) => b,
            Err(_) => {
                stats.missing += 1;
                continue;
            }
        };
        stats.bytes += bytes.len() as u64;
        stats.records_read += 1;
        let stored: StoredRecord = match bincode::deserialize(&bytes) {
            Ok(v) => v,
            Err(_) => {
                stats.discarded += 1;
                continue;
            }
        };
        let rec = stored.record;
        if rec.ad.dealer != *id
            || rec.ad.recipient != a.meta.recipient
            || rec.ad.source != a.meta.source
            || rec.ad.target != a.meta.target
            || rec.ad.nonce != a.meta.nonce
            || rec.ad.mode != a.meta.mode
            || rec.ad.key_epoch != 0
            || !merkle_verify(a.meta.root, &enc(&rec), &stored.proof)
        {
            stats.discarded += 1;
            continue;
        }
        let pk = sign_pks.get((*id - 1) as usize).context("unknown dealer")?;
        let start = Instant::now();
        let admitted = admit(&rec, *pk, sk);
        stats.aggregate_ns += start.elapsed().as_nanos() as u64;
        let p = match admitted {
            Ok(p) => p,
            Err(_) => {
                stats.discarded += 1;
                continue;
            }
        };
        stats.admitted += 1;
        selected.push((*id, p, rec));
        if localizing || selected.len() >= k {
            if selected.len() >= k {
                let start = Instant::now();
                let combined = combine(
                    &selected
                        .iter()
                        .take(k)
                        .map(|(id, p, _)| (*id, *p))
                        .collect::<Vec<_>>(),
                )?;
                let valid =
                    combined.commitment() == eval_commit(expected, Fr::from(a.meta.recipient));
                stats.aggregate_ns += start.elapsed().as_nanos() as u64;
                if valid {
                    return Ok((combined, stats));
                }
            }
            let start = Instant::now();
            localizing = true;
            let mut keep = Vec::new();
            for (id, p, rec) in selected.drain(..) {
                if checked.contains(&id) {
                    keep.push((id, p, rec));
                    continue;
                }
                if let std::collections::btree_map::Entry::Vacant(entry) = cache.vectors.entry(id) {
                    let b = fetch(&a.dir.join(format!("vectors-{id}.bin")))?;
                    stats.bytes += b.len() as u64;
                    stats.vector_bytes += b.len() as u64;
                    ensure!(
                        a.meta.vector_hashes.get(&id) == Some(&hash(&[&b])),
                        "vector authentication"
                    );
                    entry.insert(bincode::deserialize(&b)?);
                }
                let (src, tgt) = &cache.vectors[&id];
                let vector = if a.meta.mode == Mode::Difference {
                    delta(src, tgt)
                } else {
                    tgt.clone()
                };
                stats.localizations += 1;
                if hash(&[&enc(&vector)]) == rec.ad.vector_digest
                    && eval_commit(&vector, Fr::from(a.meta.recipient)) == rec.ad.e
                {
                    checked.insert(id);
                    stats.individually_validated += 1;
                    keep.push((id, p, rec));
                } else {
                    stats.discarded += 1;
                }
            }
            selected = keep;
            stats.localization_ns += start.elapsed().as_nanos() as u64;
        }
    }
    anyhow::bail!(
        "insufficient usable records: {}",
        serde_json::to_string(&stats)?
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merkle_binding() {
        let v = vec![vec![1], vec![2], vec![3]];
        let t = Merkle::new(&v);
        for (i, x) in v.iter().enumerate() {
            assert!(merkle_verify(t.root(), x, &t.proof(i)));
            assert!(!merkle_verify(t.root(), &[9], &t.proof(i)));
        }
        let mut p = t.proof(1);
        p.count = 4;
        assert!(!merkle_verify(t.root(), &v[1], &p));
    }
    #[test]
    fn recovery_fault_and_cancellation() {
        let mut r = rng(3, "recovery", 0);
        let p = Params {
            n: 7,
            k: 3,
            f: 2,
            t: 8,
        };
        let src = init(p, 0, &mut r).unwrap();
        let dst = generate(&src, 8, &mut r).unwrap();
        let sk = nonzero(&mut r);
        let keys: Vec<_> = (0..p.n).map(|_| nonzero(&mut r)).collect();
        let pks: Vec<_> = keys.iter().map(|s| s * g()).collect();
        let vectors = (0..p.n)
            .map(|j| {
                (
                    (j + 1) as u64,
                    (src.vectors[j].clone(), dst.vectors[j].clone()),
                )
            })
            .collect();
        for cancel in [false, true] {
            let records: Vec<_> = (0..p.n - p.f)
                .map(|j| {
                    make_record(
                        &src,
                        &dst,
                        j,
                        1,
                        19,
                        Mode::Difference,
                        sk * g(),
                        keys[j],
                        if j == 0 || (cancel && j == 1) {
                            Fr::ONE
                        } else {
                            Fr::ZERO
                        },
                        &mut r,
                    )
                })
                .collect();
            let d = tempfile::tempdir().unwrap();
            let a = Archive::write(d.path(), &records, &vectors).unwrap();
            let (token, stats) = recover(
                &a,
                sk,
                &pks,
                p.k,
                &delta(&src.public, &dst.public),
                &mut VectorCache::default(),
            )
            .unwrap();
            assert_eq!(src.share(1).plus(token), dst.share(1));
            if cancel {
                assert_eq!(stats.localizations, 0);
                assert_eq!(stats.individually_validated, 0);
            } else {
                assert!(stats.localizations > 0);
                assert!(stats.records_read <= p.k + p.f);
            }
        }
    }
}
