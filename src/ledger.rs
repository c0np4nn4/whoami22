use crate::{crypto::*, protocol::Mode};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

pub fn durable_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().context("file parent")?;
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(tmp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
struct Lock(File);
impl Lock {
    fn new(path: &Path) -> Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        // SAFETY: flock receives a live file descriptor; the owning File outlives this lock.
        ensure!(
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0,
            "flock"
        );
        Ok(Self(f))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub source: Hash,
    pub source_t: usize,
    pub delta: usize,
    pub incoming: BTreeSet<u64>,
    pub rho_out: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub old_root: Hash,
    pub nonce: u64,
    pub recipients: BTreeSet<u64>,
    pub target: Hash,
    pub target_t: usize,
    pub target_rho: usize,
    pub eligible: usize,
    pub mode: Mode,
}
pub fn target_check(r: &Request, delta: usize) -> Result<()> {
    ensure!(
        delta + r.recipients.len() + r.target_rho < r.target_t,
        "target budget"
    );
    ensure!(r.eligible >= r.target_t, "eligible population");
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub version: u64,
    pub request: Request,
    pub new_root: Hash,
    pub reserved: BTreeSet<u64>,
}
#[derive(Clone)]
pub struct Ledger {
    pub dir: PathBuf,
    pub policy: Policy,
}
impl Ledger {
    pub fn create(dir: &Path, policy: Policy) -> Result<Self> {
        fs::create_dir_all(dir)?;
        ensure!(
            policy.delta + policy.incoming.len() < policy.source_t,
            "initial budget"
        );
        let path = dir.join("policy.bin");
        if path.exists() {
            ensure!(fs::read(&path)? == enc(&policy), "policy cannot change");
        } else {
            durable_write(&path, &enc(&policy))?;
        }
        Ok(Self {
            dir: dir.to_owned(),
            policy,
        })
    }
    pub fn open(dir: &Path) -> Result<Self> {
        Ok(Self {
            dir: dir.to_owned(),
            policy: bincode::deserialize(&fs::read(dir.join("policy.bin"))?)?,
        })
    }
    pub fn entries(&self) -> Result<Vec<Entry>> {
        let path = self.dir.join("log.bin");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(path)?;
        let mut at = 0;
        let mut out = Vec::new();
        while at < bytes.len() {
            ensure!(at + 8 <= bytes.len(), "truncated log length");
            let len = u64::from_le_bytes(bytes[at..at + 8].try_into()?) as usize;
            at += 8;
            ensure!(
                at + len + 32 <= bytes.len(),
                "incomplete durable log record; fail closed"
            );
            let payload = &bytes[at..at + len];
            ensure!(
                hash(&[payload]) == bytes[at + len..at + len + 32],
                "log checksum"
            );
            let e: Entry = bincode::deserialize(payload)?;
            let expected = out
                .last()
                .map(|x: &Entry| x.new_root)
                .unwrap_or(self.initial_root());
            ensure!(
                e.request.old_root == expected && e.version == out.len() as u64 + 1,
                "log chain"
            );
            ensure!(
                e.new_root
                    == hash(&[&enc(&(
                        self.policy.source,
                        e.version,
                        &e.request,
                        &e.reserved
                    ))]),
                "root tamper"
            );
            out.push(e);
            at += len + 32;
        }
        Ok(out)
    }
    pub fn initial_root(&self) -> Hash {
        hash(&[b"EMPTY-LEDGER", &enc(&self.policy)])
    }
    pub fn root(&self) -> Result<Hash> {
        Ok(self
            .entries()?
            .last()
            .map(|x| x.new_root)
            .unwrap_or(self.initial_root()))
    }
    pub fn reserve(&self, r: Request) -> Result<Entry> {
        let _lock = Lock::new(&self.dir.join("lock"))?;
        target_check(&r, self.policy.delta)?;
        let entries = self.entries()?;
        for e in &entries {
            if e.request.nonce == r.nonce {
                ensure!(e.request == r, "nonce payload conflict");
                return Ok(e.clone());
            }
        }
        let old = entries
            .last()
            .map(|e| e.new_root)
            .unwrap_or(self.initial_root());
        ensure!(r.old_root == old, "stale root");
        let mut reserved = entries
            .last()
            .map(|e| e.reserved.clone())
            .unwrap_or_default();
        if r.mode == Mode::Difference {
            reserved.extend(&r.recipients);
            let union: BTreeSet<_> = reserved.union(&self.policy.incoming).copied().collect();
            ensure!(
                self.policy.delta + union.len() < self.policy.source_t,
                "source budget"
            );
            ensure!(reserved.len() <= self.policy.rho_out, "rho cap");
        }
        let version = entries.len() as u64 + 1;
        let new_root = hash(&[&enc(&(self.policy.source, version, &r, &reserved))]);
        let entry = Entry {
            version,
            request: r,
            new_root,
            reserved,
        };
        let payload = enc(&entry);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("log.bin"))?;
        file.write_all(&(payload.len() as u64).to_le_bytes())?;
        file.write_all(&payload)?;
        file.write_all(&hash(&[&payload]))?;
        file.sync_all()?;
        File::open(&self.dir)?.sync_all()?;
        Ok(entry)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub digest: Hash,
    pub signatures: Vec<(u64, Signature)>,
}
pub fn lock_and_sign(
    dir: &Path,
    source: Hash,
    version: u64,
    digest: Hash,
    sk: Fr,
) -> Result<Signature> {
    fs::create_dir_all(dir)?;
    let _lock = Lock::new(&dir.join("sign.lock"))?;
    let path = dir.join(format!("{}-{version}.bin", hex::encode(source)));
    if path.exists() {
        let (old, sig): (Hash, Signature) = bincode::deserialize(&fs::read(path)?)?;
        ensure!(old == digest, "double signing attempt");
        return Ok(sig);
    }
    let mut r = rand::rngs::OsRng;
    let sig = sign(sk, &digest, &mut r);
    durable_write(&path, &enc(&(digest, sig.clone())))?;
    Ok(sig)
}
pub fn verify_certificate(c: &Certificate, pks: &[Point], quorum: usize) -> bool {
    let mut ids = BTreeSet::new();
    c.signatures.len() >= quorum
        && c.signatures.iter().all(|(id, s)| {
            *id > 0
                && ids.insert(*id)
                && pks
                    .get((*id - 1) as usize)
                    .is_some_and(|p| verify_sig(*p, &c.digest, s))
        })
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Staged {
    pub nonce: u64,
    pub target: u64,
    pub token: Pair,
    pub target_public: Vec<Point>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Participant {
    pub id: u64,
    pub epoch: u64,
    pub share: Pair,
    pub staged: Option<Staged>,
    pub applied: BTreeSet<u64>,
}
impl Participant {
    pub fn load(path: &Path) -> Result<Self> {
        Ok(bincode::deserialize(&fs::read(path)?)?)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        durable_write(path, &enc(self))
    }
    pub fn stage(&mut self, s: Staged, path: &Path) -> Result<()> {
        ensure!(
            s.target == self.epoch + 1 && !self.applied.contains(&s.nonce),
            "stage epoch/duplicate"
        );
        ensure!(
            self.share.plus(s.token).commitment()
                == eval_commit(&s.target_public, Fr::from(self.id)),
            "staged target invalid"
        );
        self.staged = Some(s);
        self.save(path)
    }
    pub fn apply(&mut self, nonce: u64, committed_target: u64, path: &Path) -> Result<bool> {
        if self.applied.contains(&nonce) {
            return Ok(false);
        }
        let s = self.staged.as_ref().context("no staged token")?;
        ensure!(
            s.nonce == nonce && s.target == committed_target,
            "commit context"
        );
        let new = self.share.plus(s.token);
        ensure!(
            new.commitment() == eval_commit(&s.target_public, Fr::from(self.id)),
            "target verify"
        );
        use zeroize::Zeroize;
        self.share.zeroize();
        self.share = new;
        self.epoch = s.target;
        self.applied.insert(nonce);
        if let Some(mut old) = self.staged.take() {
            old.token.zeroize();
        }
        self.save(path)?;
        Ok(true)
    }
    pub fn abort(&mut self, path: &Path) -> Result<()> {
        use zeroize::Zeroize;
        if let Some(mut old) = self.staged.take() {
            old.token.zeroize();
        }
        self.save(path)
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum RegistryStatus {
    Pending,
    Issued,
    Expired,
    RecoverPending,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Registration {
    pub id: u64,
    pub pk: Point,
    pub epoch: u64,
    pub activation: u64,
    pub deadline: u64,
    pub status: RegistryStatus,
}
#[derive(Default, Serialize, Deserialize)]
pub struct Registry {
    pub entries: BTreeMap<u64, Registration>,
}
impl Registry {
    pub fn enroll(
        &mut self,
        r: Registration,
        authorization: &Signature,
        authority: Point,
    ) -> Result<()> {
        ensure!(
            verify_sig(
                authority,
                &enc(&(r.id, r.pk, r.epoch, r.activation, r.deadline)),
                authorization
            ),
            "authorization"
        );
        if let Some(old) = self.entries.get(&r.id) {
            ensure!(
                old.pk == r.pk && old.activation == r.activation && old.epoch == r.epoch,
                "conflicting registration"
            );
            return Ok(());
        }
        ensure!(!self.entries.values().any(|x| x.pk == r.pk), "key reuse");
        self.entries.insert(r.id, r);
        Ok(())
    }
    pub fn complete(&mut self, id: u64, activation: u64) -> Result<()> {
        let x = self.entries.get_mut(&id).context("unknown registration")?;
        ensure!(
            x.activation == activation
                && matches!(
                    x.status,
                    RegistryStatus::Pending | RegistryStatus::RecoverPending
                ),
            "completion state"
        );
        x.status = RegistryStatus::Issued;
        Ok(())
    }
    pub fn expire(&mut self, now: u64) {
        for x in self.entries.values_mut() {
            if x.status == RegistryStatus::Pending && now > x.deadline {
                x.status = RegistryStatus::Expired;
            }
        }
    }
    pub fn begin_recovery(&mut self, id: u64) -> Result<()> {
        let x = self.entries.get_mut(&id).context("unknown")?;
        ensure!(x.status == RegistryStatus::Issued, "recovery state");
        x.status = RegistryStatus::RecoverPending;
        Ok(())
    }
    pub fn can_finalize(&self, epoch: u64) -> bool {
        !self.entries.values().any(|x| {
            x.epoch == epoch
                && matches!(
                    x.status,
                    RegistryStatus::Pending | RegistryStatus::RecoverPending
                )
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cumulative_crash_replay() {
        let d = tempfile::tempdir().unwrap();
        let p = Policy {
            source: [7; 32],
            source_t: 8,
            delta: 1,
            incoming: [1, 2].into(),
            rho_out: 4,
        };
        let l = Ledger::create(d.path(), p).unwrap();
        for (nonce, ids, ok) in [
            (1, vec![3, 4], true),
            (2, vec![5, 6], true),
            (3, vec![7], false),
            (4, vec![3, 4], true),
        ] {
            let before = l.root().unwrap();
            let r = Request {
                old_root: before,
                nonce,
                recipients: ids.into_iter().collect(),
                target: [nonce as u8; 32],
                target_t: 16,
                target_rho: 4,
                eligible: 16,
                mode: Mode::Difference,
            };
            let result = l.reserve(r.clone());
            assert_eq!(result.is_ok(), ok);
            if ok {
                assert_eq!(l.reserve(r).unwrap().new_root, result.unwrap().new_root);
            } else {
                assert_eq!(l.root().unwrap(), before);
            }
            assert_eq!(
                Ledger::open(d.path()).unwrap().root().unwrap(),
                l.root().unwrap()
            );
        }
    }
    #[test]
    fn signing_lock_survives_restart() {
        let d = tempfile::tempdir().unwrap();
        let sk = Fr::from(19u64);
        let sig = lock_and_sign(d.path(), [1; 32], 1, [2; 32], sk).unwrap();
        assert!(verify_sig(sk * g(), &[2; 32], &sig));
        assert!(lock_and_sign(d.path(), [1; 32], 1, [3; 32], sk).is_err());
    }
}
