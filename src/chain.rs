//! Local-only Ethereum RPC, ABI and real EIP-4844 transactions; no modeled gas.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};
pub type Word = [u8; 32];
pub const E2E_GAS_POLICY: &str = "local-unrestricted-block-gas; estimated-transaction-gas";

/// Transactions still need a finite gas field. Provision from simulation with
/// headroom for concurrent state changes, without a fixed workload-size cap.
pub fn estimate_transaction_gas(url: &str, transaction: &Value) -> Result<(u64, u64)> {
    let estimate = hex_u64(&rpc(url, "eth_estimateGas", json!([transaction]))?)?;
    let allowance = estimate
        .checked_add(estimate / 4)
        .and_then(|n| n.checked_add(100_000))
        .context("transaction gas allowance overflow")?;
    Ok((estimate, allowance))
}
pub fn keccak(bytes: &[u8]) -> Word {
    Keccak256::digest(bytes).into()
}
pub fn word(v: u64) -> Word {
    let mut w = [0; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}
pub fn hhex(w: &[u8]) -> String {
    format!("0x{}", hex::encode(w))
}
pub fn unhex(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
}
pub fn address(s: &str) -> Result<Word> {
    let b = unhex(s)?;
    ensure!(b.len() == 20, "address");
    let mut w = [0; 32];
    w[12..].copy_from_slice(&b);
    Ok(w)
}
pub enum Arg {
    Word(Word),
    Bytes(Vec<u8>),
    Words(Vec<Word>),
}
pub fn abi(args: &[Arg]) -> Vec<u8> {
    let mut head = Vec::new();
    let mut tail = Vec::new();
    for a in args {
        match a {
            Arg::Word(w) => head.extend(w),
            Arg::Bytes(b) => {
                head.extend(word((32 * args.len() + tail.len()) as u64));
                tail.extend(word(b.len() as u64));
                tail.extend(b);
                tail.resize(tail.len().div_ceil(32) * 32, 0);
            }
            Arg::Words(ws) => {
                head.extend(word((32 * args.len() + tail.len()) as u64));
                tail.extend(word(ws.len() as u64));
                for w in ws {
                    tail.extend(w);
                }
            }
        }
    }
    head.extend(tail);
    head
}
pub fn calldata(sig: &str, args: &[Arg]) -> Vec<u8> {
    let mut v = keccak(sig.as_bytes())[..4].to_vec();
    v.extend(abi(args));
    v
}
pub fn rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    let host = url
        .strip_prefix("http://")
        .context("local HTTP RPC required")?;
    ensure!(
        host.starts_with("127.0.0.1:") || host.starts_with("localhost:"),
        "local devnet only"
    );
    let body =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))?;
    let mut stream = TcpStream::connect(host)?;
    stream.set_read_timeout(Some(Duration::from_secs(90)))?;
    write!(stream,"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len())?;
    stream.write_all(&body)?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    let cut = bytes
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .context("HTTP header")?;
    let header = String::from_utf8_lossy(&bytes[..cut]).to_ascii_lowercase();
    let mut body = bytes[cut + 4..].to_vec();
    if header.contains("transfer-encoding: chunked") {
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let end = body[at..]
                .windows(2)
                .position(|x| x == b"\r\n")
                .context("chunk header")?
                + at;
            let n = usize::from_str_radix(
                std::str::from_utf8(&body[at..end])?
                    .split(';')
                    .next()
                    .unwrap(),
                16,
            )?;
            at = end + 2;
            if n == 0 {
                break;
            }
            ensure!(at + n <= body.len(), "chunk length");
            out.extend(&body[at..at + n]);
            at += n + 2;
        }
        body = out;
    }
    let value: Value = serde_json::from_slice(&body).with_context(|| {
        format!(
            "RPC parse {}",
            String::from_utf8_lossy(&body[..body.len().min(200)])
        )
    })?;
    ensure!(
        value.get("error").is_none(),
        "RPC {method}: {}",
        value["error"]
    );
    Ok(value["result"].clone())
}
pub fn hex_u64(v: &Value) -> Result<u64> {
    let s = v.as_str().context("hex number")?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}
pub fn allowed(url: &str, contract: &str, digest: Word) -> Result<bool> {
    let data = calldata("allowed(bytes32)", &[Arg::Word(digest)]);
    let v = rpc(
        url,
        "eth_call",
        json!([{"to":contract,"data":hhex(&data)},"latest"]),
    )?;
    let bytes = unhex(v.as_str().context("call result")?)?;
    Ok(bytes.last() == Some(&1))
}
pub struct Devnet {
    pub child: Child,
    pub url: String,
    pub accounts: Vec<String>,
    pub dir: PathBuf,
    pub verifier: String,
    pub ledger: String,
    pub count: usize,
    relaxed_execution_gas: bool,
}
impl Drop for Devnet {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Devnet {
    pub fn start(dir: &Path) -> Result<Self> {
        Self::start_profile(dir, true, 10)
    }
    pub fn start_empty(dir: &Path) -> Result<Self> {
        Self::start_profile(dir, false, 10)
    }
    pub fn start_empty_with_accounts(dir: &Path, accounts: usize) -> Result<Self> {
        Self::start_profile(dir, false, accounts.max(10))
    }
    fn start_profile(dir: &Path, legacy: bool, account_count: usize) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let log = fs::File::create(dir.join("anvil.log"))?;
        let mut anvil = Command::new("anvil");
        anvil.args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--hardfork",
            "prague",
            // Nine hex-encoded blob sidecars exceed Anvil's default 2 MB
            // HTTP body cap. This changes RPC transport only, not EVM limits.
            "--no-request-size-limit",
            "--accounts",
            &account_count.to_string(),
            "--silent",
        ]);
        if legacy {
            anvil.args(["--gas-limit", "30000000"]);
        } else {
            // Anvil's native unlimited-block mode; conflicts with --gas-limit.
            anvil.arg("--disable-block-gas-limit");
            // Preserve immediate inclusion while guaranteeing pending bursts
            // progress even when they do not fit the current block's gas cap.
            anvil.args(["--mixed-mining", "--block-time", "1"]);
        }
        let child = anvil.stdout(log.try_clone()?).stderr(log).spawn()?;
        let url = format!("http://127.0.0.1:{port}");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if rpc(&url, "eth_chainId", json!([])).is_ok() {
                break;
            }
            ensure!(Instant::now() < deadline, "Anvil startup");
            std::thread::sleep(Duration::from_millis(25));
        }
        let accounts: Vec<String> = serde_json::from_value(rpc(&url, "eth_accounts", json!([]))?)?;
        let mut d = Self {
            child,
            url,
            accounts,
            dir: dir.to_owned(),
            verifier: String::new(),
            ledger: String::new(),
            count: 0,
            relaxed_execution_gas: !legacy,
        };
        if legacy {
            d.verifier = d.deploy("VessBench")?;
            d.ledger = d.deploy("ReservationLog")?;
        }
        let genesis = rpc(&d.url, "eth_getBlockByNumber", json!(["0x0", false]))?;
        let meta = json!({"client":rpc(&d.url,"web3_clientVersion",json!([]))?,"chain_id":rpc(&d.url,"eth_chainId",json!([]))?,"fork":"Prague","block_gas_limit":hex_u64(&genesis["gasLimit"])?,"block_gas_limit_enforced":legacy,"execution_gas_policy":if legacy{"fixed-component-profile"}else{E2E_GAS_POLICY},"mining":if legacy{"auto"}else{"mixed: auto plus 1-second interval"},"finality":"Anvil inclusion; no consensus-layer finality","genesis":genesis});
        fs::write(
            dir.join("chain_manifest.json"),
            serde_json::to_vec_pretty(&meta)?,
        )?;
        Ok(d)
    }
    fn deploy(&mut self, name: &str) -> Result<String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("contract-out/VessBench.sol/{name}.json"));
        let artifact: Value = serde_json::from_slice(
            &fs::read(&path)
                .with_context(|| format!("build contract first: {}", path.display()))?,
        )?;
        let code = artifact["bytecode"]["object"]
            .as_str()
            .context("bytecode")?;
        let receipt = self.send(None, unhex(code)?, 0, 0, &format!("deploy-{name}"))?;
        ensure!(hex_u64(&receipt["status"])? == 1, "deployment reverted");
        Ok(receipt["contractAddress"]
            .as_str()
            .context("contract address")?
            .into())
    }
    pub fn send(
        &mut self,
        to: Option<&str>,
        data: Vec<u8>,
        from: usize,
        value: u64,
        label: &str,
    ) -> Result<Value> {
        let mut tx =
            json!({"from":self.accounts[from],"data":hhex(&data),"value":format!("0x{value:x}")});
        if let Some(to) = to {
            tx["to"] = json!(to);
        }
        let gas = if self.relaxed_execution_gas {
            estimate_transaction_gas(&self.url, &tx)
                .with_context(|| format!("estimate gas for {label}"))?
                .1
        } else {
            30_000_000
        };
        tx["gas"] = json!(format!("0x{gas:x}"));
        let hash = rpc(&self.url, "eth_sendTransaction", json!([tx.clone()]))?;
        let receipt = self.receipt(hash.as_str().context("transaction hash")?)?;
        self.save(label, &receipt, &tx)?;
        Ok(receipt)
    }
    fn save(&mut self, label: &str, receipt: &Value, tx: &Value) -> Result<()> {
        let path = self.dir.join(format!("{:05}-{label}.json", self.count));
        self.count += 1;
        fs::write(
            path,
            serde_json::to_vec_pretty(&json!({"receipt":receipt,"transaction":tx}))?,
        )?;
        Ok(())
    }
    pub fn receipt(&self, hash: &str) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let v = rpc(&self.url, "eth_getTransactionReceipt", json!([hash]))?;
            if !v.is_null() {
                return Ok(v);
            }
            ensure!(Instant::now() < deadline, "receipt timeout");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub fn transact(
        &mut self,
        sig: &str,
        args: Vec<Arg>,
        from: usize,
        value: u64,
        label: &str,
    ) -> Result<Value> {
        let to = self.verifier.clone();
        self.send(Some(&to), calldata(sig, &args), from, value, label)
    }
    pub fn advance(&self, seconds: u64) -> Result<()> {
        rpc(&self.url, "evm_increaseTime", json!([seconds]))?;
        rpc(&self.url, "evm_mine", json!([]))?;
        Ok(())
    }
    pub fn blob_send(&mut self, data: Vec<u8>, blob: &BlobBundle, label: &str) -> Result<Value> {
        self.blobs_send(data, &[blob], label)
    }
    pub fn blobs_send(
        &mut self,
        data: Vec<u8>,
        blobs: &[&BlobBundle],
        label: &str,
    ) -> Result<Value> {
        ensure!(
            !blobs.is_empty() && blobs.len() <= 9,
            "Prague blob batch size"
        );
        use k256::ecdsa::SigningKey;
        let nonce = hex_u64(&rpc(
            &self.url,
            "eth_getTransactionCount",
            json!([self.accounts[0], "pending"]),
        )?)?;
        let to = unhex(&self.verifier)?;
        let gas = if self.relaxed_execution_gas {
            let tx = json!({"from":self.accounts[0],"to":self.verifier,"data":hhex(&data),
                "type":"0x3","maxFeePerBlobGas":"0x3b9aca00",
                "blobVersionedHashes":blobs.iter().map(|b|hhex(&b.versioned)).collect::<Vec<_>>()});
            estimate_transaction_gas(&self.url, &tx)
                .with_context(|| format!("estimate blob gas for {label}"))?
                .1
        } else {
            29_000_000
        };
        let fields = vec![
            rlp_int(31337),
            rlp_int(nonce),
            rlp_int(1_000_000_000),
            rlp_int(10_000_000_000),
            rlp_int(gas),
            rlp_bytes(&to),
            rlp_int(0),
            rlp_bytes(&data),
            rlp_list(&[]),
            rlp_int(1_000_000_000),
            rlp_list(
                &blobs
                    .iter()
                    .map(|blob| rlp_bytes(&blob.versioned))
                    .collect::<Vec<_>>(),
            ),
        ];
        let mut preimage = vec![3];
        preimage.extend(rlp_list(&fields));
        // Public Anvil development key, never a production wallet.
        let key = SigningKey::from_slice(&hex::decode(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )?)?;
        let (signature, recovery) = key.sign_prehash_recoverable(&keccak(&preimage))?;
        let bytes = signature.to_bytes();
        let mut fields = fields;
        fields.extend([
            rlp_int(recovery.to_byte() as u64),
            rlp_bytes(trim_zero(&bytes[..32])),
            rlp_bytes(trim_zero(&bytes[32..])),
        ]);
        let signed = rlp_list(&fields);
        let wrapper = rlp_list(&[
            signed,
            rlp_list(
                &blobs
                    .iter()
                    .map(|b| rlp_bytes(&b.bytes))
                    .collect::<Vec<_>>(),
            ),
            rlp_list(
                &blobs
                    .iter()
                    .map(|b| rlp_bytes(&b.commitment))
                    .collect::<Vec<_>>(),
            ),
            rlp_list(
                &blobs
                    .iter()
                    .map(|b| rlp_bytes(&b.blob_proof))
                    .collect::<Vec<_>>(),
            ),
        ]);
        let mut raw = vec![3];
        raw.extend(wrapper);
        let hash = rpc(&self.url, "eth_sendRawTransaction", json!([hhex(&raw)]))?;
        let receipt = self.receipt(hash.as_str().context("blob hash")?)?;
        self.save(label,&receipt,&json!({"type":3,"input":hhex(&data),"versioned_hashes":blobs.iter().map(|b|hhex(&b.versioned)).collect::<Vec<_>>(),"blob_sha256":blobs.iter().map(|b|hex::encode(Sha256::digest(&b.bytes))).collect::<Vec<_>>(),"physical_blob_bytes":blobs.len()*131072}))?;
        Ok(receipt)
    }
}
fn trim_zero(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().position(|x| *x != 0).unwrap_or(bytes.len())..]
}
fn prefix(len: usize, short: u8, long: u8) -> Vec<u8> {
    if len < 56 {
        vec![short + len as u8]
    } else {
        let n = (len as u64).to_be_bytes();
        let n = trim_zero(&n);
        let mut out = vec![long + n.len() as u8];
        out.extend(n);
        out
    }
}
fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 128 {
        return bytes.to_vec();
    }
    let mut out = prefix(bytes.len(), 128, 183);
    out.extend(bytes);
    out
}
fn rlp_int(v: u64) -> Vec<u8> {
    rlp_bytes(trim_zero(&v.to_be_bytes()))
}
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let len = items.iter().map(Vec::len).sum();
    let mut out = prefix(len, 192, 247);
    for i in items {
        out.extend(i);
    }
    out
}
pub struct BlobBundle {
    pub bytes: Vec<u8>,
    pub commitment: Vec<u8>,
    pub blob_proof: Vec<u8>,
    pub versioned: Word,
    pub point_proofs: [Vec<u8>; 2],
}
/// A domain-separated 248-bit digest, encoded as one canonical 31-byte value.
/// This is the Merkle hash suite, not a truncation of an already-built tree.
/// Its generic collision bound is 124 bits; the E2E suite does not claim 128-bit
/// security for this choice or for BN254.
pub fn field_hash(data: &[u8]) -> Word {
    let mut value = keccak(data);
    value[0] = 0;
    value
}
pub fn field_parent(left: Word, right: Word) -> Word {
    field_hash(&[b"VESS-MERKLE-v1".as_slice(), &left, &right].concat())
}
pub fn field_member(root: Word, mut leaf: Word, mut index: usize, path: &[Word]) -> bool {
    if root[0] != 0 || leaf[0] != 0 || path.iter().any(|v| v[0] != 0) {
        return false;
    }
    for sibling in path {
        leaf = if index.is_multiple_of(2) {
            field_parent(leaf, *sibling)
        } else {
            field_parent(*sibling, leaf)
        };
        index /= 2;
    }
    index == 0 && leaf == root
}
/// main.tex, Anchoring and Record Authentication, second layout: the complete
/// field-native Merkle root occupies slot zero. One native KZG evaluation at
/// z=1 binds it to the versioned blob hash. Remaining slots carry 31-byte data.
pub fn field_blob_bundle(root: Word, payload: &[u8]) -> Result<BlobBundle> {
    use c_kzg::{ethereum_kzg_settings, Blob, Bytes32};
    ensure!(root[0] == 0, "canonical 31-byte Merkle root");
    ensure!(payload.len() <= 4095 * 31, "blob payload capacity");
    let mut bytes = vec![0u8; 131072];
    bytes[..32].copy_from_slice(&root);
    for (idx, chunk) in payload.chunks(31).enumerate() {
        let start = (idx + 1) * 32 + 1;
        bytes[start..start + chunk.len()].copy_from_slice(chunk);
    }
    let blob = Blob::from_bytes(&bytes)?;
    let settings = ethereum_kzg_settings(0);
    let commitment = settings.blob_to_kzg_commitment(&blob)?.to_bytes();
    let blob_proof = settings
        .compute_blob_kzg_proof(&blob, &commitment)?
        .to_bytes();
    let mut versioned: Word = Sha256::digest(commitment.as_ref()).into();
    versioned[0] = 1;
    let z = word(1);
    let (proof, y) = settings.compute_kzg_proof(&blob, &Bytes32::from_bytes(&z)?)?;
    let proof = proof.to_bytes();
    ensure!(y.as_ref() == &root, "first blob field evaluation");
    ensure!(
        settings.verify_kzg_proof(&commitment, &Bytes32::from_bytes(&z)?, &y, &proof)?,
        "KZG self verification"
    );
    let opening = [
        versioned.as_slice(),
        z.as_slice(),
        y.as_ref(),
        commitment.as_ref(),
        proof.as_ref(),
    ]
    .concat();
    Ok(BlobBundle {
        bytes,
        commitment: commitment.as_ref().to_vec(),
        blob_proof: blob_proof.as_ref().to_vec(),
        versioned,
        // Preserve the existing calldata structure while requiring the second
        // proof to be empty. Exactly one precompile invocation is performed.
        point_proofs: [opening, Vec::new()],
    })
}
/// Slot zero is repeated in every blob; all remaining fields are ordered bytes.
pub const FIELD_PAYLOAD_BYTES: usize = 4095 * 31;
pub const BLOBS_PER_TRANSACTION: usize = 9; // Prague network limit.
pub struct FieldPublication {
    pub blobs: Vec<BlobBundle>,
}
impl FieldPublication {
    pub fn new(root: Word, payload: &[u8]) -> Result<Self> {
        ensure!(!payload.is_empty(), "empty publication");
        Ok(Self {
            blobs: payload
                .chunks(FIELD_PAYLOAD_BYTES)
                .map(|chunk| field_blob_bundle(root, chunk))
                .collect::<Result<_>>()?,
        })
    }
    /// A proof of the global root authenticates Merkle leaves in any fragment.
    pub fn anchor(&self) -> &BlobBundle {
        &self.blobs[0]
    }
    pub fn physical_bytes(&self) -> usize {
        self.blobs.len() * 131072
    }
}

/// Reject missing/extra fragments, noncanonical fields, and nonzero padding.
/// KZG/hash binding is checked separately against the transaction evidence.
pub fn field_payload(root: Word, blobs: &[Vec<u8>], length: usize) -> Result<Vec<u8>> {
    ensure!(root[0] == 0 && length > 0, "publication root/length");
    ensure!(
        blobs.len() == length.div_ceil(FIELD_PAYLOAD_BYTES),
        "fragment count"
    );
    let mut out = Vec::new();
    for blob in blobs {
        ensure!(
            blob.len() == 131072 && blob[..32] == root,
            "fragment size/root"
        );
        for field in blob[32..].chunks_exact(32) {
            ensure!(field[0] == 0, "noncanonical payload field");
            out.extend_from_slice(&field[1..]);
        }
    }
    ensure!(
        out[length..].iter().all(|v| *v == 0),
        "nonzero publication padding"
    );
    out.truncate(length);
    Ok(out)
}

pub fn blob_bundle(root: Word, payload: &[u8]) -> Result<BlobBundle> {
    use c_kzg::{ethereum_kzg_settings, Blob, Bytes32};
    let mut bytes = vec![0u8; 131072];
    bytes[16..32].copy_from_slice(&root[..16]);
    bytes[48..64].copy_from_slice(&root[16..]);
    ensure!(payload.len() <= 4094 * 31, "blob payload capacity");
    for (idx, chunk) in payload.chunks(31).enumerate() {
        bytes[(idx + 2) * 32 + 1..(idx + 2) * 32 + 1 + chunk.len()].copy_from_slice(chunk);
    }
    let blob = Blob::from_bytes(&bytes)?;
    let settings = ethereum_kzg_settings(0);
    let commitment = settings.blob_to_kzg_commitment(&blob)?.to_bytes();
    let bp = settings
        .compute_blob_kzg_proof(&blob, &commitment)?
        .to_bytes();
    let cb: Vec<u8> = commitment.as_ref().to_vec();
    let mut versioned: Word = Sha256::digest(&cb).into();
    versioned[0] = 1;
    let mut z1 = [0u8; 32];
    z1[31] = 1;
    let zm1: Word =
        hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000")?
            .try_into()
            .unwrap();
    let mut pp = [Vec::new(), Vec::new()];
    for (i, z) in [z1, zm1].iter().enumerate() {
        let (proof, y) = settings.compute_kzg_proof(&blob, &Bytes32::from_bytes(z)?)?;
        let proof = proof.to_bytes();
        ensure!(
            settings.verify_kzg_proof(&commitment, &Bytes32::from_bytes(z)?, &y, &proof)?,
            "KZG self verification"
        );
        ensure!(
            y.as_ref() == &bytes[i * 32..(i + 1) * 32],
            "blob slot/evaluation ordering"
        );
        let mut opening = Vec::new();
        opening.extend(versioned);
        opening.extend(z);
        opening.extend(y.as_ref());
        opening.extend(&cb);
        opening.extend(proof.as_ref());
        pp[i] = opening;
    }
    Ok(BlobBundle {
        bytes,
        commitment: cb,
        blob_proof: bp.as_ref().to_vec(),
        versioned,
        point_proofs: pp,
    })
}

pub mod bn {
    use super::*;
    use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, CurveGroup, Group};
    use ark_ff::{BigInteger, Field, PrimeField, UniformRand, Zero};
    use rand::{CryptoRng, RngCore};
    pub fn fq_word<F: PrimeField>(f: F) -> Word {
        let bytes = f.into_bigint().to_bytes_be();
        let mut w = [0; 32];
        w[32 - bytes.len()..].copy_from_slice(&bytes);
        w
    }
    pub fn words(p: G1Projective) -> [Word; 2] {
        let p = p.into_affine();
        if p.is_zero() {
            [[0; 32]; 2]
        } else {
            [fq_word(p.x), fq_word(p.y)]
        }
    }
    pub fn hash_point(seed: Word) -> G1Projective {
        let mut x = Fq::from_be_bytes_mod_order(&seed);
        loop {
            if let Some(mut y) = (x * x * x + Fq::from(3u64)).sqrt() {
                if y.into_bigint().is_odd() {
                    y = -y;
                }
                return G1Affine::new_unchecked(x, y).into_group();
            }
            x += Fq::from(1u64);
        }
    }
    pub fn scalar(parts: &[&[u8]]) -> Fr {
        Fr::from_be_bytes_mod_order(&keccak(&parts.concat()))
    }
    fn dleq<R: RngCore + CryptoRng>(
        sk: Fr,
        b2: G1Projective,
        p1: G1Projective,
        p2: G1Projective,
        context: Word,
        rng: &mut R,
    ) -> [Word; 2] {
        let w = Fr::rand(rng);
        let a = G1Projective::generator() * w;
        let b = b2 * w;
        let all = [words(b2), words(p1), words(p2), words(a), words(b)]
            .concat()
            .concat();
        let c = scalar(&[b"BN-DLEQ-v1", &context, &all]);
        [fq_word(c), fq_word(w + c * sk)]
    }
    #[derive(Clone)]
    pub struct Tree {
        pub layers: Vec<Vec<Word>>,
        pub len: usize,
    }
    impl Tree {
        pub fn new(leaves: Vec<Word>) -> Self {
            Self::with_parent(leaves, |left, right| keccak(&[left, right].concat()))
        }
        pub fn new_field(leaves: Vec<Word>) -> Self {
            assert!(leaves.iter().all(|v| v[0] == 0), "field-native leaves");
            Self::with_parent(leaves, field_parent)
        }
        fn with_parent(leaves: Vec<Word>, parent: fn(Word, Word) -> Word) -> Self {
            let len = leaves.len();
            let mut l = leaves;
            l.resize(len.next_power_of_two(), [0; 32]);
            let mut layers = vec![l];
            while layers.last().unwrap().len() > 1 {
                layers.push(
                    layers
                        .last()
                        .unwrap()
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|v| parent(v[0], v[1]))
                        .collect(),
                );
            }
            Self { layers, len }
        }
        pub fn root(&self) -> Word {
            self.layers.last().unwrap()[0]
        }
        pub fn proof(&self, mut i: usize) -> Vec<Word> {
            let mut out = Vec::new();
            for l in &self.layers[..self.layers.len() - 1] {
                out.push(l[i ^ 1]);
                i /= 2;
            }
            out
        }
    }
    pub fn leaf(i: usize, p: G1Projective) -> Word {
        keccak(&[word(i as u64).to_vec(), words(p).concat()].concat())
    }
    pub struct Fixture {
        pub rec: Vec<Word>,
        pub dp: Vec<Word>,
        pub pk: [Word; 2],
        pub source: Vec<G1Projective>,
        pub target: Vec<G1Projective>,
        pub src_tree: Tree,
        pub tgt_tree: Tree,
        pub record_tree: Tree,
        pub truth: Vec<G1Projective>,
        pub claimed: Vec<G1Projective>,
        pub true_tree: Tree,
        pub claimed_tree: Tree,
    }
    pub fn fixture(seed: u64, t0: usize, t1: usize, kind: &str) -> Fixture {
        let mut rng = crate::crypto::rng(seed, "bn-fixture", 0);
        let g = G1Projective::generator();
        let h = hash_point(keccak(b"VESS-BN-H-v1"));
        let sk = Fr::rand(&mut rng);
        let dealer = Fr::rand(&mut rng);
        let pk = g * sk;
        let dealer_pk = g * dealer;
        let mut source = Vec::new();
        let mut target = Vec::new();
        let mut tv = Vec::new();
        let mut tr = Vec::new();
        let mut sv = Vec::new();
        let mut sr = Vec::new();
        for _ in 0..t0 {
            let v = Fr::rand(&mut rng);
            let r = Fr::rand(&mut rng);
            source.push(g * v + h * r);
            sv.push(v);
            sr.push(r);
        }
        for l in 0..t1 {
            let v = if l == 0 { sv[0] } else { Fr::rand(&mut rng) };
            let r = if l == 0 { sr[0] } else { Fr::rand(&mut rng) };
            target.push(g * v + h * r);
            tv.push(v);
            tr.push(r);
        }
        let src_tree = Tree::new(
            source
                .iter()
                .enumerate()
                .map(|(i, p)| leaf(i, *p))
                .collect(),
        );
        let tgt_tree = Tree::new(
            target
                .iter()
                .enumerate()
                .map(|(i, p)| leaf(i, *p))
                .collect(),
        );
        let id = Fr::from(7u64);
        let mut power = Fr::from(1u64);
        let mut v = Fr::zero();
        let mut r = Fr::zero();
        let mut truth = vec![G1Projective::zero()];
        let mut delta = Vec::new();
        for l in 0..t0.max(t1) {
            v += (*tv.get(l).unwrap_or(&Fr::zero()) - *sv.get(l).unwrap_or(&Fr::zero())) * power;
            r += (*tr.get(l).unwrap_or(&Fr::zero()) - *sr.get(l).unwrap_or(&Fr::zero())) * power;
            let d = target.get(l).copied().unwrap_or_default()
                - source.get(l).copied().unwrap_or_default();
            delta.push(d);
            truth.push(*truth.last().unwrap() + d * power);
            power *= id;
        }
        if kind == "inconsistent" {
            v += Fr::from(1u64);
        }
        let e = g * v + h * r;
        let mut rec = vec![
            word(seed + 1),
            word(7),
            word(seed),
            word(0),
            word(0),
            word(0),
            word(1),
            src_tree.root(),
            tgt_tree.root(),
            keccak(
                &delta
                    .iter()
                    .flat_map(|p| words(*p))
                    .collect::<Vec<_>>()
                    .concat(),
            ),
        ];
        rec.extend(words(e));
        rec.extend(words(pk));
        let ad = keccak(&rec.concat());
        let k = Fr::rand(&mut rng);
        let ep = g * k;
        let epwords = words(ep);
        let hp = hash_point(keccak(
            &[b"epk-pop".as_slice(), &ad, &epwords.concat()].concat(),
        ));
        let ep2 = hp * k;
        rec.extend(epwords);
        rec.extend(words(ep2));
        let mut pop = dleq(k, hp, ep, ep2, ad, &mut rng);
        if kind == "bad_pop" {
            pop[0] = fq_word(Fr::from_be_bytes_mod_order(&pop[0]) + Fr::from(1u64));
        }
        rec.extend(pop);
        let shared = pk * k;
        let keyctx = [
            word(7),
            words(pk)[0],
            words(pk)[1],
            epwords[0],
            epwords[1],
            words(shared)[0],
            words(shared)[1],
        ]
        .concat();
        let kv = scalar(&[b"derive-key-0", &ad, &keyctx]);
        let kr = scalar(&[b"derive-key-1", &ad, &keyctx]);
        if kind == "bad_plaintext" {
            v += Fr::from(1u64);
        }
        rec.push(fq_word(v + kv));
        rec.push(fq_word(r + kr));
        let w = Fr::rand(&mut rng);
        let sig_r = words(g * w);
        let c = scalar(&[
            b"BN-SIG-v1",
            &words(dealer_pk).concat(),
            &sig_r.concat(),
            &keccak(&rec.concat()),
        ]);
        rec.extend(sig_r);
        rec.push(fq_word(w + c * dealer));
        let decctx = keccak(
            &[
                b"DEC".as_slice(),
                &ad,
                &epwords.concat(),
                &rec[20..22].concat(),
            ]
            .concat(),
        );
        let dec = dleq(sk, ep, pk, shared, decctx, &mut rng);
        let mut dp = words(shared).to_vec();
        dp.extend(dec);
        if kind == "bad_decryption" {
            dp[3] = fq_word(Fr::from_be_bytes_mod_order(&dp[3]) + Fr::from(1u64));
        }
        // Never publish a verifiable-decryption witness for an invalid PoP.
        if kind == "bad_pop" {
            dp.clear();
        }
        if kind == "bad_signature" {
            rec[24] = fq_word(Fr::from_be_bytes_mod_order(&rec[24]) + Fr::from(1u64));
        }
        let record_tree = Tree::new(vec![keccak(&[word(0), keccak(&rec.concat())].concat())]);
        let true_tree = Tree::new(truth.iter().enumerate().map(|(i, p)| leaf(i, *p)).collect());
        let mut claimed = truth.clone();
        *claimed.last_mut().unwrap() = e;
        let claimed_tree = Tree::new(
            claimed
                .iter()
                .enumerate()
                .map(|(i, p)| leaf(i, *p))
                .collect(),
        );
        Fixture {
            rec,
            dp,
            pk: words(dealer_pk),
            source,
            target,
            src_tree,
            tgt_tree,
            record_tree,
            truth,
            claimed,
            true_tree,
            claimed_tree,
        }
    }
}
