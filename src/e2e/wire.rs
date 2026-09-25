use super::core::*;
use anyhow::{ensure, Context, Result};
use rustls::{pki_types::ServerName, ClientConnection, ServerConnection, StreamOwned};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};
#[derive(Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: u64,
    pub role: String,
    pub port: u16,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub run: String,
    pub id: u64,
    pub role: String,
    pub port: u16,
    pub dir: PathBuf,
    pub tls: PathBuf,
    pub peers: Vec<Peer>,
    pub rpc: String,
    pub contract: String,
    pub n: usize,
    pub k: usize,
    pub f: usize,
    #[serde(default = "default_participant_corruption_budget")]
    pub participant_corruption_budget: usize,
    #[serde(default = "default_outgoing_recipient_budget")]
    pub outgoing_recipient_budget: usize,
    pub timeout_ms: u64,
}
fn default_participant_corruption_budget() -> usize {
    1
}
fn default_outgoing_recipient_budget() -> usize {
    2
}
impl NodeConfig {
    pub fn target_budget_allows(&self, offline: usize, threshold: usize) -> bool {
        offline <= self.outgoing_recipient_budget
            && self
                .participant_corruption_budget
                .checked_add(offline)
                .and_then(|count| count.checked_add(self.outgoing_recipient_budget))
                .is_some_and(|exposure| exposure < threshold)
    }
    pub fn peer(&self, id: u64) -> Result<&Peer> {
        self.peers
            .iter()
            .find(|p| p.id == id)
            .context("peer identity")
    }
    pub fn role(&self, id: u64) -> Result<&str> {
        if id == 0 {
            return Ok("runner");
        }
        Ok(&self.peer(id)?.role)
    }
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    run: String,
    from: u64,
    op: String,
    body: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Reply {
    ok: bool,
    body: Vec<u8>,
    error: String,
}
impl Drop for Envelope {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}
impl Drop for Reply {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}
static TX: AtomicU64 = AtomicU64::new(0);
static RX: AtomicU64 = AtomicU64::new(0);
static CALLS: AtomicU64 = AtomicU64::new(0);
struct Counted(TcpStream);
impl Read for Counted {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.0.read(b)?;
        RX.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}
impl Write for Counted {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self.0.write(b)?;
        TX.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
pub fn stats() -> serde_json::Value {
    serde_json::json!({"tls_stream_sent":TX.load(Ordering::Relaxed),"tls_stream_received":RX.load(Ordering::Relaxed),"rpc_calls":CALLS.load(Ordering::Relaxed),"pid":std::process::id()})
}
fn read_private_frame<S: Read>(stream: &mut S) -> Result<Zeroizing<Vec<u8>>> {
    let mut size = [0; 8];
    stream.read_exact(&mut size)?;
    let size = usize::try_from(u64::from_be_bytes(size))?;
    ensure!(size < 256 * 1024 * 1024, "frame limit");
    // Guard the allocation before the first plaintext byte is read, including
    // early EOF and timeout paths.
    let mut bytes = Zeroizing::new(vec![0; size]);
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
pub fn call<A: Serialize, B: DeserializeOwned>(
    cfg: &NodeConfig,
    id: u64,
    op: &str,
    args: &A,
) -> Result<B> {
    let peer = cfg.peer(id)?;
    let socket = TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", peer.port).parse()?,
        Duration::from_millis(cfg.timeout_ms.clamp(1, 2000)),
    )?;
    let read_timeout = if matches!(op, "owner_init" | "target_state") {
        cfg.timeout_ms.saturating_mul(10).saturating_add(5000)
    } else {
        cfg.timeout_ms
    };
    socket.set_read_timeout(Some(Duration::from_millis(read_timeout)))?;
    socket.set_write_timeout(Some(Duration::from_millis(cfg.timeout_ms)))?;
    socket.set_nodelay(true)?;
    let conn = ClientConnection::new(
        crate::network::client_config(&cfg.tls, cfg.id as usize)?,
        ServerName::try_from("localhost")?,
    )?;
    let mut stream = StreamOwned::new(conn, Counted(socket));
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    let cert = stream.conn.peer_certificates().context("TLS peer")?;
    ensure!(
        cert[0].as_ref() == fs::read(cfg.tls.join(format!("{id}.cert")))?,
        "server identity mismatch"
    );
    let request = Envelope {
        run: cfg.run.clone(),
        from: cfg.id,
        op: op.into(),
        body: enc(args),
    };
    let outgoing = Zeroizing::new(enc(&request));
    crate::network::write_frame(&mut stream, &outgoing)?;
    let incoming = read_private_frame(&mut stream)?;
    let r: Reply = decode(&incoming)?;
    CALLS.fetch_add(1, Ordering::Relaxed);
    ensure!(r.ok, "node {id} {op}: {}", r.error);
    decode(&r.body)
}
pub fn wait_call<A: Serialize, B: DeserializeOwned>(
    cfg: &NodeConfig,
    id: u64,
    op: &str,
    args: &A,
) -> Result<B> {
    let start = Instant::now();
    loop {
        match call(cfg, id, op, args) {
            Ok(v) => return Ok(v),
            Err(e) => {
                if start.elapsed() > Duration::from_millis(cfg.timeout_ms) {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
pub type Handler = dyn Fn(u64, &str, &[u8]) -> Result<Vec<u8>> + Send + Sync;
pub fn serve(cfg: NodeConfig, handler: Arc<Handler>) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", cfg.port))?;
    let server = crate::network::server_config(&cfg.tls, cfg.id as usize)?;
    for socket in listener.incoming() {
        let socket = socket?;
        let cfg = cfg.clone();
        let server = server.clone();
        let handler = handler.clone();
        std::thread::spawn(move || {
            let run = || -> Result<()> {
                socket.set_read_timeout(Some(Duration::from_millis(cfg.timeout_ms)))?;
                socket.set_write_timeout(Some(Duration::from_millis(cfg.timeout_ms)))?;
                socket.set_nodelay(true)?;
                let conn = ServerConnection::new(server)?;
                let mut stream = StreamOwned::new(conn, Counted(socket));
                while stream.conn.is_handshaking() {
                    stream.conn.complete_io(&mut stream.sock)?;
                }
                let incoming = read_private_frame(&mut stream)?;
                let e: Envelope = decode(&incoming)?;
                ensure!(e.run == cfg.run, "cross-run request");
                cfg.role(e.from)?;
                let cert = stream.conn.peer_certificates().context("peer cert")?;
                ensure!(
                    cert[0].as_ref() == fs::read(cfg.tls.join(format!("{}.cert", e.from)))?,
                    "client identity mismatch"
                );
                let reply = match handler(e.from, &e.op, &e.body) {
                    Ok(body) => Reply {
                        ok: true,
                        body,
                        error: String::new(),
                    },
                    Err(e) => Reply {
                        ok: false,
                        body: vec![],
                        error: format!("{e:#}"),
                    },
                };
                let outgoing = Zeroizing::new(enc(&reply));
                crate::network::write_frame(&mut stream, &outgoing)?;
                Ok(())
            };
            if let Err(e) = run() {
                eprintln!("TLS connection: {e:#}")
            }
        });
    }
    Ok(())
}

pub fn call_json<A: Serialize>(
    cfg: &NodeConfig,
    id: u64,
    op: &str,
    a: &A,
) -> Result<serde_json::Value> {
    let json: String = call(cfg, id, op, a)?;
    Ok(serde_json::from_str(&json)?)
}

#[cfg(test)]
mod release_policy_tests {
    use super::*;

    #[test]
    fn legacy_node_configs_default_to_the_original_release_policy() {
        let cfg: NodeConfig = serde_json::from_value(serde_json::json!({
            "run":"legacy", "id":1, "role":"dealer", "port":0,
            "dir":"", "tls":"", "peers":[], "rpc":"", "contract":"",
            "n":4, "k":2, "f":1, "timeout_ms":100
        }))
        .unwrap();
        assert_eq!(cfg.participant_corruption_budget, 1);
        assert_eq!(cfg.outgoing_recipient_budget, 2);
        assert!(cfg.target_budget_allows(1, 5));
        assert!(!cfg.target_budget_allows(2, 5));

        let mut cfg = cfg;
        cfg.outgoing_recipient_budget = 16;
        assert!(cfg.target_budget_allows(16, 34));
        assert!(!cfg.target_budget_allows(16, 33));
        assert!(!cfg.target_budget_allows(17, 128));
        cfg.participant_corruption_budget = usize::MAX;
        assert!(!cfg.target_budget_allows(1, 128));
    }
}
