use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
pub mod anchors;
pub mod core;
pub mod distributed;
pub mod evm;
pub mod extended;
pub mod load;
pub mod research;

#[derive(Clone, Deserialize, Serialize)]
pub struct Config {
    pub name: String,
    pub seed: u64,
    pub repeats: usize,
    pub warmup: usize,
    pub distributed_repeats: usize,
    pub evm_repeats: usize,
    pub thresholds: Vec<usize>,
    pub distributed_thresholds: Vec<usize>,
    pub evm_thresholds: Vec<usize>,
    pub populations: Vec<usize>,
    pub concurrency: Vec<usize>,
    pub suites: Vec<String>,
}
impl Config {
    pub fn load(p: &Path) -> Result<Self> {
        Ok(toml::from_str(&fs::read_to_string(p)?)?)
    }
    pub fn check(&self) -> Result<()> {
        ensure!(
            self.repeats > 0 && self.distributed_repeats > 0 && self.evm_repeats > 0,
            "positive repeats"
        );
        ensure!(
            self.thresholds.iter().all(|t| *t >= 4)
                && self.distributed_thresholds.iter().all(|t| *t >= 8),
            "thresholds"
        );
        ensure!(self.concurrency.iter().all(|c| *c > 0), "concurrency");
        for s in &self.suites {
            ensure!(
                ["core", "distributed", "evm", "research"].contains(&s.as_str()),
                "unknown suite {s}"
            );
        }
        Ok(())
    }
}
pub struct Recorder {
    pub dir: PathBuf,
    file: fs::File,
    pub count: u64,
}
impl Recorder {
    pub fn new(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(dir.join("samples.jsonl"))
            .context("output already has measurements; choose a fresh output directory")?;
        Ok(Self {
            dir: dir.to_owned(),
            file,
            count: 0,
        })
    }
    pub fn sample(
        &mut self,
        id: &str,
        case: &str,
        trial: usize,
        evidence: &str,
        ns: u64,
        mut metrics: Value,
    ) -> Result<()> {
        if let Some(m) = metrics.as_object_mut() {
            m.entry("classification")
                .or_insert(json!(if evidence == "not_claimed" {
                    "out_of_model"
                } else if case.contains("capacity") {
                    "capacity_only"
                } else {
                    "admissible"
                }));
        }
        let v = json!({"schema":1,"sample_id":self.count,"benchmark":id,"case":case,"trial":trial,"evidence":evidence,"wall_ns":if ns==0{Value::Null}else{json!(ns)},"metrics":metrics});
        serde_json::to_writer(&mut self.file, &v)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.count += 1;
        Ok(())
    }
    pub fn check(&mut self, id: &str, case: &str, pass: bool, metrics: Value) -> Result<()> {
        self.sample(
            id,
            case,
            0,
            "invariant",
            0,
            json!({"pass":pass,"details":metrics}),
        )?;
        ensure!(pass, "invariant failed: {id}/{case}");
        Ok(())
    }
}
pub fn ns(i: Instant) -> u64 {
    i.elapsed().as_nanos().try_into().unwrap_or(u64::MAX)
}
fn command(name: &str, args: &[&str]) -> String {
    Command::new(name)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|e| e.to_string())
}
pub fn run(config: &Path, out: &Path) -> Result<()> {
    let cfg = Config::load(config)?;
    cfg.check()?;
    let mut r = Recorder::new(out)?;
    fs::write(out.join("config.toml"), toml::to_string_pretty(&cfg)?)?;
    let manifest = json!({"start_unix":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"rustc":command("rustc",&["-Vv"]),"cargo":command("cargo",&["-V"]),"uname":command("uname",&["-a"]),"cpu":command("lscpu",&[]),"memory":fs::read_to_string("/proc/meminfo")?,"affinity":fs::read_to_string("/proc/self/status")?,"forge":command("forge",&["--version"]),"anvil":command("anvil",&["--version"]),"suites":{"local":crate::crypto::SUITE,"evm":"BN254 / keccak / uncompressed points; separate verifier fixture suite"},"security_note":"synthetic secrets; dealer generation and protocol signatures use OS entropy; no production deployment","source_snapshot":false,"build":"release, thin LTO, codegen-units=1","network":"localhost TCP, mTLS 1.3, new connection per RPC, resumption disabled","statistics":"independent fixture seed per trial; nested operations are not independent samples; p99 descriptive only"});
    fs::write(
        out.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    fs::write(out.join("loadavg-before.txt"), fs::read("/proc/loadavg")?)?;
    let started = Instant::now();
    for suite in &cfg.suites {
        eprintln!("running {suite} ({} samples saved)", r.count);
        let result = match suite.as_str() {
            "core" => core::run(&cfg, &mut r),
            "distributed" => distributed::run(&cfg, &mut r),
            "evm" => evm::run(&cfg, &mut r),
            "research" => research::run(&cfg, &mut r),
            _ => unreachable!(),
        };
        if let Err(e) = result {
            r.sample(
                "RUN",
                suite,
                0,
                "execution_error",
                0,
                json!({"error":format!("{e:#}")}),
            )?;
            return Err(e.context(format!(
                "suite {suite}; raw data preserved in {}",
                out.display()
            )));
        }
    }
    fs::write(
        out.join("completion.json"),
        serde_json::to_vec_pretty(
            &json!({"status":"complete","samples":r.count,"wall_ns":ns(started)}),
        )?,
    )?;
    crate::report::analyze(out)?;
    eprintln!("completed {} samples", r.count);
    Ok(())
}
