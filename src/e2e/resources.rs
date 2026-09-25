//! Process-local resource preparation before any Anvil or node is started.
use super::runner::Config;
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

pub fn prepare_file_limit(config: &Config) -> Result<Value> {
    let participants = *config.populations.last().context("participant schedule")?;
    let dealers = config
        .committees
        .iter()
        .map(|c| c[0])
        .max()
        .context("committees")?;
    // Include the owner and two archives.
    let peers = participants
        .checked_add(dealers)
        .and_then(|n| n.checked_add(3))
        .context("peer count overflow")?;
    // Cluster::new holds one reservation socket per peer. Leave room for
    // child-process handles, RPC sockets, logs, certificates and inherited FDs.
    // This is host provisioning, not a protocol threshold or concurrency cap.
    let required = peers
        .checked_mul(2)
        .and_then(|n| n.checked_add(128))
        .context("file descriptor budget overflow")? as libc::rlim_t;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read RLIMIT_NOFILE");
    }
    let before = limit.rlim_cur;
    ensure!(limit.rlim_max >= required,
        "RLIMIT_NOFILE hard limit {} is below the benchmark's requested FD budget {} ({} peers). Increase the shell/service hard open-file limit before retrying. No nodes have been started.",
        limit.rlim_max, required, peers);
    if limit.rlim_cur < required {
        limit.rlim_cur = required;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            return Err(std::io::Error::last_os_error()).context(format!(
                "raise process RLIMIT_NOFILE soft limit from {before} to {required}"
            ));
        }
    }
    eprintln!("Open-file limit: soft {before} -> {}, hard {}; requested FD budget {required} for {peers} peers", limit.rlim_cur, limit.rlim_max);
    Ok(
        json!({"resource":"RLIMIT_NOFILE","soft_before":before,"soft_after":limit.rlim_cur,
        "hard":limit.rlim_max,"requested_budget":required,"maximum_peers":peers,
        "scope":"runner and inherited child processes; hard limit unchanged"}),
    )
}
