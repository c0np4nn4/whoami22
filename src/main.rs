use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(version, about = "Executable VESS research benchmarks")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    E2eRun {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    E2eNode {
        #[arg(long)]
        config: PathBuf,
    },
    E2eReport {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Validate {
        #[arg(long)]
        config: PathBuf,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Analyze {
        #[arg(long)]
        input: PathBuf,
    },
    Report {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = "../report.tex")]
        out: PathBuf,
    },
    #[command(hide = true)]
    Node {
        #[arg(long)]
        config: PathBuf,
    },
    #[command(hide = true)]
    CrashParticipant {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        phase: String,
    },
    #[command(hide = true)]
    CrashReserve {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
}
fn main() -> Result<()> {
    match Cli::parse().command {
        Cmd::E2eRun { config, out } => vess_bench::e2e::runner::run(&config, &out)?,
        Cmd::E2eNode { config } => vess_bench::e2e::node::serve_node(&config)?,
        Cmd::E2eReport { input, out } => vess_bench::e2e::report::write(&input, &out)?,
        Cmd::Validate { config } => {
            let c = vess_bench::experiments::Config::load(&config)?;
            c.check()?;
            println!("valid {}", c.name);
        }
        Cmd::Run { config, out } => vess_bench::experiments::run(&config, &out)?,
        Cmd::Analyze { input } => vess_bench::report::analyze(&input)?,
        Cmd::Report { input, out } => vess_bench::report::write(&input, &out)?,
        Cmd::Node { config } => vess_bench::network::serve(&config)?,
        Cmd::CrashParticipant {
            input,
            output,
            phase,
        } => {
            let (mut participant, stage): (
                vess_bench::ledger::Participant,
                vess_bench::ledger::Staged,
            ) = bincode::deserialize(&std::fs::read(input)?)?;
            let nonce = stage.nonce;
            let target = stage.target;
            participant.stage(stage, &output)?;
            match phase.as_str() {
                "apply" => {
                    participant.apply(nonce, target, &output)?;
                }
                "abort" => participant.abort(&output)?,
                "stage" => {}
                _ => anyhow::bail!("phase"),
            };
            unsafe { libc::_exit(73) }
        }
        Cmd::CrashReserve { ledger, request } => {
            let l = vess_bench::ledger::Ledger::open(&ledger)?;
            let r = bincode::deserialize(&std::fs::read(request)?)?;
            l.reserve(r)?;
            unsafe { libc::_exit(73) }
        }
    }
    Ok(())
}
