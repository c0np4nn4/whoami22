use std::{net::TcpListener, os::unix::process::CommandExt, process::Command};
use vess_bench::e2e::{resources::prepare_file_limit, runner::Config};

// Change limits only in subprocesses, never in the parallel cargo test runner.
#[test]
fn file_limit_preflight_handles_large_port_reservations() {
    if let Ok(mode) = std::env::var("VESS_FD_TEST_CHILD") {
        let mut config: Config = toml::from_str(include_str!("../configs/e2e-smoke.toml")).unwrap();
        config.populations = vec![1024, 1024, 1280, 1280];
        config.committees = vec![[49, 17, 16]];
        if mode == "hard" {
            let error = prepare_file_limit(&config).unwrap_err().to_string();
            assert!(error.contains("hard limit 128"), "{error}");
            return;
        }
        let before = (0..140)
            .map(|_| TcpListener::bind(("127.0.0.1", 0)))
            .collect::<Vec<_>>();
        assert!(before.iter().any(|s| s
            .as_ref()
            .is_err_and(|e| e.raw_os_error() == Some(libc::EMFILE))));
        drop(before);
        let report = prepare_file_limit(&config).unwrap();
        assert_eq!(report["soft_before"], 128);
        assert_eq!(report["maximum_peers"], 1332);
        assert!(report["soft_after"].as_u64().unwrap() >= 2792);
        let sockets = (0..1332)
            .map(|_| TcpListener::bind(("127.0.0.1", 0)).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(sockets.len(), 1332);
        // Also verify that enough descriptors remain for certificate/log I/O.
        assert!(
            !std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
                .unwrap()
                .is_empty()
        );
        let again = prepare_file_limit(&config).unwrap();
        assert_eq!(report["soft_after"], again["soft_after"]);
        return;
    }
    for mode in ["soft", "hard"] {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "file_limit_preflight_handles_large_port_reservations",
            "--nocapture",
        ])
        .env("VESS_FD_TEST_CHILD", mode);
        unsafe {
            cmd.pre_exec(move || {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                limit.rlim_cur = 128;
                if mode == "hard" {
                    limit.rlim_max = 128;
                }
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let result = cmd.output().unwrap();
        assert!(
            result.status.success(),
            "{mode}: {} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
