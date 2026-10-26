//! `simpay` binary. SIMULATED payment provider — not a real payment API.

use std::path::PathBuf;
use std::process::ExitCode;

use simpay::{Config, StartOptions, log};

const USAGE: &str =
    "simpay --config <file> [--container-bind] [--restore] [--tls-cert <pem> --tls-key <pem>]
simpay gen-test-ca --out <dir> [--dns-name <name>] [--malicious-certs]

SIMULATED payment provider for Nodkey Demo P tests. Not a real payment API.

  --config <file>     JSON configuration (see README)
  --container-bind    allow binding 0.0.0.0 / :: (only inside an isolated container network)
  --restore           load snapshot_path instead of the fixture when it exists
  --tls-cert/--tls-key  serve the API listener over TLS 1.3 (admin stays plain HTTP)

gen-test-ca writes a TEST-ONLY CA and a server certificate for --dns-name (default
simpay.internal). --malicious-certs also writes a wrong-hostname and an expired certificate.";

fn gen_test_ca(mut args: impl Iterator<Item = String>) -> ExitCode {
    let mut out = None;
    let mut name = "simpay.internal".to_string();
    let mut malicious = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out = args.next().map(PathBuf::from),
            "--dns-name" => match args.next() {
                Some(n) => name = n,
                None => out = None,
            },
            "--malicious-certs" => malicious = true,
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(out) = out else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match simpay::tls::generate_test_ca(&out, &name, malicious) {
        Ok(files) => {
            log("wrote TEST-ONLY certificates (never trust this CA outside tests):");
            for f in files {
                log(&format!("  {}", f.display()));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            log(&format!("gen-test-ca failed: {e}"));
            ExitCode::from(2)
        }
    }
}

fn parse_args() -> Result<(PathBuf, StartOptions), String> {
    let mut args = std::env::args().skip(1);
    let mut config = None;
    let mut opts = StartOptions::default();
    let (mut cert, mut key) = (None, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                config = Some(PathBuf::from(args.next().ok_or("--config needs a value")?))
            }
            "--container-bind" => opts.container_bind = true,
            "--restore" => opts.restore = true,
            "--tls-cert" => {
                cert = Some(PathBuf::from(
                    args.next().ok_or("--tls-cert needs a value")?,
                ))
            }
            "--tls-key" => key = Some(PathBuf::from(args.next().ok_or("--tls-key needs a value")?)),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    opts.tls = match (cert, key) {
        (Some(cert), Some(key)) => Some(simpay::tls::TlsFiles { cert, key }),
        (None, None) => None,
        _ => return Err("--tls-cert and --tls-key must be given together".into()),
    };
    Ok((config.ok_or("--config is required")?, opts))
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("gen-test-ca") {
        return gen_test_ca(std::env::args().skip(2));
    }
    let (path, opts) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            if !e.is_empty() {
                log(&e);
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let cfg = match Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            log(&format!("refusing to start: {e}"));
            return ExitCode::from(2);
        }
    };
    let server = match simpay::start(cfg, opts).await {
        Ok(s) => s,
        Err(e) => {
            log(&format!("refusing to start: {e}"));
            return ExitCode::from(2);
        }
    };
    wait_for_signal().await;
    log("shutting down");
    if server.shared().cfg.snapshot_path.is_some()
        && let Err(e) = server.snapshot()
    {
        log(&format!("snapshot failed: {e}"));
    }
    server.shutdown().await;
    ExitCode::SUCCESS
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = term.recv() => {},
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
