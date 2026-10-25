//! `simpay` binary. SIMULATED payment provider — not a real payment API.

use std::path::PathBuf;
use std::process::ExitCode;

use simpay::{Config, StartOptions, log};

const USAGE: &str = "simpay --config <file> [--container-bind] [--restore]

SIMULATED payment provider for Nodkey Demo P tests. Not a real payment API.

  --config <file>     JSON configuration (see README)
  --container-bind    allow binding 0.0.0.0 / :: (only inside an isolated container network)
  --restore           load snapshot_path instead of the fixture when it exists";

fn parse_args() -> Result<(PathBuf, StartOptions), String> {
    let mut args = std::env::args().skip(1);
    let mut config = None;
    let mut opts = StartOptions::default();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                config = Some(PathBuf::from(args.next().ok_or("--config needs a value")?))
            }
            "--container-bind" => opts.container_bind = true,
            "--restore" => opts.restore = true,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok((config.ok_or("--config is required")?, opts))
}

#[tokio::main]
async fn main() -> ExitCode {
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
