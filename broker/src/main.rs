//! nodkey-broker: PROTOTYPE effect broker.
//!
//! Usage:
//!   nodkey-broker --config <path>        run the broker
//!   nodkey-broker --healthcheck <path>   exit 0 iff every configured socket exists and is a socket

mod config;
mod ledger;
mod protocol;
mod server;
mod strict_json;

use config::Config;
use serde_json::json;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

fn fatal(msg: &str) -> ExitCode {
    server::log_event("fatal", json!({"detail": msg}));
    ExitCode::FAILURE
}

fn load_config(path: &str) -> Result<Config, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| format!("open config: {e}"))?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read config: {e}"))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("config too large".into());
    }
    Config::parse(&bytes)
}

fn read_password(path: &Path) -> Result<String, String> {
    let mut s = String::new();
    std::fs::File::open(path)
        .map_err(|e| format!("open password file: {}", e.kind()))?
        .take(4096)
        .read_to_string(&mut s)
        .map_err(|e| format!("read password file: {}", e.kind()))?;
    let s = s.trim_end_matches(['\n', '\r']).to_owned();
    if s.is_empty() {
        return Err("password file empty".into());
    }
    Ok(s)
}

fn random_seed() -> Result<[u8; 8], String> {
    let mut seed = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|e| format!("urandom: {e}"))?;
    Ok(seed)
}

fn healthcheck(cfg: &Config) -> ExitCode {
    for w in &cfg.workloads {
        match std::fs::symlink_metadata(&w.socket_path) {
            Ok(m) if m.file_type().is_socket() => {}
            _ => return ExitCode::FAILURE,
        }
    }
    ExitCode::SUCCESS
}

fn bind(path: &Path) -> Result<tokio::net::UnixListener, String> {
    // Remove a stale socket from a previous run, but never anything that is not a socket.
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if m.file_type().is_socket() {
            std::fs::remove_file(path)
                .map_err(|e| format!("remove stale socket {}: {e}", path.display()))?;
        } else {
            return Err(format!("{} exists and is not a socket", path.display()));
        }
    }
    let l = tokio::net::UnixListener::bind(path)
        .map_err(|e| format!("bind {}: {e}", path.display()))?;
    // Access control is the per-workload mount plus the SO_PEERCRED uid check; the socket inode
    // itself must be connectable by the workload uid, which differs from the broker uid.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(l)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (mode, path) = match args.as_slice() {
        [_, flag, p] if flag == "--config" => ("run", p.clone()),
        [_, flag, p] if flag == "--healthcheck" => ("health", p.clone()),
        _ => {
            eprintln!("usage: nodkey-broker --config <path> | --healthcheck <path>");
            return ExitCode::from(2);
        }
    };
    let cfg = match load_config(&path) {
        Ok(c) => c,
        Err(e) => return fatal(&e),
    };
    if mode == "health" {
        return healthcheck(&cfg);
    }

    let password = match read_password(&cfg.db.password_file) {
        Ok(p) => p,
        Err(e) => return fatal(&e),
    };
    let seed = match random_seed() {
        Ok(s) => s,
        Err(e) => return fatal(&e),
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fatal(&format!("runtime: {e}")),
    };
    rt.block_on(async move {
        let shared = Arc::new(server::Shared {
            ledger: ledger::Ledger::new(&cfg.db, password),
            ids: server::CorrelationIds::new(seed),
            max_request_bytes: cfg.max_request_bytes,
        });
        let mut tasks = Vec::new();
        for w in &cfg.workloads {
            let listener = match bind(&w.socket_path) {
                Ok(l) => l,
                Err(e) => return fatal(&e),
            };
            server::log_event(
                "listening",
                json!({"workload": w.name, "socket": w.socket_path.display().to_string(), "uid": w.uid,
                       "allowed_ops": w.allowed_ops.iter().map(|k| k.wire_name()).collect::<Vec<_>>(),
                       "max_transfer_cents": w.max_transfer_cents}),
            );
            tasks.push(tokio::spawn(server::serve(listener, Arc::new(w.clone()), shared.clone())));
        }

        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => return fatal(&format!("signal: {e}")),
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        for t in &tasks {
            t.abort();
        }
        for w in &cfg.workloads {
            let _ = std::fs::remove_file(&w.socket_path);
        }
        server::log_event("shutdown", json!({}));
        ExitCode::SUCCESS
    })
}
