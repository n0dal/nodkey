// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! nodkey-broker: PROTOTYPE effect broker.
//!
//! Usage:
//!   nodkey-broker --config <path> [--mounts-verified-externally]   run the broker
//!   nodkey-broker --healthcheck <path>                             exit 0 iff every configured socket exists
//!
//! The configuration format selects the protocol: a document with
//! `"format": "nodkey.broker.v2"` runs protocol v2 (effect protocol v2); the legacy format runs
//! protocol v1, which exists only for the Demo 1 profile. One broker never serves both.

use nodkey_broker::config::Config;
use nodkey_broker::v2::config::{self as v2config, RawV2Config, V2Config, is_v2_document};
use nodkey_broker::v2::{db, decls, server as v2server, service};
use nodkey_broker::{ledger, server};
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

fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.len() as u64 > max {
        return Err(format!("{} too large", path.display()));
    }
    Ok(bytes)
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

fn is_socket(p: &Path) -> bool {
    matches!(std::fs::symlink_metadata(p), Ok(m) if m.file_type().is_socket())
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

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))
}

async fn wait_for_signal() -> Result<(), String> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("signal: {e}"))?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

/// This process's uid, read through `SO_PEERCRED` on a socket pair (no `unsafe`, no libc).
fn own_uid() -> Result<u32, String> {
    let (a, _b) = tokio::net::UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    a.peer_cred()
        .map(|c| c.uid())
        .map_err(|e| format!("peer_cred: {e}"))
}

fn run_v1(cfg: Config) -> ExitCode {
    let password = match read_password(&cfg.db.password_file) {
        Ok(p) => p,
        Err(e) => return fatal(&e),
    };
    let seed = match random_seed() {
        Ok(s) => s,
        Err(e) => return fatal(&e),
    };
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => return fatal(&e),
    };
    rt.block_on(async move {
        server::log_event("profile", json!({"protocol": 1, "profile": "demo1"}));
        let shared = Arc::new(server::Shared {
            ledger: ledger::Ledger::new(&cfg.db, password),
            ids: server::CorrelationIds::new(seed),
            max_request_bytes: cfg.max_request_bytes,
        });
        // EP-10: never share a database with a v2 broker. Retry while the database starts.
        let mut claimed = Err("not attempted".to_owned());
        for _ in 0..15 {
            claimed = shared.ledger.claim_protocol_v1().await;
            match &claimed {
                Ok(_) => break,
                Err(e) if e.contains("refusing") => break,
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            }
        }
        match claimed {
            Ok(()) => server::log_event("db_claimed", json!({"protocol": 1})),
            Err(e) => return fatal(&format!("database claim: {e}")),
        }
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
        if let Err(e) = wait_for_signal().await {
            return fatal(&e);
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

fn run_v2(raw: RawV2Config, mounts_verified_externally: bool) -> ExitCode {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(e) => return fatal(&e),
    };
    rt.block_on(async move {
        if mounts_verified_externally {
            server::log_event("mounts_verified_externally", json!({"detail": "operator flag set; deployment manifest not checked by the broker"}));
        }
        let ops_text = match read_limited(&raw.operations_path, MAX_CONFIG_BYTES)
            .and_then(|b| String::from_utf8(b).map_err(|e| e.to_string()))
        {
            Ok(t) => t,
            Err(e) => return fatal(&e),
        };
        let (ops, names) = match decls::load(&ops_text) {
            Ok(x) => x,
            Err(e) => return fatal(&e),
        };
        let uid = match own_uid() {
            Ok(u) => u,
            Err(e) => return fatal(&e),
        };
        let wl_bytes = match read_limited(&raw.authority_workloads_path, MAX_CONFIG_BYTES) {
            Ok(b) => b,
            Err(e) => return fatal(&e),
        };
        let broker_uid = uid;
        let cfg = match V2Config::from_raw(raw, &ops, &names, uid, mounts_verified_externally) {
            Ok(c) => c,
            Err(e) => return fatal(&e),
        };
        let mandates = match v2config::check_authority_workloads(&wl_bytes, &cfg, &ops) {
            Ok(m) => m,
            Err(e) => return fatal(&e),
        };
        let config_digest = v2config::config_digest(ops_text.as_bytes(), &wl_bytes);
        let registry_text = match read_limited(&cfg.registry_path, MAX_CONFIG_BYTES)
            .and_then(|b| String::from_utf8(b).map_err(|e| e.to_string()))
        {
            Ok(t) => t,
            Err(e) => return fatal(&e),
        };
        let registry = match nodkey_grant::Registry::load(&registry_text) {
            Ok(r) => r,
            Err(e) => return fatal(&format!("key registry: {e}")),
        };
        let password = match read_password(&cfg.db.password_file) {
            Ok(p) => p,
            Err(e) => return fatal(&e),
        };
        let seed = match random_seed() {
            Ok(s) => s,
            Err(e) => return fatal(&e),
        };
        let pool = db::Pool::new(&cfg.db, password.clone(), cfg.db_pool_size);
        let control_pool = db::Pool::new(&cfg.db, password, cfg.db_control_pool_size);
        let broker = Arc::new(service::Broker::new(
            cfg, registry, ops, names, (pool, control_pool), config_digest, service::system_clock(),
        ).with_mandates(mandates));
        let mut started = Err(String::new());
        for _ in 0..15 {
            started = broker.startup_checks().await;
            match &started {
                Ok(()) => break,
                Err(e) if e.contains("refusing") => break,
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            }
        }
        if let Err(e) = started {
            return fatal(&format!("start-up checks: {e}"));
        }
        let srv = Arc::new(v2server::Server { broker: broker.clone(), ids: server::CorrelationIds::new(seed) });
        let c = &broker.cfg;
        let mut channels: Vec<(std::path::PathBuf, v2server::Channel, u32)> = vec![
            (c.gateway.socket_path.clone(), v2server::Channel::Gateway, c.gateway.uid),
            (c.authority.socket_path.clone(), v2server::Channel::Authority, c.authority.uid),
        ];
        for w in &c.workloads {
            channels.push((w.socket_path.clone(), v2server::Channel::Workload(Arc::new(w.clone())), w.uid));
        }
        let mut tasks = Vec::new();
        for (path, ch, uid) in &channels {
            let is_workload = matches!(ch, v2server::Channel::Workload(_));
            let bound = v2server::check_socket_dir(path, broker_uid, *uid)
                .and_then(|()| v2server::bind_socket(path));
            let l = match bound {
                Ok(l) => l,
                // A workload controls its own socket directory: a bad workload path must not stop
                // the broker serving everyone else (BR-05). That workload is not served.
                Err(e) if is_workload => {
                    server::log_event("alarm", json!({"kind": "workload_socket_unusable", "detail": e}));
                    continue;
                }
                Err(e) => return fatal(&e),
            };
            server::log_event("listening", json!({"protocol": 2, "socket": path.display().to_string(), "uid": uid}));
            tasks.push(tokio::spawn(v2server::serve(l, ch.clone(), *uid, srv.clone())));
        }
        tasks.push(tokio::spawn(v2server::recovery_loop(srv.clone())));
        tasks.push(tokio::spawn(v2server::payments_loop(srv.clone())));
        if let Err(e) = wait_for_signal().await {
            return fatal(&e);
        }
        for t in &tasks {
            t.abort();
        }
        for (path, _, _) in &channels {
            let _ = std::fs::remove_file(path);
        }
        server::log_event("shutdown", json!({}));
        ExitCode::SUCCESS
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (mode, path, flag) = match args.as_slice() {
        [_, f, p] if f == "--config" => ("run", p.clone(), false),
        [_, f, p, m] if f == "--config" && m == "--mounts-verified-externally" => {
            ("run", p.clone(), true)
        }
        [_, f, p] if f == "--healthcheck" => ("health", p.clone(), false),
        _ => {
            eprintln!(
                "usage: nodkey-broker --config <path> [--mounts-verified-externally] | --healthcheck <path>"
            );
            return ExitCode::from(2);
        }
    };
    let bytes = match read_limited(Path::new(&path), MAX_CONFIG_BYTES) {
        Ok(b) => b,
        Err(e) => return fatal(&e),
    };
    if is_v2_document(&bytes) {
        let raw = match RawV2Config::parse(&bytes) {
            Ok(r) => r,
            Err(e) => return fatal(&e),
        };
        if mode == "health" {
            return if raw.socket_paths().iter().all(|p| is_socket(p)) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        return run_v2(raw, flag);
    }
    if flag {
        return fatal("--mounts-verified-externally applies only to protocol v2");
    }
    let cfg = match Config::parse(&bytes) {
        Ok(c) => c,
        Err(e) => return fatal(&e),
    };
    if mode == "health" {
        return if cfg.workloads.iter().all(|w| is_socket(&w.socket_path)) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    run_v1(cfg)
}
