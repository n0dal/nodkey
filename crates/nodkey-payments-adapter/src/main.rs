//! `nodkey-payments-adapter --config <file>` (PROTOTYPE).
//!
//! Refuses to start (exit 2) unless every payments-adapter-v1 §2/§9 check holds. Logs are JSON
//! lines on stdout and never contain secrets, idempotency keys or provider text.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use nodkey_payments_adapter::{load, log::event, own_uid, server};
use serde_json::json;

fn refuse(reason: &str) -> ExitCode {
    event("refuse_start", json!({"reason": reason}));
    ExitCode::from(2)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.as_slice() {
        [flag, p] if flag == "--config" => PathBuf::from(p),
        _ => {
            eprintln!("usage: nodkey-payments-adapter --config <file>");
            return ExitCode::from(2);
        }
    };
    let uid = match own_uid() {
        Ok(u) => u,
        Err(e) => return refuse(&e),
    };
    let (adapter, cfg) = match load(&path, uid) {
        Ok(v) => v,
        Err(e) => return refuse(&e),
    };
    let listener = match server::bind_socket(&cfg.socket_path) {
        Ok(l) => l,
        Err(e) => return refuse(&e),
    };
    event(
        "start",
        json!({"socket": cfg.socket_path.display().to_string(), "broker_uid": cfg.broker_uid,
               "provider_addr": cfg.addr.to_string(), "r_max_s": cfg.r_max_s,
               "caps": cfg.caps.iter().map(|c| c.as_str()).collect::<Vec<_>>()}),
    );
    let adapter = Arc::new(adapter);
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return refuse("cannot install SIGTERM handler"),
    };
    tokio::select! {
        _ = server::serve(listener, adapter) => {}
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    event("stop", json!({}));
    ExitCode::SUCCESS
}
