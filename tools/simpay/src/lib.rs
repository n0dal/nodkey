// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! simpay — a SIMULATED payment provider for Nodkey Demo P tests.
//!
//! It is not a real payment API, it moves no money, and it is not trusted by Nodkey:
//! it models an external party, including a malicious one (attacker G).

#![forbid(unsafe_code)]

pub mod admin;
pub mod api;
pub mod config;
pub mod faults;
pub mod http;
pub mod state;
pub mod tls;
pub mod webhook;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

pub use config::Config;
use state::Store;

/// Prefix of every log line, so simulator output is never mistaken for a real provider.
pub const LOG_PREFIX: &str = "[simpay SIMULATOR]";

/// Writes one log line to stderr. A closed stderr never crashes the simulator.
pub fn log(msg: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{LOG_PREFIX} {msg}");
}

/// Maximum concurrent connections per listener.
pub const MAX_CONNECTIONS: usize = 256;

pub struct Shared {
    store: Mutex<Store>,
    pub cfg: Config,
}

impl Shared {
    /// Locks the store. A poisoned lock is recovered: every mutation leaves the store
    /// consistent before any point that could panic.
    pub fn lock(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[derive(Debug, Clone, Default)]
pub struct StartOptions {
    /// Serve the API listener over TLS 1.3 with this certificate and key. The admin
    /// listener always stays plain HTTP.
    pub tls: Option<tls::TlsFiles>,
    /// Allow binding the unspecified address (container use only).
    pub container_bind: bool,
    /// Load `snapshot_path` instead of the fixture when the file exists.
    pub restore: bool,
}

pub struct Server {
    pub api_addr: SocketAddr,
    pub admin_addr: SocketAddr,
    shared: Arc<Shared>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Server {
    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// Writes the snapshot to `snapshot_path`, if configured.
    pub fn snapshot(&self) -> Result<(), String> {
        match &self.shared.cfg.snapshot_path {
            Some(p) => self.shared.lock().write_snapshot(p),
            None => Err("no snapshot_path configured".into()),
        }
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
        log("stopped");
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Api,
    Admin,
}

/// Validates the configuration, enforces the bind policy, and starts both listeners.
pub async fn start(cfg: Config, opts: StartOptions) -> Result<Server, String> {
    cfg.validate()?;
    config::check_bind(cfg.api_listen, opts.container_bind)?;
    config::check_bind(cfg.admin_listen, opts.container_bind)?;
    let mut store = match (&cfg.snapshot_path, opts.restore) {
        (Some(p), true) if p.exists() => {
            log(&format!("restoring snapshot {}", p.display()));
            Store::read_snapshot(p)?
        }
        _ => Store::from_config(&cfg),
    };
    store.malicious_mode = cfg.malicious_mode;
    let acceptor = match &opts.tls {
        Some(files) => Some(TlsAcceptor::from(tls::server_config(files)?)),
        None => None,
    };
    let api = TcpListener::bind(cfg.api_listen)
        .await
        .map_err(|e| format!("bind api {}: {e}", cfg.api_listen))?;
    let admin = TcpListener::bind(cfg.admin_listen)
        .await
        .map_err(|e| format!("bind admin {}: {e}", cfg.admin_listen))?;
    let api_addr = api.local_addr().map_err(|e| e.to_string())?;
    let admin_addr = admin.local_addr().map_err(|e| e.to_string())?;
    let shared = Arc::new(Shared {
        store: Mutex::new(store),
        cfg,
    });
    let (tx, rx) = watch::channel(false);
    log("SIMULATED payment provider - NOT a real payment API. Never use real keys or card data.");
    if acceptor.is_some() {
        log(&format!(
            "api listening on {api_addr} (TLS 1.3, TEST certificate)"
        ));
    } else {
        log(&format!("api listening on {api_addr}"));
    }
    log(&format!("admin (fault control) listening on {admin_addr}"));
    if shared.cfg.malicious_mode {
        log("MALICIOUS-PROVIDER MODE ENABLED at start");
    }
    let tasks = vec![
        tokio::spawn(serve(api, shared.clone(), Kind::Api, acceptor, rx.clone())),
        tokio::spawn(serve(admin, shared.clone(), Kind::Admin, None, rx.clone())),
        tokio::spawn(ticker(shared.clone(), rx)),
    ];
    Ok(Server {
        api_addr,
        admin_addr,
        shared,
        shutdown: tx,
        tasks,
    })
}

/// Applies scheduled settlement transitions (relevant in `system` clock mode; in
/// `manual` mode the admin clock-advance call also applies them).
async fn ticker(shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                let evs = shared.lock().process_due();
                if !evs.is_empty() {
                    webhook::dispatch(&shared, evs);
                }
            }
        }
    }
}

async fn serve(
    listener: TcpListener,
    shared: Arc<Shared>,
    kind: Kind,
    tls: Option<TlsAcceptor>,
    mut stop: watch::Receiver<bool>,
) {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            _ = stop.changed() => return,
            a = listener.accept() => a,
        };
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            // Over the connection limit: close immediately.
            drop(stream);
            continue;
        };
        let shared = shared.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tls {
                None => handle_conn(stream, peer, &shared, kind).await,
                Some(acc) => {
                    match tokio::time::timeout(http::READ_TIMEOUT, acc.accept(stream)).await {
                        Ok(Ok(s)) => handle_conn(s, peer, &shared, kind).await,
                        Ok(Err(e)) => log(&format!("tls handshake from {peer} failed: {e}")),
                        Err(_) => log(&format!("tls handshake from {peer} timed out")),
                    }
                }
            }
        });
    }
}

async fn handle_conn<S>(mut stream: S, peer: SocketAddr, shared: &Arc<Shared>, kind: Kind)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let resp = match http::read_request(&mut stream, peer).await {
        Ok(req) => {
            let r = match kind {
                Kind::Api => api::handle(shared, &req).await,
                Kind::Admin => admin::handle(shared, &req).await,
            };
            log(&format!(
                "{} {} {} from {} -> {}{}",
                match kind {
                    Kind::Api => "api",
                    Kind::Admin => "admin",
                },
                req.method,
                req.path,
                peer,
                r.status,
                if matches!(r.wire, http::Wire::Drop) {
                    " (connection dropped by fault)"
                } else {
                    ""
                }
            ));
            r
        }
        Err(e) if e.silent => return,
        Err(e) => api::error_response(&state::ApiError::invalid(e.message, e.message))
            .with_status(e.status),
    };
    http::write_response(&mut stream, &resp).await;
}

impl http::Response {
    fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
}
