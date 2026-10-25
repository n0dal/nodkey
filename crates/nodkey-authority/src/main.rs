//! `nodkey-authority run --config <path> [--mounts-verified-externally]`
//! `nodkey-authority keygen --out <path> --iss <issuer> [--not-before <unix>] [--not-after <unix>]`

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nodkey_authority::broker_client::BrokerClient;
use nodkey_authority::config::{Config, startup_checks};
use nodkey_authority::key::{keygen, kid_hex, load_signing_key};
use nodkey_authority::server::{Authority, Settings, system_clock};
use nodkey_authority::store::Store;
use nodkey_authority::{log, own_uid};
use serde_json::json;
use tokio::net::UnixListener;

const BROKER_STARTUP_WAIT: Duration = Duration::from_secs(30);
const DEFAULT_KEY_LIFETIME: u64 = 365 * 24 * 3600;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  nodkey-authority run --config <path> [--mounts-verified-externally]\n  \
         nodkey-authority keygen --out <path> --iss <issuer> [--not-before <unix>] [--not-after <unix>]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => cmd_keygen(&args[1..]),
        Some("run") => cmd_run(&args[1..]),
        _ => usage(),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cmd_keygen(args: &[String]) -> ExitCode {
    let (mut out, mut iss, mut nb, mut na) = (None, None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let v = it.next();
        match (a.as_str(), v) {
            ("--out", Some(v)) => out = Some(PathBuf::from(v)),
            ("--iss", Some(v)) => iss = Some(v.clone()),
            ("--not-before", Some(v)) => nb = v.parse::<u64>().ok().or(Some(u64::MAX)),
            ("--not-after", Some(v)) => na = v.parse::<u64>().ok().or(Some(u64::MAX)),
            _ => return usage(),
        }
    }
    let (Some(out), Some(iss)) = (out, iss) else {
        return usage();
    };
    let nb = nb.unwrap_or_else(now);
    let na = na.unwrap_or(nb.saturating_add(DEFAULT_KEY_LIFETIME));
    match keygen(&out, &iss, nb, na) {
        Ok(registry) => {
            // The registry document (public key only) goes to stdout for the broker.
            println!("{registry}");
            eprintln!(
                "DEV KEY written to {} (mode 0600). Registry entry above is for the broker.",
                out.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("keygen: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_run(args: &[String]) -> ExitCode {
    let mut config = None;
    let mut mounts_verified = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => match it.next() {
                Some(v) => config = Some(PathBuf::from(v)),
                None => return usage(),
            },
            "--mounts-verified-externally" => mounts_verified = true,
            _ => return usage(),
        }
    }
    let Some(config) = config else {
        return usage();
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(&config, mounts_verified)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::event("startup_refused", json!({"reason": e}));
            ExitCode::FAILURE
        }
    }
}

fn prepare_socket_path(path: &Path) -> Result<(), String> {
    let dir = path.parent().ok_or("gateway socket has no directory")?;
    let dm = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !dm.file_type().is_dir() {
        return Err(format!("{}: not a directory", dir.display()));
    }
    if dm.mode() & 0o007 != 0 {
        return Err(format!(
            "{}: socket directory must not be accessible by others",
            dir.display()
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|e| format!("stale socket: {e}"))
        }
        Ok(_) => Err(format!("{}: exists and is not a socket", path.display())),
        Err(_) => Ok(()),
    }
}

async fn run(config: &Path, mounts_verified: bool) -> Result<(), String> {
    let cfg = Config::load(config)?;
    let uid = own_uid().map_err(|e| format!("own uid: {e}"))?;
    if mounts_verified {
        log::event("mounts_verified_externally", json!({"flag": true}));
    }
    startup_checks(&cfg, uid, mounts_verified)?;

    let key = load_signing_key(&cfg.signing_key_path, uid)?;
    let kid = kid_hex(&key);
    if kid != cfg.signing_kid {
        return Err("signing key kid differs from configured signing_kid".into());
    }
    let store = Store::open(&cfg.store_path).map_err(|e| format!("store: {e:?}"))?;

    let broker = BrokerClient::new(
        cfg.broker_socket.clone(),
        cfg.broker_uid,
        cfg.config_digest,
        Duration::from_millis(cfg.broker_call_timeout_ms),
    );
    let started = Instant::now();
    loop {
        match broker.check().await {
            Ok(()) => break,
            Err(e) if started.elapsed() < BROKER_STARTUP_WAIT => {
                log::event("broker_check_retry", json!({"detail": format!("{e:?}")}));
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => return Err(format!("broker check failed: {e:?}")),
        }
    }

    let settings = Settings {
        issuer: cfg.issuer.clone(),
        broker_id: cfg.broker_id.clone(),
        gateway_uid: cfg.gateway_uid,
        grant_ttl_secs: cfg.grant_ttl_secs,
        skew_secs: cfg.skew_secs,
        approve_reply_timeout: Duration::from_millis(cfg.approve_reply_timeout_ms),
        retry_interval: Duration::from_millis(500),
    };
    let authority = Authority::new(
        settings,
        cfg.operations.clone(),
        cfg.workloads.clone(),
        key,
        store,
        broker,
        system_clock(),
    );
    let _recovery = authority.recover().await;

    prepare_socket_path(&cfg.gateway_socket)?;
    let listener =
        UnixListener::bind(&cfg.gateway_socket).map_err(|e| format!("bind gateway socket: {e}"))?;
    std::fs::set_permissions(&cfg.gateway_socket, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| format!("chmod gateway socket: {e}"))?;
    log::event(
        "started",
        json!({"issuer": cfg.issuer, "broker_id": cfg.broker_id, "kid": kid,
               "gateway_socket": cfg.gateway_socket, "broker_socket": cfg.broker_socket}),
    );

    let serve = tokio::spawn(Arc::clone(&authority).serve(listener));
    shutdown_signal().await;
    serve.abort();
    log::event("stopped", json!({}));
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! {
        _ = term.recv() => {},
        _ = int.recv() => {},
    }
}
