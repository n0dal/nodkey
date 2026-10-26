//! Nodkey payments adapter (PROTOTYPE): payments-adapter-v1 Draft 3 against the simpay
//! simulator.
//!
//! A stateless process with its own uid that alone holds the provider key and `K_idem` and alone
//! can reach the provider. It verifies the authority-signed grant itself, re-checks
//! order → charge → owner in its own read-only view, derives the idempotency key and reference
//! from the grant's `(iss, jti)`, builds the provider request only from the grant, and returns a
//! bounded, closed-enum result to the broker on socket P.
//!
//! Modules: [`config`] (§9, §2 start-up checks), [`grant`] (§3.1), [`orders`] (§3.2, PA-16),
//! [`derive`] (§3.3), [`provider`] (§5), [`result`] (§4, §6), [`server`] (socket P).

#![forbid(unsafe_code)]

pub mod config;
pub mod derive;
pub mod grant;
pub mod json;
pub mod log;
pub mod orders;
pub mod provider;
pub mod result;
pub mod server;

use std::sync::Arc;
use std::time::Duration;

use nodkey_grant::{BrokerId, Registry};

use config::{Config, Uids};
use server::Adapter;

/// Size limits for the §2 input files.
const MAX_CONFIG: u64 = 64 * 1024;
const MAX_REGISTRY: u64 = 1024 * 1024;
const MAX_CA: u64 = 64 * 1024;

/// This process's uid, read through `SO_PEERCRED` on a socket pair (no `unsafe`, no libc).
pub fn own_uid() -> Result<u32, String> {
    let (a, _b) = tokio::net::UnixStream::pair().map_err(|_| "socketpair failed".to_string())?;
    a.peer_cred()
        .map(|c| c.uid())
        .map_err(|_| "peer_cred failed".to_string())
}

/// Start-up (§2, §9): runs every file and uid check with the process's real uid and builds the
/// adapter. Any error means the adapter must not start. Production order view: PostgreSQL over
/// the `pg-adapter` Unix socket.
pub fn load(config_path: &std::path::Path, own_uid: u32) -> Result<(Adapter, Config), String> {
    // The config file's own owner check needs the broker uid, which is inside the file: read it
    // with the adapter-uid check first, then re-check with the broker uid once parsed.
    let pre = Uids {
        own: own_uid,
        broker: own_uid,
    };
    let bytes = config::read_operator_file(config_path, pre, MAX_CONFIG)?;
    let cfg = config::parse_config(&bytes)?;
    let uids = Uids {
        own: own_uid,
        broker: cfg.broker_uid,
    };
    config::read_operator_file(config_path, uids, MAX_CONFIG)?;
    config::check_own_uid(&cfg, own_uid)?;
    let sock_dir = cfg
        .socket_path
        .parent()
        .ok_or("socket_path has no directory")?;
    config::check_socket_dir(sock_dir, own_uid)?;
    for p in [&cfg.registry_path, &cfg.ca_file] {
        if config::nested(sock_dir, p) {
            return Err("socket P directory overlaps an input file".into());
        }
    }
    let registry_bytes = config::read_operator_file(&cfg.registry_path, uids, MAX_REGISTRY)?;
    let registry_text =
        std::str::from_utf8(&registry_bytes).map_err(|_| "registry is not UTF-8".to_string())?;
    let registry = Registry::load(registry_text).map_err(|_| "registry invalid".to_string())?;
    let ca = config::parse_ca(&config::read_operator_file(&cfg.ca_file, uids, MAX_CA)?)?;
    let key = config::parse_api_key(&config::read_secret_file(&cfg.key_file, own_uid)?)?;
    let kidem = config::parse_idem_key(&config::read_secret_file(&cfg.idem_key_file, own_uid)?)?;
    let password = config::parse_password(&config::read_secret_file(&cfg.password_file, own_uid)?)?;
    let orders = orders::PgUnixView {
        socket_dir: cfg.db_socket_dir.clone(),
        db_uid: cfg.db_uid,
        dbname: cfg.dbname.clone(),
        user: cfg.db_user.clone(),
        password,
        timeout: Duration::from_secs(2),
    };
    let adapter = build(
        cfg.clone(),
        registry,
        ca,
        provider::ApiKey::new(key),
        derive::IdemKey::new(kidem),
        Arc::new(orders),
    )?;
    Ok((adapter, cfg))
}

/// Builds the adapter from already-checked, parsed inputs. [`load`] is the only production
/// caller; tests use this directly because test files cannot be owned by another uid.
pub fn build(
    cfg: Config,
    registry: Registry,
    ca: rustls_pki_types::CertificateDer<'static>,
    key: provider::ApiKey,
    idem: derive::IdemKey,
    orders: Arc<dyn orders::OrderView>,
) -> Result<Adapter, String> {
    let broker_id = BrokerId::new(&cfg.broker_id).ok_or("broker_id invalid")?;
    let grants = grant::GrantInputs {
        registry,
        operations: grant::operations(),
        broker_id,
        wid: cfg.wid.clone(),
        tenants: cfg.tenants.clone(),
        r_max: cfg.r_max(),
    };
    // The retransmission context must accept the compiled-in declaration.
    nodkey_grant::RetransmissionContext::new(
        &grants.registry,
        &grants.broker_id,
        &grants.wid,
        &grants.tenants,
        &grants.operations,
        grant::OP,
        nodkey_grant::Limits::default(),
    )
    .ok_or("retransmission context refused")?;
    let tls = provider::tls_config(ca)?;
    let provider = provider::Provider::new(cfg.addr, &cfg.server_name, tls, key, cfg.limits)?;
    Ok(Adapter {
        cfg,
        grants,
        idem,
        provider,
        orders,
        ids: log::CorrelationIds::new(),
    })
}
