// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Configuration (payments-adapter-v1 §9) and the start-up checks of the inputs the broker cannot
//! write (§2). The adapter refuses to start unless every check holds and re-reads nothing at
//! runtime (rotation = restart).

use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use nodkey_grant::{BrokerId, RMax};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::{PemObject, SectionKind};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::json::check_strict;
use crate::provider::HttpLimits;

pub const FORMAT: &str = "nodkey.payments-adapter.v1";
/// 2024-01-01T00:00:00Z (§2 clock floor).
pub const CLOCK_FLOOR: u64 = 1_704_067_200;
/// Upper bound of the per-request deadline `total_ms`.
pub const MAX_TOTAL_MS: u64 = 60_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    format: String,
    socket_path: String,
    broker_uid: u32,
    broker_id: String,
    wid: String,
    tenants: Vec<String>,
    #[serde(rename = "R_max_s")]
    r_max_s: u64,
    registry_path: String,
    db: RawDb,
    provider: RawProvider,
    limits: RawLimits,
    /// payments-adapter-v1 Draft 4 §16.1 (`payments.support_refund`); absent = every
    /// `payments.support_refund` grant is refused.
    #[serde(default)]
    support: Option<RawSupport>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSupport {
    wids: Vec<String>,
    support_principals: std::collections::BTreeMap<String, Vec<String>>,
}

/// §16.1: the workloads allowed to present `payments.support_refund` grants and the support
/// principals per tenant (must equal the broker's and authority's copy; not checkable here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Support {
    pub wids: Vec<String>,
    pub principals: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
}

impl Support {
    pub fn is_principal(&self, ten: &str, sub: &str) -> bool {
        self.principals.get(ten).is_some_and(|s| s.contains(sub))
    }
}

fn parse_support(r: Option<RawSupport>, tenants: &[String]) -> Result<Option<Support>, String> {
    let Some(r) = r else { return Ok(None) };
    let wids: std::collections::BTreeSet<&String> = r.wids.iter().collect();
    if r.wids.is_empty() || wids.len() != r.wids.len() || r.wids.iter().any(|w| !is_id(w, 256)) {
        return Err("config: support.wids must be a non-empty set of IDs".into());
    }
    if r.support_principals.is_empty() {
        return Err("config: support.support_principals is empty".into());
    }
    let mut principals = std::collections::BTreeMap::new();
    for (ten, subs) in r.support_principals {
        let set: std::collections::BTreeSet<String> = subs.iter().cloned().collect();
        if !tenants.contains(&ten)
            || set.is_empty()
            || set.len() != subs.len()
            || set.iter().any(|s| !is_id(s, 256))
        {
            return Err(
                "config: support.support_principals: unknown tenant or invalid list".into(),
            );
        }
        principals.insert(ten, set);
    }
    Ok(Some(Support {
        wids: r.wids,
        principals,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDb {
    socket_dir: String,
    db_uid: u32,
    dbname: String,
    user: String,
    password_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProvider {
    profile: String,
    account: String,
    addr: String,
    server_name: String,
    ca_file: String,
    key_file: String,
    idem_key_file: String,
    idem_key_not_before: u64,
    retention_s: u64,
    resend_margin_s: u64,
    caps: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    connect_ms: u64,
    total_ms: u64,
    max_head: usize,
    max_body: usize,
    max_concurrent: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    IdemStatus,
    SendCurrency,
}

impl Cap {
    pub fn as_str(self) -> &'static str {
        match self {
            Cap::IdemStatus => "idem_status",
            Cap::SendCurrency => "send_currency",
        }
    }
}

/// The validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub socket_path: PathBuf,
    pub broker_uid: u32,
    pub broker_id: String,
    pub wid: String,
    pub tenants: Vec<String>,
    /// §16.1.
    pub support: Option<Support>,
    pub r_max_s: u64,
    pub registry_path: PathBuf,
    pub db_socket_dir: PathBuf,
    pub db_uid: u32,
    pub dbname: String,
    pub db_user: String,
    pub password_file: PathBuf,
    pub account: String,
    pub addr: SocketAddr,
    pub server_name: String,
    pub ca_file: PathBuf,
    pub key_file: PathBuf,
    pub idem_key_file: PathBuf,
    /// Activation time of the loaded `K_idem` (Unix seconds, set by the operator at every
    /// rotation; spec §3.3, PC-A-01). `refund.create` is refused for grants with `iat` below it.
    pub idem_key_not_before: u64,
    pub retention_s: u64,
    pub resend_margin_s: u64,
    pub caps: Vec<Cap>,
    pub limits: HttpLimits,
    pub max_concurrent: usize,
}

impl Config {
    pub fn has(&self, c: Cap) -> bool {
        self.caps.contains(&c)
    }
    pub fn r_max(&self) -> RMax {
        RMax::new(self.r_max_s, self.retention_s, self.resend_margin_s).expect("validated at parse")
    }
}

fn abs(p: &str, what: &str) -> Result<PathBuf, String> {
    let pb = PathBuf::from(p);
    if !pb.is_absolute()
        || pb
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(format!("{what} must be an absolute, normalized path"));
    }
    Ok(pb)
}

/// IDs: 1..=`max` bytes of visible ASCII (no space or control characters; grant-v1 §5.1).
pub fn is_id(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn is_dns_name(s: &str) -> bool {
    (1..=253).contains(&s.len())
        && s.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        && s.parse::<std::net::IpAddr>().is_err()
}

/// Parses and validates the configuration document (§9 refusals that do not need the filesystem).
pub fn parse_config(bytes: &[u8]) -> Result<Config, String> {
    check_strict(bytes, 4).map_err(|_| "config is not strict JSON".to_string())?;
    let r: RawConfig =
        serde_json::from_slice(bytes).map_err(|e| format!("config: {}", e.classify_str()))?;
    if r.format != FORMAT {
        return Err("config: wrong format".into());
    }
    if r.broker_uid == 0 {
        return Err("config: broker_uid must not be 0".into());
    }
    if r.db.db_uid == r.broker_uid {
        return Err("config: db_uid equals broker_uid".into());
    }
    BrokerId::new(&r.broker_id).ok_or("config: broker_id is not an ID")?;
    if !is_id(&r.wid, 256) {
        return Err("config: wid is not an ID".into());
    }
    if r.tenants.is_empty() {
        return Err("config: tenants is empty (RX-1)".into());
    }
    for (i, t) in r.tenants.iter().enumerate() {
        if !is_id(t, 128) || r.tenants[..i].contains(t) {
            return Err("config: invalid or duplicate tenant".into());
        }
    }
    let p = &r.provider;
    if p.profile != "simpay" {
        return Err("config: unsupported provider profile".into());
    }
    if !(1..=64).contains(&p.account.len())
        || !p
            .account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err("config: provider.account is invalid".into());
    }
    // An IP literal and port: no DNS.
    let addr: SocketAddr = p
        .addr
        .parse()
        .map_err(|_| "config: provider.addr must be an IP literal with port".to_string())?;
    if addr.port() == 0 {
        return Err("config: provider.addr port 0".into());
    }
    if !is_dns_name(&p.server_name) {
        return Err("config: provider.server_name must be a DNS name".into());
    }
    // §3.1 R_max start-up rule (the profile's documented minimum retention is the operator's
    // statement in `retention_s`; for simpay it must equal simpay's `idempotency_retention_s`).
    if RMax::new(r.r_max_s, p.retention_s, p.resend_margin_s).is_none() {
        return Err(
            "config: R_max_s violates R_max < retention - margin, margin < retention".into(),
        );
    }
    let mut caps = Vec::new();
    for c in &p.caps {
        let cap = match c.as_str() {
            "idem_status" => Cap::IdemStatus,
            "send_currency" => Cap::SendCurrency,
            _ => return Err("config: unknown capability".into()),
        };
        if caps.contains(&cap) {
            return Err("config: duplicate capability".into());
        }
        caps.push(cap);
    }
    // 2024-01-01T00:00:00Z: the same floor as the clock check (§2).
    if p.idem_key_not_before < CLOCK_FLOOR {
        return Err("config: provider.idem_key_not_before is before 2024-01-01".into());
    }
    let l = &r.limits;
    // `total_ms` is the whole per-request deadline from receipt (§1, PC-A-02): the DB phase and
    // the provider phase both fit inside it, so connect + handshake must leave room for the rest.
    if !(1 <= l.connect_ms && l.connect_ms < l.total_ms && l.total_ms <= MAX_TOTAL_MS) {
        return Err("config: limits connect_ms/total_ms out of range".into());
    }
    if !(8192..=65_536).contains(&l.max_head)
        || !(1024..=1_048_576).contains(&l.max_body)
        || !(1..=64).contains(&l.max_concurrent)
    {
        return Err("config: limits out of range".into());
    }
    for (s, what) in [(&r.db.dbname, "db.dbname"), (&r.db.user, "db.user")] {
        if !(1..=63).contains(&s.len())
            || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(format!("config: {what} is invalid"));
        }
    }
    let cfg = Config {
        socket_path: abs(&r.socket_path, "socket_path")?,
        broker_uid: r.broker_uid,
        broker_id: r.broker_id,
        support: parse_support(r.support, &r.tenants)?,
        wid: r.wid,
        tenants: r.tenants,
        r_max_s: r.r_max_s,
        registry_path: abs(&r.registry_path, "registry_path")?,
        db_socket_dir: abs(&r.db.socket_dir, "db.socket_dir")?,
        db_uid: r.db.db_uid,
        dbname: r.db.dbname,
        db_user: r.db.user,
        password_file: abs(&r.db.password_file, "db.password_file")?,
        account: p.account.clone(),
        addr,
        server_name: p.server_name.clone(),
        ca_file: abs(&p.ca_file, "provider.ca_file")?,
        key_file: abs(&p.key_file, "provider.key_file")?,
        idem_key_file: abs(&p.idem_key_file, "provider.idem_key_file")?,
        idem_key_not_before: p.idem_key_not_before,
        retention_s: p.retention_s,
        resend_margin_s: p.resend_margin_s,
        caps,
        limits: HttpLimits {
            connect_ms: l.connect_ms,
            total_ms: l.total_ms,
            max_head: l.max_head,
            max_body: l.max_body,
        },
        max_concurrent: l.max_concurrent,
    };
    let sock_dir = cfg
        .socket_path
        .parent()
        .ok_or("socket_path has no directory")?;
    if nested(sock_dir, &cfg.db_socket_dir) {
        return Err("config: socket P directory and db.socket_dir are shared or nested".into());
    }
    Ok(cfg)
}

trait ClassifyStr {
    fn classify_str(&self) -> &'static str;
}
impl ClassifyStr for serde_json::Error {
    fn classify_str(&self) -> &'static str {
        // The serde message may quote config content; keep start-up errors generic.
        match self.classify() {
            serde_json::error::Category::Data => "unknown, missing or wrongly typed member",
            _ => "syntax error",
        }
    }
}

/// True if `a` and `b` are equal or one lexically contains the other.
pub fn nested(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Process-level uid refusals (§9, effect-protocol-v2 §1.2): uid 0, or a uid shared with a role.
pub fn check_own_uid(cfg: &Config, own_uid: u32) -> Result<(), String> {
    if own_uid == 0 {
        return Err("refusing to run as uid 0".into());
    }
    if own_uid == cfg.broker_uid || own_uid == cfg.db_uid {
        return Err("adapter uid collides with broker_uid or db_uid".into());
    }
    Ok(())
}

/// Opens `path` after checking it is a regular file and not a symlink, and returns its bytes
/// together with the metadata of the opened file (same inode as the checked path).
fn open_checked(path: &Path, max: u64) -> Result<(Vec<u8>, std::fs::Metadata), String> {
    let lm = std::fs::symlink_metadata(path).map_err(|_| format!("{}: missing", path.display()))?;
    if !lm.file_type().is_file() {
        return Err(format!(
            "{}: not a regular file (or a symlink)",
            path.display()
        ));
    }
    let mut f = File::open(path).map_err(|_| format!("{}: cannot open", path.display()))?;
    let m = f
        .metadata()
        .map_err(|_| format!("{}: cannot stat", path.display()))?;
    if m.dev() != lm.dev() || m.ino() != lm.ino() {
        return Err(format!("{}: changed while opening", path.display()));
    }
    if m.len() > max {
        return Err(format!("{}: too large", path.display()));
    }
    let mut buf = Vec::with_capacity(m.len() as usize);
    f.by_ref()
        .take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|_| format!("{}: read error", path.display()))?;
    if buf.len() as u64 > max {
        return Err(format!("{}: too large", path.display()));
    }
    Ok((buf, m))
}

/// Owner uid of operator-provisioned files in production: root (§2 file table).
pub const OPERATOR_UID: u32 = 0;

/// Registry, config and pinned CA (§2, PC-A-03): regular file, not a symlink, owned by
/// `trusted_owner` (root in production, [`OPERATOR_UID`]), no group/other write bit on the file
/// or any parent directory, and every parent directory owned by root or `trusted_owner`. The
/// bytes returned are the bytes of the inode that was checked (one read).
pub fn read_operator_file(path: &Path, trusted_owner: u32, max: u64) -> Result<Vec<u8>, String> {
    let (buf, m) = open_checked(path, max)?;
    if m.uid() != trusted_owner {
        return Err(format!("{}: not owned by root", path.display()));
    }
    if m.mode() & 0o022 != 0 {
        return Err(format!("{}: group/other writable", path.display()));
    }
    let canon =
        std::fs::canonicalize(path).map_err(|_| format!("{}: cannot resolve", path.display()))?;
    let mut dir = canon.parent();
    while let Some(d) = dir {
        let dm = std::fs::metadata(d).map_err(|_| format!("{}: cannot stat", d.display()))?;
        if dm.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "{}: parent {} is group/other writable",
                path.display(),
                d.display()
            ));
        }
        if dm.uid() != OPERATOR_UID && dm.uid() != trusted_owner {
            return Err(format!(
                "{}: parent {} is not owned by root",
                path.display(),
                d.display()
            ));
        }
        dir = d.parent();
    }
    Ok(buf)
}

/// Secrets (simpay key, `K_idem`, DB password; §2): owner = adapter uid, mode exactly `0400`,
/// regular file, not a symlink. Returned in a zeroizing buffer.
pub fn read_secret_file(path: &Path, own_uid: u32) -> Result<Zeroizing<Vec<u8>>, String> {
    let (buf, m) = open_checked(path, 4096)?;
    let buf = Zeroizing::new(buf);
    if m.uid() != own_uid {
        return Err(format!("{}: not owned by the adapter uid", path.display()));
    }
    if m.mode() & 0o7777 != 0o400 {
        return Err(format!("{}: mode must be 0400", path.display()));
    }
    Ok(buf)
}

fn strip_newline(b: &[u8]) -> &[u8] {
    b.strip_suffix(b"\n").unwrap_or(b)
}

/// simpay key file: a restricted simulator key `rk_sim_…` (§1: refunds write, charges read),
/// optionally followed by one newline.
pub fn parse_api_key(b: &[u8]) -> Result<Zeroizing<String>, String> {
    let b = strip_newline(b);
    let ok = b.starts_with(b"rk_sim_")
        && (8..=255).contains(&b.len())
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
    if !ok {
        return Err("key_file: not a restricted simpay key (rk_sim_…)".into());
    }
    Ok(Zeroizing::new(
        String::from_utf8(b.to_vec()).map_err(|_| "key_file: not ASCII")?,
    ))
}

/// `K_idem` file: exactly 64 lowercase hex characters (32 bytes), optionally one newline.
pub fn parse_idem_key(b: &[u8]) -> Result<[u8; 32], String> {
    let b = strip_newline(b);
    if b.len() != 64 {
        return Err("idem_key_file: must hold 64 lowercase hex characters".into());
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        let (Some(h), Some(l)) = (nib(b[2 * i]), nib(b[2 * i + 1])) else {
            return Err("idem_key_file: must hold 64 lowercase hex characters".into());
        };
        *o = (h << 4) | l;
    }
    Ok(out)
}

/// DB password file: 1..=1024 visible ASCII bytes, optionally one newline.
pub fn parse_password(b: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let b = strip_newline(b);
    if !(1..=1024).contains(&b.len()) || !b.iter().all(|c| (0x21..=0x7e).contains(c)) {
        return Err("password_file: invalid content".into());
    }
    Ok(Zeroizing::new(b.to_vec()))
}

/// Pinned CA file: exactly one PEM section, a certificate (§2).
pub fn parse_ca(b: &[u8]) -> Result<CertificateDer<'static>, String> {
    let mut it = <(SectionKind, Vec<u8>) as PemObject>::pem_slice_iter(b);
    let first = it.next();
    let second = it.next();
    match (first, second) {
        (Some(Ok((SectionKind::Certificate, der))), None) => Ok(CertificateDer::from(der)),
        _ => Err("ca_file: must contain exactly one certificate and nothing else".into()),
    }
}

/// Socket P directory (§1, effect-protocol-v2 §1.2): a real directory owned by the adapter, mode
/// exactly `2750` (setgid, group = the broker's group, no "other" bits).
pub fn check_socket_dir(dir: &Path, own_uid: u32) -> Result<(), String> {
    let m = std::fs::symlink_metadata(dir)
        .map_err(|_| format!("socket directory {}: missing", dir.display()))?;
    if !m.file_type().is_dir() {
        return Err(format!(
            "socket directory {}: not a directory (or a symlink)",
            dir.display()
        ));
    }
    if m.uid() != own_uid {
        return Err(format!(
            "socket directory {}: not owned by the adapter",
            dir.display()
        ));
    }
    if m.mode() & 0o7777 != 0o2750 {
        return Err(format!(
            "socket directory {}: mode must be 2750",
            dir.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    pub fn sample() -> Value {
        json!({"format": FORMAT, "socket_path": "/run/nodkey/br-pay/adapter.sock",
            "broker_uid": 10002, "broker_id": "broker.test", "wid": "spiffe://nodkey.test/workload/shop",
            "tenants": ["acme"], "R_max_s": 43200, "registry_path": "/etc/nodkey-adapter/keys.json",
            "db": {"socket_dir": "/run/pg-adapter", "db_uid": 70, "dbname": "ledger",
                   "user": "nodkey_payments_adapter", "password_file": "/run/secrets/db"},
            "provider": {"profile": "simpay", "account": "acct_demomerchant01", "addr": "172.30.30.20:8443",
                "server_name": "simpay.test", "ca_file": "/etc/nodkey-adapter/ca.crt",
                "key_file": "/run/secrets/simpay", "idem_key_file": "/run/secrets/kidem",
                "idem_key_not_before": 1_761_350_400u64, "retention_s": 86400, "resend_margin_s": 7200, "caps": ["idem_status"]},
            "limits": {"connect_ms": 2000, "total_ms": 10000, "max_head": 16384, "max_body": 65536,
                       "max_concurrent": 8}})
    }

    fn with(f: impl FnOnce(&mut Value)) -> Result<Config, String> {
        let mut v = sample();
        f(&mut v);
        parse_config(v.to_string().as_bytes())
    }

    #[test]
    fn sample_parses() {
        let c = with(|_| {}).unwrap();
        assert_eq!(c.r_max().seconds(), 43200);
        assert!(c.has(Cap::IdemStatus) && !c.has(Cap::SendCurrency));
    }

    #[test]
    fn refusals() {
        type Mutation = Box<dyn FnOnce(&mut Value)>;
        let cases: Vec<(&str, Mutation)> = vec![
            ("format", Box::new(|v| v["format"] = json!("x"))),
            ("unknown member", Box::new(|v| v["extra"] = json!(1))),
            (
                "unknown nested",
                Box::new(|v| v["provider"]["proxy"] = json!("x")),
            ),
            (
                "missing",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("wid");
                }),
            ),
            ("empty tenants", Box::new(|v| v["tenants"] = json!([]))),
            (
                "dup tenants",
                Box::new(|v| v["tenants"] = json!(["a", "a"])),
            ),
            (
                "dns addr",
                Box::new(|v| v["provider"]["addr"] = json!("simpay.test:8443")),
            ),
            (
                "no port",
                Box::new(|v| v["provider"]["addr"] = json!("172.30.30.20")),
            ),
            (
                "ip server_name",
                Box::new(|v| v["provider"]["server_name"] = json!("172.30.30.20")),
            ),
            ("rmax", Box::new(|v| v["R_max_s"] = json!(80000))),
            (
                "margin>=retention",
                Box::new(|v| v["provider"]["resend_margin_s"] = json!(86400)),
            ),
            (
                "retention above",
                Box::new(|v| {
                    v["provider"]["retention_s"] = json!(300);
                }),
            ),
            ("rmax zero", Box::new(|v| v["R_max_s"] = json!(0))),
            (
                "cap",
                Box::new(|v| v["provider"]["caps"] = json!(["webhooks"])),
            ),
            (
                "dup cap",
                Box::new(|v| v["provider"]["caps"] = json!(["idem_status", "idem_status"])),
            ),
            (
                "profile",
                Box::new(|v| v["provider"]["profile"] = json!("stripe")),
            ),
            ("broker uid 0", Box::new(|v| v["broker_uid"] = json!(0))),
            (
                "db=broker uid",
                Box::new(|v| v["db"]["db_uid"] = json!(10002)),
            ),
            (
                "relative path",
                Box::new(|v| v["registry_path"] = json!("keys.json")),
            ),
            (
                "dotdot path",
                Box::new(|v| v["provider"]["ca_file"] = json!("/etc/../tmp/ca")),
            ),
            (
                "nested dirs",
                Box::new(|v| v["db"]["socket_dir"] = json!("/run/nodkey")),
            ),
            ("float", Box::new(|v| v["R_max_s"] = json!(43200.0))),
            (
                "limits",
                Box::new(|v| v["limits"]["connect_ms"] = json!(20000)),
            ),
            ("head", Box::new(|v| v["limits"]["max_head"] = json!(100))),
            (
                "connect = total",
                Box::new(|v| v["limits"]["connect_ms"] = json!(10000)),
            ),
            (
                "not_before floor",
                Box::new(|v| v["provider"]["idem_key_not_before"] = json!(1_704_067_199u64)),
            ),
            (
                "not_before missing",
                Box::new(|v| {
                    v["provider"]
                        .as_object_mut()
                        .unwrap()
                        .remove("idem_key_not_before");
                }),
            ),
        ];
        for (name, f) in cases {
            assert!(with(f).is_err(), "{name} accepted");
        }
        let dup = sample()
            .to_string()
            .replacen("\"wid\":", "\"wid\":\"x\",\"wid\":", 1);
        assert!(parse_config(dup.as_bytes()).is_err());
    }

    #[test]
    fn uid_refusals() {
        let c = with(|_| {}).unwrap();
        assert!(check_own_uid(&c, 0).is_err());
        assert!(check_own_uid(&c, 10002).is_err());
        assert!(check_own_uid(&c, 70).is_err());
        assert!(check_own_uid(&c, 10006).is_ok());
    }

    #[test]
    fn secret_parsers() {
        assert!(parse_api_key(b"rk_sim_DEMOrefundsWriteChargesRead\n").is_ok());
        assert!(parse_api_key(b"sk_sim_DEMOunrestricted00000001").is_err());
        assert!(parse_api_key(b"sk_live_abc").is_err());
        assert!(parse_api_key(b"rk_sim_a b").is_err());
        assert!(parse_api_key(b"rk_sim_ab\n\n").is_err());
        let hex: String = (0..32).map(|i| format!("{i:02x}")).collect();
        assert_eq!(
            parse_idem_key(hex.as_bytes()).unwrap(),
            core::array::from_fn(|i| i as u8)
        );
        assert!(parse_idem_key(hex.to_uppercase().as_bytes()).is_err());
        assert!(parse_idem_key(&hex.as_bytes()[..62]).is_err());
        assert!(parse_password(b"secret\n").is_ok());
        assert!(parse_password(b"").is_err());
        assert!(parse_password(b"a b").is_err());
    }

    fn uid_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().uid()
    }

    #[test]
    fn file_checks() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("cfgchk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        let me = uid_of(&base);
        let other = me.wrapping_add(1000);
        let f = base.join("keys.json");
        std::fs::write(&f, b"{}").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o444)).unwrap();
        // Test files are owned by the test user, so they pass only with `trusted_owner` = that
        // user, and must fail for any other owner (production: root).
        let parents_ok = read_operator_file(&f, me, 1024);
        if let Err(e) = &parents_ok {
            // Some ancestor of the checkout may be group/other-writable on a developer machine.
            assert!(e.contains("parent"), "{e}");
        }
        assert!(
            read_operator_file(&f, other, 1024)
                .unwrap_err()
                .contains("not owned by root")
        );
        if me != OPERATOR_UID {
            assert!(read_operator_file(&f, OPERATOR_UID, 1024).is_err());
        }
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o464)).unwrap();
        assert!(
            read_operator_file(&f, me, 1024)
                .unwrap_err()
                .contains("writable")
        );
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o444)).unwrap();
        let link = base.join("link.json");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(
            read_operator_file(&link, me, 1024)
                .unwrap_err()
                .contains("symlink")
        );
        assert!(read_secret_file(&link, me).unwrap_err().contains("symlink"));
        assert!(
            read_operator_file(&f, me, 1)
                .unwrap_err()
                .contains("too large")
        );

        let s = base.join("secret");
        std::fs::write(&s, b"x").unwrap();
        std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_secret_file(&s, me).is_ok());
        assert!(read_secret_file(&s, me + 1).is_err());
        std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o440)).unwrap();
        assert!(read_secret_file(&s, me).unwrap_err().contains("0400"));
        std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_secret_file(&s, me).unwrap_err().contains("0400"));

        let d = base.join("sock");
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o2750)).unwrap();
        assert!(check_socket_dir(&d, me).is_ok());
        assert!(check_socket_dir(&d, me + 1).is_err());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o2755)).unwrap();
        assert!(check_socket_dir(&d, me).is_err());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(check_socket_dir(&d, me).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ca_parsing() {
        assert!(parse_ca(b"").is_err());
        assert!(
            parse_ca(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n").is_err()
        );
        let one = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(parse_ca(one.as_bytes()).is_ok());
        assert!(parse_ca(format!("{one}{one}").as_bytes()).is_err());
        let with_key =
            format!("{one}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        assert!(parse_ca(with_key.as_bytes()).is_err());
    }
}
