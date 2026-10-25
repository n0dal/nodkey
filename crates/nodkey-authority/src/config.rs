//! Authority configuration, workload registrations, and start-up refusals (§1.2).
//!
//! All files are strict JSON (duplicate members rejected at any depth; unknown or missing members
//! rejected). They must be writable by administrators only (SI-13); the authority reads them once
//! at start-up.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use nodkey_grant::{Binding, OpKind, Operations};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::digest::is_id;
use crate::wire::parse_strict_object;

const MAX_FILE_BYTES: u64 = 1 << 20;

/// Label of the configuration digest compared with the broker's `config.digest` (§4.2 step 3).
pub const CONFIG_DIGEST_LABEL: &[u8] = b"nodkey.authority-config-digest.v1";

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut buf = Vec::new();
    f.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(format!("{}: too large", path.display()));
    }
    Ok(buf)
}

fn strict<T: for<'de> Deserialize<'de>>(bytes: &[u8], what: &str) -> Result<T, String> {
    parse_strict_object(bytes).map_err(|e| format!("{what}: {e}"))?;
    serde_json::from_slice(bytes).map_err(|e| format!("{what}: {e}"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    format: String,
    issuer: String,
    broker_id: String,
    signing_key_path: PathBuf,
    signing_kid: String,
    store_path: PathBuf,
    gateway_socket: PathBuf,
    broker_socket: PathBuf,
    authority_uid: u32,
    gateway_uid: u32,
    broker_uid: u32,
    workload_uids: Vec<u32>,
    operations_path: PathBuf,
    workloads_path: PathBuf,
    manifest_path: Option<PathBuf>,
    grant_ttl_secs: u64,
    skew_secs: u64,
    approve_reply_timeout_ms: u64,
    broker_call_timeout_ms: u64,
}

/// Who may approve a workload's proposals (§2.4).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ApproverSource {
    Enrolled { ten: String, sub: String },
    Named,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkload {
    wid: String,
    tenants: Vec<String>,
    approver_source: ApproverSource,
    write_ops: Vec<String>,
    read_ops: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkloads {
    format: String,
    workloads: Vec<RawWorkload>,
}

/// One registered workload (the authority's copy of the broker's registration).
#[derive(Debug, Clone)]
pub struct Workload {
    pub wid: String,
    pub tenants: BTreeSet<String>,
    pub approver_source: ApproverSource,
    pub write_ops: BTreeSet<String>,
    pub read_ops: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct Workloads {
    by_wid: BTreeMap<String, Workload>,
}

impl Workloads {
    pub fn get(&self, wid: &str) -> Option<&Workload> {
        self.by_wid.get(wid)
    }

    /// Parses and validates the registrations against the operation declarations.
    pub fn load(bytes: &[u8], ops: &Operations) -> Result<Workloads, String> {
        let raw: RawWorkloads = strict(bytes, "workloads")?;
        if raw.format != "nodkey.workloads.v1" {
            return Err("workloads: format".into());
        }
        let mut by_wid = BTreeMap::new();
        for w in raw.workloads {
            let e = |m: &str| format!("workload {:?}: {m}", w.wid);
            if !is_id(&w.wid, 256) {
                return Err(e("wid is not an ID"));
            }
            let tenants: BTreeSet<String> = w.tenants.iter().cloned().collect();
            if tenants.is_empty()
                || tenants.len() != w.tenants.len()
                || tenants.iter().any(|t| !is_id(t, 128))
            {
                return Err(e("tenants must be a non-empty set of IDs"));
            }
            if let ApproverSource::Enrolled { ten, sub } = &w.approver_source
                && (!tenants.contains(ten) || !is_id(sub, 256))
            {
                return Err(e("enrolled approver must be (registered tenant, ID)"));
            }
            let write_ops: BTreeSet<String> = w.write_ops.iter().cloned().collect();
            let read_ops: BTreeSet<String> = w.read_ops.iter().cloned().collect();
            if write_ops.len() != w.write_ops.len() || read_ops.len() != w.read_ops.len() {
                return Err(e("duplicate operation"));
            }
            for op in &write_ops {
                let d = ops.get(op).ok_or_else(|| e("undeclared write op"))?;
                if d.kind != OpKind::Write || !d.requires_confirmation {
                    return Err(e("write_ops entry is not a confirmed write operation"));
                }
                // §4.2 step 5: confirmed write grants bind every value exactly.
                if d.params
                    .iter()
                    .any(|p| matches!(p.binding, Binding::Bounded(_)))
                {
                    return Err(e("confirmed write op has a bounded parameter"));
                }
                if w.approver_source == ApproverSource::Named
                    && d.params.iter().any(|p| p.destination)
                {
                    return Err(e(
                        "named workloads may not use destination operations (§2.4)",
                    ));
                }
            }
            for op in &read_ops {
                let d = ops.get(op).ok_or_else(|| e("undeclared read op"))?;
                if d.kind != OpKind::Read {
                    return Err(e("read_ops entry is not a read operation"));
                }
            }
            let wl = Workload {
                wid: w.wid.clone(),
                tenants,
                approver_source: w.approver_source,
                write_ops,
                read_ops,
            };
            if by_wid.insert(w.wid.clone(), wl).is_some() {
                return Err(e("duplicate wid"));
            }
        }
        if by_wid.is_empty() {
            return Err("workloads: empty".into());
        }
        Ok(Workloads { by_wid })
    }
}

/// `SHA-256(label || 0x00 || u64be(len(ops)) || ops || u64be(len(workloads)) || workloads)` over
/// the exact file bytes. Byte-identical copies on the broker and the authority are required.
pub fn config_digest(ops_bytes: &[u8], workloads_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONFIG_DIGEST_LABEL);
    h.update([0u8]);
    h.update((ops_bytes.len() as u64).to_be_bytes());
    h.update(ops_bytes);
    h.update((workloads_bytes.len() as u64).to_be_bytes());
    h.update(workloads_bytes);
    h.finalize().into()
}

/// The validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub issuer: String,
    pub broker_id: String,
    pub signing_key_path: PathBuf,
    pub signing_kid: String,
    pub store_path: PathBuf,
    pub gateway_socket: PathBuf,
    pub broker_socket: PathBuf,
    pub authority_uid: u32,
    pub gateway_uid: u32,
    pub broker_uid: u32,
    pub workload_uids: Vec<u32>,
    pub manifest_path: Option<PathBuf>,
    pub grant_ttl_secs: u64,
    pub skew_secs: u64,
    pub approve_reply_timeout_ms: u64,
    pub broker_call_timeout_ms: u64,
    pub operations: Operations,
    pub workloads: Workloads,
    pub config_digest: [u8; 32],
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let raw: RawConfig = strict(&read_file(path)?, "config")?;
        if raw.format != "nodkey.authority-config.v1" {
            return Err("config: format".into());
        }
        if !is_id(&raw.issuer, 128) {
            return Err("config: issuer must be an ID of 1-128 bytes".into());
        }
        if !is_id(&raw.broker_id, 128) {
            return Err("config: broker_id must be an ID of 1-128 bytes".into());
        }
        if raw.signing_kid.len() != 32
            || !raw
                .signing_kid
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("config: signing_kid must be 32 lowercase hex".into());
        }
        if !(1..=nodkey_grant::MAX_TTL).contains(&raw.grant_ttl_secs) {
            return Err("config: grant_ttl_secs must be 1..=30".into());
        }
        if raw.skew_secs > nodkey_grant::MAX_SKEW {
            return Err("config: skew_secs must be 0..=5".into());
        }
        if !(100..=30_000).contains(&raw.approve_reply_timeout_ms)
            || !(100..=30_000).contains(&raw.broker_call_timeout_ms)
        {
            return Err("config: timeouts must be 100..=30000 ms".into());
        }
        for p in [
            &raw.signing_key_path,
            &raw.store_path,
            &raw.gateway_socket,
            &raw.broker_socket,
            &raw.operations_path,
            &raw.workloads_path,
        ] {
            if !p.is_absolute() {
                return Err(format!("config: path {} must be absolute", p.display()));
            }
        }
        let ops_bytes = read_file(&raw.operations_path)?;
        let ops_text = std::str::from_utf8(&ops_bytes).map_err(|_| "operations: utf-8")?;
        let operations = Operations::load(ops_text)
            .map_err(|e| format!("operations: {} ({})", e.as_str(), e.detail()))?;
        let wl_bytes = read_file(&raw.workloads_path)?;
        let workloads = Workloads::load(&wl_bytes, &operations)?;
        Ok(Config {
            issuer: raw.issuer,
            broker_id: raw.broker_id,
            signing_key_path: raw.signing_key_path,
            signing_kid: raw.signing_kid,
            store_path: raw.store_path,
            gateway_socket: raw.gateway_socket,
            broker_socket: raw.broker_socket,
            authority_uid: raw.authority_uid,
            gateway_uid: raw.gateway_uid,
            broker_uid: raw.broker_uid,
            workload_uids: raw.workload_uids,
            manifest_path: raw.manifest_path,
            grant_ttl_secs: raw.grant_ttl_secs,
            skew_secs: raw.skew_secs,
            approve_reply_timeout_ms: raw.approve_reply_timeout_ms,
            broker_call_timeout_ms: raw.broker_call_timeout_ms,
            operations,
            workloads,
            config_digest: config_digest(&ops_bytes, &wl_bytes),
        })
    }
}

// ---- Start-up refusals (§1.2) ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    format: String,
    workload_mounts: Vec<RawMount>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMount {
    wid: String,
    host_paths: Vec<PathBuf>,
}

/// Lexical normalization of an absolute path (`.` removed, `..` popped). No symlink resolution:
/// the manifest describes mounts, not filesystem state.
fn normalize(p: &Path) -> Option<PathBuf> {
    if !p.is_absolute() {
        return None;
    }
    let mut out = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
            Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// The §1.2 refusals. `own_uid` is the effective uid of this process.
pub fn startup_checks(
    cfg: &Config,
    own_uid: u32,
    mounts_verified_externally: bool,
) -> Result<(), String> {
    if own_uid != cfg.authority_uid {
        return Err(format!(
            "running as uid {own_uid}, configured authority_uid {}",
            cfg.authority_uid
        ));
    }
    let roles = [
        ("authority", cfg.authority_uid),
        ("gateway", cfg.gateway_uid),
        ("broker", cfg.broker_uid),
    ];
    for (i, (n1, u1)) in roles.iter().enumerate() {
        for (n2, u2) in &roles[i + 1..] {
            if u1 == u2 {
                return Err(format!("roles {n1} and {n2} share uid {u1}"));
            }
        }
        if cfg.workload_uids.contains(u1) {
            return Err(format!("{n1} uid {u1} equals a workload uid"));
        }
    }
    let gw_dir = cfg
        .gateway_socket
        .parent()
        .and_then(normalize)
        .ok_or("gateway socket has no directory")?;
    let br_dir = cfg
        .broker_socket
        .parent()
        .and_then(normalize)
        .ok_or("broker socket has no directory")?;
    if overlaps(&gw_dir, &br_dir) {
        return Err("socket directories of channels I and A are shared or nested".into());
    }
    match &cfg.manifest_path {
        Some(p) if p.exists() => {
            let m: RawManifest = strict(&read_file(p)?, "manifest")?;
            if m.format != "nodkey.deployment-manifest.v1" {
                return Err("manifest: format".into());
            }
            for mount in &m.workload_mounts {
                for hp in &mount.host_paths {
                    let hp = normalize(hp).ok_or("manifest: host paths must be absolute")?;
                    for ctl in [&gw_dir, &br_dir] {
                        if overlaps(&hp, ctl) {
                            return Err(format!(
                                "manifest: control directory {} is mounted into workload {}",
                                ctl.display(),
                                mount.wid
                            ));
                        }
                    }
                }
            }
            Ok(())
        }
        _ if mounts_verified_externally => Ok(()),
        _ => Err("deployment manifest unavailable; refusing to start without --mounts-verified-externally".into()),
    }
}
