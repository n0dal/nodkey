//! Protocol v2 broker configuration (trusted, operator-supplied) and the start-up refusals of
//! effect protocol v2 §1.2, §2.1 and §2.4.
//!
//! A v2 configuration has `"format": "nodkey.broker.v2"`. It cannot describe a v1 socket, and the
//! v1 configuration format cannot describe a v2 socket, so one broker never serves both versions
//! (§2.1). Sharing one database between a v1 and a v2 broker is refused at start-up through the
//! `broker_claim` row (see `service::claim_database`).

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use nodkey_grant::{BrokerId, Limits, OpKind, Operations};
use serde::Deserialize;

use super::decls::{self, Executor};
use super::ids::is_id;
use crate::config::DbConfig;
use crate::strict_json;

pub const FORMAT: &str = "nodkey.broker.v2";
/// Maximum line length on every v2 channel (spec §1.2).
pub const MAX_LINE_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproverSource {
    /// Agents and single-principal apps: the approver must equal the enrolment.
    Enrolled { ten: String, sub: String },
    /// Multi-user apps: `approver.ten` must be a registered tenant; never destination ops.
    Named,
}

impl ApproverSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApproverSource::Enrolled { .. } => "enrolled",
            ApproverSource::Named => "named",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkloadReg {
    pub wid: String,
    pub display_name: String,
    pub socket_path: PathBuf,
    pub uid: u32,
    pub tenants: Vec<String>,
    pub approver_source: ApproverSource,
    pub allowed_ops: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct Channel {
    pub socket_path: PathBuf,
    pub uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectLimits {
    pub pending_per_wid: i64,
    pub pending_per_approver: i64,
    pub proposals_per_min: u32,
    pub proposal_burst: u32,
    pub status_per_min: u32,
    pub pending_lifetime_s: u64,
}

impl Default for EffectLimits {
    fn default() -> Self {
        EffectLimits {
            pending_per_wid: 32,
            pending_per_approver: 8,
            proposals_per_min: 10,
            proposal_burst: 10,
            status_per_min: 120,
            pending_lifetime_s: 600,
        }
    }
}

#[derive(Debug, Clone)]
pub struct V2Config {
    pub profile: String,
    pub broker_id: BrokerId,
    pub auth_origin: String,
    pub db: DbConfig,
    pub db_pool_size: usize,
    pub registry_path: PathBuf,
    pub ledger_currency: String,
    pub ledger_exponent: u64,
    pub grant_limits: Limits,
    pub limits: EffectLimits,
    pub gateway: Channel,
    pub authority: Channel,
    pub workloads: Vec<WorkloadReg>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawV2Config {
    pub format: String,
    pub profile: String,
    pub broker_id: String,
    pub auth_origin: String,
    pub db: DbConfig,
    #[serde(default = "default_pool")]
    pub db_pool_size: usize,
    pub registry_path: PathBuf,
    pub operations_path: PathBuf,
    /// The authority's copy of the workload registrations (`nodkey.workloads.v1`, see
    /// `crates/nodkey-authority/README.md`). It must describe exactly this configuration's
    /// workloads; `config.digest` is computed over its exact bytes.
    pub authority_workloads_path: PathBuf,
    pub ledger_currency: String,
    #[serde(default = "default_skew")]
    pub skew_s: u64,
    #[serde(default = "default_ttl")]
    pub max_ttl_s: u64,
    #[serde(default)]
    pub limits: RawLimits,
    pub gateway: RawChannel,
    pub authority: RawChannel,
    pub workloads: Vec<RawWorkload>,
}

fn default_pool() -> usize {
    8
}
fn default_skew() -> u64 {
    5
}
fn default_ttl() -> u64 {
    30
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLimits {
    pending_per_wid: i64,
    pending_per_approver: i64,
    proposals_per_min: u32,
    proposal_burst: u32,
    status_per_min: u32,
    pending_lifetime_s: u64,
}

impl Default for RawLimits {
    fn default() -> Self {
        let d = EffectLimits::default();
        RawLimits {
            pending_per_wid: d.pending_per_wid,
            pending_per_approver: d.pending_per_approver,
            proposals_per_min: d.proposals_per_min,
            proposal_burst: d.proposal_burst,
            status_per_min: d.status_per_min,
            pending_lifetime_s: d.pending_lifetime_s,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawChannel {
    socket_path: PathBuf,
    uid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawApprover {
    kind: String,
    #[serde(default)]
    ten: Option<String>,
    #[serde(default)]
    sub: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawWorkload {
    wid: String,
    display_name: String,
    socket_path: PathBuf,
    uid: u32,
    tenants: Vec<String>,
    approver_source: RawApprover,
    allowed_ops: Vec<String>,
}

/// True if the document declares the v2 format (used by `main` to select the parser).
pub fn is_v2_document(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| {
            v.get("format")
                .and_then(|f| f.as_str())
                .map(|f| f == FORMAT)
        })
        .unwrap_or(false)
}

impl RawV2Config {
    /// Every socket this configuration would create.
    pub fn socket_paths(&self) -> Vec<PathBuf> {
        let mut v = vec![
            self.gateway.socket_path.clone(),
            self.authority.socket_path.clone(),
        ];
        v.extend(self.workloads.iter().map(|w| w.socket_path.clone()));
        v
    }

    pub fn parse(bytes: &[u8]) -> Result<RawV2Config, String> {
        strict_json::check_strict(bytes).map_err(|e| format!("config: {e}"))?;
        let raw: RawV2Config = serde_json::from_slice(bytes).map_err(|e| format!("config: {e}"))?;
        if raw.format != FORMAT {
            return Err("config: format".into());
        }
        Ok(raw)
    }
}

fn valid_origin(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && host
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-');
    let port_ok = port.is_none_or(|p| {
        !p.is_empty()
            && p.len() <= 5
            && !p.starts_with('0')
            && p.bytes().all(|c| c.is_ascii_digit())
            && p.parse::<u16>().is_ok()
    });
    host_ok && port_ok
}

fn socket_dir(p: &Path) -> Result<PathBuf, String> {
    if !p.is_absolute() {
        return Err(format!("{} must be absolute", p.display()));
    }
    p.parent()
        .filter(|d| *d != Path::new("/"))
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("{} needs its own directory", p.display()))
}

impl V2Config {
    /// Validates the raw configuration against the loaded operation declarations.
    ///
    /// `broker_uid` is this process's uid. `mounts_verified_externally` is the operator flag of
    /// §1.2: this broker has no deployment-manifest reader, so the manifest is always
    /// "unavailable" and start-up requires the flag.
    pub fn from_raw(
        raw: RawV2Config,
        ops: &Operations,
        declared: &[String],
        broker_uid: u32,
        mounts_verified_externally: bool,
    ) -> Result<V2Config, String> {
        let e = |m: String| Err(format!("config: {m}"));
        if !mounts_verified_externally {
            return e("deployment manifest unavailable and --mounts-verified-externally not set (refusing to start)".into());
        }
        if raw.profile != "phase3" {
            return e(format!(
                "profile {:?} is not a v2 profile (only \"phase3\")",
                raw.profile
            ));
        }
        let Some(broker_id) = BrokerId::new(&raw.broker_id) else {
            return e("broker_id is not an ID of 1-128 bytes".into());
        };
        if !valid_origin(&raw.auth_origin) {
            return e(
                "auth_origin must be https://<lowercase host>[:port] with nothing else".into(),
            );
        }
        if !(1..=32).contains(&raw.db_pool_size) {
            return e("db_pool_size must be 1..=32".into());
        }
        let Some(ledger_exponent) = decls::iso4217_exponent(&raw.ledger_currency) else {
            return e("ledger_currency is not in the broker's ISO 4217 table".into());
        };
        let Some(grant_limits) = Limits::new(raw.skew_s, raw.max_ttl_s) else {
            return e("skew_s must be 0..=5 and max_ttl_s 1..=30".into());
        };
        let l = raw.limits;
        if !(60..=900).contains(&l.pending_lifetime_s) {
            return e("pending_lifetime_s must be 60..=900".into());
        }
        if !(1..=1024).contains(&l.pending_per_wid)
            || !(1..=l.pending_per_wid).contains(&l.pending_per_approver)
            || !(1..=600).contains(&l.proposals_per_min)
            || !(1..=600).contains(&l.proposal_burst)
            || !(1..=6000).contains(&l.status_per_min)
        {
            return e("limits out of range".into());
        }
        let limits = EffectLimits {
            pending_per_wid: l.pending_per_wid,
            pending_per_approver: l.pending_per_approver,
            proposals_per_min: l.proposals_per_min,
            proposal_burst: l.proposal_burst,
            status_per_min: l.status_per_min,
            pending_lifetime_s: l.pending_lifetime_s,
        };

        // §1.2 start-up refusals: distinct uids per role, distinct directories per socket.
        let mut uids: HashSet<u32> = HashSet::from([broker_uid]);
        let mut dirs: HashSet<PathBuf> = HashSet::new();
        let mut role = |name: &str, path: &Path, uid: u32| -> Result<(), String> {
            if uid == 0 {
                return Err(format!("config: {name} must not be uid 0"));
            }
            if !uids.insert(uid) {
                return Err(format!(
                    "config: {name} uid {uid} is shared with another role (refusing to start)"
                ));
            }
            let d = socket_dir(path).map_err(|m| format!("config: {name}: {m}"))?;
            if !dirs.insert(d.clone()) {
                return Err(format!(
                    "config: {name}: socket directory {} is shared between channels (refusing to start)",
                    d.display()
                ));
            }
            Ok(())
        };
        role("gateway", &raw.gateway.socket_path, raw.gateway.uid)?;
        role("authority", &raw.authority.socket_path, raw.authority.uid)?;

        if raw.workloads.is_empty() {
            return e("at least one workload required".into());
        }
        let mut wids = HashSet::new();
        let mut workloads = Vec::with_capacity(raw.workloads.len());
        for w in raw.workloads {
            if !is_id(&w.wid, 256) || !wids.insert(w.wid.clone()) {
                return e(format!("invalid or duplicate wid {:?}", w.wid));
            }
            role(&format!("workload {}", w.wid), &w.socket_path, w.uid)?;
            let dn_ok = !w.display_name.is_empty()
                && w.display_name.len() <= 64
                && w.display_name.bytes().all(|c| (0x20..=0x7e).contains(&c));
            if !dn_ok {
                return e(format!(
                    "{}: display_name must be 1-64 printable ASCII",
                    w.wid
                ));
            }
            let mut tenants = Vec::new();
            for t in &w.tenants {
                if !is_id(t, 128) || tenants.contains(t) {
                    return e(format!("{}: invalid or duplicate tenant", w.wid));
                }
                tenants.push(t.clone());
            }
            if tenants.is_empty() {
                return e(format!("{}: at least one tenant required", w.wid));
            }
            let approver_source = match (
                w.approver_source.kind.as_str(),
                w.approver_source.ten,
                w.approver_source.sub,
            ) {
                ("enrolled", Some(ten), Some(sub)) => {
                    if !is_id(&ten, 128) || !is_id(&sub, 256) || !tenants.contains(&ten) {
                        return e(format!(
                            "{}: enrolled principal invalid or tenant not registered",
                            w.wid
                        ));
                    }
                    ApproverSource::Enrolled { ten, sub }
                }
                ("named", None, None) => ApproverSource::Named,
                _ => {
                    return e(format!(
                        "{}: approver_source must be {{kind:enrolled,ten,sub}} or {{kind:named}}",
                        w.wid
                    ));
                }
            };
            let mut allowed = BTreeSet::new();
            for op in &w.allowed_ops {
                let Some(d) = ops.get(op).filter(|_| declared.contains(op)) else {
                    return e(format!("{}: op {op} is not declared", w.wid));
                };
                if decls::executor(op) == Some(Executor::NotImplemented) {
                    return e(format!("{}: op {op} is not implemented in Phase 3", w.wid));
                }
                if approver_source == ApproverSource::Named
                    && d.kind == OpKind::Write
                    && decls::has_destination(d)
                {
                    return e(format!(
                        "{}: named workloads may not use destination operations ({op})",
                        w.wid
                    ));
                }
                if !allowed.insert(op.clone()) {
                    return e(format!("{}: duplicate op {op}", w.wid));
                }
            }
            workloads.push(WorkloadReg {
                wid: w.wid,
                display_name: w.display_name,
                socket_path: w.socket_path,
                uid: w.uid,
                tenants,
                approver_source,
                allowed_ops: allowed,
            });
        }
        Ok(V2Config {
            profile: raw.profile,
            broker_id,
            auth_origin: raw.auth_origin,
            db: raw.db,
            db_pool_size: raw.db_pool_size,
            registry_path: raw.registry_path,
            ledger_currency: raw.ledger_currency,
            ledger_exponent,
            grant_limits,
            limits,
            gateway: Channel {
                socket_path: raw.gateway.socket_path,
                uid: raw.gateway.uid,
            },
            authority: Channel {
                socket_path: raw.authority.socket_path,
                uid: raw.authority.uid,
            },
            workloads,
        })
    }

    pub fn workload(&self, wid: &str) -> Option<&WorkloadReg> {
        self.workloads.iter().find(|w| w.wid == wid)
    }
}

/// Label of `config.digest` (authority wire format, spec gap AU-2).
pub const CONFIG_DIGEST_LABEL: &[u8] = b"nodkey.authority-config-digest.v1";

/// `SHA-256(label || 0x00 || u64be(len(ops)) || ops || u64be(len(wl)) || wl)` over the exact
/// operations and authority-workloads file bytes (the authority's definition, AU-2).
pub fn config_digest(ops_bytes: &[u8], workloads_bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(CONFIG_DIGEST_LABEL);
    h.update([0u8]);
    h.update((ops_bytes.len() as u64).to_be_bytes());
    h.update(ops_bytes);
    h.update((workloads_bytes.len() as u64).to_be_bytes());
    h.update(workloads_bytes);
    h.finalize().into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthWorkloads {
    format: String,
    workloads: Vec<AuthWorkload>,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum AuthApprover {
    Enrolled { ten: String, sub: String },
    Named,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthWorkload {
    wid: String,
    tenants: Vec<String>,
    approver_source: AuthApprover,
    write_ops: Vec<String>,
    read_ops: Vec<String>,
}

/// Refuses to start unless the authority's registration file describes exactly this broker's
/// workloads (same wids, tenant sets, approver sources, and write/read operation sets).
pub fn check_authority_workloads(
    bytes: &[u8],
    cfg: &V2Config,
    ops: &Operations,
) -> Result<(), String> {
    let e = |m: String| Err(format!("authority workloads: {m} (refusing to start)"));
    strict_json::check_strict(bytes).map_err(|x| format!("authority workloads: {x}"))?;
    let doc: AuthWorkloads =
        serde_json::from_slice(bytes).map_err(|x| format!("authority workloads: {x}"))?;
    if doc.format != "nodkey.workloads.v1" {
        return e("format".into());
    }
    if doc.workloads.len() != cfg.workloads.len() {
        return e("workload count differs".into());
    }
    let mut seen = HashSet::new();
    for a in &doc.workloads {
        if !seen.insert(a.wid.clone()) {
            return e(format!("duplicate wid {}", a.wid));
        }
        let Some(w) = cfg.workload(&a.wid) else {
            return e(format!("wid {} not registered at the broker", a.wid));
        };
        let at: BTreeSet<&String> = a.tenants.iter().collect();
        let bt: BTreeSet<&String> = w.tenants.iter().collect();
        if at != bt || at.len() != a.tenants.len() {
            return e(format!("{}: tenants differ", a.wid));
        }
        let same_src = match (&a.approver_source, &w.approver_source) {
            (AuthApprover::Named, ApproverSource::Named) => true,
            (AuthApprover::Enrolled { ten, sub }, ApproverSource::Enrolled { ten: t, sub: s }) => {
                ten == t && sub == s
            }
            _ => false,
        };
        if !same_src {
            return e(format!("{}: approver_source differs", a.wid));
        }
        let mut all = BTreeSet::new();
        for (list, kind) in [(&a.write_ops, OpKind::Write), (&a.read_ops, OpKind::Read)] {
            for op in list {
                if ops.get(op).map(|d| d.kind) != Some(kind) || !all.insert(op.clone()) {
                    return e(format!("{}: op {op} kind or duplicate", a.wid));
                }
            }
        }
        if all != w.allowed_ops {
            return e(format!("{}: operation sets differ", a.wid));
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::v2::decls;

    pub fn sample() -> String {
        r#"{"format":"nodkey.broker.v2","profile":"phase3","broker_id":"nodkey.broker.test",
 "auth_origin":"https://auth.nodkey.test","ledger_currency":"EUR",
 "db":{"host":"db","port":5432,"dbname":"ledger","user":"nodkey_broker","password_file":"/run/secrets/p"},
 "registry_path":"/etc/nodkey/keys.json","operations_path":"/etc/nodkey/ops.json",
 "authority_workloads_path":"/etc/nodkey/workloads.json",
 "gateway":{"socket_path":"/run/nodkey/gw-broker/broker.sock","uid":20001},
 "authority":{"socket_path":"/run/nodkey/au-broker/broker.sock","uid":20002},
 "workloads":[
  {"wid":"spiffe://nodkey.test/workload/agent","display_name":"Budget agent","socket_path":"/run/nodkey/wl/agent/broker.sock","uid":10001,
   "tenants":["acme"],"approver_source":{"kind":"enrolled","ten":"acme","sub":"user:alice"},"allowed_ops":["ledger.transfer","ledger.get_balance"]},
  {"wid":"spiffe://nodkey.test/workload/shop","display_name":"Shop","socket_path":"/run/nodkey/wl/shop/broker.sock","uid":10003,
   "tenants":["acme","globex"],"approver_source":{"kind":"named"},"allowed_ops":["ledger.get_balance"]}]}"#
            .to_string()
    }

    pub fn build(s: &str, flag: bool) -> Result<V2Config, String> {
        let (ops, names) = decls::load(decls::tests::OPS_JSON).unwrap();
        V2Config::from_raw(RawV2Config::parse(s.as_bytes())?, &ops, &names, 10002, flag)
    }

    pub const AUTH_WL: &str = r#"{"format":"nodkey.workloads.v1","workloads":[
 {"wid":"spiffe://nodkey.test/workload/agent","tenants":["acme"],"approver_source":{"enrolled":{"ten":"acme","sub":"user:alice"}},
  "write_ops":["ledger.transfer"],"read_ops":["ledger.get_balance"]},
 {"wid":"spiffe://nodkey.test/workload/shop","tenants":["globex","acme"],"approver_source":"named",
  "write_ops":[],"read_ops":["ledger.get_balance"]}]}"#;

    #[test]
    fn authority_workloads_must_match() {
        let c = build(&sample(), true).unwrap();
        let (ops, _) = decls::load(decls::tests::OPS_JSON).unwrap();
        check_authority_workloads(AUTH_WL.as_bytes(), &c, &ops).unwrap();
        for (from, to) in [
            (r#""tenants":["globex","acme"]"#, r#""tenants":["acme"]"#),
            (r#""sub":"user:alice""#, r#""sub":"user:bob""#),
            (
                r#""approver_source":"named""#,
                r#""approver_source":{"enrolled":{"ten":"acme","sub":"x"}}"#,
            ),
            (r#""write_ops":["ledger.transfer"]"#, r#""write_ops":[]"#),
            (
                r#""read_ops":["ledger.get_balance"]},"#,
                r#""read_ops":["ledger.get_balance","payments.get_order"]},"#,
            ),
            (
                r#""write_ops":["ledger.transfer"],"read_ops":["ledger.get_balance"]"#,
                r#""write_ops":["ledger.get_balance"],"read_ops":["ledger.transfer"]"#,
            ),
            (r#""format":"nodkey.workloads.v1""#, r#""format":"x""#),
            (
                r#""wid":"spiffe://nodkey.test/workload/shop""#,
                r#""wid":"spiffe://nodkey.test/workload/other""#,
            ),
        ] {
            let bad = AUTH_WL.replacen(from, to, 1);
            assert_ne!(bad, AUTH_WL);
            assert!(
                check_authority_workloads(bad.as_bytes(), &c, &ops).is_err(),
                "{to}"
            );
        }
    }

    #[test]
    fn config_digest_is_length_prefixed() {
        assert_ne!(config_digest(b"ab", b"c"), config_digest(b"a", b"bc"));
    }

    #[test]
    fn valid_config() {
        let c = build(&sample(), true).unwrap();
        assert_eq!(c.workloads.len(), 2);
        assert_eq!(c.ledger_exponent, 2);
        assert_eq!(c.limits, EffectLimits::default());
        assert!(is_v2_document(sample().as_bytes()));
        assert!(!is_v2_document(br#"{"max_request_bytes":1}"#));
    }

    /// T42 (broker side) and T32 (profile): start-up refusals.
    #[test]
    fn startup_refusals() {
        let s = sample();
        assert!(
            build(&s, false)
                .unwrap_err()
                .contains("mounts-verified-externally")
        );
        let bad = [
            // gateway uid = a workload uid
            s.replace(r#""uid":20001"#, r#""uid":10001"#),
            // authority uid = gateway uid
            s.replace(r#""uid":20002"#, r#""uid":20001"#),
            // a role shares the broker's own uid
            s.replace(r#""uid":10003"#, r#""uid":10002"#),
            // shared socket directory
            s.replace(
                "/run/nodkey/au-broker/broker.sock",
                "/run/nodkey/gw-broker/a.sock",
            ),
            s.replace(
                "/run/nodkey/wl/shop/broker.sock",
                "/run/nodkey/wl/agent/x.sock",
            ),
            // v1/demo1 profile on a v2 config
            s.replace(r#""profile":"phase3""#, r#""profile":"demo1""#),
            // named workload with a destination operation (§2.4)
            s.replace(
                r#""allowed_ops":["ledger.get_balance"]}"#,
                r#""allowed_ops":["ledger.transfer"]}"#,
            ),
            // unimplemented operation allowed
            s.replace(
                r#""allowed_ops":["ledger.get_balance"]}"#,
                r#""allowed_ops":["payments.get_order"]}"#,
            ),
            // enrolled tenant not registered
            s.replace(r#""ten":"acme","sub""#, r#""ten":"other","sub""#),
            s.replace("https://auth.nodkey.test", "https://auth.nodkey.test/"),
            s.replace("https://auth.nodkey.test", "http://auth.nodkey.test"),
            s.replace(r#""ledger_currency":"EUR""#, r#""ledger_currency":"XXX""#),
            s.replace(r#""uid":10001"#, r#""uid":0"#),
            s.replace(
                r#""broker_id":"nodkey.broker.test""#,
                r#""broker_id":"a b""#,
            ),
            s.replace(r#""profile":"phase3""#, r#""profile":"phase3","extra":1"#),
            s.replace(
                "/run/nodkey/gw-broker/broker.sock",
                "relative/broker.sock",
            ),
        ];
        for b in bad {
            assert!(build(&b, true).is_err(), "should refuse: {b}");
        }
    }
}
