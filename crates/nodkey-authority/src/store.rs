// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! The authority's durable issuance store (effect-protocol-v2 §4.2 step 4).
//!
//! `issuance(jti = pending_id PRIMARY KEY, digest, ten, sub, wid, op, signed_at, grant, status)`
//!
//! Implementation: an append-only log file, one record per line, each line
//! `<sha256-hex of the JSON> <JSON>\n`, written with a single `write_all` and made durable with
//! `fdatasync` (`File::sync_data`) before the call returns. The index is rebuilt at start-up.
//!
//! - An `issue` record holds the complete row **including the signed grant bytes**, so the row
//!   and the grant become durable together: there is no "reserved but unsigned" state. A grant
//!   that was signed but whose record did not become durable never left the process (delivery
//!   happens only after `insert` returns), so at most one grant per `jti` is ever observable.
//! - A `status` record moves a row from `signed` to a final status.
//! - Start-up: a final line without a newline whose checksum verifies is kept (newline
//!   appended); any other newline-less tail is a torn write of an append that never returned
//!   and is truncated (alarm). Any complete line with a bad checksum, unknown
//!   kind, duplicate `jti`, status for an unknown `jti`, or a transition out of a final status
//!   is corruption: the store refuses to open (fail closed, SI-15).
//! - After any failed write the store is poisoned: every later call fails until restart, because
//!   the file tail is then unknown.
//! - An exclusive `flock` on the log file prevents two authority processes from sharing it.
//! - **Mandates** (agent-interface-v1 §4.2 step 3, §4.4; ADR-0006 Amendment 3): an `issue` record may
//!   carry one extra member. `mandate` (the template's issuance row) holds the mandate terms,
//!   window and `cfg`; `mandated` (a `cfm = 2` row) holds the `mid`, the refund amount it
//!   consumes and the params key for C6. The refund counters of a mandate are the count and sum of
//!   its `mandated` refund rows, so they become durable in the **same** fsync'd line as the grant
//!   and never release. A `mandate_revoke` record marks a mandate revoked (idempotent).
//! - **Activation (MD-7, fail closed).** A `mandate_activation{mid, active}` record stores the
//!   broker's activation outcome for a mandate, at most once. A mandate without a stored `true`
//!   outcome is not active for mandated issuance.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nodkey_grant::{decode_transport, encode_transport};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::digest::{PendingId, hex, parse_hex_digest};
use crate::log;

/// Largest store file accepted at start-up (bounded memory; compaction is future work).
pub const MAX_STORE_BYTES: u64 = 1 << 30;
/// Appends are refused (with an alarm) beyond this size, leaving headroom below the open limit.
pub const INSERT_LIMIT_BYTES: u64 = 3 << 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Signed,
    Accepted,
    Rejected,
    Expired,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Signed => "signed",
            Status::Accepted => "accepted",
            Status::Rejected => "rejected",
            Status::Expired => "expired",
        }
    }
    fn from_final(s: &str) -> Option<Status> {
        match s {
            "accepted" => Some(Status::Accepted),
            "rejected" => Some(Status::Rejected),
            "expired" => Some(Status::Expired),
            _ => None,
        }
    }
    pub fn is_final(self) -> bool {
        self != Status::Signed
    }
}

/// One issuance row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuance {
    pub jti: PendingId,
    pub digest: [u8; 32],
    pub ten: String,
    pub sub: String,
    pub wid: String,
    pub op: String,
    pub signed_at: u64,
    /// The grant's `exp` (delivery deadline).
    pub exp: u64,
    pub grant: Vec<u8>,
    pub status: Status,
}

/// The terms of a mandate, recorded in the template's issuance row (AI §4.2 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandateTerms {
    pub customer_sub: String,
    pub customer_email: String,
    pub currency: String,
    pub refund_max_count: u64,
    pub refund_max_per_call_minor: u64,
    pub refund_max_total_minor: u64,
    pub message_max_count: u64,
    pub nbf: u64,
    pub exp: u64,
    /// `config.digest` at signing; the mandate is active only while it is current.
    pub cfg: [u8; 32],
}

/// What a `cfm = 2` row consumed (AI §4.4 step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandatedUse {
    pub mid: PendingId,
    /// `Some(amount)` for refunds (counted); `None` for messages (no authority counter, R-A9).
    pub refund_minor: Option<u64>,
    /// SHA-256 over op and params (C6: identical repeats).
    pub pkey: [u8; 32],
}

/// The optional extra member of an `issue` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extra {
    Mandate(MandateTerms),
    Mandated(MandatedUse),
}

fn extra_json(e: &Extra) -> (&'static str, Value) {
    match e {
        Extra::Mandate(m) => (
            "mandate",
            json!({"customer_sub": m.customer_sub, "customer_email": m.customer_email,
                   "currency": m.currency, "refund_max_count": m.refund_max_count,
                   "refund_max_per_call_minor": m.refund_max_per_call_minor,
                   "refund_max_total_minor": m.refund_max_total_minor,
                   "message_max_count": m.message_max_count, "nbf": m.nbf, "exp": m.exp,
                   "cfg": hex(&m.cfg)}),
        ),
        Extra::Mandated(u) => (
            "mandated",
            json!({"mid": u.mid.to_text(), "refund_minor": u.refund_minor, "pkey": hex(&u.pkey)}),
        ),
    }
}

fn parse_extra(v: &Value) -> Result<Option<Extra>, String> {
    let exact = |o: &Value, n: usize| o.as_object().is_some_and(|m| m.len() == n);
    match (v.get("mandate"), v.get("mandated")) {
        (None, None) => Ok(None),
        (Some(m), None) => {
            if !exact(m, 10) {
                return Err("mandate member set".into());
            }
            Ok(Some(Extra::Mandate(MandateTerms {
                customer_sub: s(m, "customer_sub")?,
                customer_email: s(m, "customer_email")?,
                currency: s(m, "currency")?,
                refund_max_count: u(m, "refund_max_count")?,
                refund_max_per_call_minor: u(m, "refund_max_per_call_minor")?,
                refund_max_total_minor: u(m, "refund_max_total_minor")?,
                message_max_count: u(m, "message_max_count")?,
                nbf: u(m, "nbf")?,
                exp: u(m, "exp")?,
                cfg: parse_hex_digest(&s(m, "cfg")?).map_err(|e| e.0.to_string())?,
            })))
        }
        (None, Some(m)) => {
            if !exact(m, 3) {
                return Err("mandated member set".into());
            }
            let refund_minor = match m.get("refund_minor") {
                Some(Value::Null) => None,
                Some(x) => Some(x.as_u64().ok_or("refund_minor")?),
                None => return Err("refund_minor".into()),
            };
            Ok(Some(Extra::Mandated(MandatedUse {
                mid: PendingId::parse(&s(m, "mid")?).map_err(|e| e.0.to_string())?,
                refund_minor,
                pkey: parse_hex_digest(&s(m, "pkey")?).map_err(|e| e.0.to_string())?,
            })))
        }
        (Some(_), Some(_)) => Err("both mandate and mandated".into()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// A row for this `jti` already exists (nothing written).
    Exists,
    /// No row for this `jti`.
    Unknown,
    /// The row is already final (nothing written).
    AlreadyFinal,
    /// I/O failure or poisoned store: the caller must fail closed.
    Io(String),
    /// The file is corrupt or locked: refuse to start.
    Corrupt(String),
}

#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    file: File,
    index: HashMap<PendingId, Issuance>,
    extras: HashMap<PendingId, Extra>,
    /// Refund count and total per mandate (derived from `mandated` rows; never decrease).
    counters: HashMap<PendingId, (u64, u64)>,
    /// `(mid, pkey)` of every `mandated` row (C6).
    uses: std::collections::HashSet<(PendingId, [u8; 32])>,
    revoked: std::collections::HashSet<PendingId>,
    /// Broker-confirmed activation outcome per mandate (MD-7); absent = unconfirmed.
    activation: HashMap<PendingId, bool>,
    poisoned: bool,
    /// Current file size in bytes.
    size: u64,
}

fn checksum(json: &str) -> String {
    hex(&Sha256::digest(json.as_bytes()))
}

fn s(v: &Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("member {k}"))
}

fn u(v: &Value, k: &str) -> Result<u64, String> {
    v.get(k)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("member {k}"))
}

fn parse_issue(v: &Value) -> Result<Issuance, String> {
    let obj = v.as_object().ok_or("not an object")?;
    let extra =
        usize::from(obj.contains_key("mandate")) + usize::from(obj.contains_key("mandated"));
    if obj.len() != 10 + extra {
        return Err("member set".into());
    }
    Ok(Issuance {
        jti: PendingId::parse(&s(v, "jti")?).map_err(|e| e.0.to_string())?,
        digest: parse_hex_digest(&s(v, "digest")?).map_err(|e| e.0.to_string())?,
        ten: s(v, "ten")?,
        sub: s(v, "sub")?,
        wid: s(v, "wid")?,
        op: s(v, "op")?,
        signed_at: u(v, "signed_at")?,
        exp: u(v, "exp")?,
        grant: decode_transport(Some(&s(v, "grant")?)).map_err(|e| e.as_str().to_string())?,
        status: Status::Signed,
    })
}

impl Store {
    /// Opens (creating if absent, mode 0600) and replays the log. `owner_uid` is the authority's
    /// uid: an existing store must be a regular file (not a symlink) owned by it with no group or
    /// other permission bits (AU-R-02), and must not change between the check and the open.
    pub fn open(path: &Path, owner_uid: u32) -> Result<Store, StoreError> {
        let before = match std::fs::symlink_metadata(path) {
            Ok(m) => {
                if !m.file_type().is_file() {
                    return Err(StoreError::Corrupt("store: not a regular file".into()));
                }
                Some(m)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(StoreError::Corrupt(format!("store: {e}"))),
        };
        let created = before.is_none();
        let mut opts = OpenOptions::new();
        opts.read(true).append(true).mode(0o600);
        if created {
            // O_EXCL: also refuses a symlink planted after the check.
            opts.create_new(true);
        }
        let mut file = opts
            .open(path)
            .map_err(|e| StoreError::Corrupt(format!("open: {e}")))?;
        let meta = file
            .metadata()
            .map_err(|e| StoreError::Corrupt(format!("store: {e}")))?;
        if let Some(b) = &before
            && (b.dev() != meta.dev() || b.ino() != meta.ino())
        {
            return Err(StoreError::Corrupt(
                "store: file changed while opening".into(),
            ));
        }
        if meta.uid() != owner_uid {
            return Err(StoreError::Corrupt(
                "store: not owned by the authority uid".into(),
            ));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(StoreError::Corrupt(format!(
                "store: mode {:o} grants group/other access; require 0600",
                meta.mode() & 0o777
            )));
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(_) => {
                return Err(StoreError::Corrupt(
                    "store is locked by another process".into(),
                ));
            }
        }
        if created {
            file.sync_all()
                .map_err(|e| StoreError::Corrupt(format!("fsync: {e}")))?;
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                File::open(dir)
                    .and_then(|d| d.sync_all())
                    .map_err(|e| StoreError::Corrupt(format!("fsync dir: {e}")))?;
            }
        }
        let len = file
            .metadata()
            .map_err(|e| StoreError::Corrupt(e.to_string()))?
            .len();
        if len > MAX_STORE_BYTES {
            return Err(StoreError::Corrupt("store exceeds size limit".into()));
        }
        let mut data = Vec::with_capacity(len as usize);
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.read_to_end(&mut data))
            .map_err(|e| StoreError::Corrupt(format!("read: {e}")))?;

        let complete = match data.iter().rposition(|&b| b == b'\n') {
            Some(p) => p + 1,
            None => 0,
        };
        let mut complete = complete;
        if complete < data.len() {
            // AU-R-08: a tail that is a complete, checksummed record missing only its newline is
            // kept (newline appended and fsync'd); only a genuinely partial tail is truncated.
            let tail_ok = std::str::from_utf8(&data[complete..])
                .ok()
                .and_then(|t| t.split_once(' '))
                .is_some_and(|(sum, body)| {
                    checksum(body) == sum && serde_json::from_str::<Value>(body).is_ok()
                });
            if tail_ok {
                log::alarm(
                    "store_tail_missing_newline_repaired",
                    json!({"bytes": data.len() - complete}),
                );
                file.write_all(b"\n")
                    .and_then(|_| file.sync_all())
                    .map_err(|e| StoreError::Corrupt(format!("repair: {e}")))?;
                data.push(b'\n');
                complete = data.len();
            } else {
                log::alarm(
                    "store_torn_tail_truncated",
                    json!({"bytes": data.len() - complete}),
                );
                file.set_len(complete as u64)
                    .and_then(|_| file.sync_all())
                    .map_err(|e| StoreError::Corrupt(format!("truncate: {e}")))?;
            }
        }

        let mut index: HashMap<PendingId, Issuance> = HashMap::new();
        let mut extras: HashMap<PendingId, Extra> = HashMap::new();
        let mut revoked = std::collections::HashSet::new();
        let mut activation: HashMap<PendingId, bool> = HashMap::new();
        // `data[..complete]` is empty or ends with '\n': drop the empty slice after the final
        // newline. Any other empty line is corrupt (it fails the format check below).
        let mut lines: Vec<&[u8]> = data[..complete].split(|&b| b == b'\n').collect();
        lines.pop();
        for (n, line) in lines.into_iter().enumerate() {
            let corrupt = |m: &str| StoreError::Corrupt(format!("line {}: {m}", n + 1));
            let text = std::str::from_utf8(line).map_err(|_| corrupt("utf-8"))?;
            let (sum, body) = text.split_once(' ').ok_or_else(|| corrupt("format"))?;
            if checksum(body) != sum {
                return Err(corrupt("checksum"));
            }
            let v: Value = serde_json::from_str(body).map_err(|_| corrupt("json"))?;
            match v.get("k").and_then(Value::as_str) {
                Some("issue") => {
                    let row = parse_issue(&v).map_err(|e| corrupt(&e))?;
                    if index.contains_key(&row.jti) {
                        return Err(corrupt("duplicate jti"));
                    }
                    if let Some(x) = parse_extra(&v).map_err(|e| corrupt(&e))? {
                        if let Extra::Mandated(u) = &x
                            && !matches!(extras.get(&u.mid), Some(Extra::Mandate(_)))
                        {
                            return Err(corrupt("mandated row for an unknown mandate"));
                        }
                        extras.insert(row.jti, x);
                    }
                    index.insert(row.jti, row);
                }
                Some("mandate_revoke") => {
                    if v.as_object().map(|o| o.len()) != Some(2) {
                        return Err(corrupt("member set"));
                    }
                    let mid = PendingId::parse(&s(&v, "mid").map_err(|e| corrupt(&e))?)
                        .map_err(|_| corrupt("mid"))?;
                    if !matches!(extras.get(&mid), Some(Extra::Mandate(_))) || !revoked.insert(mid)
                    {
                        return Err(corrupt("revocation of an unknown or revoked mandate"));
                    }
                }
                Some("mandate_activation") => {
                    if v.as_object().map(|o| o.len()) != Some(3) {
                        return Err(corrupt("member set"));
                    }
                    let mid = PendingId::parse(&s(&v, "mid").map_err(|e| corrupt(&e))?)
                        .map_err(|_| corrupt("mid"))?;
                    let active = v
                        .get("active")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| corrupt("active"))?;
                    if !matches!(extras.get(&mid), Some(Extra::Mandate(_)))
                        || activation.insert(mid, active).is_some()
                    {
                        return Err(corrupt("activation of an unknown or settled mandate"));
                    }
                }
                Some("status") => {
                    if v.as_object().map(|o| o.len()) != Some(3) {
                        return Err(corrupt("member set"));
                    }
                    let jti = PendingId::parse(&s(&v, "jti").map_err(|e| corrupt(&e))?)
                        .map_err(|_| corrupt("jti"))?;
                    let st = Status::from_final(&s(&v, "status").map_err(|e| corrupt(&e))?)
                        .ok_or_else(|| corrupt("status"))?;
                    let row = index
                        .get_mut(&jti)
                        .ok_or_else(|| corrupt("status for unknown jti"))?;
                    if row.status.is_final() {
                        return Err(corrupt("transition out of a final status"));
                    }
                    row.status = st;
                }
                _ => return Err(corrupt("kind")),
            }
        }
        let mut counters: HashMap<PendingId, (u64, u64)> = HashMap::new();
        let mut uses = std::collections::HashSet::new();
        for x in extras.values() {
            if let Extra::Mandated(u) = x {
                uses.insert((u.mid, u.pkey));
                if let Some(a) = u.refund_minor {
                    let c = counters.entry(u.mid).or_default();
                    *c = (c.0 + 1, c.1.saturating_add(a));
                }
            }
        }
        Ok(Store {
            path: path.to_owned(),
            file,
            index,
            extras,
            counters,
            uses,
            revoked,
            activation,
            poisoned: false,
            size: complete as u64,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, jti: &PendingId) -> Option<&Issuance> {
        self.index.get(jti)
    }

    /// Latest `signed_at` in the store: the persisted clock high-water mark (AU-R-04).
    pub fn max_signed_at(&self) -> u64 {
        self.index.values().map(|r| r.signed_at).max().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Rows still in `signed` (delivery outcome unknown), for the recovery loop.
    pub fn unfinished(&self) -> Vec<Issuance> {
        let mut v: Vec<Issuance> = self
            .index
            .values()
            .filter(|r| r.status == Status::Signed)
            .cloned()
            .collect();
        v.sort_by_key(|r| r.jti);
        v
    }

    fn append(&mut self, body: &Value) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::Io(
                "store poisoned by an earlier failure".into(),
            ));
        }
        let body = body.to_string();
        let line = format!("{} {}\n", checksum(&body), body);
        // AU-R-07: stop accepting writes well below the open limit, so the next start still opens.
        if self.size + line.len() as u64 > INSERT_LIMIT_BYTES {
            log::alarm("store_full", json!({"size": self.size}));
            return Err(StoreError::Io(
                "store size limit reached; compaction required".into(),
            ));
        }
        let r = self
            .file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.sync_data());
        if let Err(e) = r {
            self.poisoned = true;
            log::alarm("store_write_failed", json!({"detail": e.to_string()}));
            return Err(StoreError::Io(e.to_string()));
        }
        self.size += line.len() as u64;
        Ok(())
    }

    /// Durably inserts a new `signed` row. Fails with `Exists` (nothing written) if `jti` exists.
    pub fn insert(&mut self, row: Issuance) -> Result<(), StoreError> {
        self.insert_with(row, None)
    }

    /// The extra member of `jti`'s row, if any.
    pub fn extra(&self, jti: &PendingId) -> Option<&Extra> {
        self.extras.get(jti)
    }

    /// Every mandate row with its issuance row (for the active-mandate lookup).
    pub fn mandates(&self) -> impl Iterator<Item = (&Issuance, &MandateTerms)> {
        self.extras.iter().filter_map(|(jti, x)| match x {
            Extra::Mandate(m) => self.index.get(jti).map(|r| (r, m)),
            Extra::Mandated(_) => None,
        })
    }

    /// Refund count and total signed under `mid` (ADR-0006 Amendment 3; never released).
    pub fn refund_counters(&self, mid: &PendingId) -> (u64, u64) {
        self.counters.get(mid).copied().unwrap_or((0, 0))
    }

    /// C6: a `cfm = 2` row with this params key exists under `mid`.
    pub fn used(&self, mid: &PendingId, pkey: &[u8; 32]) -> bool {
        self.uses.contains(&(*mid, *pkey))
    }

    pub fn is_revoked(&self, mid: &PendingId) -> bool {
        self.revoked.contains(mid)
    }

    /// The broker-confirmed activation outcome of `mid` (MD-7): `None` while unconfirmed.
    pub fn activation(&self, mid: &PendingId) -> Option<bool> {
        self.activation.get(mid).copied()
    }

    /// Durably records the broker's activation outcome of `mid` (MD-7). Recorded once; repeating
    /// the same outcome is a no-op, a different outcome is refused (`AlreadyFinal`).
    pub fn set_activation(&mut self, mid: &PendingId, active: bool) -> Result<(), StoreError> {
        if !matches!(self.extras.get(mid), Some(Extra::Mandate(_))) {
            return Err(StoreError::Unknown);
        }
        match self.activation.get(mid) {
            Some(&a) if a == active => return Ok(()),
            Some(_) => return Err(StoreError::AlreadyFinal),
            None => {}
        }
        self.append(&json!({"k": "mandate_activation", "mid": mid.to_text(), "active": active}))?;
        self.activation.insert(*mid, active);
        Ok(())
    }

    /// Durably marks a mandate revoked. Idempotent; `Unknown` if `mid` is not a mandate.
    pub fn revoke_mandate(&mut self, mid: &PendingId) -> Result<(), StoreError> {
        if !matches!(self.extras.get(mid), Some(Extra::Mandate(_))) {
            return Err(StoreError::Unknown);
        }
        if self.revoked.contains(mid) {
            return Ok(());
        }
        self.append(&json!({"k": "mandate_revoke", "mid": mid.to_text()}))?;
        self.revoked.insert(*mid);
        Ok(())
    }

    /// [`Store::insert`] with an optional mandate extra, in the same durable line.
    pub fn insert_with(&mut self, row: Issuance, extra: Option<Extra>) -> Result<(), StoreError> {
        if self.index.contains_key(&row.jti) {
            return Err(StoreError::Exists);
        }
        if let Some(Extra::Mandated(u)) = &extra
            && !matches!(self.extras.get(&u.mid), Some(Extra::Mandate(_)))
        {
            return Err(StoreError::Io("mandated row for an unknown mandate".into()));
        }
        if row.status != Status::Signed {
            return Err(StoreError::Io("insert requires status signed".into()));
        }
        let mut body = json!({
            "k": "issue",
            "jti": row.jti.to_text(),
            "digest": hex(&row.digest),
            "ten": row.ten,
            "sub": row.sub,
            "wid": row.wid,
            "op": row.op,
            "signed_at": row.signed_at,
            "exp": row.exp,
            "grant": encode_transport(&row.grant),
        });
        if let (Some(x), Some(o)) = (&extra, body.as_object_mut()) {
            let (k, v) = extra_json(x);
            o.insert(k.into(), v);
        }
        self.append(&body)?;
        if let Some(x) = extra {
            if let Extra::Mandated(u) = &x {
                self.uses.insert((u.mid, u.pkey));
                if let Some(a) = u.refund_minor {
                    let c = self.counters.entry(u.mid).or_default();
                    *c = (c.0 + 1, c.1.saturating_add(a));
                }
            }
            self.extras.insert(row.jti, x);
        }
        self.index.insert(row.jti, row);
        Ok(())
    }

    /// Durably moves a `signed` row to a final status.
    pub fn set_status(&mut self, jti: &PendingId, status: Status) -> Result<(), StoreError> {
        let cur = self.index.get(jti).ok_or(StoreError::Unknown)?.status;
        if cur.is_final() {
            return Err(StoreError::AlreadyFinal);
        }
        if !status.is_final() {
            return Err(StoreError::Io("status must be final".into()));
        }
        self.append(&json!({"k": "status", "jti": jti.to_text(), "status": status.as_str()}))?;
        if let Some(r) = self.index.get_mut(jti) {
            r.status = status;
        }
        Ok(())
    }
}
