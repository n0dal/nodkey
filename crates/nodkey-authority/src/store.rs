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
//! - Start-up: a final line without a newline is a torn write of an append that never
//!   returned; it is truncated (and logged). Any complete line with a bad checksum, unknown
//!   kind, duplicate `jti`, status for an unknown `jti`, or a transition out of a final status
//!   is corruption: the store refuses to open (fail closed, SI-15).
//! - After any failed write the store is poisoned: every later call fails until restart, because
//!   the file tail is then unknown.
//! - An exclusive `flock` on the log file prevents two authority processes from sharing it.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use nodkey_grant::{decode_transport, encode_transport};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::digest::{PendingId, hex, parse_hex_digest};
use crate::log;

/// Largest store file accepted at start-up (bounded memory; compaction is future work).
pub const MAX_STORE_BYTES: u64 = 1 << 30;

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
    poisoned: bool,
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
    if obj.len() != 10 {
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
    /// Opens (creating if absent, mode 0600) and replays the log.
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        let created = !path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| StoreError::Corrupt(format!("open: {e}")))?;
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
        if complete < data.len() {
            log::event(
                "store_torn_tail_truncated",
                json!({"bytes": data.len() - complete}),
            );
            file.set_len(complete as u64)
                .and_then(|_| file.sync_all())
                .map_err(|e| StoreError::Corrupt(format!("truncate: {e}")))?;
        }

        let mut index: HashMap<PendingId, Issuance> = HashMap::new();
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
                    index.insert(row.jti, row);
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
        Ok(Store {
            path: path.to_owned(),
            file,
            index,
            poisoned: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, jti: &PendingId) -> Option<&Issuance> {
        self.index.get(jti)
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
        let r = self
            .file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.sync_data());
        if let Err(e) = r {
            self.poisoned = true;
            log::alarm("store_write_failed", json!({"detail": e.to_string()}));
            return Err(StoreError::Io(e.to_string()));
        }
        Ok(())
    }

    /// Durably inserts a new `signed` row. Fails with `Exists` (nothing written) if `jti` exists.
    pub fn insert(&mut self, row: Issuance) -> Result<(), StoreError> {
        if self.index.contains_key(&row.jti) {
            return Err(StoreError::Exists);
        }
        if row.status != Status::Signed {
            return Err(StoreError::Io("insert requires status signed".into()));
        }
        let body = json!({
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
        self.append(&body)?;
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
