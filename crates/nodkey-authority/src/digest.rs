// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Pending-effect record parsing and the normative digest (effect-protocol-v2 §3.2).
//!
//! `digest = SHA-256("nodkey.pending.v1" || 0x00 || dcbor(M))`. The authority computes it
//! itself from the record it fetches from the broker (§4.2 step 3); it never trusts the broker's
//! `digest` member alone.

use std::collections::BTreeMap;

use nodkey_grant::{ParamType, ParamValue, decode_transport, encode_transport};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Domain tag of the record format (§3.2).
pub const DIGEST_LABEL: &[u8] = b"nodkey.pending.v1";
/// Largest integer allowed anywhere in the record, 2^53 − 1.
pub const MAX_UINT: u64 = (1 << 53) - 1;

/// Why a record (or a field of it) was rejected. Static text, for the audit log only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordError(pub &'static str);

/// A 16-byte pending id, decoded canonically from its 22-character base64url text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PendingId(pub [u8; 16]);

impl PendingId {
    /// Canonical decode (grant-v1 §2 rules): alphabet, no padding, zero trailing bits, exactly
    /// 22 characters and 16 bytes. Non-canonical text is rejected, never normalized.
    pub fn parse(s: &str) -> Result<PendingId, RecordError> {
        if s.len() != 22 {
            return Err(RecordError("pending_id: length"));
        }
        let bytes = decode_transport(Some(s)).map_err(|_| RecordError("pending_id: encoding"))?;
        let arr: [u8; 16] = bytes
            .try_into()
            .map_err(|_| RecordError("pending_id: length"))?;
        Ok(PendingId(arr))
    }

    pub fn to_text(&self) -> String {
        encode_transport(&self.0)
    }
}

/// Exactly 64 lowercase hex characters → 32 bytes (§3.2 "Hex digest").
pub fn parse_hex_digest(s: &str) -> Result<[u8; 32], RecordError> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(RecordError("digest: length"));
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(RecordError("digest: not lowercase hex")),
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = nib(b[2 * i])? << 4 | nib(b[2 * i + 1])?;
    }
    Ok(out)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An ID: 1..=max bytes of 0x21..=0x7E.
pub fn is_id(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|c| (0x21..=0x7e).contains(&c))
}

/// Op name: `[a-z0-9_.]{1,64}`.
pub fn is_op_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'.')
}

/// Parameter name: `[a-z0-9_]{1,64}`.
pub fn is_param_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn type_name(t: ParamType) -> &'static str {
    match t {
        ParamType::Uint => "uint",
        ParamType::AccountId => "account_id",
        ParamType::Currency => "currency",
        ParamType::Text64 => "text64",
        ParamType::Text256 => "text256",
    }
}

/// A display value (key 11): uint or 0–64 bytes of 0x20–0x7E.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayValue {
    Uint(u64),
    Text(String),
}

/// A validated pending-effect record (the §3.2 fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRecord {
    pub pending_id: PendingId,
    pub broker_id: String,
    pub wid: String,
    pub ten: String,
    pub approver_sub: String,
    pub op: String,
    pub opv: u16,
    pub params: BTreeMap<String, ParamValue>,
    pub param_types: BTreeMap<String, ParamType>,
    pub created_at: u64,
    pub expires_at: u64,
    pub display: BTreeMap<String, DisplayValue>,
}

/// The member names of a record, exactly (unknown or missing members are rejected).
pub const RECORD_FIELDS: [&str; 12] = [
    "pending_id",
    "broker_id",
    "wid",
    "ten",
    "approver_sub",
    "op",
    "opv",
    "params",
    "param_types",
    "created_at",
    "expires_at",
    "display",
];

fn uint(v: &Value, what: &'static str) -> Result<u64, RecordError> {
    match v.as_u64() {
        Some(n) if n <= MAX_UINT && !v.is_f64() => Ok(n),
        _ => Err(RecordError(what)),
    }
}

fn text<'a>(v: &'a Value, what: &'static str) -> Result<&'a str, RecordError> {
    v.as_str().ok_or(RecordError(what))
}

fn obj<'a>(v: &'a Value, what: &'static str) -> Result<&'a Map<String, Value>, RecordError> {
    v.as_object().ok_or(RecordError(what))
}

impl PendingRecord {
    /// Parses a record from a JSON object whose member set is exactly `RECORD_FIELDS` plus
    /// `extra` (which the caller handles). Every §3.2 value rule is enforced; the CBOR type of
    /// each parameter comes from its declared type, never from the JSON value type.
    pub fn from_json(o: &Map<String, Value>, extra: &[&str]) -> Result<PendingRecord, RecordError> {
        for k in o.keys() {
            if !RECORD_FIELDS.contains(&k.as_str()) && !extra.contains(&k.as_str()) {
                return Err(RecordError("record: unknown member"));
            }
        }
        let get = |k: &'static str| o.get(k).ok_or(RecordError("record: missing member"));

        let pending_id = PendingId::parse(text(get("pending_id")?, "pending_id: type")?)?;
        let id = |k: &'static str, max: usize| -> Result<String, RecordError> {
            let s = text(get(k)?, "record: ID type")?;
            if is_id(s, max) {
                Ok(s.to_owned())
            } else {
                Err(RecordError("record: not an ID"))
            }
        };
        let broker_id = id("broker_id", 128)?;
        let wid = id("wid", 256)?;
        let ten = id("ten", 128)?;
        let approver_sub = id("approver_sub", 256)?;
        let op = text(get("op")?, "op: type")?;
        if !is_op_name(op) {
            return Err(RecordError("op: grammar"));
        }
        let opv = uint(get("opv")?, "opv: type")?;
        let opv = u16::try_from(opv)
            .ok()
            .filter(|v| *v >= 1)
            .ok_or(RecordError("opv: range"))?;
        let created_at = uint(get("created_at")?, "created_at: type")?;
        let expires_at = uint(get("expires_at")?, "expires_at: type")?;

        let types_json = obj(get("param_types")?, "param_types: type")?;
        let params_json = obj(get("params")?, "params: type")?;
        if types_json.len() != params_json.len()
            || types_json.keys().any(|k| !params_json.contains_key(k))
        {
            return Err(RecordError(
                "params: key set differs from param_types (every declared parameter is required)",
            ));
        }
        let mut param_types = BTreeMap::new();
        let mut params = BTreeMap::new();
        for (name, tv) in types_json {
            if !is_param_name(name) {
                return Err(RecordError("param name: grammar"));
            }
            let ty = ParamType::from_name(text(tv, "param_types: value type")?)
                .ok_or(RecordError("param_types: unknown type"))?;
            let jv = &params_json[name];
            let value = match ty {
                ParamType::Uint => {
                    ParamValue::Uint(uint(jv, "param: declared uint, value is not")?)
                }
                _ => ParamValue::Text(
                    text(jv, "param: declared text type, value is not a string")?.to_owned(),
                ),
            };
            if !ty.accepts_value(&value) {
                return Err(RecordError("param: value violates its type grammar"));
            }
            param_types.insert(name.clone(), ty);
            params.insert(name.clone(), value);
        }

        let mut display = BTreeMap::new();
        for (k, v) in obj(get("display")?, "display: type")? {
            if !(1..=64).contains(&k.len()) || !k.bytes().all(|c| (0x20..=0x7e).contains(&c)) {
                return Err(RecordError("display: key"));
            }
            let dv = if let Some(s) = v.as_str() {
                if s.len() > 64 || !s.bytes().all(|c| (0x20..=0x7e).contains(&c)) {
                    return Err(RecordError("display: text value"));
                }
                DisplayValue::Text(s.to_owned())
            } else {
                DisplayValue::Uint(uint(v, "display: value type")?)
            };
            display.insert(k.clone(), dv);
        }

        Ok(PendingRecord {
            pending_id,
            broker_id,
            wid,
            ten,
            approver_sub,
            op: op.to_owned(),
            opv,
            params,
            param_types,
            created_at,
            expires_at,
            display,
        })
    }

    /// `dcbor(M)` of §3.2.
    pub fn cbor(&self) -> Vec<u8> {
        let t = |s: &str| {
            let mut o = Vec::new();
            enc_text(s, &mut o);
            o
        };
        let u = |n: u64| {
            let mut o = Vec::new();
            head(0, n, &mut o);
            o
        };
        let params = self
            .params
            .iter()
            .map(|(k, v)| {
                let val = match v {
                    ParamValue::Uint(n) => u(*n),
                    ParamValue::Text(s) => t(s),
                };
                (t(k), val)
            })
            .collect();
        let types = self
            .param_types
            .iter()
            .map(|(k, ty)| (t(k), t(type_name(*ty))))
            .collect();
        let display = self
            .display
            .iter()
            .map(|(k, v)| {
                let val = match v {
                    DisplayValue::Uint(n) => u(*n),
                    DisplayValue::Text(s) => t(s),
                };
                (t(k), val)
            })
            .collect();
        let mut pid = Vec::with_capacity(17);
        head(2, 16, &mut pid);
        pid.extend_from_slice(&self.pending_id.0);
        let m = vec![
            (u(0), pid),
            (u(1), t(&self.broker_id)),
            (u(2), t(&self.wid)),
            (u(3), t(&self.ten)),
            (u(4), t(&self.approver_sub)),
            (u(5), t(&self.op)),
            (u(6), u(u64::from(self.opv))),
            (u(7), enc_map(params)),
            (u(8), u(self.created_at)),
            (u(9), u(self.expires_at)),
            (u(10), enc_map(types)),
            (u(11), enc_map(display)),
        ];
        enc_map(m)
    }

    /// The normative digest.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DIGEST_LABEL);
        h.update([0u8]);
        h.update(self.cbor());
        h.finalize().into()
    }
}

/// Deterministic CBOR head (shortest form, RFC 8949 §4.2.1).
fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn enc_text(s: &str, out: &mut Vec<u8>) {
    head(3, s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

/// A map from pre-encoded (key, value) pairs, keys in bytewise order of their encoded bytes (C8).
/// Keys are unique by construction (they come from `BTreeMap`s or fixed integers).
fn enc_map(mut entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    head(5, entries.len() as u64, &mut out);
    for (k, v) in entries {
        out.extend_from_slice(&k);
        out.extend_from_slice(&v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_are_shortest() {
        let enc = |n| {
            let mut o = vec![];
            head(0, n, &mut o);
            o
        };
        assert_eq!(enc(23), vec![0x17]);
        assert_eq!(enc(24), vec![0x18, 24]);
        assert_eq!(enc(256), vec![0x19, 1, 0]);
        assert_eq!(enc(65536), vec![0x1a, 0, 1, 0, 0]);
        assert_eq!(
            enc(MAX_UINT),
            vec![0x1b, 0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn text_keys_sort_shorter_first() {
        let t = |s: &str| {
            let mut o = vec![];
            enc_text(s, &mut o);
            o
        };
        let m = enc_map(vec![(t("from"), vec![0]), (t("to"), vec![1])]);
        assert_eq!(&m[1..4], &t("to")[..]);
    }

    #[test]
    fn hex_digest_rules() {
        assert!(parse_hex_digest(&"a".repeat(64)).is_ok());
        assert!(parse_hex_digest(&"A".repeat(64)).is_err());
        assert!(parse_hex_digest(&"a".repeat(63)).is_err());
        assert!(parse_hex_digest(&"a".repeat(65)).is_err());
        assert!(parse_hex_digest(&"g".repeat(64)).is_err());
    }

    #[test]
    fn pending_id_canonical() {
        assert!(PendingId::parse("-xEiM0RVZneImaq7zN3u_w").is_ok());
        assert!(PendingId::parse("-xEiM0RVZneImaq7zN3u_x").is_err());
        assert!(PendingId::parse("-xEiM0RVZneImaq7zN3u_w=").is_err());
        assert!(PendingId::parse("-xEiM0RVZneImaq7zN3u/w").is_err());
        assert!(PendingId::parse("").is_err());
        let p = PendingId::parse("-xEiM0RVZneImaq7zN3u_w").unwrap();
        assert_eq!(p.to_text(), "-xEiM0RVZneImaq7zN3u_w");
    }
}
