// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! The normative pending-effect digest (effect protocol v2 §3.2):
//!
//! `digest = SHA-256("nodkey.pending.v1" || 0x00 || dcbor(M))`
//!
//! `dcbor` is the core deterministic encoding of grant-v1 §4: shortest heads, definite lengths,
//! map keys ordered by their encoded bytes (so text keys sort shorter first). Only unsigned
//! integers, byte strings, text strings and maps are produced. The CBOR type of each parameter
//! comes from its declared type (key 10), never from the JSON value type.
//!
//! This encoder is a few lines of fixed formatting, not a cryptographic primitive; the hash is
//! `sha2`. Its output is checked against `tests/vectors/effect-v2/digest-vectors.json`.

use std::collections::BTreeMap;

use nodkey_grant::{ParamType, ParamValue, Params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::ids::{decode_id, encode_id, is_id};

pub const LABEL: &[u8] = b"nodkey.pending.v1";
pub const MAX_UINT: u64 = (1 << 53) - 1;

/// A display fact value (key 11): uint or 0–64 bytes of 0x20–0x7E.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayValue {
    Uint(u64),
    Text(String),
}

/// The immutable fields of a pending-effect record that enter the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingFields {
    pub pending_id: [u8; 16],
    pub broker_id: String,
    pub wid: String,
    pub ten: String,
    pub approver_sub: String,
    pub op: String,
    pub opv: u64,
    pub params: Params,
    /// Declared type name per parameter (key 10).
    pub param_types: BTreeMap<String, String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub display: BTreeMap<String, DisplayValue>,
}

const RECORD_KEYS: [&str; 12] = [
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

fn is_op_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'.')
}

fn is_key_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn display_text_ok(s: &str) -> bool {
    s.len() <= 64 && s.bytes().all(|c| (0x20..=0x7e).contains(&c))
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

fn uint(n: u64) -> Vec<u8> {
    let mut v = Vec::new();
    head(&mut v, 0, n);
    v
}

fn bstr(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(b.len() + 9);
    head(&mut v, 2, b.len() as u64);
    v.extend_from_slice(b);
    v
}

fn tstr(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 9);
    head(&mut v, 3, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    v
}

/// Map with keys in bytewise order of their encodings (grant-v1 §4 C8); duplicates rejected.
fn map(mut entries: Vec<(Vec<u8>, Vec<u8>)>) -> Result<Vec<u8>, String> {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    if entries.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err("duplicate map key".into());
    }
    let mut v = Vec::new();
    head(&mut v, 5, entries.len() as u64);
    for (k, x) in entries {
        v.extend(k);
        v.extend(x);
    }
    Ok(v)
}

impl PendingFields {
    /// Checks every value rule of §3.2.
    pub fn validate(&self) -> Result<(), String> {
        for (name, v, max) in [
            ("broker_id", &self.broker_id, 128),
            ("wid", &self.wid, 256),
            ("ten", &self.ten, 128),
            ("approver_sub", &self.approver_sub, 256),
        ] {
            if !is_id(v, max) {
                return Err(format!("{name}: not an ID"));
            }
        }
        if !is_op_name(&self.op) {
            return Err("op: not an op name".into());
        }
        if !(1..=65535).contains(&self.opv) {
            return Err("opv: out of range".into());
        }
        if self.created_at > MAX_UINT || self.expires_at > MAX_UINT {
            return Err("time: above 2^53-1".into());
        }
        if self.param_types.len() != self.params.len()
            || !self.param_types.keys().all(|k| self.params.contains_key(k))
        {
            return Err("params: key set differs from param_types".into());
        }
        for (name, ty) in &self.param_types {
            if !is_key_name(name) {
                return Err(format!("{name}: not a parameter name"));
            }
            let t = ParamType::from_name(ty).ok_or_else(|| format!("{name}: unknown type"))?;
            if !t.accepts_value(&self.params[name]) {
                return Err(format!("{name}: value violates the declared type {ty}"));
            }
        }
        for (k, v) in &self.display {
            if !is_key_name(k) {
                return Err(format!("display.{k}: bad key"));
            }
            let ok = match v {
                DisplayValue::Uint(n) => *n <= MAX_UINT,
                DisplayValue::Text(s) => display_text_ok(s),
            };
            if !ok {
                return Err(format!("display.{k}: not an allowed value"));
            }
        }
        Ok(())
    }

    /// `dcbor(M)` after [`Self::validate`].
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut pm = Vec::with_capacity(self.params.len());
        let mut tm = Vec::with_capacity(self.params.len());
        for (name, ty) in &self.param_types {
            let enc = match &self.params[name] {
                ParamValue::Uint(n) => uint(*n),
                ParamValue::Text(s) => tstr(s),
            };
            pm.push((tstr(name), enc));
            tm.push((tstr(name), tstr(ty)));
        }
        let dm = self
            .display
            .iter()
            .map(|(k, v)| {
                let enc = match v {
                    DisplayValue::Uint(n) => uint(*n),
                    DisplayValue::Text(s) => tstr(s),
                };
                (tstr(k), enc)
            })
            .collect();
        map(vec![
            (uint(0), bstr(&self.pending_id)),
            (uint(1), tstr(&self.broker_id)),
            (uint(2), tstr(&self.wid)),
            (uint(3), tstr(&self.ten)),
            (uint(4), tstr(&self.approver_sub)),
            (uint(5), tstr(&self.op)),
            (uint(6), uint(self.opv)),
            (uint(7), map(pm)?),
            (uint(8), uint(self.created_at)),
            (uint(9), uint(self.expires_at)),
            (uint(10), map(tm)?),
            (uint(11), map(dm)?),
        ])
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        let m = self.encode()?;
        Ok(digest_of(&m))
    }

    pub fn params_json(&self) -> Value {
        Value::Object(
            self.params
                .iter()
                .map(|(k, v)| {
                    let j = match v {
                        ParamValue::Uint(n) => json!(n),
                        ParamValue::Text(s) => json!(s),
                    };
                    (k.clone(), j)
                })
                .collect(),
        )
    }

    pub fn param_types_json(&self) -> Value {
        Value::Object(
            self.param_types
                .iter()
                .map(|(k, v)| (k.clone(), json!(v)))
                .collect(),
        )
    }

    pub fn display_json(&self) -> Value {
        Value::Object(
            self.display
                .iter()
                .map(|(k, v)| {
                    let j = match v {
                        DisplayValue::Uint(n) => json!(n),
                        DisplayValue::Text(s) => json!(s),
                    };
                    (k.clone(), j)
                })
                .collect(),
        )
    }

    /// The record as it appears in broker JSON responses (§4.1, §4.3).
    pub fn to_json(&self) -> Value {
        json!({
            "pending_id": encode_id(&self.pending_id),
            "broker_id": self.broker_id,
            "wid": self.wid,
            "ten": self.ten,
            "approver_sub": self.approver_sub,
            "op": self.op,
            "opv": self.opv,
            "params": self.params_json(),
            "param_types": self.param_types_json(),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "display": self.display_json(),
        })
    }

    /// Parses the record JSON form strictly: exactly the 12 members; the parameter CBOR type
    /// comes from `param_types`; a JSON value of the other kind is rejected.
    pub fn from_json(record: &Value) -> Result<PendingFields, String> {
        let r = record.as_object().ok_or("record: not an object")?;
        if r.len() != RECORD_KEYS.len() || !RECORD_KEYS.iter().all(|k| r.contains_key(*k)) {
            return Err("record: member set".into());
        }
        let s = |k: &str| -> Result<String, String> {
            r[k].as_str()
                .map(str::to_owned)
                .ok_or(format!("{k}: not a string"))
        };
        let u = |k: &str| -> Result<u64, String> {
            json_uint(&r[k]).ok_or(format!("{k}: not a uint <= 2^53-1"))
        };
        let pending_id = decode_id(&s("pending_id")?).ok_or("pending_id: not canonical")?;
        let types = r["param_types"]
            .as_object()
            .ok_or("param_types: not an object")?;
        let raw_params = r["params"].as_object().ok_or("params: not an object")?;
        let mut param_types = BTreeMap::new();
        for (k, t) in types {
            param_types.insert(
                k.clone(),
                t.as_str().ok_or("param type: not a string")?.to_owned(),
            );
        }
        let params = typed_params(raw_params, &param_types)?;
        let disp = r["display"].as_object().ok_or("display: not an object")?;
        let mut display = BTreeMap::new();
        for (k, v) in disp {
            let dv = match v {
                Value::String(t) => DisplayValue::Text(t.clone()),
                v => DisplayValue::Uint(json_uint(v).ok_or(format!("display.{k}: bad value"))?),
            };
            display.insert(k.clone(), dv);
        }
        let f = PendingFields {
            pending_id,
            broker_id: s("broker_id")?,
            wid: s("wid")?,
            ten: s("ten")?,
            approver_sub: s("approver_sub")?,
            op: s("op")?,
            opv: u("opv")?,
            params,
            param_types,
            created_at: u("created_at")?,
            expires_at: u("expires_at")?,
            display,
        };
        f.validate()?;
        Ok(f)
    }
}

/// A JSON integer `0 ..= 2^53-1` (no sign, fraction or exponent; serde_json parses those as
/// i64/f64, which are rejected here).
pub fn json_uint(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) if n.is_u64() => n.as_u64().filter(|x| *x <= MAX_UINT),
        _ => None,
    }
}

/// Types JSON parameter values by their declared types: `uint` needs a JSON integer, every text
/// type a JSON string. The key sets must be equal. Grammar checks happen in `validate`.
pub fn typed_params(
    raw: &Map<String, Value>,
    types: &BTreeMap<String, String>,
) -> Result<Params, String> {
    if raw.len() != types.len() || !types.keys().all(|k| raw.contains_key(k)) {
        return Err("params: key set differs from param_types".into());
    }
    let mut params = BTreeMap::new();
    for (name, ty) in types {
        let v = &raw[name];
        let pv = if ty == "uint" {
            ParamValue::Uint(json_uint(v).ok_or(format!("{name}: declared uint"))?)
        } else {
            ParamValue::Text(
                v.as_str()
                    .ok_or(format!("{name}: declared {ty}, not a string"))?
                    .to_owned(),
            )
        };
        params.insert(name.clone(), pv);
    }
    Ok(params)
}

pub fn digest_of(m: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update([0u8]);
    h.update(m);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::ids::hex;

    fn vectors() -> Value {
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/vectors/effect-v2/digest-vectors.json"
        );
        let s = std::fs::read_to_string(p).expect("digest vectors");
        serde_json::from_str(&s).unwrap()
    }

    /// T28 / T37 (broker side): every DG vector reproduces its CBOR bytes and digest exactly,
    /// every rejection is rejected.
    #[test]
    fn digest_vectors_all() {
        let doc = vectors();
        assert_eq!(doc["label"], "nodkey.pending.v1");
        let vs = doc["vectors"].as_array().unwrap();
        assert_eq!(vs.len(), 12);
        let (mut accepted, mut rejected) = (0, 0);
        for v in vs {
            let id = v["id"].as_str().unwrap();
            let r = PendingFields::from_json(&v["record"]).and_then(|f| f.encode());
            if v.get("expected").and_then(Value::as_str) == Some("reject") {
                assert!(r.is_err(), "{id} must be rejected");
                rejected += 1;
            } else {
                let m = r.unwrap_or_else(|e| panic!("{id}: {e}"));
                assert_eq!(hex(&m), v["cbor_hex"].as_str().unwrap(), "{id} cbor");
                assert_eq!(
                    hex(&digest_of(&m)),
                    v["digest"].as_str().unwrap(),
                    "{id} digest"
                );
                // Round trip through the broker's own JSON form gives the same bytes.
                let f = PendingFields::from_json(&v["record"]).unwrap();
                let again = PendingFields::from_json(&f.to_json()).unwrap();
                assert_eq!(again.encode().unwrap(), m, "{id} roundtrip");
                accepted += 1;
            }
        }
        assert_eq!((accepted, rejected), (8, 4));
    }

    #[test]
    fn rejects_non_integer_numbers_and_signs() {
        let doc = vectors();
        let base = doc["vectors"][0]["record"].clone();
        for bad in ["1250.0", "1.25e3", "-1250", "-0", "9007199254740992"] {
            let mut r = base.clone();
            r["params"]["amount_minor"] = serde_json::from_str(bad).unwrap();
            assert!(PendingFields::from_json(&r).is_err(), "{bad}");
        }
        let mut r = base.clone();
        r["extra"] = json!(1);
        assert!(PendingFields::from_json(&r).is_err());
        let mut r = base;
        r["params"]["currency"] = json!("eur");
        assert!(PendingFields::from_json(&r).is_err());
    }
}
