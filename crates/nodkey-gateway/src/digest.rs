// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Pending-effect digest (effect-protocol-v2 §3.2), computed by the gateway itself from the render
//! response it displays.
//!
//! `digest = SHA-256("nodkey.pending.v1" || 0x00 || dcbor(M))`. The deterministic CBOR here covers
//! only what `M` needs (uint, bstr, tstr, maps); keys are sorted by their encoded bytes.

use nodkey_grant::{ParamType, ParamValue};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::json::{Scalar, StrictMap, de_uint};
use crate::util::{decode_pending_id, is_id, is_op_name, is_param_name};

pub const LABEL: &[u8] = b"nodkey.pending.v1";

/// The §3.2 fields as they appear in a broker JSON response.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingRecord {
    pub pending_id: String,
    pub broker_id: String,
    pub wid: String,
    pub ten: String,
    pub approver_sub: String,
    pub op: String,
    #[serde(deserialize_with = "de_uint")]
    pub opv: u64,
    pub params: StrictMap<Scalar>,
    pub param_types: StrictMap<String>,
    #[serde(deserialize_with = "de_uint")]
    pub created_at: u64,
    #[serde(deserialize_with = "de_uint")]
    pub expires_at: u64,
    pub display: StrictMap<Scalar>,
}

/// A record that passed every §3.2 rule, with its digest.
#[derive(Debug, Clone)]
pub struct CheckedRecord {
    pub rec: PendingRecord,
    pub pending_id: [u8; 16],
    pub digest: [u8; 32],
}

/// Why a record was rejected (internal; the user always sees the uniform error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject(pub &'static str);

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
    let mut v = Vec::new();
    head(&mut v, 2, b.len() as u64);
    v.extend_from_slice(b);
    v
}
fn tstr(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    head(&mut v, 3, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    v
}
/// Map with keys sorted by encoded bytes; duplicate encoded keys are an error.
fn map(mut e: Vec<(Vec<u8>, Vec<u8>)>) -> Result<Vec<u8>, Reject> {
    e.sort_by(|a, b| a.0.cmp(&b.0));
    if e.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(Reject("duplicate map key"));
    }
    let mut v = Vec::new();
    head(&mut v, 5, e.len() as u64);
    for (k, val) in e {
        v.extend_from_slice(&k);
        v.extend_from_slice(&val);
    }
    Ok(v)
}

fn printable(s: &str) -> bool {
    s.bytes().all(|c| (0x20..=0x7e).contains(&c))
}

/// Validates a record per §3.2 and returns its deterministic CBOR `M`.
pub fn encode_record(r: &PendingRecord) -> Result<(Vec<u8>, [u8; 16]), Reject> {
    let pid = decode_pending_id(&r.pending_id).ok_or(Reject("pending_id not canonical"))?;
    for (v, max) in [
        (&r.broker_id, 128),
        (&r.wid, 256),
        (&r.ten, 128),
        (&r.approver_sub, 256),
    ] {
        if !is_id(v, max) {
            return Err(Reject("not an ID"));
        }
    }
    if !is_op_name(&r.op) {
        return Err(Reject("op name"));
    }
    let types = &r.param_types.0;
    let params = &r.params.0;
    if types.len() != params.len() || !types.keys().all(|k| params.contains_key(k)) {
        return Err(Reject("params key set differs from param_types"));
    }
    let mut pm = Vec::with_capacity(types.len());
    let mut tm = Vec::with_capacity(types.len());
    for (name, ty_name) in types {
        if !is_param_name(name) {
            return Err(Reject("param name"));
        }
        let ty = ParamType::from_name(ty_name).ok_or(Reject("unknown param type"))?;
        let val = &params[name];
        // The CBOR type comes from the declared type, never from the JSON value type.
        let enc = match (ty, val) {
            (ParamType::Uint, Scalar::Uint(n)) => {
                if !ty.accepts_value(&ParamValue::Uint(*n)) {
                    return Err(Reject("uint range"));
                }
                uint(*n)
            }
            (ParamType::Uint, Scalar::Text(_)) => return Err(Reject("declared uint, got text")),
            (_, Scalar::Uint(_)) => return Err(Reject("declared text, got uint")),
            (_, Scalar::Text(t)) => {
                if !ty.accepts_value(&ParamValue::Text(t.clone())) {
                    return Err(Reject("value grammar"));
                }
                tstr(t)
            }
        };
        pm.push((tstr(name), enc));
        tm.push((tstr(name), tstr(ty_name)));
    }
    let mut dm = Vec::with_capacity(r.display.0.len());
    for (k, v) in &r.display.0 {
        if !is_param_name(k) {
            return Err(Reject("display key"));
        }
        let enc = match v {
            Scalar::Uint(n) => uint(*n),
            Scalar::Text(t) if t.len() <= 64 && printable(t) => tstr(t),
            Scalar::Text(_) => return Err(Reject("display text")),
        };
        dm.push((tstr(k), enc));
    }
    let m = map(vec![
        (uint(0), bstr(&pid)),
        (uint(1), tstr(&r.broker_id)),
        (uint(2), tstr(&r.wid)),
        (uint(3), tstr(&r.ten)),
        (uint(4), tstr(&r.approver_sub)),
        (uint(5), tstr(&r.op)),
        (uint(6), uint(r.opv)),
        (uint(7), map(pm)?),
        (uint(8), uint(r.created_at)),
        (uint(9), uint(r.expires_at)),
        (uint(10), map(tm)?),
        (uint(11), map(dm)?),
    ])?;
    Ok((m, pid))
}

/// Validates the record and computes its digest.
pub fn check(rec: PendingRecord) -> Result<CheckedRecord, Reject> {
    let (m, pid) = encode_record(&rec)?;
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update([0u8]);
    h.update(&m);
    Ok(CheckedRecord {
        rec,
        pending_id: pid,
        digest: h.finalize().into(),
    })
}
