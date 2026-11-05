// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Generates `digest-vectors.json` for effect protocol v2 §3.2 (pending-effect digest).
//! Each vector gives the record as it appears in a broker JSON response, the dCBOR encoding of `M`
//! (hex), and the SHA-256 digest (lowercase hex), or an expected rejection with its reason.
//! Deterministic; no randomness.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const LABEL: &[u8] = b"nodkey.pending.v1";
const MAX_UINT: u64 = (1 << 53) - 1;

// ---- minimal deterministic CBOR (RFC 8949 4.2.1 core deterministic encoding)
fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=0xff => vec![m | 24, n as u8],
        0x100..=0xffff => [vec![m | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![m | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![m | 27], n.to_be_bytes().to_vec()].concat(),
    }
}
fn uint(n: u64) -> Vec<u8> {
    head(0, n)
}
fn bstr(b: &[u8]) -> Vec<u8> {
    [head(2, b.len() as u64), b.to_vec()].concat()
}
fn tstr(s: &str) -> Vec<u8> {
    [head(3, s.len() as u64), s.as_bytes().to_vec()].concat()
}
fn map(mut e: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    e.sort_by(|a, b| a.0.cmp(&b.0));
    for w in e.windows(2) {
        assert!(w[0].0 != w[1].0, "duplicate key");
    }
    let mut v = head(5, e.len() as u64);
    for (k, x) in e {
        v.extend(k);
        v.extend(x);
    }
    v
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Canonical unpadded base64url decode of exactly 16 bytes (22 chars; the last char's 4 low bits zero).
fn decode_pending_id(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() != 22 {
        return Err("pending_id: not 22 characters");
    }
    let (mut acc, mut n, mut out) = (0u32, 0u32, Vec::with_capacity(16));
    for c in s.bytes() {
        let v = B64.iter().position(|x| *x == c).ok_or("pending_id: character outside base64url alphabet")? as u32;
        acc = (acc << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
            acc &= (1 << n) - 1;
        }
    }
    // 132 bits = 16 bytes + 4 leftover bits, which must be zero.
    if n != 4 || acc != 0 {
        return Err("pending_id: non-zero trailing bits (non-canonical alias)");
    }
    Ok(out)
}

fn encode_pending_id(b: &[u8; 16]) -> String {
    let (mut acc, mut n, mut out) = (0u32, 0u32, String::new());
    for x in b {
        acc = (acc << 8) | *x as u32;
        n += 8;
        while n >= 6 {
            n -= 6;
            out.push(B64[((acc >> n) & 63) as usize] as char);
            acc &= (1 << n) - 1;
        }
    }
    out.push(B64[((acc << (6 - n)) & 63) as usize] as char);
    out
}

fn is_id(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn text_ok(ty: &str, s: &str) -> bool {
    let printable = |s: &str| s.bytes().all(|b| (0x20..=0x7e).contains(&b));
    match ty {
        "account_id" => !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "currency" => s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase()),
        "text64" => s.len() <= 64 && printable(s),
        "text256" => s.len() <= 256 && printable(s),
        _ => false,
    }
}

/// Builds M from a record JSON object (spec 3.2). Returns the dCBOR bytes or a rejection reason.
fn encode_record(r: &Map<String, Value>) -> Result<Vec<u8>, String> {
    let s = |k: &str| r[k].as_str().ok_or(format!("{k}: not a string"));
    let u = |k: &str| r[k].as_u64().filter(|n| *n <= MAX_UINT).ok_or(format!("{k}: not a uint <= 2^53-1"));
    let pid = decode_pending_id(s("pending_id")?)?;
    let mut ids = Vec::new();
    for (k, max) in [("broker_id", 128), ("wid", 256), ("ten", 128), ("approver_sub", 256)] {
        let v = s(k)?;
        if !is_id(v, max) {
            return Err(format!("{k}: not an ID"));
        }
        ids.push(v.to_owned());
    }
    let op = s("op")?;
    let types = r["param_types"].as_object().ok_or("param_types: not an object")?;
    let params = r["params"].as_object().ok_or("params: not an object")?;
    if types.len() != params.len() || !types.keys().all(|k| params.contains_key(k)) {
        return Err("params: key set differs from param_types (every declared parameter is required)".into());
    }
    let mut pm = Vec::new();
    let mut tm = Vec::new();
    for (name, ty) in types {
        let ty = ty.as_str().ok_or("param type: not a string")?;
        let val = &params[name];
        let enc = if ty == "uint" {
            uint(val.as_u64().filter(|n| *n <= MAX_UINT).ok_or(format!("{name}: declared uint, value is not a uint <= 2^53-1"))?)
        } else {
            let t = val.as_str().ok_or(format!("{name}: declared {ty}, value is not a string"))?;
            if !text_ok(ty, t) {
                return Err(format!("{name}: value violates the {ty} grammar"));
            }
            tstr(t)
        };
        pm.push((tstr(name), enc));
        tm.push((tstr(name), tstr(ty)));
    }
    let disp = r["display"].as_object().ok_or("display: not an object")?;
    let mut dm = Vec::new();
    for (k, v) in disp {
        let enc = match v {
            Value::String(t) if t.bytes().all(|b| (0x20..=0x7e).contains(&b)) && t.len() <= 64 => tstr(t),
            v if v.as_u64().is_some_and(|n| n <= MAX_UINT) => uint(v.as_u64().unwrap()),
            _ => return Err(format!("display.{k}: not an allowed value")),
        };
        dm.push((tstr(k), enc));
    }
    Ok(map(vec![
        (uint(0), bstr(&pid)),
        (uint(1), tstr(&ids[0])),
        (uint(2), tstr(&ids[1])),
        (uint(3), tstr(&ids[2])),
        (uint(4), tstr(&ids[3])),
        (uint(5), tstr(op)),
        (uint(6), uint(u("opv")?)),
        (uint(7), map(pm)),
        (uint(8), uint(u("created_at")?)),
        (uint(9), uint(u("expires_at")?)),
        (uint(10), map(tm)),
        (uint(11), map(dm)),
    ]))
}

fn digest(m: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update([0u8]);
    h.update(m);
    hex(&h.finalize())
}

fn main() {
    let out = std::env::args().nth(1).expect("usage: gen <output-dir>");
    let pid_bytes: [u8; 16] = *b"\xfb\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
    let pid = encode_pending_id(&pid_bytes);
    assert_eq!(decode_pending_id(&pid).unwrap(), pid_bytes.to_vec());
    let base = |op: &str, types: Value, params: Value, display: Value| -> Value {
        json!({
            "pending_id": pid, "broker_id": "nodkey.broker.payments-test",
            "wid": "spiffe://nodkey.test/workload/shop", "ten": "acme", "approver_sub": "user:u-17",
            "op": op, "opv": 1, "params": params, "param_types": types,
            "created_at": 1792886400u64, "expires_at": 1792887000u64, "display": display,
        })
    };
    let refund = base(
        "payments.refund",
        json!({"order_id": "uint", "amount_minor": "uint", "currency": "currency"}),
        json!({"order_id": 9821, "amount_minor": 1250, "currency": "EUR"}),
        json!({"amount_exponent": 2, "currency": "EUR"}),
    );
    let mut vectors: Vec<(String, String, Value, Option<String>)> = Vec::new();
    let mut add = |id: &str, d: &str, rec: Value| vectors.push((id.into(), d.into(), rec, None));
    add("DG-01-refund", "payments.refund; parameter names of different lengths (sorted shorter first)", refund.clone());
    add("DG-02-transfer", "ledger.transfer with a destination parameter", base(
        "ledger.transfer",
        json!({"from": "account_id", "to": "account_id", "amount_minor": "uint"}),
        json!({"from": "alice", "to": "bob", "amount_minor": 12500}),
        json!({"amount_exponent": 2, "currency": "EUR"}),
    ));
    add("DG-03-numeric-looking-text", "account_id \"12345\" is a tstr because the declared type is account_id", base(
        "ledger.transfer",
        json!({"from": "account_id", "to": "account_id", "amount_minor": "uint"}),
        json!({"from": "12345", "to": "bob", "amount_minor": 1}),
        json!({"amount_exponent": 2, "currency": "EUR"}),
    ));
    let mut big = refund.clone();
    big["params"]["amount_minor"] = json!(MAX_UINT);
    add("DG-04-uint-max", "amount_minor = 2^53 - 1 (8-byte head)", big);
    let mut jpy = refund.clone();
    jpy["params"]["currency"] = json!("JPY");
    jpy["display"] = json!({"amount_exponent": 0, "currency": "JPY"});
    add("DG-05-display-exponent", "Same amount, JPY with exponent 0: the display facts change the digest", jpy);
    add("DG-06-free-text-param", "Test-only operation with a free text64 parameter: included in M like any other", base(
        "test.note",
        json!({"account": "account_id", "memo": "text64"}),
        json!({"account": "alice", "memo": "rent for \"October\""}),
        json!({}),
    ));
    // Rejections.
    let mut alias = refund.clone();
    let mut a = pid.clone().into_bytes();
    let last = a.len() - 1;
    let p = B64.iter().position(|c| *c == a[last]).unwrap();
    a[last] = B64[p | 1];
    alias["pending_id"] = json!(String::from_utf8(a).unwrap());
    vectors.push(("DG-07-pending-id-alias".into(), "pending_id with a non-zero trailing bit (alias of DG-01's id)".into(), alias, Some("reject".into())));
    let mut wrongtype = refund.clone();
    wrongtype["params"]["order_id"] = json!("9821");
    vectors.push(("DG-08-type-from-declaration".into(), "order_id given as a JSON string while declared uint".into(), wrongtype, Some("reject".into())));
    let mut missing = refund.clone();
    missing["params"].as_object_mut().unwrap().remove("currency");
    vectors.push(("DG-09-missing-param".into(), "A declared parameter is absent".into(), missing, Some("reject".into())));
    let mut nonascii = refund.clone();
    nonascii["approver_sub"] = json!("user:u-\u{e9}");
    vectors.push(("DG-10-non-ascii-id".into(), "approver_sub contains U+00E9".into(), nonascii, Some("reject".into())));
    // Draft 3.1: payments.refund binds the broker-resolved charge_id (con2, text64).
    let charged = |charge: &str| base(
        "payments.refund",
        json!({"order_id": "uint", "amount_minor": "uint", "currency": "currency", "charge_id": "text64"}),
        json!({"order_id": 9821, "amount_minor": 1250, "currency": "EUR", "charge_id": charge}),
        json!({"amount_exponent": 2, "currency": "EUR"}),
    );
    vectors.push(("DG-11-refund-charge-id".into(), "payments.refund (Draft 3.1) with the broker-resolved charge_id as a text64 parameter".into(), charged("ch_demoorder0001"), None));
    vectors.push(("DG-12-refund-charge-unresolved".into(), "payments.refund (Draft 3.1) for an order with no trusted row: charge_id = reserved value \"unresolved\"".into(), charged("unresolved"), None));

    let mut arr = Vec::new();
    for (id, d, rec, rej) in vectors {
        let r = encode_record(rec.as_object().unwrap());
        match (r, rej) {
            (Ok(m), None) => arr.push(json!({"id": id, "description": d, "record": rec, "cbor_hex": hex(&m), "digest": digest(&m)})),
            (Err(e), Some(_)) => arr.push(json!({"id": id, "description": d, "record": rec, "expected": "reject", "reason": e})),
            (r, rej) => panic!("{id}: unexpected {r:?} / {rej:?}"),
        }
    }
    let doc = json!({
        "format": "nodkey.effect-v2.digest-vectors",
        "spec": "docs/specs/effect-protocol-v2.md section 3.2",
        "label": "nodkey.pending.v1",
        "digest_input": "SHA-256(label || 0x00 || hex_decode(cbor_hex))",
        "vectors": arr,
    });
    std::fs::write(Path::new(&out).join("digest-vectors.json"), serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    eprintln!("wrote {} digest vectors", doc["vectors"].as_array().unwrap().len());
}
