// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Reference implementation of Nodkey-Grant v1 Draft 2: transport decoding (spec §2), the
//! verification procedure (§7), operation-declaration loading (§6) and key-registry loading (§8).
//! Used only to cross-check the expected results in the manifest. It is NOT the broker
//! implementation and is not hardened for production use.

use crate::cbor::{self, Item, Rules};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

pub const TYP: &str = "application/nodkey-grant+cbor";
pub const AAD_TAG: &[u8] = b"nodkey.grant.v1";
pub const KID_LABEL: &[u8] = b"nodkey.kid.v1";
pub const RQH_LABEL: &[u8] = b"nodkey.rqh.v1";
pub const MAX_GRANT_BYTES: usize = 2048;
pub const MAX_TEXT_CHARS: usize = 2731;
pub const MAX_UINT: u64 = (1 << 53) - 1;
pub const ALG_ED25519: i128 = -19;

pub fn derive_kid(pk: &[u8; 32]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(KID_LABEL);
    h.update([0u8]);
    h.update(pk);
    h.finalize()[..16].try_into().unwrap()
}

pub fn aad(tag: &[u8], aud: &str) -> Vec<u8> {
    let mut v = tag.to_vec();
    v.push(0);
    v.extend_from_slice(aud.as_bytes());
    v
}

pub fn sig_structure(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    cbor::array(&[cbor::tstr("Signature1"), cbor::bstr(protected), cbor::bstr(external_aad), cbor::bstr(payload)])
}

fn is_id(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn op_name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

// ---------------------------------------------------------------- strict JSON (duplicate members rejected)

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_string<E>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut v = Vec::new();
                while let Some(Strict(x)) = a.next_element()? {
                    v.push(x);
                }
                Ok(Strict(Value::Array(v)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut m = serde_json::Map::new();
                while let Some((k, Strict(x))) = a.next_entry::<String, Strict>()? {
                    if m.insert(k.clone(), x).is_some() {
                        return Err(A::Error::custom(format!("duplicate member {k}")));
                    }
                }
                Ok(Strict(Value::Object(m)))
            }
        }
        d.deserialize_any(V)
    }
}

/// Parses JSON text, rejecting duplicate object members at any depth.
pub fn strict_json(text: &str) -> Option<Value> {
    serde_json::from_str::<Strict>(text).ok().map(|s| s.0)
}

/// A JSON integer in 0..=2^53-1 written without fraction or exponent (serde_json yields u64 only then).
fn json_uint(v: &Value) -> Option<u64> {
    v.as_u64().filter(|n| *n <= MAX_UINT)
}

// ---------------------------------------------------------------- transport (spec §2)

pub fn decode_transport(text: &str) -> Result<Vec<u8>, &'static str> {
    if text.len() > MAX_TEXT_CHARS {
        return Err("grant_too_large");
    }
    const BAD: &str = "grant_encoding_invalid";
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32)
    };
    let b = text.as_bytes();
    if b.len() % 4 == 1 {
        return Err(BAD);
    }
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    for chunk in b.chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c).ok_or(BAD)? << (18 - 6 * i);
        }
        let bytes = acc.to_be_bytes();
        let n = chunk.len() - 1; // 4 chars -> 3 bytes, 3 -> 2, 2 -> 1
        // Unused low bits of the final character must be zero (canonical form).
        let used_bits = 8 * n;
        let mask = if chunk.len() == 4 { 0 } else { (1u32 << (24 - used_bits)) - 1 };
        if acc & mask != 0 {
            return Err(BAD);
        }
        out.extend_from_slice(&bytes[1..1 + n]);
    }
    if out.len() > MAX_GRANT_BYTES {
        return Err("grant_too_large");
    }
    Ok(out)
}

// ---------------------------------------------------------------- key registry (spec §8)

pub struct KeyEntry {
    pub kid: [u8; 16],
    pub vk: VerifyingKey,
    pub iss: String,
    pub not_before: u64,
    pub not_after: u64,
    pub status: String,
}

pub struct Registry {
    pub keys: Vec<KeyEntry>,
}

fn lower_hex(s: &str, nbytes: usize) -> Option<Vec<u8>> {
    if s.len() != nbytes * 2 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    (0..nbytes).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}

/// Validates a public key per spec §8.3: canonical encoding of a point of order exactly L.
pub fn check_public_key(pk: &[u8; 32]) -> Result<VerifyingKey, &'static str> {
    let pt = CompressedEdwardsY(*pk).decompress().ok_or("registry_key_invalid")?;
    if pt.compress().to_bytes() != *pk {
        return Err("registry_key_invalid");
    }
    if pt.is_small_order() || !pt.is_torsion_free() {
        return Err("registry_key_weak");
    }
    VerifyingKey::from_bytes(pk).map_err(|_| "registry_key_invalid")
}

pub fn load_registry(text: &str) -> Result<Registry, &'static str> {
    const INVALID: &str = "registry_entry_invalid";
    let doc = strict_json(text).ok_or(INVALID)?;
    let obj = doc.as_object().ok_or(INVALID)?;
    if obj.len() != 2 || obj.get("format") != Some(&Value::from("nodkey.grant-keys.v1")) {
        return Err(INVALID);
    }
    let arr = obj.get("keys").and_then(Value::as_array).ok_or(INVALID)?;
    if arr.is_empty() {
        return Err(INVALID);
    }
    const FIELDS: [&str; 8] = ["kid", "alg", "public_key", "iss", "purpose", "not_before", "not_after", "status"];
    let mut keys: Vec<KeyEntry> = Vec::new();
    for e in arr {
        let o = e.as_object().ok_or(INVALID)?;
        if o.len() != FIELDS.len() || !FIELDS.iter().all(|f| o.contains_key(*f)) {
            return Err(INVALID);
        }
        let s = |f: &str| o[f].as_str().ok_or(INVALID);
        let u = |f: &str| json_uint(&o[f]).ok_or(INVALID);
        let (alg, iss, purpose, status) = (s("alg")?, s("iss")?, s("purpose")?, s("status")?);
        let (nb, na) = (u("not_before")?, u("not_after")?);
        let kid_hex = s("kid")?;
        let pk_hex = s("public_key")?;
        if alg != "Ed25519" || purpose != "grant" || !is_id(iss, 128) || !matches!(status, "active" | "revoked") || nb >= na {
            return Err(INVALID);
        }
        let kid: [u8; 16] = lower_hex(kid_hex, 16).ok_or(INVALID)?.try_into().unwrap();
        let pk: [u8; 32] = lower_hex(pk_hex, 32).ok_or("registry_key_invalid")?.try_into().unwrap();
        let vk = check_public_key(&pk)?;
        if kid != derive_kid(&pk) {
            return Err("registry_kid_mismatch");
        }
        if keys.iter().any(|k| k.kid == kid || k.vk.as_bytes() == &pk) {
            return Err("registry_duplicate_key");
        }
        keys.push(KeyEntry { kid, vk, iss: iss.to_owned(), not_before: nb, not_after: na, status: status.to_owned() });
    }
    Ok(Registry { keys })
}

// ---------------------------------------------------------------- operation declarations (spec §6)

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Place {
    Res,
    Con,
    Request,
}
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Class {
    Exact,
    Bounded,
    Free,
    OwnerScoped,
}
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Ty {
    Uint,
    AccountId,
    Currency,
    Text64,
    Text256,
}

fn parse_ty(s: &str) -> Option<Ty> {
    Some(match s {
        "uint" => Ty::Uint,
        "account_id" => Ty::AccountId,
        "currency" => Ty::Currency,
        "text64" => Ty::Text64,
        "text256" => Ty::Text256,
        _ => return None,
    })
}

fn text_ty_ok(ty: Ty, s: &str) -> bool {
    let printable = |s: &str| s.bytes().all(|b| (0x20..=0x7e).contains(&b));
    match ty {
        Ty::AccountId => !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        Ty::Currency => s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase()),
        Ty::Text64 => s.len() <= 64 && printable(s),
        Ty::Text256 => s.len() <= 256 && printable(s),
        Ty::Uint => false,
    }
}

pub struct Param {
    pub name: String,
    pub place: Place,
    pub key: Option<u64>,
    pub class: Class,
    pub ty: Ty,
}

pub struct OpDecl {
    pub op: String,
    pub kind: String,
    pub opv: u64,
    pub confirm: bool,
    pub mandate_eligible: bool,
    pub params: Vec<Param>,
}

pub fn load_operations(text: &str) -> Result<Vec<OpDecl>, &'static str> {
    const BAD: &str = "ops_declaration_invalid";
    let doc = strict_json(text).ok_or(BAD)?;
    let obj = doc.as_object().ok_or(BAD)?;
    if obj.len() != 2 || obj.get("format") != Some(&Value::from("nodkey.operations.v1")) {
        return Err(BAD);
    }
    let arr = obj.get("operations").and_then(Value::as_array).filter(|a| !a.is_empty()).ok_or(BAD)?;
    let mut out: Vec<OpDecl> = Vec::new();
    for o in arr {
        let o = o.as_object().ok_or(BAD)?;
        const OF: [&str; 5] = ["op", "kind", "opv", "requires_confirmation", "params"];
        // Draft 4: `mandate_eligible` is the only optional member.
        let n_opt = usize::from(o.contains_key("mandate_eligible"));
        if o.len() != OF.len() + n_opt || !OF.iter().all(|f| o.contains_key(*f)) {
            return Err(BAD);
        }
        let op = o["op"].as_str().filter(|s| op_name_ok(s)).ok_or(BAD)?;
        let kind = o["kind"].as_str().filter(|k| matches!(*k, "write" | "read")).ok_or(BAD)?;
        let opv = o["opv"].as_u64().filter(|v| (1..=65535).contains(v)).ok_or(BAD)?;
        let confirm = o["requires_confirmation"].as_bool().ok_or(BAD)?;
        let mandate_eligible = match o.get("mandate_eligible") {
            None => false,
            Some(v) => v.as_bool().ok_or(BAD)?,
        };
        if out.iter().any(|d| d.op == op) || (confirm && kind != "write") || (mandate_eligible && (kind != "write" || !confirm)) {
            return Err(BAD);
        }
        let mut params: Vec<Param> = Vec::new();
        for q in o["params"].as_array().ok_or(BAD)? {
            let q = q.as_object().ok_or(BAD)?;
            let allowed = ["name", "in", "key", "class", "type", "destination", "justification"];
            if !q.keys().all(|k| allowed.contains(&k.as_str())) {
                return Err(BAD);
            }
            for req in ["name", "in", "key", "class", "type", "destination"] {
                if !q.contains_key(req) {
                    return Err(BAD);
                }
            }
            let name = q["name"].as_str().filter(|n| {
                !n.is_empty() && n.len() <= 64 && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            });
            let name = name.ok_or(BAD)?;
            let place = match q["in"].as_str() {
                Some("res") => Place::Res,
                Some("con") => Place::Con,
                Some("request") => Place::Request,
                _ => return Err(BAD),
            };
            let class = match q["class"].as_str() {
                Some("exact") => Class::Exact,
                Some("bounded") => Class::Bounded,
                Some("free") => Class::Free,
                Some("owner_scoped") => Class::OwnerScoped,
                _ => return Err(BAD),
            };
            let ty = q["type"].as_str().and_then(parse_ty).ok_or(BAD)?;
            let destination = q["destination"].as_bool().ok_or(BAD)?;
            let key = match &q["key"] {
                Value::Null => None,
                v => Some(v.as_u64().filter(|k| *k <= 15).ok_or(BAD)?),
            };
            let justified = q.get("justification").and_then(Value::as_str).is_some_and(|j| !j.is_empty());
            let ok = match (kind, place, class) {
                ("write", Place::Res, Class::Exact) => key.is_some(),
                ("write", Place::Con, Class::Exact) => key.is_some(),
                ("write", Place::Con, Class::Bounded) => key.is_some() && ty == Ty::Uint && !destination,
                ("write", Place::Con, Class::Free) => key.is_none() && !destination && justified,
                ("read", Place::Request, Class::OwnerScoped) => key.is_none(),
                _ => false,
            };
            if !ok || (q.contains_key("justification") && class != Class::Free) {
                return Err(BAD);
            }
            if params.iter().any(|p| p.name == name || (p.place == place && key.is_some() && p.key == key)) {
                return Err(BAD);
            }
            params.push(Param { name: name.to_owned(), place, key, class, ty });
        }
        // D2-3: a write operation must bind at least one parameter (res, or exact/bounded con).
        if kind == "write" && !params.iter().any(|p| p.key.is_some()) {
            return Err(BAD);
        }
        out.push(OpDecl { op: op.to_owned(), kind: kind.to_owned(), opv, confirm, mandate_eligible, params });
    }
    Ok(out)
}

// ---------------------------------------------------------------- broker context

pub struct Env {
    pub registry: Registry,
    pub workloads: HashMap<String, Vec<String>>,
    pub ops: Vec<OpDecl>,
    pub skew: u64,
    pub max_ttl: u64,
}

pub struct Revocation {
    pub ten: String,
    pub wid: Option<String>,
    pub sub: Option<String>,
    pub before: u64,
}

pub struct Ctx {
    pub now: u64,
    pub broker_id: String,
    pub peer_wid: String,
    pub revocations: Vec<Revocation>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum ReqVal {
    Text(String),
    Uint(u64),
}

pub struct Request {
    pub op: String,
    pub args: BTreeMap<String, ReqVal>,
}

/// Replay store: (iss, jti) -> (request hash, recorded outcome).
pub type Store = HashMap<(String, [u8; 16]), ([u8; 32], String)>;

/// Spec §5.4: SHA-256("nodkey.rqh.v1" || 0x00 || dcbor([requested op, {param name: value}])).
pub fn request_hash(op: &str, args: &BTreeMap<String, ReqVal>) -> [u8; 32] {
    let entries: Vec<(Vec<u8>, Vec<u8>)> = args
        .iter()
        .map(|(k, v)| {
            let val = match v {
                ReqVal::Text(s) => cbor::tstr(s),
                ReqVal::Uint(n) => cbor::uint(*n),
            };
            (cbor::tstr(k), val)
        })
        .collect();
    let body = cbor::array(&[cbor::tstr(op), cbor::map(&entries)]);
    let mut h = Sha256::new();
    h.update(RQH_LABEL);
    h.update([0u8]);
    h.update(&body);
    h.finalize().into()
}

// ---------------------------------------------------------------- payload (spec §5)

enum Kind {
    /// `cfm`: 0 = not confirmed, 1 = user confirmed, 2 = mandate-issued (Draft 4; `mid` then present and checked).
    Write { op: String, opv: u64, res: Vec<(u64, Item)>, con: Vec<(u64, u64, Item)>, cfm: u64 },
    Read { rop: Vec<(String, u64)> },
}

struct Payload {
    iss: String,
    aud: String,
    jti: [u8; 16],
    iat: u64,
    nbf: u64,
    exp: u64,
    wid: String,
    ten: String,
    sub: String,
    kind: Kind,
}

const COMMON_KEYS: [u64; 11] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 17];
const WRITE_KEYS: [u64; 6] = [10, 11, 12, 13, 14, 18];
const READ_KEYS: [u64; 1] = [19];

fn value_ok(v: &Item) -> bool {
    match v {
        Item::Uint(n) => *n <= MAX_UINT,
        Item::Text(s) => s.len() <= 256 && s.bytes().all(|b| (0x20..=0x7e).contains(&b)),
        _ => false,
    }
}

fn parse_payload(map: &[(Item, Item)]) -> Result<Payload, &'static str> {
    const BAD: &str = "grant_payload_invalid";
    if let Some((_, Item::Uint(v))) = map.iter().find(|(k, _)| *k == Item::Uint(0))
        && *v != 1 {
            return Err("grant_version_unsupported");
        }
    let mut f: BTreeMap<u64, &Item> = BTreeMap::new();
    for (k, v) in map {
        match k {
            Item::Uint(n) => {
                f.insert(*n, v);
            }
            _ => return Err(BAD),
        }
    }
    let knd = match f.get(&17) {
        Some(Item::Uint(1)) => 1,
        Some(Item::Uint(2)) => 2,
        _ => return Err(BAD),
    };
    let mut want: Vec<u64> = COMMON_KEYS.to_vec();
    want.extend(if knd == 1 { WRITE_KEYS.to_vec() } else { READ_KEYS.to_vec() });
    // Draft 4: key 20 (`mid`) belongs to the write key set exactly when cfm = 2.
    if knd == 1 && matches!(f.get(&18), Some(Item::Uint(2))) {
        want.push(20);
    }
    want.sort();
    if f.keys().copied().collect::<Vec<_>>() != want {
        return Err(BAD);
    }
    let uint = |k: u64| match f[&k] {
        Item::Uint(n) => Ok(*n),
        _ => Err(BAD),
    };
    let text = |k: u64, max: usize| match f[&k] {
        Item::Text(s) if is_id(s, max) => Ok(s.clone()),
        _ => Err(BAD),
    };
    let time = |k: u64| uint(k).and_then(|t| if t <= MAX_UINT { Ok(t) } else { Err(BAD) });
    if uint(0)? != 1 {
        return Err(BAD);
    }
    let jti: [u8; 16] = match f[&3] {
        Item::Bytes(b) if b.len() == 16 => b.as_slice().try_into().unwrap(),
        _ => return Err(BAD),
    };
    let kind = if knd == 1 {
        let op = match f[&10] {
            Item::Text(s) if op_name_ok(s) => s.clone(),
            _ => return Err(BAD),
        };
        let opv = uint(11)?;
        if !(1..=65535).contains(&opv) {
            return Err(BAD);
        }
        let res = match f[&12] {
            Item::Map(m) if m.len() <= 16 => {
                let mut out = Vec::new();
                for (k, v) in m {
                    match k {
                        Item::Uint(n) if *n <= 15 && value_ok(v) => out.push((*n, v.clone())),
                        _ => return Err(BAD),
                    }
                }
                out
            }
            _ => return Err(BAD),
        };
        let con = match f[&13] {
            Item::Map(m) if m.len() <= 16 => {
                let mut out = Vec::new();
                for (k, v) in m {
                    let n = match k {
                        Item::Uint(n) if *n <= 15 => *n,
                        _ => return Err(BAD),
                    };
                    match v {
                        Item::Array(a) if a.len() == 2 => match (&a[0], &a[1]) {
                            (Item::Uint(0), val) if value_ok(val) => out.push((n, 0, val.clone())),
                            (Item::Uint(1), Item::Uint(c)) if *c <= MAX_UINT => out.push((n, 1, Item::Uint(*c))),
                            _ => return Err(BAD),
                        },
                        _ => return Err(BAD),
                    }
                }
                out
            }
            _ => return Err(BAD),
        };
        if uint(14)? != 1 {
            return Err(BAD);
        }
        let cfm = match uint(18)? {
            c @ 0..=2 => c,
            _ => return Err(BAD),
        };
        if cfm == 2 && !matches!(f[&20], Item::Bytes(b) if b.len() == 16) {
            return Err(BAD);
        }
        Kind::Write { op, opv, res, con, cfm }
    } else {
        let rop = match f[&19] {
            Item::Map(m) if !m.is_empty() && m.len() <= 16 => {
                let mut out = Vec::new();
                for (k, v) in m {
                    match (k, v) {
                        (Item::Text(op), Item::Uint(opv)) if op_name_ok(op) && (1..=65535).contains(opv) => out.push((op.clone(), *opv)),
                        _ => return Err(BAD),
                    }
                }
                out
            }
            _ => return Err(BAD),
        };
        Kind::Read { rop }
    };
    Ok(Payload {
        iss: text(1, 128)?,
        aud: text(2, 128)?,
        jti,
        iat: time(4)?,
        nbf: time(5)?,
        exp: time(6)?,
        wid: text(7, 256)?,
        ten: text(8, 128)?,
        sub: text(9, 256)?,
        kind,
    })
}

fn ty_ok(ty: Ty, v: &Item) -> bool {
    match v {
        Item::Uint(_) => ty == Ty::Uint,
        Item::Text(s) => text_ty_ok(ty, s),
        _ => false,
    }
}

fn eq_req(g: &Item, r: Option<&ReqVal>) -> bool {
    match (g, r) {
        (Item::Text(a), Some(ReqVal::Text(b))) => a.as_bytes() == b.as_bytes(),
        (Item::Uint(a), Some(ReqVal::Uint(b))) => a == b,
        _ => false,
    }
}

// ---------------------------------------------------------------- verification (spec §7)

/// Runs the full procedure. Returns "ACCEPT", "STORED_OUTCOME:<ACCEPT|DENIED>", or a broker-facing
/// error code.
pub fn process(g: &[u8], req: &Request, ctx: &Ctx, env: &Env, store: &mut Store) -> String {
    match process_inner(g, req, ctx, env, store) {
        Ok(s) => s,
        Err(e) => e.to_owned(),
    }
}

fn process_inner(g: &[u8], req: &Request, ctx: &Ctx, env: &Env, store: &mut Store) -> Result<String, &'static str> {
    // Step 1c: size.
    if g.len() > MAX_GRANT_BYTES {
        return Err("grant_too_large");
    }
    // Step 2: envelope structure.
    const MAL: &str = "grant_malformed";
    if g.first() != Some(&0xd2) {
        return Err(MAL);
    }
    let env_item = cbor::decode(&g[1..], Rules { allow_nint: true, max_depth: 4 }).map_err(|_| MAL)?;
    let Item::Array(a) = env_item else { return Err(MAL) };
    if a.len() != 4 {
        return Err(MAL);
    }
    let (Item::Bytes(prot), Item::Map(unprot), Item::Bytes(payload), Item::Bytes(sig)) = (&a[0], &a[1], &a[2], &a[3]) else {
        return Err(MAL);
    };
    if sig.len() != 64 {
        return Err(MAL);
    }
    // Step 3: headers.
    const HDR: &str = "grant_header_invalid";
    if !unprot.is_empty() {
        return Err(HDR);
    }
    let ph = cbor::decode(prot, Rules { allow_nint: true, max_depth: 1 }).map_err(|_| HDR)?;
    let Item::Map(pm) = ph else { return Err(HDR) };
    if pm.len() != 3 {
        return Err(HDR);
    }
    let alg: i128 = match &pm[0] {
        (Item::Uint(1), Item::Uint(n)) => *n as i128,
        (Item::Uint(1), Item::Nint(n)) => -1 - *n as i128,
        _ => return Err(HDR),
    };
    let kid: [u8; 16] = match &pm[1] {
        (Item::Uint(4), Item::Bytes(b)) if b.len() == 16 => b.as_slice().try_into().unwrap(),
        _ => return Err(HDR),
    };
    match &pm[2] {
        (Item::Uint(16), Item::Text(t)) if t == TYP => {}
        _ => return Err(HDR),
    }
    // Step 4: key.
    let key = env.registry.keys.iter().find(|k| k.kid == kid).ok_or("grant_unknown_kid")?;
    if alg != ALG_ED25519 {
        return Err("grant_alg_mismatch");
    }
    if key.status != "active" {
        return Err("grant_key_revoked");
    }
    if !(key.not_before <= ctx.now && ctx.now < key.not_after) {
        return Err("grant_key_inactive");
    }
    // Step 5: signature (verify_strict: S < L, R and A not small order, cofactorless, R bytes compared).
    let msg = sig_structure(prot, &aad(AAD_TAG, &ctx.broker_id), payload);
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    key.vk.verify_strict(&msg, &sig).map_err(|_| "grant_signature_invalid")?;
    // Step 6-7: payload.
    let p = cbor::decode(payload, Rules { allow_nint: false, max_depth: 3 }).map_err(|_| "grant_payload_malformed")?;
    let Item::Map(pmap) = p else { return Err("grant_payload_invalid") };
    let p = parse_payload(&pmap)?;
    // Step 8: issuer and time.
    if p.iss != key.iss {
        return Err("grant_issuer_mismatch");
    }
    if p.nbf < p.iat || p.exp <= p.nbf || p.nbf - p.iat > env.skew {
        return Err("grant_time_invalid");
    }
    if p.exp - p.iat > env.max_ttl {
        return Err("grant_ttl_exceeded");
    }
    if ctx.now + env.skew < p.iat || ctx.now + env.skew < p.nbf {
        return Err("grant_not_yet_valid");
    }
    if ctx.now >= p.exp + env.skew {
        return Err("grant_expired");
    }
    // Step 9: binding.
    if p.aud != ctx.broker_id {
        return Err("grant_audience_mismatch");
    }
    if p.wid != ctx.peer_wid {
        return Err("grant_workload_mismatch");
    }
    if !env.workloads.get(&ctx.peer_wid).is_some_and(|t| t.contains(&p.ten)) {
        return Err("grant_tenant_mismatch");
    }
    // ---- VERIFIED.
    let revoked = |p: &Payload| {
        ctx.revocations.iter().any(|r| {
            r.ten == p.ten && r.wid.as_ref().is_none_or(|w| *w == p.wid) && r.sub.as_ref().is_none_or(|s| *s == p.sub) && p.iat < r.before
        })
    };
    let (op, opv, res, con, cfm) = match &p.kind {
        Kind::Read { rop } => {
            // R11a: every rop entry, independent of the request.
            for (op, v) in rop {
                let d = env.ops.iter().find(|d| d.op == *op).ok_or("grant_op_mismatch")?;
                if d.kind != "read" {
                    return Err("grant_kind_mismatch");
                }
                if d.opv != *v {
                    return Err("grant_opv_unsupported");
                }
            }
            // R11b-c: the requested operation.
            let decl = env.ops.iter().find(|d| d.op == req.op).ok_or("grant_op_mismatch")?;
            if decl.kind != "read" {
                return Err("grant_kind_mismatch");
            }
            if !rop.iter().any(|(op, _)| *op == req.op) {
                return Err("grant_op_mismatch");
            }
            // R13: revocation in the READ ONLY transaction.
            if revoked(&p) {
                return Err("grant_revoked");
            }
            return Ok("ACCEPT".to_owned());
        }
        Kind::Write { op, opv, res, con, cfm } => (op, *opv, res, con, *cfm),
    };
    // W10: consumption, first statement of the effect transaction.
    let h = request_hash(&req.op, &req.args);
    let key_id = (p.iss.clone(), p.jti);
    if let Some((h0, outcome)) = store.get(&key_id) {
        return if *h0 == h { Ok(format!("STORED_OUTCOME:{outcome}")) } else { Err("grant_replayed") };
    }
    // From here every denial rolls back to the savepoint and commits outcome = DENIED atomically.
    let decide = |res: Result<(), &'static str>, store: &mut Store| -> Result<String, &'static str> {
        match res {
            Ok(()) => {
                store.insert(key_id.clone(), (h, "ACCEPT".to_owned()));
                Ok("ACCEPT".to_owned())
            }
            Err(code) => {
                store.insert(key_id.clone(), (h, "DENIED".to_owned()));
                Err(code)
            }
        }
    };
    let checks = || -> Result<(), &'static str> {
        // W11: operation.
        let Some(decl) = env.ops.iter().find(|d| d.op == *op && d.op == req.op) else {
            return Err("grant_op_mismatch");
        };
        if decl.kind != "write" {
            return Err("grant_kind_mismatch");
        }
        if decl.opv != opv {
            return Err("grant_opv_unsupported");
        }
        // W11d (Draft 4).
        if (cfm == 2 && !decl.mandate_eligible) || (decl.confirm && !(cfm == 1 || (cfm == 2 && decl.mandate_eligible))) {
            return Err("grant_confirmation_required");
        }
        // W12a: res/con shape against the declaration.
        let res_decl: Vec<&Param> = decl.params.iter().filter(|q| q.place == Place::Res).collect();
        let con_decl: Vec<&Param> = decl.params.iter().filter(|q| q.place == Place::Con && q.class != Class::Free).collect();
        let schema_ok = res.len() == res_decl.len()
            && res.iter().all(|(k, v)| res_decl.iter().any(|q| q.key == Some(*k) && ty_ok(q.ty, v)))
            && con.len() == con_decl.len()
            && con.iter().all(|(k, class, v)| {
                con_decl.iter().any(|q| {
                    q.key == Some(*k)
                        && match q.class {
                            Class::Exact => *class == 0 && ty_ok(q.ty, v),
                            Class::Bounded => *class == 1,
                            _ => false,
                        }
                })
            });
        if !schema_ok {
            return Err("grant_op_schema_invalid");
        }
        // W12b: resource.
        for (k, v) in res {
            let q = res_decl.iter().find(|q| q.key == Some(*k)).unwrap();
            if !eq_req(v, req.args.get(&q.name)) {
                return Err("grant_resource_mismatch");
            }
        }
        // W12c: constraints, ascending key order.
        for (k, class, v) in con {
            let q = con_decl.iter().find(|q| q.key == Some(*k)).unwrap();
            if *class == 0 {
                if !eq_req(v, req.args.get(&q.name)) {
                    return Err("grant_constraint_mismatch");
                }
            } else {
                let (Item::Uint(ceiling), Some(ReqVal::Uint(r))) = (v, req.args.get(&q.name)) else {
                    return Err("grant_constraint_mismatch");
                };
                if r > ceiling {
                    return Err("grant_bound_exceeded");
                }
            }
        }
        // W13: revocation.
        if revoked(&p) {
            return Err("grant_revoked");
        }
        Ok(())
    };
    decide(checks(), store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_rules() {
        assert_eq!(decode_transport("AAEC").unwrap(), vec![0, 1, 2]);
        assert_eq!(decode_transport("AAE").unwrap(), vec![0, 1]);
        assert_eq!(decode_transport("AA").unwrap(), vec![0]);
        assert!(decode_transport("AB").is_err()); // non-zero trailing bits
        assert!(decode_transport("AAF").is_err());
        assert!(decode_transport("A").is_err());
        assert!(decode_transport("AA==").is_err());
        assert!(decode_transport("+/AA").is_err());
        assert_eq!(decode_transport("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn write_op_must_bind_a_parameter() {
        let free_only = r#"{"format":"nodkey.operations.v1","operations":[{"op":"t.x","kind":"write","opv":1,
            "requires_confirmation":false,"params":[{"name":"memo","in":"con","key":null,"class":"free",
            "type":"text64","destination":false,"justification":"j"}]}]}"#;
        assert_eq!(load_operations(free_only).err(), Some("ops_declaration_invalid"));
        let bound = free_only.replace(r#"[{"name":"memo""#, r#"[{"name":"a","in":"res","key":0,"class":"exact","type":"uint","destination":false},{"name":"memo""#);
        assert!(load_operations(&bound).is_ok());
    }

    #[test]
    fn strict_json_rejects_duplicates() {
        assert!(strict_json(r#"{"a":1,"a":2}"#).is_none());
        assert!(strict_json(r#"{"a":{"b":1,"b":1}}"#).is_none());
        assert!(strict_json(r#"{"a":1,"b":[{"c":2}]}"#).is_some());
    }
}
