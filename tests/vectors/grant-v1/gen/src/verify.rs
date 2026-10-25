//! Reference implementation of the Nodkey-Grant v1 verification procedure (spec §7) and key
//! registry loading (spec §8). Used only to cross-check the expected results in the manifest.
//! It is NOT the broker implementation and is not hardened for production use.

use crate::cbor::{self, Item, Rules};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub const TYP: &str = "application/nodkey-grant+cbor";
pub const AAD_TAG: &[u8] = b"nodkey.grant.v1";
pub const KID_LABEL: &[u8] = b"nodkey.kid.v1";
pub const RQH_LABEL: &[u8] = b"nodkey.rqh.v1";
pub const MAX_GRANT_BYTES: usize = 2048;
pub const MAX_TIME: u64 = (1 << 53) - 1;
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
    cbor::array(&[
        cbor::tstr("Signature1"),
        cbor::bstr(protected),
        cbor::bstr(external_aad),
        cbor::bstr(payload),
    ])
}

// ---------------------------------------------------------------- key registry (spec §8)

pub struct KeyEntry {
    pub kid: [u8; 16],
    pub vk: VerifyingKey,
    pub iss: String,
    pub role: String,
    pub not_before: u64,
    pub not_after: u64,
    pub status: String,
}

pub struct Registry {
    pub keys: Vec<KeyEntry>,
}

fn is_id(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn lower_hex(s: &str, nbytes: usize) -> Option<Vec<u8>> {
    if s.len() != nbytes * 2 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    (0..nbytes).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}

pub fn load_registry(doc: &Value) -> Result<Registry, &'static str> {
    const INVALID: &str = "registry_entry_invalid";
    let obj = doc.as_object().ok_or(INVALID)?;
    if obj.len() != 2 || obj.get("format") != Some(&Value::from("nodkey.grant-keys.v1")) {
        return Err(INVALID);
    }
    let arr = obj.get("keys").and_then(Value::as_array).ok_or(INVALID)?;
    if arr.is_empty() {
        return Err(INVALID);
    }
    const FIELDS: [&str; 9] =
        ["kid", "alg", "public_key", "iss", "role", "purpose", "not_before", "not_after", "status"];
    let mut keys: Vec<KeyEntry> = Vec::new();
    for e in arr {
        let o = e.as_object().ok_or(INVALID)?;
        if o.len() != FIELDS.len() || !FIELDS.iter().all(|f| o.contains_key(*f)) {
            return Err(INVALID);
        }
        let s = |f: &str| o[f].as_str().ok_or(INVALID);
        let u = |f: &str| o[f].as_u64().filter(|n| *n <= MAX_TIME).ok_or(INVALID);
        let (alg, iss, role, purpose, status) = (s("alg")?, s("iss")?, s("role")?, s("purpose")?, s("status")?);
        let (nb, na) = (u("not_before")?, u("not_after")?);
        if alg != "Ed25519"
            || purpose != "grant"
            || !is_id(iss, 128)
            || !matches!(role, "user_authority" | "scheduler")
            || !matches!(status, "active" | "revoked")
            || nb >= na
        {
            return Err(INVALID);
        }
        let kid_hex = s("kid")?;
        let pk_hex = s("public_key")?;
        // Public key: 32 bytes, a valid point, canonically encoded.
        let pk: [u8; 32] = lower_hex(pk_hex, 32).ok_or("registry_key_invalid")?.try_into().unwrap();
        let pt = CompressedEdwardsY(pk).decompress().ok_or("registry_key_invalid")?;
        if pt.compress().to_bytes() != pk {
            return Err("registry_key_invalid");
        }
        if pt.is_small_order() {
            return Err("registry_key_weak");
        }
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "registry_key_invalid")?;
        debug_assert!(!vk.is_weak());
        let kid: [u8; 16] = lower_hex(kid_hex, 16).ok_or(INVALID)?.try_into().unwrap();
        if kid != derive_kid(&pk) {
            return Err("registry_kid_mismatch");
        }
        if keys.iter().any(|k| k.kid == kid || k.vk.as_bytes() == &pk) {
            return Err("registry_duplicate_key");
        }
        keys.push(KeyEntry {
            kid,
            vk,
            iss: iss.to_owned(),
            role: role.to_owned(),
            not_before: nb,
            not_after: na,
            status: status.to_owned(),
        });
    }
    Ok(Registry { keys })
}

// ---------------------------------------------------------------- broker configuration (test)

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Place {
    Res,
    Con,
    /// Read operations: a request parameter whose ownership by (ten, sub) the broker checks.
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
    AccountId,
    Currency,
    Uint,
    Text64,
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
    /// "write" or "read".
    pub kind: String,
    /// Write operations only: the grant must carry cfm = 1.
    pub confirm: bool,
    pub opv: Vec<u64>,
    pub authority: String,
    pub params: Vec<Param>,
}

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

pub fn request_hash(op: &str, opv: u64, args: &BTreeMap<String, ReqVal>) -> [u8; 32] {
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
    let body = cbor::array(&[cbor::tstr(op), cbor::uint(opv), cbor::map(&entries)]);
    let mut h = Sha256::new();
    h.update(RQH_LABEL);
    h.update([0u8]);
    h.update(&body);
    h.finalize().into()
}

// ---------------------------------------------------------------- verification (spec §7)

enum Kind {
    Write { op: String, opv: u64, res: Vec<(u64, Item)>, con: Vec<(u64, u64, Item)>, cfm: bool },
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

fn op_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

fn value_ok(v: &Item) -> bool {
    match v {
        Item::Uint(_) => true,
        Item::Text(s) => s.len() <= 256 && s.bytes().all(|b| (0x20..=0x7e).contains(&b)),
        _ => false,
    }
}

fn parse_payload(map: &[(Item, Item)]) -> Result<Payload, &'static str> {
    const BAD: &str = "grant_payload_invalid";
    // Version first: a different version is reported as such, before the key-set checks.
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
    // Kind selects the exact key set.
    let knd = match f.get(&17) {
        Some(Item::Uint(1)) => 1,
        Some(Item::Uint(2)) => 2,
        _ => return Err(BAD),
    };
    let mut want: Vec<u64> = COMMON_KEYS.to_vec();
    want.extend(if knd == 1 { WRITE_KEYS.to_vec() } else { READ_KEYS.to_vec() });
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
    let time = |k: u64| uint(k).and_then(|t| if t <= MAX_TIME { Ok(t) } else { Err(BAD) });
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
                            (Item::Uint(1), Item::Uint(c)) => out.push((n, 1, Item::Uint(*c))),
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
            0 => false,
            1 => true,
            _ => return Err(BAD),
        };
        Kind::Write { op, opv, res, con, cfm }
    } else {
        let rop = match f[&19] {
            Item::Map(m) if !m.is_empty() && m.len() <= 16 => {
                let mut out = Vec::new();
                for (k, v) in m {
                    match (k, v) {
                        (Item::Text(op), Item::Uint(opv)) if op_name_ok(op) && (1..=65535).contains(opv) => {
                            out.push((op.clone(), *opv))
                        }
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
    match (ty, v) {
        (Ty::Uint, Item::Uint(_)) => true,
        (Ty::AccountId, Item::Text(s)) => {
            !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        }
        (Ty::Currency, Item::Text(s)) => s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase()),
        (Ty::Text64, Item::Text(s)) => s.len() <= 64,
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

/// Runs the full procedure. Returns "ACCEPT", "STORED_OUTCOME:<ACCEPT|DENIED>", or a broker-facing error code.
pub fn process(g: &[u8], req: &Request, ctx: &Ctx, env: &Env, store: &mut Store) -> String {
    match process_inner(g, req, ctx, env, store) {
        Ok(s) => s,
        Err(e) => e.to_owned(),
    }
}

fn process_inner(
    g: &[u8],
    req: &Request,
    ctx: &Ctx,
    env: &Env,
    store: &mut Store,
) -> Result<String, &'static str> {
    // Step 1: size.
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
    let (Item::Bytes(prot), Item::Map(unprot), Item::Bytes(payload), Item::Bytes(sig)) = (&a[0], &a[1], &a[2], &a[3])
    else {
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
    // Step 4: key lookup.
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
    // Step 5: signature.
    let msg = sig_structure(prot, &aad(AAD_TAG, &ctx.broker_id), payload);
    let sig = Signature::from_bytes(sig.as_slice().try_into().unwrap());
    key.vk.verify_strict(&msg, &sig).map_err(|_| "grant_signature_invalid")?;
    // Step 6: payload decoding.
    let p = cbor::decode(payload, Rules { allow_nint: false, max_depth: 3 }).map_err(|_| "grant_payload_malformed")?;
    // Step 7: payload schema.
    let Item::Map(pmap) = p else { return Err("grant_payload_invalid") };
    let p = parse_payload(&pmap)?;
    // Step 8: issuer and time.
    if p.iss != key.iss {
        return Err("grant_issuer_mismatch");
    }
    if p.nbf < p.iat || p.exp <= p.nbf {
        return Err("grant_time_invalid");
    }
    if p.exp - p.nbf > env.max_ttl {
        return Err("grant_ttl_exceeded");
    }
    if ctx.now + env.skew < p.nbf {
        return Err("grant_not_yet_valid");
    }
    if ctx.now >= p.exp + env.skew {
        return Err("grant_expired");
    }
    // Step 9: binding to trusted context.
    if p.aud != ctx.broker_id {
        return Err("grant_audience_mismatch");
    }
    if p.wid != ctx.peer_wid {
        return Err("grant_workload_mismatch");
    }
    if !env.workloads.get(&ctx.peer_wid).is_some_and(|t| t.contains(&p.ten)) {
        return Err("grant_tenant_mismatch");
    }
    // ---- The grant is now VERIFIED.
    let revoked = |p: &Payload| {
        ctx.revocations.iter().any(|r| {
            r.ten == p.ten
                && r.wid.as_ref().is_none_or(|w| *w == p.wid)
                && r.sub.as_ref().is_none_or(|s| *s == p.sub)
                && p.iat < r.before
        })
    };
    let role_ok = |decl: &OpDecl| {
        matches!(
            (decl.authority.as_str(), key.role.as_str()),
            ("user_grant", "user_authority") | ("scheduler_grant", "scheduler")
        )
    };
    let (op, opv, res, con, cfm) = match &p.kind {
        Kind::Read { rop } => {
            // Step 10R: read grants are multi-use; nothing is consumed or recorded.
            let decl = env.ops.iter().find(|d| d.op == req.op).ok_or("grant_op_mismatch")?;
            if decl.kind != "read" {
                return Err("grant_kind_mismatch");
            }
            for (op, _) in rop {
                let d = env.ops.iter().find(|d| d.op == *op).ok_or("grant_op_mismatch")?;
                if d.kind != "read" {
                    return Err("grant_kind_mismatch");
                }
            }
            let (_, opv) = rop.iter().find(|(op, _)| *op == req.op).ok_or("grant_op_mismatch")?;
            if !decl.opv.contains(opv) {
                return Err("grant_opv_unsupported");
            }
            if !role_ok(decl) {
                return Err("grant_issuer_not_permitted");
            }
            // Step 13R: revocation, in the read transaction.
            if revoked(&p) {
                return Err("grant_revoked");
            }
            // Step 14R: ownership of the requested resource by (ten, sub) is checked in-query.
            return Ok("ACCEPT".to_owned());
        }
        Kind::Write { op, opv, res, con, cfm } => (op, *opv, res, con, *cfm),
    };
    // Write grants: every later denial is recorded (one decision per grant).
    let h = request_hash(&req.op, opv, &req.args);
    let key_id = (p.iss.clone(), p.jti);
    let deny = |code: &'static str, store: &mut Store| {
        store.entry(key_id.clone()).or_insert((h, "DENIED".to_owned()));
        Err(code)
    };
    // Step 10W: operation.
    let Some(decl) = env.ops.iter().find(|d| d.op == *op && d.op == req.op) else {
        return deny("grant_op_mismatch", store);
    };
    if decl.kind != "write" {
        return deny("grant_kind_mismatch", store);
    }
    if !decl.opv.contains(&opv) {
        return deny("grant_opv_unsupported", store);
    }
    if !role_ok(decl) {
        return deny("grant_issuer_not_permitted", store);
    }
    if decl.confirm && !cfm {
        return deny("grant_confirmation_required", store);
    }
    // Step 11a: res/con shape against the declaration.
    let res_decl: Vec<&Param> = decl.params.iter().filter(|q| q.place == Place::Res).collect();
    let con_decl: Vec<&Param> =
        decl.params.iter().filter(|q| q.place == Place::Con && q.class != Class::Free).collect();
    let schema_ok = res.len() == res_decl.len()
        && res.iter().all(|(k, v)| res_decl.iter().any(|q| q.key == Some(*k) && ty_ok(q.ty, v)))
        && con.len() == con_decl.len()
        && con.iter().all(|(k, class, v)| {
            con_decl.iter().any(|q| {
                q.key == Some(*k)
                    && match q.class {
                        Class::Exact => *class == 0 && ty_ok(q.ty, v),
                        Class::Bounded => *class == 1 && q.ty == Ty::Uint,
                        _ => false,
                    }
            })
        });
    if !schema_ok {
        return deny("grant_op_schema_invalid", store);
    }
    // Step 11b: resource.
    for (k, v) in res {
        let q = res_decl.iter().find(|q| q.key == Some(*k)).unwrap();
        if !eq_req(v, req.args.get(&q.name)) {
            return deny("grant_resource_mismatch", store);
        }
    }
    // Step 11c: constraints, in ascending key order.
    for (k, class, v) in con {
        let q = con_decl.iter().find(|q| q.key == Some(*k)).unwrap();
        if *class == 0 {
            if !eq_req(v, req.args.get(&q.name)) {
                return deny("grant_constraint_mismatch", store);
            }
        } else {
            let (Item::Uint(ceiling), Some(ReqVal::Uint(r))) = (v, req.args.get(&q.name)) else {
                return deny("grant_constraint_mismatch", store);
            };
            if r > ceiling {
                return deny("grant_bound_exceeded", store);
            }
        }
    }
    // Step 12: consumption (effect transaction begins).
    if let Some((h0, outcome)) = store.get(&key_id) {
        return if *h0 == h { Ok(format!("STORED_OUTCOME:{outcome}")) } else { Err("grant_replayed") };
    }
    // Step 13: revocation, inside the transaction.
    if revoked(&p) {
        // The effect transaction rolls back; DENIED is recorded separately (ADR-0006 section 4).
        store.insert(key_id, (h, "DENIED".to_owned()));
        return Err("grant_revoked");
    }
    // Step 14: policy/state/budget preconditions and the effect are outside this spec.
    store.insert(key_id, (h, "ACCEPT".to_owned()));
    Ok("ACCEPT".to_owned())
}
