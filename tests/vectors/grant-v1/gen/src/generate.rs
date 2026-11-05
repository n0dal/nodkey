// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Generates the Nodkey-Grant v1 test vectors. Output is fully deterministic: Ed25519 signatures
//! are deterministic, `jti` values are derived from the vector id, and JSON key order is fixed.
//!
//! ALL KEYS HERE ARE TEST-ONLY. They are the published RFC 8032 §7.1 test keys; anyone can sign
//! with them. A registry containing any of them must never be deployed.

use crate::cbor::{self, array, bstr, map, nint, tstr, uint};
use crate::verify::{aad, derive_kid, sig_structure, AAD_TAG, TYP};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const T0: u64 = 1_792_886_400; // 2026-10-25T00:00:00Z
pub const BROKER: &str = "nodkey.broker.ledger-test";
pub const OTHER_BROKER: &str = "nodkey.broker.other-test";
pub const ISS: &str = "nodkey.authority.test";
pub const OTHER_ISS: &str = "nodkey.other-issuer.test";
pub const APP1: &str = "spiffe://nodkey.test/workload/app1";
pub const APP2: &str = "spiffe://nodkey.test/workload/app2";
pub const SUB: &str = "user:u-17";
pub const SKEW: u64 = 5;
pub const MAX_TTL: u64 = 30;
const KEY_NB: u64 = 1_767_225_600; // 2026-01-01T00:00:00Z
const KEY_NA: u64 = 1_798_761_600; // 2027-01-01T00:00:00Z

pub struct TestKey {
    pub name: &'static str,
    pub source: &'static str,
    pub seed: &'static str,
    pub public: &'static str,
    pub iss: &'static str,
    pub status: &'static str,
    pub not_before: u64,
    pub not_after: u64,
    pub in_registry: bool,
    pub purpose: &'static str,
}

pub const KEYS: [TestKey; 6] = [
    TestKey {
        name: "A",
        source: "RFC 8032 section 7.1 TEST 1",
        seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        iss: ISS,
        status: "active",
        not_before: KEY_NB,
        not_after: KEY_NA,
        in_registry: true,
        purpose: "the authority's active grant key; signs every valid user grant",
    },
    TestKey {
        name: "B",
        source: "RFC 8032 section 7.1 TEST 2",
        seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        iss: ISS,
        status: "active",
        not_before: KEY_NB,
        not_after: KEY_NA,
        in_registry: false,
        purpose: "NOT in the registry; wrong-key and unknown-kid cases",
    },
    TestKey {
        name: "C",
        source: "RFC 8032 section 7.1 TEST 3",
        seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        iss: ISS,
        status: "revoked",
        not_before: KEY_NB,
        not_after: KEY_NA,
        in_registry: true,
        purpose: "registered with status revoked",
    },
    TestKey {
        name: "D",
        source: "RFC 8032 section 7.1 TEST 1024",
        seed: "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        public: "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        iss: ISS,
        status: "active",
        not_before: 1_735_689_600, // 2025-01-01
        not_after: KEY_NB,         // 2026-01-01: outside its window at T0
        in_registry: true,
        purpose: "registered active but outside its validity window at the test time",
    },
    TestKey {
        name: "E",
        source: "RFC 8032 section 7.1 TEST SHA(abc)",
        seed: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        public: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        iss: ISS,
        status: "active",
        not_before: KEY_NB,
        not_after: KEY_NA,
        in_registry: true,
        purpose: "a second active key of the same issuer (rotation overlap)",
    },
    TestKey {
        name: "F",
        source: "RFC 8032 section 7.2 (Ed25519ctx test key, used here as a plain Ed25519 key)",
        seed: "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
        public: "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
        iss: ISS,
        status: "active",
        not_before: KEY_NA,        // 2027-01-01: not yet valid at T0
        not_after: 1_830_297_600, // 2028-01-01
        in_registry: true,
        purpose: "registered active but not yet inside its validity window at the test time",
    },
];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn key(name: &str) -> &'static TestKey {
    KEYS.iter().find(|k| k.name == name).unwrap()
}

fn signing_key(name: &str) -> SigningKey {
    let k = key(name);
    let sk = SigningKey::from_bytes(&unhex(k.seed).try_into().unwrap());
    // Guard against a mistyped seed: the derived public key must equal the RFC's.
    assert_eq!(hex(sk.verifying_key().as_bytes()), k.public, "key {} public key mismatch", k.name);
    sk
}

fn kid_of(name: &str) -> [u8; 16] {
    derive_kid(&unhex(key(name).public).try_into().unwrap())
}

pub fn std_protected(alg: i64, kid: &[u8], typ: &str) -> Vec<u8> {
    let a = if alg < 0 { nint(alg) } else { uint(alg as u64) };
    map(&[(uint(1), a), (uint(4), bstr(kid)), (uint(16), tstr(typ))])
}

pub fn envelope(prot: &[u8], unprot_raw: &[u8], payload: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut v = vec![0xd2];
    v.extend(array(&[bstr(prot), unprot_raw.to_vec(), bstr(payload), bstr(sig)]));
    v
}

/// Deterministic TEST-ONLY mandate id (stands for the `jti` of a mandate's own grant).
fn test_mid() -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"nodkey.test.mid\x00");
    h.update(b"MND");
    h.finalize()[..16].try_into().unwrap()
}

fn con_exact(v: Vec<u8>) -> Vec<u8> {
    array(&[uint(0), v])
}
fn con_bound(n: u64) -> Vec<u8> {
    array(&[uint(1), uint(n)])
}

#[derive(Clone)]
struct G {
    fields: BTreeMap<u64, Vec<u8>>,
    signer: &'static str,
    kid: [u8; 16],
    prot: Option<Vec<u8>>,
    aad: Vec<u8>,
}

impl G {
    fn base(id: &str, signer: &'static str, iss: &str, op: &str, res: Vec<u8>, con: Vec<u8>, cfm: u64) -> G {
        let jti: [u8; 16] = {
            let mut h = Sha256::new();
            h.update(b"nodkey.test.jti\x00");
            h.update(id.as_bytes());
            h.finalize()[..16].try_into().unwrap()
        };
        let mut f = BTreeMap::new();
        f.insert(0, uint(1));
        f.insert(1, tstr(iss));
        f.insert(2, tstr(BROKER));
        f.insert(3, bstr(&jti));
        f.insert(4, uint(T0));
        f.insert(5, uint(T0));
        f.insert(6, uint(T0 + MAX_TTL));
        f.insert(7, tstr(APP1));
        f.insert(8, tstr("acme"));
        f.insert(9, tstr(SUB));
        f.insert(10, tstr(op));
        f.insert(11, uint(1));
        f.insert(12, res);
        f.insert(13, con);
        f.insert(14, uint(1));
        f.insert(17, uint(1));
        f.insert(18, uint(cfm));
        G { fields: f, signer, kid: kid_of(signer), prot: None, aad: aad(AAD_TAG, BROKER) }
    }

    fn transfer(id: &str) -> G {
        G::base(
            id,
            "A",
            ISS,
            "ledger.transfer",
            map(&[(uint(0), tstr("alice"))]),
            map(&[(uint(0), con_exact(tstr("bob"))), (uint(1), con_exact(uint(12_500)))]),
            1,
        )
    }

    /// Test-only write op exercising bounded, exact and free classes without confirmation.
    fn hold(id: &str) -> G {
        G::base(
            id,
            "A",
            ISS,
            "test.hold",
            map(&[(uint(0), tstr("alice"))]),
            map(&[(uint(0), con_bound(50_000)), (uint(1), con_exact(tstr("EUR")))]),
            0,
        )
    }

    /// Test-only mandate-eligible write op (Draft 4): `cfm = 2` with the mandate id `mid` (key 20).
    fn mandated(id: &str) -> G {
        G::base(id, "A", ISS, "test.mandated", map(&[(uint(0), tstr("alice"))]), map(&[]), 2).set(20, bstr(&test_mid()))
    }

    /// Read grant (knd = 2) for the given set of read operations (all opv 1 unless stated).
    fn read(id: &str, rop: &[(&str, u64)]) -> G {
        let mut g = G::base(id, "A", ISS, "x", vec![], vec![], 0);
        for k in [10, 11, 12, 13, 14, 18] {
            g.fields.remove(&k);
        }
        g.fields.insert(17, uint(2));
        let e: Vec<(Vec<u8>, Vec<u8>)> = rop.iter().map(|(op, v)| (tstr(op), uint(*v))).collect();
        g.fields.insert(19, map(&e));
        g
    }

    fn balance(id: &str) -> G {
        G::read(id, &[("ledger.get_balance", 1)])
    }

    /// Test-only write op with many exact text256 parameters (used to reach the 2048-byte limit).
    fn bulk(id: &str, vals: &[String]) -> G {
        let con: Vec<(Vec<u8>, Vec<u8>)> = vals.iter().enumerate().map(|(i, v)| (uint(i as u64), con_exact(tstr(v)))).collect();
        G::base(id, "A", ISS, "test.bulk", map(&[(uint(0), tstr("alice"))]), map(&con), 0)
    }

    fn times(self, iat: u64, nbf: u64, exp: u64) -> G {
        self.set(4, uint(iat)).set(5, uint(nbf)).set(6, uint(exp))
    }

    fn set(mut self, k: u64, v: Vec<u8>) -> G {
        self.fields.insert(k, v);
        self
    }
    fn del(mut self, k: u64) -> G {
        self.fields.remove(&k);
        self
    }
    fn signer(mut self, s: &'static str) -> G {
        self.signer = s;
        self
    }
    fn kid(mut self, k: [u8; 16]) -> G {
        self.kid = k;
        self
    }
    fn prot(mut self, p: Vec<u8>) -> G {
        self.prot = Some(p);
        self
    }
    fn aad(mut self, a: Vec<u8>) -> G {
        self.aad = a;
        self
    }
    fn protected(&self) -> Vec<u8> {
        self.prot.clone().unwrap_or_else(|| std_protected(-19, &self.kid, TYP))
    }
    /// Canonical payload (uint keys: numeric order equals bytewise order of the encodings).
    fn payload(&self) -> Vec<u8> {
        let e: Vec<(Vec<u8>, Vec<u8>)> = self.fields.iter().map(|(k, v)| (uint(*k), v.clone())).collect();
        cbor::map_raw(&e)
    }
    fn sign(&self, prot: &[u8], payload: &[u8]) -> Vec<u8> {
        signing_key(self.signer).sign(&sig_structure(prot, &self.aad, payload)).to_bytes().to_vec()
    }
    /// Signs an arbitrary payload byte string under this grant's protected header.
    fn build_raw(&self, payload: &[u8]) -> Vec<u8> {
        let p = self.protected();
        envelope(&p, &[0xa0], payload, &self.sign(&p, payload))
    }
    fn build(&self) -> Vec<u8> {
        self.build_raw(&self.payload())
    }
    /// (protected, payload, signature) of the correctly signed grant.
    fn parts(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let p = self.protected();
        let pl = self.payload();
        let s = self.sign(&p, &pl);
        (p, pl, s)
    }
}

// ------------------------------------------------------------------- requests and steps

fn transfer_req_full(from: &str, to: &str, amount: u64) -> Value {
    json!({"op": "ledger.transfer", "args": {"from": from, "to": to, "amount_cents": amount}})
}
fn transfer_req() -> Value {
    transfer_req_full("alice", "bob", 12_500)
}
fn hold_req(amount: u64, cur: &str, memo: &str) -> Value {
    json!({"op": "test.hold", "args": {"account": "alice", "amount_cents": amount, "currency": cur, "memo": memo}})
}
fn balance_req() -> Value {
    json!({"op": "ledger.get_balance", "args": {"account": "alice"}})
}
fn list_req() -> Value {
    json!({"op": "ledger.list_transfers", "args": {"account": "alice"}})
}
fn bulk_req(vals: &[String]) -> Value {
    let mut args = serde_json::Map::new();
    args.insert("account".into(), json!("alice"));
    for (i, v) in vals.iter().enumerate() {
        args.insert(format!("p{i}"), json!(v));
    }
    json!({"op": "test.bulk", "args": args})
}
fn mandated_req() -> Value {
    json!({"op": "test.mandated", "args": {"account": "alice"}})
}
fn peek_req() -> Value {
    json!({"op": "test.peek", "args": {"account": "alice"}})
}

/// Base64url without padding (RFC 4648 section 5).
pub fn b64url(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

#[derive(Clone)]
struct Step {
    now: u64,
    broker_id: &'static str,
    peer_wid: &'static str,
    revoked_before: Vec<Value>,
    request: Value,
    expected: String,
}

fn st(expected: &str) -> Step {
    Step {
        now: T0 + 10,
        broker_id: BROKER,
        peer_wid: APP1,
        revoked_before: vec![],
        request: transfer_req(),
        expected: expected.to_owned(),
    }
}
impl Step {
    fn now(mut self, n: u64) -> Step {
        self.now = n;
        self
    }
    fn broker(mut self, b: &'static str) -> Step {
        self.broker_id = b;
        self
    }
    fn peer(mut self, p: &'static str) -> Step {
        self.peer_wid = p;
        self
    }
    fn req(mut self, r: Value) -> Step {
        self.request = r;
        self
    }
    fn rev(mut self, r: Value) -> Step {
        self.revoked_before.push(r);
        self
    }
}

struct Vector {
    id: String,
    category: &'static str,
    description: String,
    grant: Vec<u8>,
    steps: Vec<Step>,
}

struct Out {
    v: Vec<Vector>,
}
impl Out {
    fn add(&mut self, id: &str, category: &'static str, desc: &str, grant: Vec<u8>, steps: Vec<Step>) {
        assert!(!self.v.iter().any(|x| x.id == id), "duplicate id {id}");
        self.v.push(Vector { id: id.to_owned(), category, description: desc.to_owned(), grant, steps });
    }
    fn one(&mut self, id: &str, category: &'static str, desc: &str, grant: Vec<u8>, step: Step) {
        self.add(id, category, desc, grant, vec![step]);
    }
}

// ------------------------------------------------------------------- vector definitions

/// Adds the Ed25519 group order L to the little-endian scalar S (yields S + L < 2^256).
fn add_l(s: &[u8]) -> Vec<u8> {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut out = vec![0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let t = s[i] as u16 + L[i] as u16 + carry;
        out[i] = t as u8;
        carry = t >> 8;
    }
    assert_eq!(carry, 0);
    out
}

fn vectors() -> Vec<Vector> {
    let mut o = Out { v: Vec::new() };
    let a_kid = kid_of("A");

    // ---------------- ACCEPT controls
    o.one("ACC-01-valid-transfer", "accept", "Valid ledger.transfer grant; request within every constraint.",
        G::transfer("ACC-01").build(), st("ACCEPT"));
    o.one("ACC-02-valid-read-grant", "accept", "Valid read grant (knd = 2) for ledger.get_balance.",
        G::balance("ACC-02").build(), st("ACCEPT").req(balance_req()));
    o.add("ACC-09-read-grant-multi-use", "accept",
        "One read grant naming two read operations, used three times within its TTL; nothing is consumed.",
        G::read("ACC-09", &[("ledger.get_balance", 1), ("ledger.list_transfers", 1)]).build(),
        vec![st("ACCEPT").req(balance_req()), st("ACCEPT").req(list_req()).now(T0 + 11), st("ACCEPT").req(balance_req()).now(T0 + 12)]);
    o.one("ACC-03-amount-equals-bound", "accept",
        "test.hold: bounded parameter equal to its ceiling is accepted (inclusive); cfm = 0 is fine where confirmation is not required.",
        G::hold("ACC-03").build(), st("ACCEPT").req(hold_req(50_000, "EUR", "rent")));
    o.one("ACC-04-free-param-any-value", "accept",
        "test.hold: the free parameter memo is not bound by the grant; any value passes (published residual).",
        G::hold("ACC-04").build(), st("ACCEPT").req(hold_req(12_500, "EUR", "anything at all")));
    o.one("ACC-05-iat-before-nbf", "accept", "iat = nbf - 2 (within skew), exp - iat = max_ttl (30 s).",
        G::transfer("ACC-05").times(T0 - 2, T0, T0 + 28).build(), st("ACCEPT"));
    o.one("ACC-06-multi-tenant-workload", "accept", "Workload app2 is registered for tenants acme and globex; grant for globex.",
        G::transfer("ACC-06").set(7, tstr(APP2)).set(8, tstr("globex")).build(), st("ACCEPT").peer(APP2));
    o.one("ACC-07-other-audience-at-its-broker", "accept",
        "Grant signed for audience nodkey.broker.other-test, presented to that broker (control for SIG-07).",
        G::transfer("ACC-07").set(2, tstr(OTHER_BROKER)).aad(aad(AAD_TAG, OTHER_BROKER)).build(),
        st("ACCEPT").broker(OTHER_BROKER));
    o.one("ACC-08-rotation-overlap-second-key", "accept",
        "Signed by key E, a second active key registered for the same issuer (rotation overlap).",
        G::transfer("ACC-08").signer("E").kid(kid_of("E")).build(), st("ACCEPT"));
    o.add("ACC-10-rop-length-first-order", "accept",
        "Read grant whose rop keys sort differently by encoded bytes (length first: test.peek) than by raw string order.",
        G::read("ACC-10", &[("test.peek", 1), ("ledger.get_balance", 1)]).build(),
        vec![st("ACCEPT").req(balance_req()), st("ACCEPT").req(peek_req()).now(T0 + 11)]);
    o.one("ACC-11-grant-exactly-2048-bytes", "accept", "A valid write grant (test.bulk) of exactly 2048 bytes.",
        bulk_2048().0, st("ACCEPT").req(bulk_req(&bulk_2048().1)));
    o.one("ACC-12-tenant-128-bytes", "accept", "ten of 128 bytes (maximum), registered for app2.",
        G::transfer("ACC-12").set(7, tstr(APP2)).set(8, tstr(LONG_TEN)).build(), st("ACCEPT").peer(APP2));

    // ---------------- Step 1-2: size and envelope structure
    let valid = G::transfer("ENV").build();
    let (vp, vpl, vs) = G::transfer("ENV").parts();
    let pad_to = |target: usize, id: &str, key: u64| -> Vec<u8> {
        for n in 1500..2100 {
            let g = G::transfer(id).set(key, bstr(&vec![0u8; n])).build();
            if g.len() == target {
                return g;
            }
        }
        panic!("no padding length hits {target}");
    };
    o.one("ENV-01-oversized-2049", "envelope", "Validly signed grant of 2049 bytes (limit 2048; padded with a long bstr under key 20, invalid in this grant); rejected before decoding.",
        pad_to(2049, "ENV-01", 20), st("grant_too_large"));
    o.one("ENV-02-at-size-limit-2048", "envelope",
        "Validly signed grant of exactly 2048 bytes passes the size check; fails later on its padding key 21 (unknown).",
        pad_to(2048, "ENV-02", 21), st("grant_payload_invalid"));
    o.one("ENV-03-empty", "envelope", "Zero-length input.", vec![], st("grant_malformed"));
    o.one("ENV-04-truncated", "envelope", "Valid grant with its last byte removed.", valid[..valid.len() - 1].to_vec(), st("grant_malformed"));
    o.one("ENV-05-trailing-byte", "envelope", "Valid grant followed by one 0x00 byte.", [valid.clone(), vec![0]].concat(), st("grant_malformed"));
    o.one("ENV-06-untagged", "envelope", "COSE_Sign1 array without tag 18.", valid[1..].to_vec(), st("grant_malformed"));
    o.one("ENV-07-tag-17", "envelope", "Tag 17 (COSE_Mac0) instead of 18.", [vec![0xd1], valid[1..].to_vec()].concat(), st("grant_malformed"));
    o.one("ENV-08-tag-98", "envelope", "Tag 98 (COSE_Sign) instead of 18.", [vec![0xd8, 0x62], valid[1..].to_vec()].concat(), st("grant_malformed"));
    o.one("ENV-09-double-tag", "envelope", "Tag 18 nested twice.", [vec![0xd2], valid.clone()].concat(), st("grant_malformed"));
    o.one("ENV-10-tag-non-minimal", "envelope", "Tag 18 encoded with a one-byte argument (0xd8 0x12).",
        [vec![0xd8, 0x12], valid[1..].to_vec()].concat(), st("grant_malformed"));
    o.one("ENV-11-array-3", "envelope", "Array of 3 elements (signature omitted).",
        [vec![0xd2], array(&[bstr(&vp), vec![0xa0], bstr(&vpl)])].concat(), st("grant_malformed"));
    o.one("ENV-12-array-5", "envelope", "Array of 5 elements (extra trailing bstr).",
        [vec![0xd2], array(&[bstr(&vp), vec![0xa0], bstr(&vpl), bstr(&vs), bstr(&vs)])].concat(), st("grant_malformed"));
    {
        let mut v = vec![0xd2, 0x9f];
        v.extend(bstr(&vp));
        v.push(0xa0);
        v.extend(bstr(&vpl));
        v.extend(bstr(&vs));
        v.push(0xff);
        o.one("ENV-13-indefinite-array", "envelope", "Indefinite-length outer array.", v, st("grant_malformed"));
    }
    o.one("ENV-14-array-head-non-minimal", "envelope", "Outer array length encoded as 0x98 0x04.",
        [vec![0xd2, 0x98, 0x04], valid[2..].to_vec()].concat(), st("grant_malformed"));
    {
        let mut pl = vec![0x5b];
        pl.extend((vpl.len() as u64).to_be_bytes());
        pl.extend(&vpl);
        let v = [vec![0xd2, 0x84], bstr(&vp), vec![0xa0], pl, bstr(&vs)].concat();
        o.one("ENV-15-payload-length-non-minimal", "envelope", "Payload bstr length encoded with an 8-byte argument.", v, st("grant_malformed"));
    }
    {
        let mut pl = vec![0x5f];
        pl.extend(bstr(&vpl[..10]));
        pl.extend(bstr(&vpl[10..]));
        pl.push(0xff);
        let v = [vec![0xd2, 0x84], bstr(&vp), vec![0xa0], pl, bstr(&vs)].concat();
        o.one("ENV-16-payload-indefinite-bstr", "envelope", "Payload as an indefinite-length (chunked) byte string.", v, st("grant_malformed"));
    }
    o.one("ENV-17-signature-63-bytes", "envelope", "Signature truncated to 63 bytes.", envelope(&vp, &[0xa0], &vpl, &vs[..63]), st("grant_malformed"));
    o.one("ENV-18-signature-65-bytes", "envelope", "Signature with one extra byte.",
        envelope(&vp, &[0xa0], &vpl, &[vs.clone(), vec![0]].concat()), st("grant_malformed"));
    o.one("ENV-19-payload-nil", "envelope", "Detached payload (nil, 0xf6) is not supported.",
        [vec![0xd2, 0x84], bstr(&vp), vec![0xa0, 0xf6], bstr(&vs)].concat(), st("grant_malformed"));
    o.one("ENV-20-unprotected-not-map", "envelope", "Unprotected header encoded as an empty bstr instead of a map.",
        envelope(&vp, &[0x40], &vpl, &vs), st("grant_malformed"));
    o.one("ENV-21-protected-not-bstr", "envelope", "Protected header given as a bare map instead of a bstr.",
        [vec![0xd2, 0x84], vp.clone(), vec![0xa0], bstr(&vpl), bstr(&vs)].concat(), st("grant_malformed"));
    o.one("ENV-22-envelope-is-map", "envelope", "Tag 18 wrapping a map.",
        [vec![0xd2], map(&[(uint(0), bstr(&vp))])].concat(), st("grant_malformed"));
    o.one("ENV-23-huge-declared-length", "envelope", "Payload bstr declares 2^32 bytes; must fail without allocating.",
        [vec![0xd2, 0x84], bstr(&vp), vec![0xa0, 0x5b, 0, 0, 0, 1, 0, 0, 0, 0]].concat(), st("grant_malformed"));

    // ---------------- Step 3-4: headers and key lookup (each correctly signed by key A over its header)
    let hdr = |id: &str, desc: &str, prot: Vec<u8>, exp: &str, o: &mut Out| {
        o.one(id, "header", desc, G::transfer(id).prot(prot).build(), st(exp));
    };
    {
        let g = G::transfer("HDR-01");
        let (p, pl, _) = g.parts();
        let s = g.sign(&p, &pl);
        o.one("HDR-01-alg-in-unprotected", "header", "Unprotected header {1: -19} (label present in both headers).",
            envelope(&p, &map(&[(uint(1), nint(-19))]), &pl, &s), st("grant_header_invalid"));
        let p2 = map(&[(uint(1), nint(-19)), (uint(16), tstr(TYP))]);
        let s2 = g.sign(&p2, &pl);
        o.one("HDR-02-kid-only-in-unprotected", "header", "kid moved from the protected to the unprotected header.",
            envelope(&p2, &map(&[(uint(4), bstr(&a_kid))]), &pl, &s2), st("grant_header_invalid"));
    }
    hdr("HDR-03-missing-typ", "Protected header without typ (16).",
        map(&[(uint(1), nint(-19)), (uint(4), bstr(&a_kid))]), "grant_header_invalid", &mut o);
    hdr("HDR-04-missing-kid", "Protected header without kid (4).",
        map(&[(uint(1), nint(-19)), (uint(16), tstr(TYP))]), "grant_header_invalid", &mut o);
    hdr("HDR-05-missing-alg", "Protected header without alg (1).",
        map(&[(uint(4), bstr(&a_kid)), (uint(16), tstr(TYP))]), "grant_header_invalid", &mut o);
    hdr("HDR-06-extra-crit", "Extra protected label 2 (crit).",
        map(&[(uint(1), nint(-19)), (uint(2), array(&[uint(16)])), (uint(4), bstr(&a_kid)), (uint(16), tstr(TYP))]),
        "grant_header_invalid", &mut o);
    hdr("HDR-07-extra-content-type", "Extra protected label 3 (content type).",
        map(&[(uint(1), nint(-19)), (uint(3), tstr("application/cbor")), (uint(4), bstr(&a_kid)), (uint(16), tstr(TYP))]),
        "grant_header_invalid", &mut o);
    hdr("HDR-08-extra-unknown-label", "Extra protected label 99.",
        map(&[(uint(1), nint(-19)), (uint(4), bstr(&a_kid)), (uint(16), tstr(TYP)), (uint(99), uint(0))]),
        "grant_header_invalid", &mut o);
    hdr("HDR-09-typ-receipt", "typ of another Nodkey object (application/nodkey-receipt+cbor).",
        std_protected(-19, &a_kid, "application/nodkey-receipt+cbor"), "grant_header_invalid", &mut o);
    hdr("HDR-10-typ-generic-cose", "typ application/cose.", std_protected(-19, &a_kid, "application/cose"), "grant_header_invalid", &mut o);
    hdr("HDR-11-typ-as-uint", "typ given as a CoAP content-format integer.",
        map(&[(uint(1), nint(-19)), (uint(4), bstr(&a_kid)), (uint(16), uint(61))]), "grant_header_invalid", &mut o);
    hdr("HDR-12-kid-15-bytes", "kid of 15 bytes.", std_protected(-19, &a_kid[..15], TYP), "grant_header_invalid", &mut o);
    hdr("HDR-13-kid-17-bytes", "kid of 17 bytes.", std_protected(-19, &[a_kid.to_vec(), vec![0]].concat(), TYP), "grant_header_invalid", &mut o);
    hdr("HDR-14-kid-as-text", "kid given as tstr (hex of the real kid).",
        map(&[(uint(1), nint(-19)), (uint(4), tstr(&hex(&a_kid))), (uint(16), tstr(TYP))]), "grant_header_invalid", &mut o);
    hdr("HDR-15-unsorted-labels", "Protected labels in order 4, 1, 16 (not deterministic).",
        cbor::map_raw(&[(uint(4), bstr(&a_kid)), (uint(1), nint(-19)), (uint(16), tstr(TYP))]), "grant_header_invalid", &mut o);
    hdr("HDR-16-alg-non-minimal", "alg -19 encoded as 0x38 0x12 (non-minimal).",
        cbor::map_raw(&[(uint(1), vec![0x38, 0x12]), (uint(4), bstr(&a_kid)), (uint(16), tstr(TYP))]), "grant_header_invalid", &mut o);
    hdr("HDR-17-protected-empty-bstr", "Protected header is the zero-length bstr.", vec![], "grant_header_invalid", &mut o);
    hdr("HDR-18-protected-empty-map", "Protected header is an encoded empty map.", map(&[]), "grant_header_invalid", &mut o);
    hdr("HDR-19-protected-trailing-byte", "Protected header bstr has a byte after the map.",
        [std_protected(-19, &a_kid, TYP), vec![0]].concat(), "grant_header_invalid", &mut o);
    hdr("HDR-20-alg-text", "alg given as tstr \"EdDSA\".",
        map(&[(uint(1), tstr("EdDSA")), (uint(4), bstr(&a_kid)), (uint(16), tstr(TYP))]), "grant_header_invalid", &mut o);
    hdr("HDR-21-alg-minus-8", "alg -8 (polymorphic EdDSA) disagrees with the key registry (Ed25519 = -19).",
        std_protected(-8, &a_kid, TYP), "grant_alg_mismatch", &mut o);
    hdr("HDR-22-alg-minus-7", "alg -7 (ES256) disagrees with the key registry.", std_protected(-7, &a_kid, TYP), "grant_alg_mismatch", &mut o);
    hdr("HDR-23-alg-zero", "alg 0 (reserved) disagrees with the key registry.", std_protected(0, &a_kid, TYP), "grant_alg_mismatch", &mut o);

    o.one("KEY-01-unknown-kid", "key", "Signed by key B under B's own kid; B is not in the registry.",
        G::transfer("KEY-01").signer("B").kid(kid_of("B")).build(), st("grant_unknown_kid"));
    o.one("KEY-02-unknown-kid-random", "key", "kid of 16 0x00 bytes, signed by A.",
        G::transfer("KEY-02").kid([0; 16]).build(), st("grant_unknown_kid"));
    o.one("KEY-03-revoked-key", "key", "Signed by key C, registered with status revoked.",
        G::transfer("KEY-03").signer("C").kid(kid_of("C")).build(), st("grant_key_revoked"));
    o.one("KEY-04-key-outside-window", "key", "Signed by key D, whose validity window ended before the test time.",
        G::transfer("KEY-04").signer("D").kid(kid_of("D")).build(), st("grant_key_inactive"));

    // ---------------- Step 5: signature
    o.one("SIG-01-wrong-key", "signature", "kid of key A, signature by key B.",
        G::transfer("SIG-01").signer("B").build(), st("grant_signature_invalid"));
    {
        let g = G::transfer("SIG-02");
        let (p, pl, s) = g.parts();
        let p_e = std_protected(-19, &kid_of("E"), TYP);
        o.one("SIG-02-kid-swapped-post-signing", "signature",
            "Signed by A under A's kid; kid then replaced by key E's (active, registered).",
            envelope(&p_e, &[0xa0], &pl, &s), st("grant_signature_invalid"));
        let mut r = s.clone();
        r[0] ^= 0x01;
        o.one("SIG-03-signature-R-bitflip", "signature", "One bit flipped in R.", envelope(&p, &[0xa0], &pl, &r), st("grant_signature_invalid"));
        let mut sb = s.clone();
        sb[32] ^= 0x01;
        o.one("SIG-04-signature-S-bitflip", "signature", "One bit flipped in S.", envelope(&p, &[0xa0], &pl, &sb), st("grant_signature_invalid"));
        let mal = [s[..32].to_vec(), add_l(&s[32..])].concat();
        o.one("SIG-05-malleable-S-plus-L", "signature",
            "S replaced by S + L (non-canonical scalar). Lax verifiers that reduce S mod L accept it; verify_strict must not.",
            envelope(&p, &[0xa0], &pl, &mal), st("grant_signature_invalid"));
        o.one("SIG-06-signature-zero", "signature", "Signature of 64 zero bytes.", envelope(&p, &[0xa0], &pl, &[0u8; 64]), st("grant_signature_invalid"));
    }
    o.one("SIG-07-signed-for-other-audience", "signature",
        "Grant for nodkey.broker.other-test (aud field and external_aad) presented to nodkey.broker.ledger-test.",
        G::transfer("SIG-07").set(2, tstr(OTHER_BROKER)).aad(aad(AAD_TAG, OTHER_BROKER)).build(), st("grant_signature_invalid"));
    o.one("SIG-08-aad-wrong-domain-tag", "signature", "external_aad built with tag nodkey.receipt.v1.",
        G::transfer("SIG-08").aad(aad(b"nodkey.receipt.v1", BROKER)).build(), st("grant_signature_invalid"));
    o.one("SIG-09-aad-empty", "signature", "Signed with an empty external_aad.",
        G::transfer("SIG-09").aad(vec![]).build(), st("grant_signature_invalid"));
    o.one("SIG-10-aad-no-separator", "signature", "external_aad without the 0x00 separator.",
        G::transfer("SIG-10").aad([AAD_TAG, BROKER.as_bytes()].concat()).build(), st("grant_signature_invalid"));
    {
        let g = G::transfer("SIG-11");
        let (p, pl, _) = g.parts();
        let msg = array(&[tstr("Signature"), bstr(&p), bstr(&[]), bstr(&g.aad), bstr(&pl)]);
        let s = signing_key("A").sign(&msg).to_bytes();
        o.one("SIG-11-cose-sign-context", "signature", "Signed over a COSE_Sign (\"Signature\") structure instead of Sig_structure1.",
            envelope(&p, &[0xa0], &pl, &s), st("grant_signature_invalid"));
        let s2 = signing_key("A").sign(&pl).to_bytes();
        o.one("SIG-12-raw-payload-signed", "signature", "Ed25519 signature over the payload bytes alone.",
            envelope(&p, &[0xa0], &pl, &s2), st("grant_signature_invalid"));
    }
    // Each payload field altered after signing.
    let alterations: [(u64, &str, Vec<u8>); 17] = [
        (0, "ver", uint(2)),
        (1, "iss", tstr("nodkey.authority.tesu")),
        (2, "aud", tstr("nodkey.broker.ledger-tesu")),
        (3, "jti", bstr(&[0x55; 16])),
        (4, "iat", uint(T0 - 1)),
        (5, "nbf", uint(T0 + 1)),
        (6, "exp", uint(T0 + 29)),
        (7, "wid", tstr(APP2)),
        (8, "ten", tstr("globex")),
        (9, "sub", tstr("user:u-18")),
        (10, "op", tstr("ledger.get_balance")),
        (11, "opv", uint(2)),
        (12, "res", map(&[(uint(0), tstr("mallory"))])),
        (13, "con", map(&[(uint(0), con_exact(tstr("bob"))), (uint(1), con_exact(uint(1_250_000)))])),
        (14, "use", uint(2)),
        (17, "knd", uint(2)),
        (18, "cfm", uint(0)),
    ];
    for (k, name, val) in alterations {
        let id = format!("SIG-{}-altered-{name}", 20 + k);
        let g = G::transfer(&id);
        let (p, _, s) = g.parts();
        let altered = g.clone().set(k, val).payload();
        o.one(&id, "signature", &format!("Payload field {k} ({name}) altered after signing."),
            envelope(&p, &[0xa0], &altered, &s), st("grant_signature_invalid"));
    }

    // ---------------- Step 6: payload decoding (all correctly signed)
    let pdec = |id: &str, desc: &str, payload: Vec<u8>, o: &mut Out| {
        o.one(id, "payload-decode", desc, G::transfer(id).build_raw(&payload), st("grant_payload_malformed"));
    };
    let entries = |id: &str| -> Vec<(Vec<u8>, Vec<u8>)> {
        G::transfer(id).fields.iter().map(|(k, v)| (uint(*k), v.clone())).collect()
    };
    pdec("PDEC-01-int-non-minimal", "ver encoded as 0x18 0x01.", G::transfer("PDEC-01").set(0, vec![0x18, 0x01]).payload(), &mut o);
    pdec("PDEC-02-text-length-non-minimal", "iss (23 bytes) with its length encoded as 0x78 0x17.",
        G::transfer("PDEC-02").set(1, [vec![0x78, 23], ISS.as_bytes().to_vec()].concat()).payload(), &mut o);
    {
        let mut p = vec![0xb8, 17];
        p.extend(&G::transfer("PDEC-03").payload()[1..]);
        pdec("PDEC-03-map-head-non-minimal", "Top-level map count (17) encoded as 0xb8 0x11.", p, &mut o);
    }
    {
        let mut e = entries("PDEC-04");
        e.swap(0, 1);
        pdec("PDEC-04-keys-unsorted", "Keys 1 and 0 swapped.", cbor::map_raw(&e), &mut o);
    }
    {
        let mut e = entries("PDEC-05");
        e.insert(7, (uint(6), uint(T0 + 3600)));
        pdec("PDEC-05-duplicate-key-exp", "Key 6 (exp) appears twice; the second would widen the window.", cbor::map_raw(&e), &mut o);
    }
    {
        let mut e = entries("PDEC-06");
        e.push((uint(13), map(&[(uint(0), con_exact(tstr("mallory")))])));
        let last = e.pop().unwrap();
        let pos = e.iter().position(|(k, _)| *k == uint(13)).unwrap();
        e.insert(pos, last);
        pdec("PDEC-06-duplicate-key-con", "Key 13 (con) appears twice with different values.", cbor::map_raw(&e), &mut o);
    }
    {
        let mut p = vec![0xbf];
        for (k, v) in entries("PDEC-07") {
            p.extend(k);
            p.extend(v);
        }
        p.push(0xff);
        pdec("PDEC-07-indefinite-map", "Top-level map with indefinite length.", p, &mut o);
    }
    {
        let mut s = vec![0x7f];
        s.extend(tstr("user:"));
        s.extend(tstr("u-17"));
        s.push(0xff);
        pdec("PDEC-08-indefinite-text", "sub as an indefinite-length text string.", G::transfer("PDEC-08").set(9, s).payload(), &mut o);
    }
    {
        let mut con = vec![0xa2, 0x00, 0x9f, 0x00];
        con.extend(tstr("bob"));
        con.push(0xff);
        con.extend([0x01]);
        con.extend(con_exact(uint(12_500)));
        pdec("PDEC-09-indefinite-array-in-con", "con entry 0 as an indefinite-length array.", G::transfer("PDEC-09").set(13, con).payload(), &mut o);
    }
    {
        let mut f = vec![0xfb];
        f.extend(((T0 + 30) as f64).to_be_bytes());
        pdec("PDEC-10-float-exp", "exp as a float64 with the correct numeric value.", G::transfer("PDEC-10").set(6, f).payload(), &mut o);
    }
    pdec("PDEC-11-half-float-use", "use as float16 1.0 (0xf9 0x3c00).", G::transfer("PDEC-11").set(14, vec![0xf9, 0x3c, 0x00]).payload(), &mut o);
    pdec("PDEC-12-negative-int", "exp as negative integer -1.", G::transfer("PDEC-12").set(6, nint(-1)).payload(), &mut o);
    pdec("PDEC-13-tag-in-payload", "exp wrapped in tag 1 (epoch time).", G::transfer("PDEC-13").set(6, cbor::tag(1, &uint(T0 + 30))).payload(), &mut o);
    pdec("PDEC-14-bool", "use as true (0xf5).", G::transfer("PDEC-14").set(14, vec![0xf5]).payload(), &mut o);
    pdec("PDEC-15-null", "res as null (0xf6).", G::transfer("PDEC-15").set(12, vec![0xf6]).payload(), &mut o);
    pdec("PDEC-16-trailing-byte", "Payload map followed by one 0x00 byte.", [G::transfer("PDEC-16").payload(), vec![0]].concat(), &mut o);
    {
        let p = G::transfer("PDEC-17").payload();
        pdec("PDEC-17-truncated", "Payload map with its last byte removed.", p[..p.len() - 1].to_vec(), &mut o);
    }
    pdec("PDEC-18-invalid-utf8", "sub contains the invalid UTF-8 sequence 0xc3 0x28.",
        G::transfer("PDEC-18").set(9, [vec![0x67], b"user:".to_vec(), vec![0xc3, 0x28]].concat()).payload(), &mut o);
    pdec("PDEC-19-depth-4", "con entry value nested one array deeper than allowed (depth 4).",
        G::transfer("PDEC-19").set(13, map(&[(uint(0), array(&[uint(0), array(&[tstr("bob")])]))])).payload(), &mut o);

    // ---------------- Step 7: payload schema
    let psch = |id: &str, desc: &str, g: G, exp: &str, o: &mut Out| {
        o.one(id, "payload-schema", desc, g.build(), st(exp));
    };
    o.one("PSCH-01-payload-array", "payload-schema", "Payload is an array.",
        G::transfer("PSCH-01").build_raw(&array(&[uint(1)])), st("grant_payload_invalid"));
    o.one("PSCH-02-payload-uint", "payload-schema", "Payload is the integer 1.",
        G::transfer("PSCH-02").build_raw(&uint(1)), st("grant_payload_invalid"));
    psch("PSCH-03-unknown-key-21", "Unknown top-level key 21.", G::transfer("PSCH-03").set(21, uint(0)), "grant_payload_invalid", &mut o);
    psch("PSCH-04-reserved-key-15-epo", "Reserved key 15 (removed epo).", G::transfer("PSCH-04").set(15, uint(0)), "grant_payload_invalid", &mut o);
    psch("PSCH-05-reserved-key-16-rqh", "Reserved key 16 (removed rqh).", G::transfer("PSCH-05").set(16, bstr(&[0; 32])), "grant_payload_invalid", &mut o);
    {
        let mut e = entries("PSCH-06");
        e.push((tstr("exp"), uint(T0 + 30)));
        o.one("PSCH-06-text-key", "payload-schema", "Extra text key \"exp\".",
            G::transfer("PSCH-06").build_raw(&cbor::map_raw(&e)), st("grant_payload_invalid"));
    }
    let names = [
        (0, "ver"), (1, "iss"), (2, "aud"), (3, "jti"), (4, "iat"), (5, "nbf"), (6, "exp"), (7, "wid"), (8, "ten"),
        (9, "sub"), (10, "op"), (11, "opv"), (12, "res"), (13, "con"), (14, "use"), (17, "knd"), (18, "cfm"),
    ];
    for (i, (k, name)) in names.iter().enumerate() {
        let id = format!("PSCH-{}-missing-{name}", 10 + i);
        psch(&id, &format!("Write grant: required key {k} ({name}) absent."), G::transfer(&id).del(*k), "grant_payload_invalid", &mut o);
    }
    let bad: Vec<(&str, &str, u64, Vec<u8>, &str)> = vec![
        ("PSCH-30-exp-text", "exp as tstr.", 6, tstr("1792886430"), "grant_payload_invalid"),
        ("PSCH-31-iat-bytes", "iat as bstr.", 4, bstr(&T0.to_be_bytes()), "grant_payload_invalid"),
        ("PSCH-32-jti-15-bytes", "jti of 15 bytes.", 3, bstr(&[7; 15]), "grant_payload_invalid"),
        ("PSCH-33-jti-17-bytes", "jti of 17 bytes.", 3, bstr(&[7; 17]), "grant_payload_invalid"),
        ("PSCH-34-jti-text", "jti as tstr.", 3, tstr("0123456789abcdef"), "grant_payload_invalid"),
        ("PSCH-35-ver-2", "ver = 2.", 0, uint(2), "grant_version_unsupported"),
        ("PSCH-36-ver-0", "ver = 0.", 0, uint(0), "grant_version_unsupported"),
        ("PSCH-37-ver-text", "ver as tstr \"1\".", 0, tstr("1"), "grant_payload_invalid"),
        ("PSCH-38-use-0", "use = 0.", 14, uint(0), "grant_payload_invalid"),
        ("PSCH-39-use-2", "use = 2 (multi-use not supported in v1).", 14, uint(2), "grant_payload_invalid"),
        ("PSCH-40-op-uppercase", "op with an uppercase letter.", 10, tstr("Ledger.transfer"), "grant_payload_invalid"),
        ("PSCH-41-op-empty", "op empty.", 10, tstr(""), "grant_payload_invalid"),
        ("PSCH-42-ten-nul", "ten contains NUL.", 8, tstr("ac\u{0}me"), "grant_payload_invalid"),
        ("PSCH-43-ten-non-ascii", "ten contains U+00E9 (valid UTF-8, outside the ID alphabet).", 8, tstr("acm\u{e9}"), "grant_payload_invalid"),
        ("PSCH-44-ten-empty", "ten empty.", 8, tstr(""), "grant_payload_invalid"),
        ("PSCH-45-iss-space", "iss contains a space.", 1, tstr("nodkey authority.test"), "grant_payload_invalid"),
        ("PSCH-46-sub-257", "sub of 257 bytes (max 256).", 9, tstr(&"u".repeat(257)), "grant_payload_invalid"),
        ("PSCH-47-exp-2pow53", "exp = 2^53 (max 2^53 - 1).", 6, uint(1 << 53), "grant_payload_invalid"),
        ("PSCH-48-opv-0", "opv = 0.", 11, uint(0), "grant_payload_invalid"),
        ("PSCH-49-con-value-not-array", "con entry 0 is a bare tstr.", 13, map(&[(uint(0), tstr("bob"))]), "grant_payload_invalid"),
        ("PSCH-50-con-array-3", "con entry 0 is a 3-element array.", 13, map(&[(uint(0), array(&[uint(0), tstr("bob"), uint(0)]))]), "grant_payload_invalid"),
        ("PSCH-51-con-class-2", "con entry with class 2 (undefined).", 13, map(&[(uint(0), array(&[uint(2), tstr("bob")]))]), "grant_payload_invalid"),
        ("PSCH-52-con-bounded-text", "Bounded (class 1) entry with a tstr ceiling.", 13, map(&[(uint(1), array(&[uint(1), tstr("50000")]))]), "grant_payload_invalid"),
        ("PSCH-53-res-value-bytes", "res value as bstr.", 12, map(&[(uint(0), bstr(b"alice"))]), "grant_payload_invalid"),
        ("PSCH-54-res-key-16", "res key 16 (max 15).", 12, map(&[(uint(16), tstr("alice"))]), "grant_payload_invalid"),
        ("PSCH-55-con-key-text", "con with a text key.", 13, map(&[(tstr("to"), con_exact(tstr("bob")))]), "grant_payload_invalid"),
        ("PSCH-56-res-value-control-char", "res value contains LF.", 12, map(&[(uint(0), tstr("alice\n"))]), "grant_payload_invalid"),
        ("PSCH-57-res-not-map", "res as an array.", 12, array(&[tstr("alice")]), "grant_payload_invalid"),
    ];
    for (id, desc, k, v, exp) in bad {
        psch(id, desc, G::transfer(id).set(k, v), exp, &mut o);
    }
    let rd = |id: &str| G::balance(id);
    let read_bad: Vec<(&str, &str, G)> = vec![
        ("PSCH-60-knd-3", "knd = 3 (undefined).", G::transfer("PSCH-60").set(17, uint(3))),
        ("PSCH-61-cfm-2", "cfm = 2 without mid (20).", G::transfer("PSCH-61").set(18, uint(2))),
        ("PSCH-62-read-with-con", "Read grant carrying con (13).", rd("PSCH-62").set(13, map(&[]))),
        ("PSCH-63-read-with-cfm", "Read grant carrying cfm (18).", rd("PSCH-63").set(18, uint(1))),
        ("PSCH-64-read-with-op", "Read grant carrying op (10).", rd("PSCH-64").set(10, tstr("ledger.get_balance"))),
        ("PSCH-65-read-missing-rop", "Read grant without rop (19).", rd("PSCH-65").del(19)),
        ("PSCH-66-read-missing-jti", "Read grant without jti (3).", rd("PSCH-66").del(3)),
        ("PSCH-67-read-rop-empty", "Read grant with an empty rop map.", rd("PSCH-67").set(19, map(&[]))),
        ("PSCH-68-read-rop-uint-key", "rop keyed by integer.", rd("PSCH-68").set(19, map(&[(uint(0), uint(1))]))),
        ("PSCH-69-read-rop-opv-0", "rop entry with opv 0.", rd("PSCH-69").set(19, map(&[(tstr("ledger.get_balance"), uint(0))]))),
        ("PSCH-70-write-with-rop", "Write grant carrying rop (19).", G::transfer("PSCH-70").set(19, map(&[(tstr("ledger.get_balance"), uint(1))]))),
        ("PSCH-71-write-knd-read-fields", "Write fields with knd = 2.", G::transfer("PSCH-71").set(17, uint(2))),
    ];
    for (id, desc, g) in read_bad {
        o.one(id, "payload-schema", desc, g.build(), st("grant_payload_invalid").req(balance_req()));
    }

    // ---------------- Step 8: issuer and time
    o.one("ISS-01-issuer-of-other-key", "issuer", "iss names another issuer than the one registered for key A.",
        G::transfer("ISS-01").set(1, tstr(OTHER_ISS)).build(), st("grant_issuer_mismatch"));
    o.one("ISS-02-issuer-unknown", "issuer", "iss names an unregistered issuer.",
        G::transfer("ISS-02").set(1, tstr("evil.authority")).build(), st("grant_issuer_mismatch"));
    let exp = T0 + MAX_TTL;
    o.one("TIME-01-expired", "time", "now = exp + skew + 100.", G::transfer("TIME-01").build(), st("grant_expired").now(exp + SKEW + 100));
    o.one("TIME-02-expired-boundary", "time", "now = exp + skew: first rejected second.", G::transfer("TIME-02").build(), st("grant_expired").now(exp + SKEW));
    o.one("TIME-03-expiry-boundary-accept", "time", "now = exp + skew - 1: last accepted second.", G::transfer("TIME-03").build(), st("ACCEPT").now(exp + SKEW - 1));
    o.one("TIME-04-not-yet-valid", "time", "now = nbf - 100.", G::transfer("TIME-04").build(), st("grant_not_yet_valid").now(T0 - 100));
    o.one("TIME-05-not-yet-valid-boundary", "time", "now = nbf - skew - 1: last rejected second.",
        G::transfer("TIME-05").build(), st("grant_not_yet_valid").now(T0 - SKEW - 1));
    o.one("TIME-06-nbf-boundary-accept", "time", "now = nbf - skew: first accepted second.", G::transfer("TIME-06").build(), st("ACCEPT").now(T0 - SKEW));
    o.one("TIME-07-ttl-31", "time", "exp - iat = 31 > max_ttl (30).", G::transfer("TIME-07").set(6, uint(T0 + 31)).build(), st("grant_ttl_exceeded"));
    o.one("TIME-08-nbf-before-iat", "time", "nbf = iat - 1.", G::transfer("TIME-08").set(5, uint(T0 - 1)).build(), st("grant_time_invalid"));
    o.one("TIME-09-exp-equals-nbf", "time", "exp = nbf (empty window).", G::transfer("TIME-09").set(6, uint(T0)).build(), st("grant_time_invalid"));
    o.one("TIME-10-exp-before-nbf", "time", "exp = nbf - 1.", G::transfer("TIME-10").set(6, uint(T0 - 1)).build(), st("grant_time_invalid"));
    o.one("TIME-12-read-grant-expired", "time", "Read grants expire like write grants: now = exp + skew.",
        G::balance("TIME-12").build(), st("grant_expired").req(balance_req()).now(exp + SKEW));
    const YEAR: u64 = 31_536_000;
    o.one("TIME-13-nbf-iat-equals-skew", "time", "nbf - iat = skew (5 s), exp - iat = 30: accepted.",
        G::transfer("TIME-13").times(T0 - 5, T0, T0 + 25).build(), st("ACCEPT"));
    o.one("TIME-14-nbf-iat-exceeds-skew", "time", "nbf - iat = 6 > skew.",
        G::transfer("TIME-14").times(T0 - 6, T0, T0 + 24).build(), st("grant_time_invalid"));
    o.one("TIME-15-future-dated-issuance", "time", "iat = nbf = one year after now (future-dated issuance).",
        G::transfer("TIME-15").times(T0 + YEAR, T0 + YEAR, T0 + YEAR + 30).build(), st("grant_not_yet_valid"));
    o.one("TIME-16-nbf-far-beyond-iat", "time",
        "iat = T, nbf = T + 30 days, exp = nbf + 30, presented inside that window (key still valid): rejected because nbf - iat > skew (GS-01).",
        G::transfer("TIME-16").times(T0, T0 + 30 * 86_400, T0 + 30 * 86_400 + 30).build(), st("grant_time_invalid").now(T0 + 30 * 86_400 + 1));
    o.one("TIME-17-ttl-from-iat", "time", "iat = T, nbf = T + 1, exp = T + 31: exp - nbf = 30 but exp - iat = 31.",
        G::transfer("TIME-17").times(T0, T0 + 1, T0 + 31).build(), st("grant_ttl_exceeded"));
    o.one("TIME-18-iat-just-beyond-skew", "time", "iat = nbf = now + skew + 1.",
        G::transfer("TIME-18").build(), st("grant_not_yet_valid").now(T0 - SKEW - 1));
    o.one("TIME-11-long-ttl-far-future", "time", "exp = 2^53 - 1 (would overflow naive arithmetic only if unchecked); TTL exceeded.",
        G::transfer("TIME-11").set(6, uint((1 << 53) - 1)).build(), st("grant_ttl_exceeded"));

    // ---------------- Step 9: binding to trusted context
    o.one("BIND-01-audience-field", "binding", "aud field names another broker; external_aad is this broker's (so the signature verifies).",
        G::transfer("BIND-01").set(2, tstr(OTHER_BROKER)).build(), st("grant_audience_mismatch"));
    o.one("BIND-02-workload-other-peer", "binding", "Grant for app1 presented over app2's socket.",
        G::transfer("BIND-02").build(), st("grant_workload_mismatch").peer(APP2));
    o.one("BIND-03-workload-other-grant", "binding", "Grant for app2 presented over app1's socket.",
        G::transfer("BIND-03").set(7, tstr(APP2)).build(), st("grant_workload_mismatch"));
    o.one("BIND-04-tenant-not-registered", "binding", "Grant for tenant globex presented by app1 (registered for acme only).",
        G::transfer("BIND-04").set(8, tstr("globex")).build(), st("grant_tenant_mismatch"));
    o.one("BIND-05-tenant-unknown", "binding", "Grant for tenant initech presented by app2 (acme, globex).",
        G::transfer("BIND-05").set(7, tstr(APP2)).set(8, tstr("initech")).build(), st("grant_tenant_mismatch").peer(APP2));
    o.one("BIND-06-tenant-case", "binding", "Tenant \"Acme\": comparisons are byte-exact, no case folding.",
        G::transfer("BIND-06").set(8, tstr("Acme")).build(), st("grant_tenant_mismatch"));

    // ---------------- Step 10: operation
    o.one("OP-01-read-grant-for-write-op", "operation",
        "Read grant for ledger.get_balance presented for ledger.transfer: a read grant never authorizes a write.",
        G::balance("OP-01").build(), st("grant_kind_mismatch"));
    o.one("OP-07-read-grant-lists-write-op", "operation",
        "Read grant whose operation set includes ledger.transfer (a write op), presented for ledger.transfer.",
        G::read("OP-07", &[("ledger.get_balance", 1), ("ledger.transfer", 1)]).build(), st("grant_kind_mismatch"));
    o.one("OP-08-read-grant-lists-write-op-read-request", "operation",
        "Same malformed read grant presented for the read op ledger.get_balance: the whole grant is rejected.",
        G::read("OP-08", &[("ledger.get_balance", 1), ("ledger.transfer", 1)]).build(), st("grant_kind_mismatch").req(balance_req()));
    o.one("OP-09-write-grant-for-read-op", "operation", "Write grant (knd = 1) naming the read op ledger.get_balance.",
        G::transfer("OP-09").set(10, tstr("ledger.get_balance")).set(12, map(&[(uint(0), tstr("alice"))])).set(13, map(&[])).build(),
        st("grant_kind_mismatch").req(balance_req()));
    o.one("OP-10-read-op-not-in-set", "operation", "Read grant for ledger.list_transfers presented for ledger.get_balance.",
        G::read("OP-10", &[("ledger.list_transfers", 1)]).build(), st("grant_op_mismatch").req(balance_req()));
    o.one("OP-11-read-undeclared-op-in-set", "operation", "Read grant whose set includes the undeclared op ledger.audit.",
        G::read("OP-11", &[("ledger.audit", 1), ("ledger.get_balance", 1)]).build(), st("grant_op_mismatch").req(balance_req()));
    o.one("OP-12-read-opv-unsupported", "operation", "Read grant naming ledger.get_balance version 2.",
        G::read("OP-12", &[("ledger.get_balance", 2)]).build(), st("grant_opv_unsupported").req(balance_req()));
    o.one("OP-13-confirmation-required", "operation",
        "ledger.transfer requires auth-origin confirmation; otherwise valid grant has cfm = 0.",
        G::transfer("OP-13").set(18, uint(0)).build(), st("grant_confirmation_required"));
    o.one("OP-02-grant-transfer-request-balance", "operation", "Grant for ledger.transfer, request ledger.get_balance.",
        G::transfer("OP-02").build(), st("grant_op_mismatch").req(balance_req()));
    o.one("OP-03-undeclared-op", "operation", "Grant for undeclared op ledger.delete, request ledger.transfer.",
        G::transfer("OP-03").set(10, tstr("ledger.delete")).build(), st("grant_op_mismatch"));
    o.one("OP-04-opv-unsupported", "operation", "opv = 2; the broker supports only version 1 of ledger.transfer.",
        G::transfer("OP-04").set(11, uint(2)).build(), st("grant_opv_unsupported"));
    o.one("OP-14-rop-unsupported-opv-not-requested", "operation",
        "Read grant lists get_balance:1 and list_transfers:9; request get_balance. Every rop entry is checked: whole grant rejected.",
        G::read("OP-14", &[("ledger.get_balance", 1), ("ledger.list_transfers", 9)]).build(), st("grant_opv_unsupported").req(balance_req()));

    // ---------------- Draft 4: mandate-issued write grants (cfm = 2, mid)
    let mnd = |id: &str, desc: &str, grant: Vec<u8>, step: Step, o: &mut Out| o.one(id, "mandate", desc, grant, step);
    let mreq = || mandated_req();
    mnd("MND-01-mandated-valid", "test.mandated (mandate_eligible) with cfm = 2 and a 16-byte mid.",
        G::mandated("MND-01").build(), st("ACCEPT").req(mreq()), &mut o);
    mnd("MND-02-mandated-transfer-not-eligible", "cfm = 2 with mid on ledger.transfer, which requires confirmation but is not mandate_eligible.",
        G::transfer("MND-02").set(18, uint(2)).set(20, bstr(&test_mid())).build(), st("grant_confirmation_required"), &mut o);
    mnd("MND-03-mandated-unconfirmed-op", "cfm = 2 with mid on test.hold, a write without requires_confirmation (hence not mandate_eligible).",
        G::hold("MND-03").set(18, uint(2)).set(20, bstr(&test_mid())).build(),
        st("grant_confirmation_required").req(hold_req(12_500, "EUR", "rent")), &mut o);
    mnd("MND-04-mid-with-cfm-1", "mid (20) present with cfm = 1.",
        G::mandated("MND-04").set(18, uint(1)).build(), st("grant_payload_invalid").req(mreq()), &mut o);
    mnd("MND-05-mid-with-cfm-0", "mid (20) present with cfm = 0.",
        G::mandated("MND-05").set(18, uint(0)).build(), st("grant_payload_invalid").req(mreq()), &mut o);
    mnd("MND-06-mid-15-bytes", "cfm = 2 with a mid of 15 bytes.",
        G::mandated("MND-06").set(20, bstr(&[7; 15])).build(), st("grant_payload_invalid").req(mreq()), &mut o);
    mnd("MND-07-mid-17-bytes", "cfm = 2 with a mid of 17 bytes.",
        G::mandated("MND-07").set(20, bstr(&[7; 17])).build(), st("grant_payload_invalid").req(mreq()), &mut o);
    mnd("MND-08-mid-text", "cfm = 2 with mid as a 16-byte tstr.",
        G::mandated("MND-08").set(20, tstr("0123456789abcdef")).build(), st("grant_payload_invalid").req(mreq()), &mut o);
    mnd("MND-09-read-with-mid", "Read grant carrying mid (20).",
        G::balance("MND-09").set(20, bstr(&test_mid())).build(), st("grant_payload_invalid").req(balance_req()), &mut o);
    mnd("MND-10-cfm-3", "cfm = 3 (undefined), no mid.",
        G::mandated("MND-10").set(18, uint(3)).del(20).build(), st("grant_payload_invalid").req(mreq()), &mut o);
    {
        let g = G::mandated("MND-11");
        let (p, _, s) = g.parts();
        let mut other = test_mid();
        other[0] ^= 0x01;
        let altered = g.clone().set(20, bstr(&other)).payload();
        mnd("MND-11-mid-altered", "Payload field 20 (mid) altered after signing (one bit).",
            envelope(&p, &[0xa0], &altered, &s), st("grant_signature_invalid").req(mreq()), &mut o);
    }
    mnd("MND-12-mandated-op-human-confirmed", "test.mandated with cfm = 1 and no mid: human approval remains valid on a mandate_eligible operation.",
        G::mandated("MND-12").set(18, uint(1)).del(20).build(), st("ACCEPT").req(mreq()), &mut o);

    // ---------------- Step 11: resource and constraints
    o.one("CON-01-amount-exceeds-bound", "constraint", "test.hold: amount_cents = ceiling + 1.",
        G::hold("CON-01").build(), st("grant_bound_exceeded").req(hold_req(50_001, "EUR", "rent")));
    o.one("CON-02-exact-to-mismatch", "constraint", "ledger.transfer: request destination to = mallory; grant binds bob exactly.",
        G::transfer("CON-02").build(), st("grant_constraint_mismatch").req(transfer_req_full("alice", "mallory", 12_500)));
    o.one("CON-03-exact-currency-mismatch", "constraint", "test.hold: request currency USD; grant binds EUR exactly.",
        G::hold("CON-03").build(), st("grant_constraint_mismatch").req(hold_req(12_500, "USD", "rent")));
    o.one("CON-04-resource-mismatch", "constraint", "ledger.transfer: request from = carol; grant res binds alice.",
        G::transfer("CON-04").build(), st("grant_resource_mismatch").req(transfer_req_full("carol", "bob", 12_500)));
    o.one("CON-06-exact-amount-higher", "constraint", "ledger.transfer: amount is exact (Phase 3 profile); request 12501 vs bound 12500.",
        G::transfer("CON-06").build(), st("grant_constraint_mismatch").req(transfer_req_full("alice", "bob", 12_501)));
    o.one("CON-07-exact-amount-lower", "constraint", "ledger.transfer: exact means equal, not at most; request 12499.",
        G::transfer("CON-07").build(), st("grant_constraint_mismatch").req(transfer_req_full("alice", "bob", 12_499)));
    o.one("CON-20-request-exact-wrong-type", "constraint", "Request amount_cents is the string \"12500\"; grant binds uint 12500.",
        G::transfer("CON-20").build(), st("grant_constraint_mismatch").req(json!({"op": "ledger.transfer", "args": {"from": "alice", "to": "bob", "amount_cents": "12500"}})));
    o.one("CON-21-request-bounded-wrong-type", "constraint", "test.hold request amount_cents is a string: not a uint, so not within the bound.",
        G::hold("CON-21").build(), st("grant_constraint_mismatch").req(json!({"op": "test.hold", "args": {"account": "alice", "amount_cents": "50", "currency": "EUR", "memo": "rent"}})));
    o.one("CON-22-request-missing-exact", "constraint", "Request lacks the exact parameter to.",
        G::transfer("CON-22").build(), st("grant_constraint_mismatch").req(json!({"op": "ledger.transfer", "args": {"from": "alice", "amount_cents": 12500}})));
    o.one("CON-23-request-missing-resource", "constraint", "Request lacks the resource parameter from.",
        G::transfer("CON-23").build(), st("grant_resource_mismatch").req(json!({"op": "ledger.transfer", "args": {"to": "bob", "amount_cents": 12500}})));
    o.one("CON-24-con-text-257", "constraint", "test.bulk con value of 257 bytes (max 256): generic shape check fails first.",
        G::bulk("CON-24", &["x".repeat(257)]).build(), st("grant_payload_invalid").req(bulk_req(&["x".repeat(257)])));
    let tr = |id: &str, k: u64, v: Vec<u8>| (G::transfer(id).set(k, v), transfer_req());
    let hd = |id: &str, k: u64, v: Vec<u8>| (G::hold(id).set(k, v), hold_req(12_500, "EUR", "rent"));
    let schema: Vec<(&str, &str, (G, Value))> = vec![
        ("CON-10-missing-exact-param", "ledger.transfer: con lacks the exact parameter amount_cents (key 1).",
            tr("CON-10", 13, map(&[(uint(0), con_exact(tstr("bob")))]))),
        ("CON-11-bounded-encoded-exact", "test.hold: amount (declared bounded) encoded with class 0 (exact).",
            hd("CON-11", 13, map(&[(uint(0), con_exact(uint(12_500))), (uint(1), con_exact(tstr("EUR")))]))),
        ("CON-12-exact-encoded-bounded",
            "ledger.transfer: amount (declared exact) encoded as a bounded ceiling; must not be read as a broader grant.",
            tr("CON-12", 13, map(&[(uint(0), con_exact(tstr("bob"))), (uint(1), con_bound(12_500))]))),
        ("CON-13-free-param-in-con", "test.hold: con carries key 2 for the free parameter memo, which has no con key.",
            hd("CON-13", 13, map(&[(uint(0), con_bound(50_000)), (uint(1), con_exact(tstr("EUR"))), (uint(2), con_exact(tstr("rent")))]))),
        ("CON-14-unknown-con-key", "ledger.transfer: con carries undeclared key 7.",
            tr("CON-14", 13, map(&[(uint(0), con_exact(tstr("bob"))), (uint(1), con_exact(uint(12_500))), (uint(7), con_bound(1))]))),
        ("CON-15-unknown-res-key", "ledger.transfer: res carries undeclared key 1.",
            tr("CON-15", 12, map(&[(uint(0), tstr("alice")), (uint(1), tstr("bob"))]))),
        ("CON-16-res-empty", "ledger.transfer: res is empty; the declaration has res key 0.", tr("CON-16", 12, map(&[]))),
        ("CON-17-res-wrong-type", "ledger.transfer: res key 0 as uint; declared account_id.", tr("CON-17", 12, map(&[(uint(0), uint(1))]))),
        ("CON-18-currency-lowercase", "test.hold: currency \"eur\" violates the declared currency type.",
            hd("CON-18", 13, map(&[(uint(0), con_bound(50_000)), (uint(1), con_exact(tstr("eur")))]))),
        ("CON-19-to-wrong-type", "ledger.transfer: destination to as uint; declared account_id.",
            tr("CON-19", 13, map(&[(uint(0), con_exact(uint(7))), (uint(1), con_exact(uint(12_500)))]))),
    ];
    for (id, desc, (g, req)) in schema {
        o.one(id, "constraint", desc, g.build(), st("grant_op_schema_invalid").req(req));
    }

    // ---------------- Step 12: consumption and replay (each vector starts with an empty replay store)
    o.add("RPL-01-identical-resubmission", "replay",
        "Same grant and same request twice: the second returns the stored outcome without a second effect (ADR-0006 section 5).",
        G::transfer("RPL-01").build(), vec![st("ACCEPT"), st("STORED_OUTCOME:ACCEPT").now(T0 + 12)]);
    o.add("RPL-02-replay-different-request", "replay",
        "test.hold grant used twice; the second request differs (amount still within the bound) and is rejected as a replay.",
        G::hold("RPL-02").build(),
        vec![st("ACCEPT").req(hold_req(12_500, "EUR", "rent")), st("grant_replayed").req(hold_req(40_000, "EUR", "rent")).now(T0 + 12)]);
    o.add("RPL-03-denied-grant-is-consumed", "replay",
        "A verified write grant denied at the constraint step is consumed (DENIED recorded atomically): a different request is a replay, the identical one gets the stored denial.",
        G::hold("RPL-03").build(),
        vec![
            st("grant_bound_exceeded").req(hold_req(60_000, "EUR", "rent")),
            st("grant_replayed").req(hold_req(12_500, "EUR", "rent")).now(T0 + 11),
            st("STORED_OUTCOME:DENIED").req(hold_req(60_000, "EUR", "rent")).now(T0 + 12),
        ]);
    o.add("RPL-08-retry-after-expiry", "replay",
        "Accepted, then the identical request after exp + skew: steps 1-9 run first, so the result is grant_expired, not the stored outcome.",
        G::transfer("RPL-08").build(), vec![st("ACCEPT"), st("grant_expired").now(T0 + MAX_TTL + SKEW)]);
    o.add("RPL-07-memo-change-is-replay", "replay",
        "test.hold: a resubmission differing only in the free parameter has a different request hash: replay.",
        G::hold("RPL-07").build(),
        vec![st("ACCEPT").req(hold_req(12_500, "EUR", "rent")), st("grant_replayed").req(hold_req(12_500, "EUR", "other")).now(T0 + 12)]);
    o.add("RPL-04-unverified-grant-not-consumed", "replay",
        "Presented first over another workload's socket (not verified, nothing consumed), then by its own workload.",
        G::transfer("RPL-04").build(), vec![st("grant_workload_mismatch").peer(APP2), st("ACCEPT").now(T0 + 11)]);
    o.add("RPL-05-revoked-then-retried", "replay",
        "Denied by revocation (consumed as DENIED); the identical retry returns the stored denial.",
        G::transfer("RPL-05").build(),
        vec![st("grant_revoked").rev(json!({"ten": "acme", "before": T0 + 1})), st("STORED_OUTCOME:DENIED").rev(json!({"ten": "acme", "before": T0 + 1})).now(T0 + 11)]);
    o.add("RPL-06-revocation-after-consumption", "replay",
        "Accepted, then the tenant is revoked: an identical retry returns the stored ACCEPT; no second effect.",
        G::transfer("RPL-06").build(),
        vec![st("ACCEPT"), st("STORED_OUTCOME:ACCEPT").rev(json!({"ten": "acme", "before": T0 + 11})).now(T0 + 12)]);

    // ---------------- Step 13: revocation (revoked_before; deny iff iat < before)
    o.one("REV-01-tenant", "revocation", "revoked_before for (acme) = iat + 1.",
        G::transfer("REV-01").build(), st("grant_revoked").rev(json!({"ten": "acme", "before": T0 + 1})));
    o.one("REV-02-tenant-workload", "revocation", "revoked_before for (acme, app1) = iat + 1.",
        G::transfer("REV-02").build(), st("grant_revoked").rev(json!({"ten": "acme", "wid": APP1, "before": T0 + 1})));
    o.one("REV-03-tenant-subject", "revocation", "revoked_before for (acme, user:u-17) = iat + 1.",
        G::transfer("REV-03").build(), st("grant_revoked").rev(json!({"ten": "acme", "sub": SUB, "before": T0 + 1})));
    o.one("REV-04-boundary-equal", "revocation", "revoked_before = iat: not revoked (strict less-than).",
        G::transfer("REV-04").build(), st("ACCEPT").rev(json!({"ten": "acme", "before": T0})));
    o.one("REV-05-other-tenant", "revocation", "Revocation for tenant globex does not affect acme.",
        G::transfer("REV-05").build(), st("ACCEPT").rev(json!({"ten": "globex", "before": T0 + 100})));
    o.one("REV-06-other-subject", "revocation", "Revocation for (acme, user:u-18) does not affect user:u-17.",
        G::transfer("REV-06").build(), st("ACCEPT").rev(json!({"ten": "acme", "sub": "user:u-18", "before": T0 + 100})));
    o.add("REV-08-read-grant", "revocation",
        "Read grant revoked for (acme, user:u-17): denied every time (read grants record nothing).",
        G::balance("REV-08").build(),
        vec![
            st("grant_revoked").req(balance_req()).rev(json!({"ten": "acme", "sub": SUB, "before": T0 + 1})),
            st("grant_revoked").req(balance_req()).rev(json!({"ten": "acme", "sub": SUB, "before": T0 + 1})).now(T0 + 11),
        ]);
    o.one("REV-07-other-workload", "revocation", "Revocation for (acme, app2) does not affect app1.",
        G::transfer("REV-07").build(), st("ACCEPT").rev(json!({"ten": "acme", "wid": APP2, "before": T0 + 100})));
    o.one("REV-09-future-iat-escapes-earlier-revocation", "revocation",
        "RESIDUAL (spec 11): a grant whose iat is later than an earlier revoked_before row is not revoked by it. Prevented only by the issuer clock rule (spec 9) or key revocation.",
        G::transfer("REV-09").times(T0 + 100, T0 + 100, T0 + 130).build(),
        st("ACCEPT").now(T0 + 100).rev(json!({"ten": "acme", "before": T0 + 50})));

    // ---------------- Draft 2 additions: rop ordering and limits, read-grant key sets, ID boundaries
    {
        let g = G::read("PDEC-20", &[]);
        let raw = cbor::map_raw(&[(tstr("ledger.get_balance"), uint(1)), (tstr("test.peek"), uint(1))]);
        o.one("PDEC-20-rop-raw-string-order", "payload-decode",
            "rop keys in raw string order (ledger.get_balance before test.peek) instead of encoded-bytes order.",
            g.clone().set(19, raw).build(), st("grant_payload_malformed").req(balance_req()));
        let dup = cbor::map_raw(&[(tstr("ledger.get_balance"), uint(1)), (tstr("ledger.get_balance"), uint(2))]);
        o.one("PDEC-21-rop-duplicate-key", "payload-decode", "rop names ledger.get_balance twice with different opv.",
            G::read("PDEC-21", &[]).set(19, dup).build(), st("grant_payload_malformed").req(balance_req()));
    }
    let many: Vec<String> = (0..17).map(|i| format!("ledger.op{i:02}")).collect();
    let many_ref: Vec<(&str, u64)> = many.iter().map(|n| (n.as_str(), 1)).collect();
    let read_more: Vec<(&str, &str, G)> = vec![
        ("PSCH-72-rop-17-entries", "rop with 17 entries (max 16).", G::read("PSCH-72", &many_ref)),
        ("PSCH-73-rop-name-65", "rop op name of 65 bytes (max 64).", G::read("PSCH-73", &[(&"a".repeat(65), 1)])),
        ("PSCH-74-read-carrying-opv", "Read grant carrying opv (11).", G::balance("PSCH-74").set(11, uint(1))),
        ("PSCH-75-read-carrying-res", "Read grant carrying res (12).", G::balance("PSCH-75").set(12, map(&[]))),
        ("PSCH-76-read-carrying-use", "Read grant carrying use (14).", G::balance("PSCH-76").set(14, uint(1))),
    ];
    for (id, desc, g) in read_more {
        o.one(id, "payload-schema", desc, g.build(), st("grant_payload_invalid").req(balance_req()));
    }
    for (k, name) in [(0, "ver"), (1, "iss"), (2, "aud"), (4, "iat"), (5, "nbf"), (6, "exp"), (7, "wid"), (8, "ten"), (9, "sub")] {
        let id = format!("PSCH-{}-read-missing-{name}", 80 + k);
        o.one(&id, "payload-schema", &format!("Read grant: required key {k} ({name}) absent."),
            G::balance(&id).del(k).build(), st("grant_payload_invalid").req(balance_req()));
    }
    let ids: Vec<(&str, &str, u64, Vec<u8>)> = vec![
        ("PSCH-90-ten-del-0x7f", "ten contains 0x7F (DEL).", 8, tstr("ac\u{7f}me")),
        ("PSCH-91-ten-space-0x20", "ten contains 0x20 (space; IDs exclude it).", 8, tstr("ac me")),
        ("PSCH-92-ten-129", "ten of 129 bytes (max 128).", 8, tstr(&"t".repeat(129))),
        ("PSCH-93-aud-129", "aud of 129 bytes (max 128).", 2, tstr(&"b".repeat(129))),
        ("PSCH-94-iss-129", "iss of 129 bytes (max 128).", 1, tstr(&"i".repeat(129))),
        ("PSCH-95-wid-257", "wid of 257 bytes (max 256).", 7, tstr(&"w".repeat(257))),
        ("PSCH-96-opv-65536", "opv = 65536 (max 65535).", 11, uint(65_536)),
        ("PSCH-97-con-uint-2pow53", "con exact uint value 2^53 (max 2^53 - 1).", 13,
            map(&[(uint(0), con_exact(tstr("bob"))), (uint(1), con_exact(uint(1 << 53)))])),
        ("PSCH-98-con-ceiling-2pow53", "Bounded ceiling 2^53 (max 2^53 - 1).", 13, map(&[(uint(0), con_bound(1 << 53)), (uint(1), con_exact(tstr("EUR")))])),
    ];
    for (id, desc, k, v) in ids {
        o.one(id, "payload-schema", desc, G::transfer(id).set(k, v).build(), st("grant_payload_invalid"));
    }

    // ---------------- Draft 2 additions: signatures and keys
    {
        let g = G::balance("SIG-39");
        let (p, _, s) = g.parts();
        let altered = g.clone().set(19, map(&[(tstr("ledger.get_balance"), uint(1)), (tstr("ledger.list_transfers"), uint(1))])).payload();
        o.one("SIG-39-altered-rop", "signature", "Read grant: ledger.list_transfers added to rop (19) after signing.",
            envelope(&p, &[0xa0], &altered, &s), st("grant_signature_invalid").req(list_req()));
        // Signatures whose cofactorless equation holds with R = identity: [S]B - [k]A = identity when S = k*a.
        for (id, r_hex, desc) in [
            ("SIG-40-small-order-R", "0100000000000000000000000000000000000000000000000000000000000000",
                "R is the identity (small order) and S = k*a mod L, so [S]B - [k]A = R holds; verify_strict rejects small-order R. STRICT-ONLY: lax verifiers accept."),
            ("SIG-41-non-canonical-R", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "R = non-canonical encoding of the identity (y = p + 1), S = k*a for that R; the recomputed R encoding differs from the received bytes."),
        ] {
            let g = G::transfer(id);
            let (p, pl, _) = g.parts();
            let r: [u8; 32] = unhex(r_hex).try_into().unwrap();
            let s = forge_identity_r(&r, &sig_structure(&p, &g.aad, &pl));
            o.one(id, "signature", desc, envelope(&p, &[0xa0], &pl, &[r.to_vec(), s.to_vec()].concat()), st("grant_signature_invalid"));
        }
    }
    o.one("KEY-05-key-not-yet-active", "key", "Signed by key F, whose validity window starts after the test time.",
        G::transfer("KEY-05").signer("F").kid(kid_of("F")).build(), st("grant_key_inactive"));
    {
        let t = KEY_NB - 10; // key D's window ends at KEY_NB
        o.one("KEY-06-key-window-end-boundary", "key", "Key D at now = not_after (window is half-open).",
            G::transfer("KEY-06").signer("D").kid(kid_of("D")).times(t, t, t + 30).build(), st("grant_key_inactive").now(KEY_NB));
        o.one("KEY-07-key-window-last-second", "key", "Key D at now = not_after - 1: accepted.",
            G::transfer("KEY-07").signer("D").kid(kid_of("D")).times(t, t, t + 30).build(), st("ACCEPT").now(KEY_NB - 1));
    }

    o.v
}

/// For a TEST-ONLY key A = a*B, returns S = k*a mod L with k = SHA-512(R || A || msg) mod L.
fn forge_identity_r(r: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    use curve25519_dalek::scalar::Scalar;
    use sha2::Sha512;
    let sk = signing_key("A");
    let mut h = Sha512::new();
    h.update(r);
    h.update(sk.verifying_key().as_bytes());
    h.update(msg);
    let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    (k * sk.to_scalar()).to_bytes()
}

pub const LONG_TEN: &str = "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt";

/// A test.bulk grant of exactly 2048 bytes and the values it binds.
fn bulk_2048() -> (Vec<u8>, Vec<String>) {
    for n in (100..=256).rev() {
        for m in 0..=256 {
            let vals: Vec<String> = (0..7).map(|i| ((b'a' + i) as char).to_string().repeat(n)).chain(std::iter::once("z".repeat(m))).collect();
            let g = G::bulk("ACC-11", &vals).build();
            if g.len() == 2048 {
                return (g, vals);
            }
            if g.len() > 2048 {
                break;
            }
        }
    }
    panic!("no 2048-byte bulk grant");
}


// ------------------------------------------------------------------- registries

fn registry_entry(k: &TestKey) -> Value {
    json!({
        "kid": hex(&kid_of(k.name)),
        "alg": "Ed25519",
        "public_key": k.public,
        "iss": k.iss,
        "purpose": "grant",
        "not_before": k.not_before,
        "not_after": k.not_after,
        "status": k.status,
    })
}

fn registry(entries: Vec<Value>) -> Value {
    json!({"format": "nodkey.grant-keys.v1", "keys": entries})
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap() + "\n"
}

fn raw_entry(pk: &[u8; 32]) -> Value {
    let mut e = registry_entry(key("B"));
    e["public_key"] = json!(hex(pk));
    e["kid"] = json!(hex(&derive_kid(pk)));
    e
}

/// (id, description, registry JSON text, expected)
fn registry_vectors() -> Vec<(String, String, String, String)> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let valid: Vec<Value> = KEYS.iter().filter(|k| k.in_registry).map(registry_entry).collect();
    let mut out: Vec<(String, String, String, String)> = Vec::new();
    let mut add_text = |id: &str, desc: &str, text: String, exp: &str| {
        out.push((id.to_owned(), desc.to_owned(), text, exp.to_owned()));
    };
    let with = |extra: Value| pretty(&registry([valid.clone(), vec![extra]].concat()));

    add_text("REG-01-valid", "The registry used by every grant vector (keys A, C, D, E, F).", pretty(&registry(valid.clone())), "LOAD_OK");
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(CompressedEdwardsY(identity).decompress().unwrap().is_small_order());
    add_text("REG-02-small-order-identity", "Public key is the identity point (order 1).", with(raw_entry(&identity)), "registry_key_weak");
    let order8: [u8; 32] = unhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a").try_into().unwrap();
    let t8 = CompressedEdwardsY(order8).decompress().unwrap();
    assert!(t8.is_small_order());
    add_text("REG-03-small-order-8", "Public key is a point of order 8.", with(raw_entry(&order8)), "registry_key_weak");
    // y = p + y0 (non-canonical) for the smallest y0 that decodes to a point that is not small order.
    let mut noncanon = None;
    for y0 in 2u8..19 {
        let mut b = unhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        b[0] += y0;
        let b: [u8; 32] = b.try_into().unwrap();
        if let Some(pt) = CompressedEdwardsY(b).decompress()
            && !pt.is_small_order()
        {
            assert_ne!(pt.compress().to_bytes(), b);
            noncanon = Some(b);
            break;
        }
    }
    add_text("REG-04-non-canonical-encoding", "Public key encodes y >= p (non-canonical encoding of a valid, not small-order point).",
        with(raw_entry(&noncanon.expect("no non-canonical encoding"))), "registry_key_invalid");
    let mut not_point = None;
    for y in 2u8..=255 {
        let mut b = [0u8; 32];
        b[0] = y;
        if CompressedEdwardsY(b).decompress().is_none() {
            not_point = Some(b);
            break;
        }
    }
    add_text("REG-05-not-a-point", "Public key bytes do not decode to a curve point.", with(raw_entry(&not_point.unwrap())), "registry_key_invalid");
    let mut short = registry_entry(key("B"));
    short["public_key"] = json!(&key("B").public[..62]);
    add_text("REG-06-key-31-bytes", "Public key of 31 bytes.", with(short), "registry_key_invalid");
    let mut upper = registry_entry(key("B"));
    upper["public_key"] = json!(key("B").public.to_uppercase());
    add_text("REG-07-key-uppercase-hex", "Public key in uppercase hex (lowercase required).", with(upper), "registry_key_invalid");
    let mut kidm = registry_entry(key("B"));
    kidm["kid"] = json!(format!("00{}", &hex(&kid_of("B"))[2..]));
    add_text("REG-08-kid-not-derived", "kid (well-formed) does not equal the derivation from the public key.", with(kidm), "registry_kid_mismatch");
    add_text("REG-09-duplicate-entry", "Key A listed twice.", with(registry_entry(key("A"))), "registry_duplicate_key");
    let field = |f: &str, v: Value| {
        let mut e = registry_entry(key("B"));
        e[f] = v;
        e
    };
    add_text("REG-10-alg-eddsa", "alg \"EdDSA\" instead of \"Ed25519\".", with(field("alg", json!("EdDSA"))), "registry_entry_invalid");
    add_text("REG-11-purpose-receipt", "purpose \"receipt\".", with(field("purpose", json!("receipt"))), "registry_entry_invalid");
    add_text("REG-12-status-verify-only", "Undefined status \"verify_only\".", with(field("status", json!("verify_only"))), "registry_entry_invalid");
    add_text("REG-13-empty-window", "not_before = not_after.", with(field("not_after", json!(KEY_NB))), "registry_entry_invalid");
    add_text("REG-14-unknown-field", "Entry with an extra member \"comment\".", with(field("comment", json!("x"))), "registry_entry_invalid");
    let mut missing = registry_entry(key("B"));
    missing.as_object_mut().unwrap().remove("iss");
    add_text("REG-15-missing-field", "Entry without iss.", with(missing), "registry_entry_invalid");
    add_text("REG-16-no-keys", "Empty keys array.", pretty(&registry(vec![])), "registry_entry_invalid");
    add_text("REG-17-role-member", "Entry carrying the Draft 1 member \"role\" (removed in Draft 2).",
        with(field("role", json!("scheduler"))), "registry_entry_invalid");
    // Draft 2 additions.
    let a_pt = CompressedEdwardsY(unhex(key("B").public).try_into().unwrap()).decompress().unwrap();
    let mixed = (a_pt + t8).compress().to_bytes();
    let mp = CompressedEdwardsY(mixed).decompress().unwrap();
    assert!(!mp.is_small_order() && !mp.is_torsion_free());
    add_text("REG-18-mixed-order-key", "Public key = B + T8 (valid key plus a point of order 8): not small order, but not torsion-free.",
        with(raw_entry(&mixed)), "registry_key_weak");
    // Duplicate member: written as text because JSON libraries cannot emit it.
    let b = registry_entry(key("B"));
    let dup_text = pretty(&registry([valid.clone(), vec![b.clone()]].concat()))
        .replacen("\"status\": \"active\"\n    }\n  ]", "\"status\": \"revoked\",\n      \"status\": \"active\"\n    }\n  ]", 1);
    assert!(dup_text.contains("\"status\": \"revoked\",\n      \"status\": \"active\""));
    add_text("REG-19-duplicate-member", "Entry with two status members (\"revoked\" then \"active\"); first-wins and last-wins parsers would disagree.",
        dup_text, "registry_entry_invalid");
    let nb = KEY_NB.to_string();
    let base_text = with(registry_entry(key("B")));
    add_text("REG-20-time-with-fraction", "not_before written as 1767225600.0.",
        base_text.replacen(&format!("\"not_before\": {nb}"), &format!("\"not_before\": {nb}.0"), 1), "registry_entry_invalid");
    add_text("REG-21-time-exponent", "not_before written as 1.7672256e9.",
        base_text.replacen(&format!("\"not_before\": {nb}"), "\"not_before\": 1.7672256e9", 1), "registry_entry_invalid");
    add_text("REG-22-not-after-2pow53", "not_after = 2^53 (max 2^53 - 1).", with(field("not_after", json!(1u64 << 53))), "registry_entry_invalid");
    add_text("REG-23-window-inverted", "not_before > not_after.", with(field("not_before", json!(KEY_NA + 1))), "registry_entry_invalid");
    let mut kup = registry_entry(key("B"));
    kup["kid"] = json!(hex(&kid_of("B")).to_uppercase());
    add_text("REG-24-kid-uppercase", "kid in uppercase hex: a member-format error.", with(kup), "registry_entry_invalid");
    add_text("REG-25-not-json", "The file is not JSON.", "format = nodkey.grant-keys.v1\n".into(), "registry_entry_invalid");
    add_text("REG-26-negative-time", "not_before = -1.", with(field("not_before", json!(-1))), "registry_entry_invalid");
    for (id, _, t, _) in &out {
        assert!(id.starts_with("REG-25") || id.starts_with("REG-19") || serde_json::from_str::<Value>(t).is_ok());
    }
    out
}

// ------------------------------------------------------------------- operation declarations

fn operations() -> Value {
    json!({"format": "nodkey.operations.v1", "operations": [
        {"op": "ledger.transfer", "kind": "write", "opv": 1, "requires_confirmation": true, "params": [
            {"name": "from", "in": "res", "key": 0, "class": "exact", "type": "account_id", "destination": false},
            {"name": "to", "in": "con", "key": 0, "class": "exact", "type": "account_id", "destination": true},
            {"name": "amount_cents", "in": "con", "key": 1, "class": "exact", "type": "uint", "destination": false}
        ]},
        {"op": "test.hold", "kind": "write", "opv": 1, "requires_confirmation": false, "params": [
            {"name": "account", "in": "res", "key": 0, "class": "exact", "type": "account_id", "destination": false},
            {"name": "amount_cents", "in": "con", "key": 0, "class": "bounded", "type": "uint", "destination": false},
            {"name": "currency", "in": "con", "key": 1, "class": "exact", "type": "currency", "destination": false},
            {"name": "memo", "in": "con", "key": null, "class": "free", "type": "text64", "destination": false,
             "justification": "TEST-ONLY operation; display-only note with no effect on authority"}
        ]},
        {"op": "test.bulk", "kind": "write", "opv": 1, "requires_confirmation": false, "params":
            std::iter::once(json!({"name": "account", "in": "res", "key": 0, "class": "exact", "type": "account_id", "destination": false}))
                .chain((0..8).map(|i| json!({"name": format!("p{i}"), "in": "con", "key": i, "class": "exact", "type": "text256", "destination": false})))
                .collect::<Vec<_>>()
        },
        {"op": "ledger.get_balance", "kind": "read", "opv": 1, "requires_confirmation": false, "params": [
            {"name": "account", "in": "request", "key": null, "class": "owner_scoped", "type": "account_id", "destination": false}
        ]},
        {"op": "ledger.list_transfers", "kind": "read", "opv": 1, "requires_confirmation": false, "params": [
            {"name": "account", "in": "request", "key": null, "class": "owner_scoped", "type": "account_id", "destination": false}
        ]},
        {"op": "test.peek", "kind": "read", "opv": 1, "requires_confirmation": false, "params": [
            {"name": "account", "in": "request", "key": null, "class": "owner_scoped", "type": "account_id", "destination": false}
        ]},
        {"op": "test.mandated", "kind": "write", "opv": 1, "requires_confirmation": true, "mandate_eligible": true, "params": [
            {"name": "account", "in": "res", "key": 0, "class": "exact", "type": "account_id", "destination": false}
        ]}
    ]})
}

/// (id, description, operations JSON text, expected)
fn ops_vectors() -> Vec<(String, String, String, String)> {
    let base = operations();
    let mut out = vec![("OPS-01-valid".to_owned(), "The declarations used by every grant vector.".to_owned(), pretty(&base), "LOAD_OK".to_owned())];
    let mut m = |id: &str, desc: &str, f: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        f(&mut v);
        out.push((id.to_owned(), desc.to_owned(), pretty(&v), "ops_declaration_invalid".to_owned()));
    };
    m("OPS-02-free-destination", "Destination parameter to declared free.", &|v| {
        let p = &mut v["operations"][0]["params"][1];
        p["class"] = json!("free");
        p["key"] = Value::Null;
        p["justification"] = json!("x");
    });
    m("OPS-03-destination-bounded", "Destination parameter declared bounded (destination implies exact).", &|v| {
        let p = &mut v["operations"][0]["params"][2];
        p["destination"] = json!(true);
        p["class"] = json!("bounded");
    });
    m("OPS-04-bounded-non-uint", "Bounded parameter of type currency.", &|v| v["operations"][1]["params"][2]["class"] = json!("bounded"));
    m("OPS-05-duplicate-con-key", "Two con parameters with key 0.", &|v| v["operations"][0]["params"][2]["key"] = json!(0));
    m("OPS-06-res-bounded", "res parameter declared bounded.", &|v| v["operations"][0]["params"][0]["class"] = json!("bounded"));
    m("OPS-07-unclassified", "Parameter without class.", &|v| {
        v["operations"][0]["params"][1].as_object_mut().unwrap().remove("class");
    });
    m("OPS-08-two-opv", "opv as a list of two versions (v1 allows exactly one).", &|v| v["operations"][0]["opv"] = json!([1, 2]));
    m("OPS-09-confirm-on-read", "requires_confirmation on a read operation.", &|v| v["operations"][3]["requires_confirmation"] = json!(true));
    m("OPS-10-unknown-type", "Parameter type \"email\".", &|v| v["operations"][0]["params"][1]["type"] = json!("email"));
    m("OPS-11-free-unjustified", "Free parameter without a justification.", &|v| {
        v["operations"][1]["params"][3].as_object_mut().unwrap().remove("justification");
    });
    m("OPS-12-duplicate-op", "Two declarations named ledger.transfer.", &|v| {
        let d = v["operations"][0].clone();
        v["operations"].as_array_mut().unwrap().push(d);
    });
    m("OPS-13-read-with-res", "Read operation with a res parameter.", &|v| v["operations"][3]["params"][0]["in"] = json!("res"));
    m("OPS-14-unknown-param-member", "Parameter with an unknown member \"default\".", &|v| v["operations"][0]["params"][1]["default"] = json!("bob"));
    m("OPS-15-free-with-key", "Free parameter with a con key.", &|v| v["operations"][1]["params"][3]["key"] = json!(2));
    m("OPS-16-missing-destination", "Parameter without the destination member.", &|v| {
        v["operations"][0]["params"][1].as_object_mut().unwrap().remove("destination");
    });
    m("OPS-17-write-owner-scoped", "Write operation with an owner_scoped parameter.", &|v| {
        let p = &mut v["operations"][0]["params"][1];
        p["in"] = json!("request");
        p["class"] = json!("owner_scoped");
        p["key"] = Value::Null;
    });
    m("OPS-18-justification-on-exact", "Exact parameter carrying a justification.", &|v| v["operations"][0]["params"][1]["justification"] = json!("x"));
    let dup = pretty(&base).replacen("\"kind\": \"write\",", "\"kind\": \"read\",\n      \"kind\": \"write\",", 1);
    out.push(("OPS-19-duplicate-member".to_owned(), "Declaration with two kind members.".to_owned(), dup, "ops_declaration_invalid".to_owned()));
    // Draft 4: mandate_eligible. OPS-20 stays reserved (spec section 6.3, binds-no-parameter rule).
    // Index 6 is test.mandated, index 3 ledger.get_balance, index 1 test.hold, index 0 ledger.transfer.
    let mut mx = |id: &str, desc: &str, exp: &str, f: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        f(&mut v);
        out.push((id.to_owned(), desc.to_owned(), pretty(&v), exp.to_owned()));
    };
    const INV: &str = "ops_declaration_invalid";
    mx("OPS-21-mandate-eligible-on-read", "mandate_eligible: true on the read operation ledger.get_balance.", INV,
        &|v| v["operations"][3]["mandate_eligible"] = json!(true));
    mx("OPS-22-mandate-eligible-unconfirmed-write", "mandate_eligible: true on test.hold, a write without requires_confirmation.", INV,
        &|v| v["operations"][1]["mandate_eligible"] = json!(true));
    mx("OPS-23-mandate-eligible-non-boolean", "mandate_eligible given as the string \"true\".", INV,
        &|v| v["operations"][6]["mandate_eligible"] = json!("true"));
    mx("OPS-24-mandate-eligible-confirmed-write", "mandate_eligible: true also on ledger.transfer (a write with requires_confirmation).", "LOAD_OK",
        &|v| v["operations"][0]["mandate_eligible"] = json!(true));
    mx("OPS-25-mandate-eligible-absent", "No operation carries mandate_eligible (member removed from test.mandated; absent = false).", "LOAD_OK",
        &|v| {
            v["operations"][6].as_object_mut().unwrap().remove("mandate_eligible");
        });
    out
}

// ------------------------------------------------------------------- transport

/// (id, description, text, expected, decoded-grant file or None)
fn transport_vectors() -> Vec<(String, String, String, String, Option<String>)> {
    // The first positive grant whose length is not a multiple of 3 (so its text has unused bits).
    let candidates = [
        (G::transfer("ACC-01").build(), "ACC-01-valid-transfer"),
        (G::balance("ACC-02").build(), "ACC-02-valid-read-grant"),
        (G::hold("ACC-03").build(), "ACC-03-amount-equals-bound"),
        (G::hold("ACC-04").build(), "ACC-04-free-param-any-value"),
    ];
    let (acc01, name) = candidates.into_iter().find(|(g, _)| !g.len().is_multiple_of(3)).expect("no candidate");
    let t = b64url(&acc01);
    let f = Some(format!("grants/{name}.hex"));
    let mut out = Vec::new();
    let mut add = |id: &str, d: &str, text: String, exp: &str, file: Option<String>| out.push((id.into(), d.into(), text, exp.into(), file));
    add("TRN-01-canonical", &format!("Canonical unpadded base64url of {name}."), t.clone(), "DECODED", f.clone());
    let padded = format!("{t}{}", "=".repeat((4 - t.len() % 4) % 4));
    assert_ne!(padded, t);
    add("TRN-02-padding", &format!("{name} with = padding."), padded, "grant_encoding_invalid", None);
    let i = t.find(['-', '_']).expect("text has no - or _");
    let mut std_alpha = t.clone().into_bytes();
    std_alpha[i] = if std_alpha[i] == b'-' { b'+' } else { b'/' };
    add("TRN-03-standard-alphabet", &format!("{name} with one - or _ replaced by its standard-alphabet counterpart."),
        String::from_utf8(std_alpha).unwrap(), "grant_encoding_invalid", None);
    add("TRN-04-embedded-lf", &format!("{name} with a line feed after 76 characters."), format!("{}\n{}", &t[..76], &t[76..]), "grant_encoding_invalid", None);
    let k = (t.len() / 4) * 4 + 1;
    let k = if k <= t.len() { k } else { k - 4 };
    add("TRN-05-length-1-mod-4", &format!("First 4n+1 characters of {name}."), t[..k].to_owned(), "grant_encoding_invalid", None);
    let mut tb = t.clone().into_bytes();
    let last = tb.len() - 1;
    let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let pos = alpha.iter().position(|c| *c == tb[last]).unwrap();
    tb[last] = alpha[pos | 1];
    assert_ne!(tb[last], t.as_bytes()[last]);
    add("TRN-06-non-zero-trailing-bits", &format!("{name} with a non-zero unused low bit in the final character."),
        String::from_utf8(tb).unwrap(), "grant_encoding_invalid", None);
    let (g2048, _) = bulk_2048();
    let t2048 = b64url(&g2048);
    assert_eq!(t2048.len(), 2731);
    add("TRN-07-2731-chars", "The 2048-byte grant ACC-11: 2731 characters, the maximum.", t2048, "DECODED",
        Some("grants/ACC-11-grant-exactly-2048-bytes.hex".into()));
    let t2049 = b64url(&[g2048.clone(), vec![0]].concat());
    assert_eq!(t2049.len(), 2732);
    add("TRN-08-2732-chars", "2732 characters (a 2049-byte value): rejected before decoding.", t2049, "grant_too_large", None);
    add("TRN-09-empty", "Empty string: a supplied grant of zero bytes (then grant_malformed at step 2, see ENV-03).", String::new(), "DECODED", None);
    add("TRN-10-leading-space", &format!("{name} with a leading space."), format!(" {t}"), "grant_encoding_invalid", None);
    add("TRN-11-non-ascii", &format!("{name} with a trailing U+00E9."), format!("{t}\u{e9}"), "grant_encoding_invalid", None);
    out
}

// ------------------------------------------------------------------- manifest

pub fn run(dir: &Path) {
    for sub in ["grants", "registries", "operations"] {
        fs::create_dir_all(dir.join(sub)).unwrap();
        // Remove stale outputs so that the directory reflects exactly this run.
        for e in fs::read_dir(dir.join(sub)).unwrap() {
            fs::remove_file(e.unwrap().path()).unwrap();
        }
    }
    let write = |rel: &str, s: String| fs::write(dir.join(rel), s).unwrap();

    let mut vecs_json = Vec::new();
    for v in vectors() {
        let file = format!("grants/{}.hex", v.id);
        write(&file, hex(&v.grant) + "\n");
        let steps: Vec<Value> = v
            .steps
            .iter()
            .map(|s| {
                json!({
                    "now": s.now,
                    "broker_id": s.broker_id,
                    "peer_wid": s.peer_wid,
                    "revoked_before": s.revoked_before,
                    "request": s.request,
                    "expected": s.expected,
                })
            })
            .collect();
        vecs_json.push(json!({
            "id": v.id, "kind": "grant", "category": v.category, "description": v.description,
            "registry": "registry.json", "operations": "operations.json",
            "grant": file, "grant_len": v.grant.len(), "steps": steps,
        }));
    }
    for (id, desc, text, exp) in registry_vectors() {
        let file = if id == "REG-01-valid" { "registry.json".to_owned() } else { format!("registries/{id}.json") };
        write(&file, text);
        vecs_json.push(json!({"id": id, "kind": "registry", "category": "registry", "description": desc, "registry": file, "expected": exp}));
    }
    for (id, desc, text, exp) in ops_vectors() {
        let file = if id == "OPS-01-valid" { "operations.json".to_owned() } else { format!("operations/{id}.json") };
        write(&file, text);
        vecs_json.push(json!({"id": id, "kind": "operations", "category": "operations", "description": desc, "operations": file, "expected": exp}));
    }
    for (id, desc, text, exp, file) in transport_vectors() {
        vecs_json.push(json!({"id": id, "kind": "transport", "category": "transport", "description": desc,
            "text": text, "text_len": text.len(), "expected": exp, "decoded": file}));
    }

    let rh = |req: &Value| {
        let mut args = BTreeMap::new();
        for (k, v) in req["args"].as_object().unwrap() {
            args.insert(k.clone(), match v {
                Value::String(s) => crate::verify::ReqVal::Text(s.clone()),
                v => crate::verify::ReqVal::Uint(v.as_u64().unwrap()),
            });
        }
        hex(&crate::verify::request_hash(req["op"].as_str().unwrap(), &args))
    };
    let hash_examples: Vec<Value> = [transfer_req(), hold_req(12_500, "EUR", "rent"), balance_req()]
        .iter()
        .map(|r| json!({"request": r, "request_hash": rh(r)}))
        .collect();

    let keys: Vec<Value> = KEYS
        .iter()
        .map(|k| {
            json!({
                "name": k.name, "source": k.source, "secret_seed": k.seed, "public_key": k.public,
                "kid": hex(&kid_of(k.name)), "in_registry": k.in_registry, "purpose": k.purpose,
            })
        })
        .collect();

    let manifest = json!({
        "format": "nodkey.grant-v1.vectors",
        "spec": "docs/specs/grant-v1.md",
        "spec_draft": 4,
        "warning": "TEST-ONLY. Every key below is a published RFC 8032 test key. Never deploy a registry containing them.",
        "constants": {
            "typ": TYP,
            "external_aad_tag": "nodkey.grant.v1",
            "kid_label": "nodkey.kid.v1",
            "request_hash_label": "nodkey.rqh.v1",
            "max_grant_bytes": 2048,
            "max_transport_chars": 2731,
            "skew_seconds": SKEW,
            "max_ttl_seconds": MAX_TTL,
        },
        "types": {
            "uint": "unsigned integer 0..=2^53-1",
            "account_id": "1-32 bytes of [a-z0-9_]",
            "currency": "exactly 3 bytes of [A-Z]",
            "text64": "0-64 bytes of 0x20-0x7E",
            "text256": "0-256 bytes of 0x20-0x7E",
        },
        "keys": keys,
        "workloads": [
            {"wid": APP1, "tenants": ["acme"]},
            {"wid": APP2, "tenants": ["acme", "globex", LONG_TEN]},
        ],
        "request_hash_examples": hash_examples,
        "vectors": vecs_json,
    });
    write("manifest.json", pretty(&manifest));
    eprintln!("wrote {} vectors to {}", manifest["vectors"].as_array().unwrap().len(), dir.display());
}
