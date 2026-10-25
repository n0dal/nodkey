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
pub const SCHED_ISS: &str = "nodkey.scheduler.test";
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
    pub role: &'static str,
    pub status: &'static str,
    pub not_before: u64,
    pub not_after: u64,
    pub in_registry: bool,
    pub purpose: &'static str,
}

pub const KEYS: [TestKey; 5] = [
    TestKey {
        name: "A",
        source: "RFC 8032 section 7.1 TEST 1",
        seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        iss: ISS,
        role: "user_authority",
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
        role: "user_authority",
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
        role: "user_authority",
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
        role: "user_authority",
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
        iss: SCHED_ISS,
        role: "scheduler",
        status: "active",
        not_before: KEY_NB,
        not_after: KEY_NA,
        in_registry: true,
        purpose: "the trusted scheduler's grant key (ADR-0009)",
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

    fn capture(id: &str) -> G {
        G::base(id, "E", SCHED_ISS, "orders.capture", map(&[(uint(0), uint(9821))]), map(&[(uint(0), con_bound(4200))]), 0)
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
fn capture_req(amount: u64) -> Value {
    json!({"op": "orders.capture", "args": {"order_id": 9821, "amount_cents": amount}})
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
    o.one("ACC-05-iat-before-nbf", "accept", "iat < nbf, exp - nbf = max_ttl (30 s).",
        G::transfer("ACC-05").set(4, uint(T0 - 2)).build(), st("ACCEPT"));
    o.one("ACC-06-multi-tenant-workload", "accept", "Workload app2 is registered for tenants acme and globex; grant for globex.",
        G::transfer("ACC-06").set(7, tstr(APP2)).set(8, tstr("globex")).build(), st("ACCEPT").peer(APP2));
    o.one("ACC-07-other-audience-at-its-broker", "accept",
        "Grant signed for audience nodkey.broker.other-test, presented to that broker (control for SIG-07).",
        G::transfer("ACC-07").set(2, tstr(OTHER_BROKER)).aad(aad(AAD_TAG, OTHER_BROKER)).build(),
        st("ACCEPT").broker(OTHER_BROKER));
    o.one("ACC-08-scheduler-grant", "accept",
        "Scheduler key E signs orders.capture (authority class scheduler_grant; cfm = 0, confirmation not required).",
        G::capture("ACC-08").build(), st("ACCEPT").req(capture_req(4200)));

    // ---------------- Step 1-2: size and envelope structure
    let valid = G::transfer("ENV").build();
    let (vp, vpl, vs) = G::transfer("ENV").parts();
    let pad_to = |target: usize, id: &str| -> Vec<u8> {
        for n in 1500..2100 {
            let g = G::transfer(id).set(20, bstr(&vec![0u8; n])).build();
            if g.len() == target {
                return g;
            }
        }
        panic!("no padding length hits {target}");
    };
    o.one("ENV-01-oversized-2049", "envelope", "Validly signed grant of 2049 bytes (limit 2048; padded with unknown key 20); rejected before decoding.",
        pad_to(2049, "ENV-01"), st("grant_too_large"));
    o.one("ENV-02-at-size-limit-2048", "envelope",
        "Validly signed grant of exactly 2048 bytes passes the size check; fails later on its padding key 20.",
        pad_to(2048, "ENV-02"), st("grant_payload_invalid"));
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
    psch("PSCH-03-unknown-key-20", "Unknown top-level key 20.", G::transfer("PSCH-03").set(20, uint(0)), "grant_payload_invalid", &mut o);
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
        ("PSCH-61-cfm-2", "cfm = 2.", G::transfer("PSCH-61").set(18, uint(2))),
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
    o.one("ISS-01-issuer-of-other-key", "issuer", "iss names the scheduler, but key A is registered for the authority.",
        G::transfer("ISS-01").set(1, tstr(SCHED_ISS)).build(), st("grant_issuer_mismatch"));
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
    o.one("TIME-07-ttl-31", "time", "exp - nbf = 31 > max_ttl (30).", G::transfer("TIME-07").set(6, uint(T0 + 31)).build(), st("grant_ttl_exceeded"));
    o.one("TIME-08-nbf-before-iat", "time", "nbf = iat - 1.", G::transfer("TIME-08").set(5, uint(T0 - 1)).build(), st("grant_time_invalid"));
    o.one("TIME-09-exp-equals-nbf", "time", "exp = nbf (empty window).", G::transfer("TIME-09").set(6, uint(T0)).build(), st("grant_time_invalid"));
    o.one("TIME-10-exp-before-nbf", "time", "exp = nbf - 1.", G::transfer("TIME-10").set(6, uint(T0 - 1)).build(), st("grant_time_invalid"));
    o.one("TIME-12-read-grant-expired", "time", "Read grants expire like write grants: now = exp + skew.",
        G::balance("TIME-12").build(), st("grant_expired").req(balance_req()).now(exp + SKEW));
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
    o.one("OP-05-scheduler-signs-user-op", "operation", "Scheduler key E signs a ledger.transfer (user_grant) grant.",
        G::transfer("OP-05").signer("E").kid(kid_of("E")).set(1, tstr(SCHED_ISS)).build(), st("grant_issuer_not_permitted"));
    o.one("OP-06-authority-signs-scheduler-op", "operation", "Authority key A signs an orders.capture (scheduler_grant) grant.",
        G::capture("OP-06").signer("A").kid(a_kid).set(1, tstr(ISS)).build(), st("grant_issuer_not_permitted").req(capture_req(4200)));

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
    o.one("CON-05-capture-exceeds-bound", "constraint", "orders.capture amount above the scheduler grant's ceiling.",
        G::capture("CON-05").build(), st("grant_bound_exceeded").req(capture_req(4201)));
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
        "A verified grant denied at the constraint step is consumed: a later in-bound request with it is a replay.",
        G::hold("RPL-03").build(),
        vec![
            st("grant_bound_exceeded").req(hold_req(60_000, "EUR", "rent")),
            st("grant_replayed").req(hold_req(12_500, "EUR", "rent")).now(T0 + 11),
            st("grant_bound_exceeded").req(hold_req(60_000, "EUR", "rent")).now(T0 + 12),
        ]);
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

    o.v
}

// ------------------------------------------------------------------- registries

fn registry_entry(k: &TestKey) -> Value {
    json!({
        "kid": hex(&kid_of(k.name)),
        "alg": "Ed25519",
        "public_key": k.public,
        "iss": k.iss,
        "role": k.role,
        "purpose": "grant",
        "not_before": k.not_before,
        "not_after": k.not_after,
        "status": k.status,
    })
}

fn registry(entries: Vec<Value>) -> Value {
    json!({"format": "nodkey.grant-keys.v1", "keys": entries})
}

fn raw_entry(pk: &[u8; 32]) -> Value {
    let mut e = registry_entry(key("A"));
    e["public_key"] = json!(hex(pk));
    e["kid"] = json!(hex(&derive_kid(pk)));
    e
}

fn registry_vectors() -> Vec<(String, String, Value, String)> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let valid: Vec<Value> = KEYS.iter().filter(|k| k.in_registry).map(registry_entry).collect();
    let mut out: Vec<(String, String, Value, String)> = Vec::new();
    let mut add = |id: &str, desc: &str, entries: Vec<Value>, exp: &str| {
        out.push((id.to_owned(), desc.to_owned(), registry(entries), exp.to_owned()));
    };
    let with = |extra: Value| [valid.clone(), vec![extra]].concat();

    add("REG-01-valid", "The registry used by every grant vector (keys A, C, D, E).", valid.clone(), "LOAD_OK");
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(CompressedEdwardsY(identity).decompress().unwrap().is_small_order());
    add("REG-02-small-order-identity", "Public key is the identity point (order 1).", with(raw_entry(&identity)), "registry_key_weak");
    let order8: [u8; 32] = unhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a").try_into().unwrap();
    assert!(CompressedEdwardsY(order8).decompress().unwrap().is_small_order());
    add("REG-03-small-order-8", "Public key is a point of order 8.", with(raw_entry(&order8)), "registry_key_weak");
    // y = p + y0 (non-canonical) for the smallest y0 that decodes to a point that is not small order.
    let mut noncanon = None;
    for y0 in 2u8..19 {
        let mut b = unhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        b[0] += y0;
        let b: [u8; 32] = b.try_into().unwrap();
        if let Some(pt) = CompressedEdwardsY(b).decompress()
            && !pt.is_small_order() {
                assert_ne!(pt.compress().to_bytes(), b);
                noncanon = Some(b);
                break;
            }
    }
    let noncanon = noncanon.expect("no non-canonical encoding found");
    add("REG-04-non-canonical-encoding", "Public key encodes y >= p (non-canonical encoding of a valid, not small-order point).",
        with(raw_entry(&noncanon)), "registry_key_invalid");
    let mut not_point = None;
    for y in 2u8..=255 {
        let mut b = [0u8; 32];
        b[0] = y;
        if CompressedEdwardsY(b).decompress().is_none() {
            not_point = Some(b);
            break;
        }
    }
    add("REG-05-not-a-point", "Public key bytes do not decode to a curve point.", with(raw_entry(&not_point.unwrap())), "registry_key_invalid");
    let mut short = registry_entry(key("B"));
    short["public_key"] = json!(&key("B").public[..62]);
    add("REG-06-key-31-bytes", "Public key of 31 bytes.", with(short), "registry_key_invalid");
    let mut upper = registry_entry(key("B"));
    upper["public_key"] = json!(key("B").public.to_uppercase());
    add("REG-07-key-uppercase-hex", "Public key in uppercase hex (lowercase required).", with(upper), "registry_key_invalid");
    let mut kidm = registry_entry(key("B"));
    kidm["kid"] = json!(hex(&kid_of("A")).replace(&hex(&kid_of("A"))[..2], "00"));
    add("REG-08-kid-not-derived", "kid does not equal the derivation from the public key.", with(kidm), "registry_kid_mismatch");
    add("REG-09-duplicate-entry", "Key A listed twice.", with(registry_entry(key("A"))), "registry_duplicate_key");
    let field = |f: &str, v: Value| {
        let mut e = registry_entry(key("B"));
        e[f] = v;
        e
    };
    add("REG-10-alg-eddsa", "alg \"EdDSA\" instead of \"Ed25519\".", with(field("alg", json!("EdDSA"))), "registry_entry_invalid");
    add("REG-11-purpose-receipt", "purpose \"receipt\".", with(field("purpose", json!("receipt"))), "registry_entry_invalid");
    add("REG-12-status-verify-only", "Undefined status \"verify_only\".", with(field("status", json!("verify_only"))), "registry_entry_invalid");
    add("REG-13-empty-window", "not_before = not_after.", with(field("not_after", json!(KEY_NB))), "registry_entry_invalid");
    add("REG-14-unknown-field", "Entry with an extra field \"comment\".", with(field("comment", json!("x"))), "registry_entry_invalid");
    let mut missing = registry_entry(key("B"));
    missing.as_object_mut().unwrap().remove("iss");
    add("REG-15-missing-field", "Entry without iss.", with(missing), "registry_entry_invalid");
    add("REG-16-no-keys", "Empty keys array.", vec![], "registry_entry_invalid");
    add("REG-17-role-unknown", "role \"admin\".", with(field("role", json!("admin"))), "registry_entry_invalid");
    out
}

// ------------------------------------------------------------------- manifest

fn operations() -> Value {
    json!([
        {"op": "ledger.transfer", "kind": "write", "opv": [1], "authority": "user_grant", "requires_confirmation": true, "params": [
            {"name": "from", "in": "res", "key": 0, "class": "exact", "type": "account_id"},
            {"name": "to", "in": "con", "key": 0, "class": "exact", "type": "account_id"},
            {"name": "amount_cents", "in": "con", "key": 1, "class": "exact", "type": "uint"}
        ]},
        {"op": "test.hold", "kind": "write", "opv": [1], "authority": "user_grant", "requires_confirmation": false, "params": [
            {"name": "account", "in": "res", "key": 0, "class": "exact", "type": "account_id"},
            {"name": "amount_cents", "in": "con", "key": 0, "class": "bounded", "type": "uint"},
            {"name": "currency", "in": "con", "key": 1, "class": "exact", "type": "currency"},
            {"name": "memo", "in": "con", "key": null, "class": "free", "type": "text64",
             "justification": "TEST-ONLY operation; display-only note with no effect on authority"}
        ]},
        {"op": "ledger.get_balance", "kind": "read", "opv": [1], "authority": "user_grant", "requires_confirmation": false, "params": [
            {"name": "account", "in": "request", "key": null, "class": "owner_scoped", "type": "account_id"}
        ]},
        {"op": "ledger.list_transfers", "kind": "read", "opv": [1], "authority": "user_grant", "requires_confirmation": false, "params": [
            {"name": "account", "in": "request", "key": null, "class": "owner_scoped", "type": "account_id"}
        ]},
        {"op": "orders.capture", "kind": "write", "opv": [1], "authority": "scheduler_grant", "requires_confirmation": false, "params": [
            {"name": "order_id", "in": "res", "key": 0, "class": "exact", "type": "uint"},
            {"name": "amount_cents", "in": "con", "key": 0, "class": "bounded", "type": "uint"}
        ]}
    ])
}

pub fn run(dir: &Path) {
    fs::create_dir_all(dir.join("grants")).unwrap();
    fs::create_dir_all(dir.join("registries")).unwrap();
    // Remove stale outputs so that the directory reflects exactly this run.
    for sub in ["grants", "registries"] {
        for e in fs::read_dir(dir.join(sub)).unwrap() {
            fs::remove_file(e.unwrap().path()).unwrap();
        }
    }
    let write = |rel: &str, s: String| fs::write(dir.join(rel), s).unwrap();

    let valid: Vec<Value> = KEYS.iter().filter(|k| k.in_registry).map(registry_entry).collect();
    write("registry.json", serde_json::to_string_pretty(&registry(valid)).unwrap() + "\n");

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
            "id": v.id,
            "kind": "grant",
            "category": v.category,
            "description": v.description,
            "registry": "registry.json",
            "grant": file,
            "grant_len": v.grant.len(),
            "steps": steps,
        }));
    }
    for (id, desc, reg, exp) in registry_vectors() {
        let file = if id == "REG-01-valid" { "registry.json".to_owned() } else { format!("registries/{id}.json") };
        if file != "registry.json" {
            write(&file, serde_json::to_string_pretty(&reg).unwrap() + "\n");
        }
        vecs_json.push(json!({
            "id": id, "kind": "registry", "category": "registry", "description": desc,
            "registry": file, "expected": exp,
        }));
    }

    let keys: Vec<Value> = KEYS
        .iter()
        .map(|k| {
            json!({
                "name": k.name,
                "source": k.source,
                "secret_seed": k.seed,
                "public_key": k.public,
                "kid": hex(&kid_of(k.name)),
                "in_registry": k.in_registry,
                "purpose": k.purpose,
            })
        })
        .collect();

    let manifest = json!({
        "format": "nodkey.grant-v1.vectors",
        "spec": "docs/specs/grant-v1.md",
        "warning": "TEST-ONLY. Every key below is a published RFC 8032 test key. Never deploy a registry containing them.",
        "constants": {
            "typ": TYP,
            "external_aad_tag": "nodkey.grant.v1",
            "kid_label": "nodkey.kid.v1",
            "max_grant_bytes": 2048,
            "skew_seconds": SKEW,
            "max_ttl_seconds": MAX_TTL,
        },
        "keys": keys,
        "workloads": [
            {"wid": APP1, "tenants": ["acme"]},
            {"wid": APP2, "tenants": ["acme", "globex"]},
        ],
        "operations": operations(),
        "vectors": vecs_json,
    });
    write("manifest.json", serde_json::to_string_pretty(&manifest).unwrap() + "\n");
    eprintln!("wrote {} vectors to {}", manifest["vectors"].as_array().unwrap().len(), dir.display());
}
