// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Shared test harness: loads `tests/vectors/grant-v1/manifest.json` and simulates the broker
//! parts this crate does not own (the W10 replay store with an in-memory map, the savepoint
//! recording rule of spec §7.3), as described in the vectors README.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use nodkey_grant::{
    BrokerId, Limits, Operations, ParamValue, Params, Registry, Request, RevocationScope,
    RevokedBefore, Verified, VerifyContext, verify,
};
use serde_json::Value as J;

pub fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/grant-v1")
}

pub fn hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len() % 2 == 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

pub fn read(rel: &str) -> String {
    std::fs::read_to_string(vectors_dir().join(rel)).expect(rel)
}

pub fn manifest() -> J {
    serde_json::from_str(&read("manifest.json")).expect("manifest json")
}

pub fn operations() -> Operations {
    Operations::load(&read("operations.json")).expect("operations.json loads")
}

pub fn workloads(m: &J) -> HashMap<String, Vec<String>> {
    m["workloads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| {
            (
                w["wid"].as_str().unwrap().to_owned(),
                w["tenants"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|t| t.as_str().unwrap().to_owned())
                    .collect(),
            )
        })
        .collect()
}

pub fn params(args: &J) -> Params {
    args.as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| {
            let pv = match v {
                J::String(s) => ParamValue::Text(s.clone()),
                J::Number(n) => ParamValue::Uint(n.as_u64().expect("uint arg")),
                other => panic!("arg {other}"),
            };
            (k.clone(), pv)
        })
        .collect()
}

pub fn revocations(rows: &J) -> Vec<RevokedBefore> {
    rows.as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let ten = r["ten"].as_str().unwrap().to_owned();
            let scope = match (r.get("wid"), r.get("sub")) {
                (None, None) => RevocationScope::Tenant { ten },
                (Some(w), None) => RevocationScope::TenantWorkload {
                    ten,
                    wid: w.as_str().unwrap().to_owned(),
                },
                (None, Some(s)) => RevocationScope::TenantSubject {
                    ten,
                    sub: s.as_str().unwrap().to_owned(),
                },
                _ => panic!("revocation row {r}"),
            };
            RevokedBefore {
                scope,
                before: r["before"].as_u64().unwrap(),
            }
        })
        .collect()
}

/// Builds the request the way a broker would: strict validation first. Vectors that
/// deliberately pass an ill-formed request (CON-20..23) are built with the test-only unvalidated
/// constructor so they reach W12, and the harness records that the strict parser rejects them.
pub fn request(ops: &Operations, op: &str, p: Params, unvalidated: &mut Vec<String>) -> Request {
    match ops.parse_request(op, p.clone()) {
        Ok(r) => r,
        Err(e) => {
            unvalidated.push(format!("{op}: {e}"));
            Request::unvalidated_for_conformance(op, p).expect("encodable request")
        }
    }
}

type ReplayKey = (String, [u8; 16]);
type ReplayRow = ([u8; 32], &'static str);

/// In-memory replay store: (iss, jti) -> (request hash, outcome).
#[derive(Default)]
pub struct ReplayStore {
    rows: HashMap<ReplayKey, ReplayRow>,
}

/// One submission's trusted context and request (one manifest step).
pub struct Submission<'a> {
    pub now: u64,
    pub broker_id: &'a BrokerId,
    pub peer_wid: &'a str,
    pub revoked: &'a [RevokedBefore],
    pub request: &'a Request,
}

pub struct Broker<'a> {
    pub registry: &'a Registry,
    pub operations: &'a Operations,
    pub workloads: &'a HashMap<String, Vec<String>>,
}

impl Broker<'_> {
    /// Steps 1c–9, then W10–W13 (write: consumption first, every denial recorded in the same
    /// "transaction") or R11/R13 (read). Returns the manifest's expected-result string.
    pub fn submit(&self, store: &mut ReplayStore, grant: &[u8], sub: &Submission<'_>) -> String {
        let empty = Vec::new();
        let ctx = VerifyContext {
            now: sub.now,
            broker_id: sub.broker_id,
            workload: sub.peer_wid,
            workload_tenants: self.workloads.get(sub.peer_wid).unwrap_or(&empty),
            request: sub.request,
            operations: self.operations,
            limits: Limits::default(),
        };
        match verify(grant, self.registry, &ctx) {
            Err(code) => code.as_str().into(),
            Ok(Verified::Read(r)) => match r.decide(sub.revoked) {
                Ok(_) => "ACCEPT".into(),
                Err(code) => code.as_str().into(),
            },
            Ok(Verified::Write(w)) => {
                // W10: first statement of the effect transaction.
                let c = w.consumption();
                let key = (c.iss.clone(), c.jti);
                if let Some((stored, outcome)) = store.rows.get(&key) {
                    return if *stored == c.request_hash {
                        format!("STORED_OUTCOME:{outcome}")
                    } else {
                        "grant_replayed".into()
                    };
                }
                store.rows.insert(key.clone(), (c.request_hash, "PENDING"));
                // W11–W13 after the savepoint; commit ACCEPT or DENIED with the row.
                let result = w.decide(sub.revoked);
                let row = store.rows.get_mut(&key).unwrap();
                match result {
                    Ok(_) => {
                        row.1 = "ACCEPT";
                        "ACCEPT".into()
                    }
                    Err(code) => {
                        row.1 = "DENIED";
                        code.as_str().into()
                    }
                }
            }
        }
    }
}

pub fn load_registry(file: &str) -> Result<Registry, String> {
    Registry::load(&read(file)).map_err(|e| e.code.as_str().to_owned())
}

/// Deterministic xorshift64* PRNG for the smoke and property tests (no external dependency).
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

pub const SEED_A: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
pub const SEED_E: &str = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
pub const BROKER: &str = "nodkey.broker.ledger-test";
pub const APP1: &str = "spiffe://nodkey.test/workload/app1";

pub fn broker_id() -> BrokerId {
    BrokerId::new(BROKER).unwrap()
}

pub fn signing_key(seed_hex: &str) -> nodkey_grant::SigningKey {
    nodkey_grant::SigningKey::from_bytes(&hex(seed_hex).try_into().unwrap())
}
