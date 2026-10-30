// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Shared fixture for the grant fuzz targets: the published grant-v1 test vectors
//! (tests/vectors/grant-v1), embedded at compile time.

use std::collections::HashSet;
use std::sync::OnceLock;

use nodkey_grant::{
    BrokerId, Limits, Operations, ParamValue, Params, Registry, Request, Verified, VerifyContext,
    verify,
};
use serde_json::Value as J;

const MANIFEST: &str = include_str!("../../../../tests/vectors/grant-v1/manifest.json");
const REGISTRY: &str = include_str!("../../../../tests/vectors/grant-v1/registry.json");
const OPERATIONS: &str = include_str!("../../../../tests/vectors/grant-v1/operations.json");

pub const NOW: u64 = 1_792_886_410;
pub const BROKER: &str = "nodkey.broker.ledger-test";
pub const APP1: &str = "spiffe://nodkey.test/workload/app1";

#[allow(dead_code)] // `vector_grants` is used by verify_raw only.
pub struct Fixture {
    pub registry: Registry,
    pub ops: Operations,
    pub bid: BrokerId,
    pub tenants: Vec<String>,
    /// Requests in order of first appearance in the manifest; `None` where the strict parser
    /// rejects the request (those vectors use a test-only constructor this harness does not enable).
    pub requests: Vec<Option<Request>>,
    /// Every grant byte string published in the vectors (accepted or not).
    pub vector_grants: HashSet<Vec<u8>>,
}

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

pub fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let m: J = serde_json::from_str(MANIFEST).expect("manifest");
        let ops = Operations::load(OPERATIONS).expect("operations");
        let tenants = m["workloads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["wid"] == APP1)
            .unwrap()["tenants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_owned())
            .collect();
        let mut seen: Vec<String> = Vec::new();
        let mut requests = Vec::new();
        for v in m["vectors"].as_array().unwrap() {
            for st in v["steps"].as_array().into_iter().flatten() {
                let Some(r) = st.get("request") else { continue };
                let key = r.to_string();
                if seen.contains(&key) {
                    continue;
                }
                seen.push(key);
                let params: Option<Params> = r["args"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| {
                        let pv = match v {
                            J::String(s) => ParamValue::Text(s.clone()),
                            J::Number(n) => ParamValue::Uint(n.as_u64()?),
                            _ => return None,
                        };
                        Some((k.clone(), pv))
                    })
                    .collect();
                requests.push(
                    params.and_then(|p| ops.parse_request(r["op"].as_str().unwrap(), p).ok()),
                );
            }
        }
        // Grant hex files are read once at start-up from the source tree (oracle set only).
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../tests/vectors/grant-v1/");
        let vector_grants = m["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["grant"].as_str())
            .map(|p| hex(&std::fs::read_to_string(format!("{dir}{p}")).expect("vector file")))
            .collect();
        Fixture {
            registry: Registry::load(REGISTRY).expect("registry"),
            ops,
            bid: BrokerId::new(BROKER).unwrap(),
            tenants,
            requests,
            vector_grants,
        }
    })
}

/// Full broker-side decision (steps 1c-9, then W12/W13 or R11/R13) for one request.
/// Returns true iff the grant is authorized.
pub fn decide(f: &Fixture, grant: &[u8], req: &Request) -> bool {
    let ctx = VerifyContext {
        now: NOW,
        broker_id: &f.bid,
        workload: APP1,
        workload_tenants: &f.tenants,
        request: req,
        operations: &f.ops,
        limits: Limits::default(),
    };
    match verify(grant, &f.registry, &ctx) {
        Err(e) => {
            let _ = e.as_str();
            false
        }
        Ok(Verified::Write(w)) => {
            let _ = w.consumption();
            w.decide(&[]).is_ok()
        }
        Ok(Verified::Read(r)) => r.decide(&[]).is_ok(),
    }
}

/// First input byte selects the request; falls back to request 0 (ACC-01's ledger.transfer).
pub fn pick_request(f: &Fixture, sel: u8) -> &Request {
    let n = f.requests.len();
    f.requests[usize::from(sel) % n]
        .as_ref()
        .or(f.requests[0].as_ref())
        .expect("request 0 is strictly valid")
}
