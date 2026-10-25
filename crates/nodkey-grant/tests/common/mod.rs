//! Shared test harness: loads `tests/vectors/grant-v1/manifest.json` and simulates the broker
//! steps this crate does not own (step 12 consumption with an in-memory replay store, step 13
//! revocation), as described in the vectors README.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use nodkey_grant::{
    Authority, Binding, GrantKind, OpKind, OperationDecl, Operations, ParamDecl, ParamType,
    ParamValue, Params, Registry, RevocationScope, RevokedBefore, Skew, TextRule, VerifyContext,
    request_hash, verify,
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

pub fn manifest() -> J {
    let text = std::fs::read_to_string(vectors_dir().join("manifest.json")).expect("manifest");
    serde_json::from_str(&text).expect("manifest json")
}

// Parameter types are not defined by the spec (SPEC_ISSUES.md SI-1). These definitions are the
// harness's: account_id follows the broker's existing AccountId rule; currency is ISO 4217 style.
fn account_byte(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'
}
fn currency_byte(c: u8) -> bool {
    c.is_ascii_uppercase()
}
fn printable(c: u8) -> bool {
    (0x20..=0x7e).contains(&c)
}

pub fn param_type(name: &str) -> ParamType {
    match name {
        "uint" => ParamType::Uint,
        "account_id" => ParamType::Text(TextRule {
            min_len: 1,
            max_len: 32,
            allowed: account_byte,
        }),
        "currency" => ParamType::Text(TextRule {
            min_len: 3,
            max_len: 3,
            allowed: currency_byte,
        }),
        "text64" => ParamType::Text(TextRule {
            min_len: 0,
            max_len: 64,
            allowed: printable,
        }),
        other => panic!("unknown param type {other}"),
    }
}

pub fn operations(m: &J) -> Operations {
    let mut decls = Vec::new();
    for o in m["operations"].as_array().unwrap() {
        let kind = match o["kind"].as_str().unwrap() {
            "write" => OpKind::Write,
            "read" => OpKind::Read,
            k => panic!("kind {k}"),
        };
        let authority = match o["authority"].as_str().unwrap() {
            "user_grant" => Authority::UserGrant,
            "scheduler_grant" => Authority::SchedulerGrant,
            a => panic!("authority {a}"),
        };
        let params = o["params"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                let key = p["key"].as_u64().map(|k| u8::try_from(k).unwrap());
                let binding = match (p["in"].as_str().unwrap(), p["class"].as_str().unwrap()) {
                    ("res", "exact") => Binding::Resource(key.unwrap()),
                    ("con", "exact") => Binding::Exact(key.unwrap()),
                    ("con", "bounded") => Binding::Bounded(key.unwrap()),
                    ("con", "free") => Binding::Free,
                    ("request", "owner_scoped") => Binding::OwnerScoped,
                    (i, c) => panic!("binding {i}/{c}"),
                };
                ParamDecl {
                    name: p["name"].as_str().unwrap().to_owned(),
                    binding,
                    ty: param_type(p["type"].as_str().unwrap()),
                }
            })
            .collect();
        decls.push(OperationDecl {
            name: o["op"].as_str().unwrap().to_owned(),
            kind,
            versions: o["opv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| u16::try_from(v.as_u64().unwrap()).unwrap())
                .collect(),
            authority,
            requires_confirmation: o["requires_confirmation"].as_bool().unwrap(),
            params,
        });
    }
    Operations::new(decls).expect("declarations valid")
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

type ReplayKey = (String, [u8; 16]);
type ReplayRow = ([u8; 32], &'static str);

/// One submission's trusted context and request (one manifest step).
pub struct Submission<'a> {
    pub now: u64,
    pub broker_id: &'a str,
    pub peer_wid: &'a str,
    pub revoked: &'a [RevokedBefore],
    pub op: &'a str,
    pub params: &'a Params,
}

/// In-memory replay store: (iss, jti) -> (request hash, outcome).
#[derive(Default)]
pub struct ReplayStore {
    rows: HashMap<ReplayKey, ReplayRow>,
}

/// The broker simulation for one submission: verify (1c–11), then 12 and 13 for write grants,
/// 13 for read grants. Returns the expected-result string format of the manifest.
pub struct Broker<'a> {
    pub registry: &'a Registry,
    pub operations: &'a Operations,
    pub workloads: &'a HashMap<String, Vec<String>>,
}

impl Broker<'_> {
    pub fn submit(&self, store: &mut ReplayStore, grant: &[u8], sub: &Submission<'_>) -> String {
        let Submission {
            now,
            broker_id,
            peer_wid,
            revoked,
            op,
            params,
        } = *sub;
        let empty = Vec::new();
        let tenants = self.workloads.get(peer_wid).unwrap_or(&empty);
        let ctx = VerifyContext {
            now,
            audience: broker_id,
            workload: peer_wid,
            workload_tenants: tenants,
            requested_op: op,
            requested_params: params,
            operations: self.operations,
            skew: Skew::default(),
        };
        match verify(grant, self.registry, &ctx) {
            Ok(g) => match g.kind() {
                GrantKind::Read => {
                    if g.identity().is_revoked(revoked) {
                        "grant_revoked".into()
                    } else {
                        "ACCEPT".into()
                    }
                }
                GrantKind::Write => {
                    let h = request_hash(op, g.opv(), params);
                    let key = (g.iss().to_owned(), *g.jti());
                    // Step 12 then 13, one transaction.
                    if let Some((stored, outcome)) = store.rows.get(&key) {
                        return if *stored == h {
                            format!("STORED_OUTCOME:{outcome}")
                        } else {
                            "grant_replayed".into()
                        };
                    }
                    if g.identity().is_revoked(revoked) {
                        store.rows.insert(key, (h, "DENIED"));
                        "grant_revoked".into()
                    } else {
                        store.rows.insert(key, (h, "ACCEPT"));
                        "ACCEPT".into()
                    }
                }
            },
            Err(rej) => {
                // Spec §7.3: a verified write grant denied at steps 10-11 is recorded once.
                if let Some(id) = &rej.verified {
                    if id.kind == GrantKind::Write {
                        let opv = id.write_op.as_ref().map(|(_, v)| *v).unwrap_or(0);
                        let h = request_hash(op, opv, params);
                        store
                            .rows
                            .entry((id.iss.clone(), id.jti))
                            .or_insert((h, "DENIED"));
                    }
                }
                rej.code.as_str().into()
            }
        }
    }
}

pub fn load_registry(file: &str) -> Result<Registry, String> {
    let text = std::fs::read_to_string(vectors_dir().join(file)).expect("registry file");
    Registry::load(&text).map_err(|e| e.code.as_str().to_owned())
}

pub type Cache = BTreeMap<String, Registry>;

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

pub fn signing_key(seed_hex: &str) -> nodkey_grant::SigningKey {
    nodkey_grant::SigningKey::from_bytes(&hex(seed_hex).try_into().unwrap())
}
