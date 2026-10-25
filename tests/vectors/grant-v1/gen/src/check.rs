//! Runs every vector in a manifest through the reference verifier and compares the results.
//! Reads only the manifest and the files it references (never the generator's internal data).

use crate::verify::{self, Class, Ctx, Env, OpDecl, Param, Place, ReqVal, Request, Revocation, Store, Ty};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len().is_multiple_of(2));
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn read_json(p: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

fn parse_ops(v: &Value) -> Vec<OpDecl> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|o| OpDecl {
            op: o["op"].as_str().unwrap().to_owned(),
            kind: o["kind"].as_str().unwrap().to_owned(),
            confirm: o["requires_confirmation"].as_bool().unwrap(),
            opv: o["opv"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect(),
            authority: o["authority"].as_str().unwrap().to_owned(),
            params: o["params"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| Param {
                    name: q["name"].as_str().unwrap().to_owned(),
                    place: match q["in"].as_str().unwrap() {
                        "res" => Place::Res,
                        "con" => Place::Con,
                        "request" => Place::Request,
                        x => panic!("place {x}"),
                    },
                    key: q["key"].as_u64(),
                    class: match q["class"].as_str().unwrap() {
                        "exact" => Class::Exact,
                        "bounded" => Class::Bounded,
                        "free" => Class::Free,
                        "owner_scoped" => Class::OwnerScoped,
                        x => panic!("class {x}"),
                    },
                    ty: match q["type"].as_str().unwrap() {
                        "account_id" => Ty::AccountId,
                        "currency" => Ty::Currency,
                        "uint" => Ty::Uint,
                        "text64" => Ty::Text64,
                        x => panic!("type {x}"),
                    },
                })
                .collect(),
        })
        .collect()
}

fn parse_request(v: &Value) -> Request {
    let mut args = BTreeMap::new();
    for (k, x) in v["args"].as_object().unwrap() {
        let val = match x {
            Value::String(s) => ReqVal::Text(s.clone()),
            Value::Number(n) => ReqVal::Uint(n.as_u64().unwrap()),
            _ => panic!("arg type"),
        };
        args.insert(k.clone(), val);
    }
    Request { op: v["op"].as_str().unwrap().to_owned(), args }
}

pub fn run(dir: &Path) -> bool {
    let m = read_json(&dir.join("manifest.json"));
    let skew = m["constants"]["skew_seconds"].as_u64().unwrap();
    let max_ttl = m["constants"]["max_ttl_seconds"].as_u64().unwrap();
    let mut workloads = HashMap::new();
    for w in m["workloads"].as_array().unwrap() {
        let t = w["tenants"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_owned()).collect();
        workloads.insert(w["wid"].as_str().unwrap().to_owned(), t);
    }
    let (mut pass, mut fail) = (0, 0);
    for v in m["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let reg_doc = read_json(&dir.join(v["registry"].as_str().unwrap()));
        let reg = verify::load_registry(&reg_doc);
        if v["kind"] == "registry" {
            let got = match reg {
                Ok(_) => "LOAD_OK".to_owned(),
                Err(e) => e.to_owned(),
            };
            let want = v["expected"].as_str().unwrap();
            if got == want {
                pass += 1;
            } else {
                fail += 1;
                println!("FAIL {id}: expected {want}, got {got}");
            }
            continue;
        }
        let env = Env {
            registry: reg.unwrap_or_else(|e| panic!("{id}: registry failed to load: {e}")),
            workloads: workloads.clone(),
            ops: parse_ops(&m["operations"]),
            skew,
            max_ttl,
        };
        let grant = unhex(&fs::read_to_string(dir.join(v["grant"].as_str().unwrap())).unwrap());
        assert_eq!(grant.len() as u64, v["grant_len"].as_u64().unwrap(), "{id}: grant_len");
        let mut store = Store::new();
        for (i, s) in v["steps"].as_array().unwrap().iter().enumerate() {
            let ctx = Ctx {
                now: s["now"].as_u64().unwrap(),
                broker_id: s["broker_id"].as_str().unwrap().to_owned(),
                peer_wid: s["peer_wid"].as_str().unwrap().to_owned(),
                revocations: s["revoked_before"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| Revocation {
                        ten: r["ten"].as_str().unwrap().to_owned(),
                        wid: r.get("wid").map(|x| x.as_str().unwrap().to_owned()),
                        sub: r.get("sub").map(|x| x.as_str().unwrap().to_owned()),
                        before: r["before"].as_u64().unwrap(),
                    })
                    .collect(),
            };
            let got = verify::process(&grant, &parse_request(&s["request"]), &ctx, &env, &mut store);
            let want = s["expected"].as_str().unwrap();
            if got == want {
                pass += 1;
            } else {
                fail += 1;
                println!("FAIL {id} step {}: expected {want}, got {got}", i + 1);
            }
        }
    }
    println!("checked: {pass} passed, {fail} failed");
    fail == 0
}
