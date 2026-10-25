//! Runs every vector in a manifest through the reference verifier and compares the results.
//! Reads only the manifest and the files it references (never the generator's internal data).

use crate::verify::{self, Ctx, Env, ReqVal, Request, Revocation, Store};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len().is_multiple_of(2));
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn read(dir: &Path, rel: &str) -> String {
    fs::read_to_string(dir.join(rel)).unwrap()
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
    let m: Value = serde_json::from_str(&read(dir, "manifest.json")).unwrap();
    let skew = m["constants"]["skew_seconds"].as_u64().unwrap();
    let max_ttl = m["constants"]["max_ttl_seconds"].as_u64().unwrap();
    let mut workloads = HashMap::new();
    for w in m["workloads"].as_array().unwrap() {
        let t = w["tenants"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_owned()).collect();
        workloads.insert(w["wid"].as_str().unwrap().to_owned(), t);
    }
    let (mut pass, mut fail) = (0, 0);
    let mut verdict = |id: &str, got: String, want: &str| {
        if got == want {
            pass += 1;
        } else {
            fail += 1;
            println!("FAIL {id}: expected {want}, got {got}");
        }
    };
    for ex in m["request_hash_examples"].as_array().unwrap() {
        let r = parse_request(&ex["request"]);
        let got: String = verify::request_hash(&r.op, &r.args).iter().map(|b| format!("{b:02x}")).collect();
        verdict("request_hash_example", got, ex["request_hash"].as_str().unwrap());
    }
    for v in m["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let want = v["expected"].as_str();
        match v["kind"].as_str().unwrap() {
            "registry" => {
                let got = verify::load_registry(&read(dir, v["registry"].as_str().unwrap())).map(|_| "LOAD_OK".to_owned()).unwrap_or_else(|e| e.to_owned());
                verdict(id, got, want.unwrap());
            }
            "operations" => {
                let got = verify::load_operations(&read(dir, v["operations"].as_str().unwrap())).map(|_| "LOAD_OK".to_owned()).unwrap_or_else(|e| e.to_owned());
                verdict(id, got, want.unwrap());
            }
            "transport" => {
                let text = v["text"].as_str().unwrap();
                assert_eq!(text.len() as u64, v["text_len"].as_u64().unwrap());
                let got = match verify::decode_transport(text) {
                    Ok(bytes) => {
                        let expect_bytes = v["decoded"].as_str().map(|f| unhex(&read(dir, f))).unwrap_or_default();
                        if bytes == expect_bytes { "DECODED".to_owned() } else { "DECODED_WRONG_BYTES".to_owned() }
                    }
                    Err(e) => e.to_owned(),
                };
                verdict(id, got, want.unwrap());
            }
            "grant" => {
                let env = Env {
                    registry: verify::load_registry(&read(dir, v["registry"].as_str().unwrap())).unwrap_or_else(|e| panic!("{id}: {e}")),
                    workloads: workloads.clone(),
                    ops: verify::load_operations(&read(dir, v["operations"].as_str().unwrap())).unwrap_or_else(|e| panic!("{id}: {e}")),
                    skew,
                    max_ttl,
                };
                let grant = unhex(&read(dir, v["grant"].as_str().unwrap()));
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
                    verdict(&format!("{id} step {}", i + 1), got, s["expected"].as_str().unwrap());
                }
            }
            k => panic!("unknown kind {k}"),
        }
    }
    println!("checked: {pass} passed, {fail} failed");
    fail == 0
}
