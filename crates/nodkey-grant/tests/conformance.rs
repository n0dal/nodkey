//! Runs every vector and every step of `tests/vectors/grant-v1/manifest.json` and asserts the
//! exact expected result.

mod common;

use common::*;
use nodkey_grant::{AAD_TAG, KID_LABEL, MAX_GRANT_BYTES, MAX_SKEW, MAX_TTL, TYP};

#[test]
fn all_vectors() {
    let m = manifest();
    assert_eq!(m["format"], "nodkey.grant-v1.vectors");
    let c = &m["constants"];
    assert_eq!(c["typ"], TYP);
    assert_eq!(c["external_aad_tag"], AAD_TAG);
    assert_eq!(c["kid_label"], KID_LABEL);
    assert_eq!(c["max_grant_bytes"], MAX_GRANT_BYTES as u64);
    assert_eq!(c["skew_seconds"], MAX_SKEW);
    assert_eq!(c["max_ttl_seconds"], MAX_TTL);

    let ops = operations(&m);
    let wl = workloads(&m);
    let mut cache = Cache::new();

    let mut failures = Vec::new();
    let (mut grant_vectors, mut steps, mut registry_vectors) = (0usize, 0usize, 0usize);

    for v in m["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let reg_file = v["registry"].as_str().unwrap();
        match v["kind"].as_str().unwrap() {
            "registry" => {
                registry_vectors += 1;
                let got = match load_registry(reg_file) {
                    Ok(_) => "LOAD_OK".to_owned(),
                    Err(code) => code,
                };
                let want = v["expected"].as_str().unwrap();
                if got != want {
                    failures.push(format!("{id}: expected {want}, got {got}"));
                }
            }
            "grant" => {
                grant_vectors += 1;
                if !cache.contains_key(reg_file) {
                    let r = load_registry(reg_file).expect("grant vector registry loads");
                    cache.insert(reg_file.to_owned(), r);
                }
                let registry = &cache[reg_file];
                let grant_hex =
                    std::fs::read_to_string(vectors_dir().join(v["grant"].as_str().unwrap()))
                        .unwrap();
                let grant = hex(&grant_hex);
                assert_eq!(grant.len() as u64, v["grant_len"].as_u64().unwrap(), "{id}");
                let broker = Broker {
                    registry,
                    operations: &ops,
                    workloads: &wl,
                };
                let mut store = ReplayStore::default();
                for (i, s) in v["steps"].as_array().unwrap().iter().enumerate() {
                    steps += 1;
                    let revoked = revocations(&s["revoked_before"]);
                    let req_params = params(&s["request"]["args"]);
                    let sub = Submission {
                        now: s["now"].as_u64().unwrap(),
                        broker_id: s["broker_id"].as_str().unwrap(),
                        peer_wid: s["peer_wid"].as_str().unwrap(),
                        revoked: &revoked,
                        op: s["request"]["op"].as_str().unwrap(),
                        params: &req_params,
                    };
                    let got = broker.submit(&mut store, &grant, &sub);
                    let want = s["expected"].as_str().unwrap();
                    if got != want {
                        failures.push(format!("{id} step {i}: expected {want}, got {got}"));
                    }
                }
            }
            k => panic!("unknown vector kind {k}"),
        }
    }

    println!(
        "grant vectors: {grant_vectors}, grant steps: {steps}, registry vectors: {registry_vectors}, failures: {}",
        failures.len()
    );
    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
    // Counts stated in spec §12.1; guards against a silently truncated manifest.
    assert_eq!(grant_vectors, 235);
    assert_eq!(steps, 246);
    assert_eq!(registry_vectors, 17);
}

#[test]
fn manifest_keys_match_registry_and_kid_derivation() {
    let m = manifest();
    let reg = load_registry("registry.json").unwrap();
    for k in m["keys"].as_array().unwrap() {
        let pk: [u8; 32] = hex(k["public_key"].as_str().unwrap()).try_into().unwrap();
        let kid: [u8; 16] = hex(k["kid"].as_str().unwrap()).try_into().unwrap();
        assert_eq!(nodkey_grant::derive_kid(&pk), kid);
        let seed: [u8; 32] = hex(k["secret_seed"].as_str().unwrap()).try_into().unwrap();
        let sk = nodkey_grant::SigningKey::from_bytes(&seed);
        assert_eq!(sk.verifying_key().to_bytes(), pk);
        assert_eq!(reg.get(&kid).is_some(), k["in_registry"].as_bool().unwrap());
    }
}
