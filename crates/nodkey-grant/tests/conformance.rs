// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Runs every vector of `tests/vectors/grant-v1/manifest.json` (spec Draft 4): grant vectors
//! (every step), registry, operation-declaration and transport vectors, and the request-hash
//! examples. Each must give exactly the expected result.

mod common;

use std::collections::BTreeMap;

use common::*;
use nodkey_grant::{
    AAD_TAG, BrokerId, KID_LABEL, MAX_GRANT_BYTES, MAX_SKEW, MAX_TRANSPORT_CHARS, MAX_TTL,
    Operations, RQH_LABEL, Registry, TYP, decode_transport,
};

#[derive(Default, Debug)]
struct Counts {
    grant: usize,
    steps: usize,
    registry: usize,
    operations: usize,
    transport: usize,
    request_hash: usize,
}

#[test]
fn all_vectors() {
    let m = manifest();
    assert_eq!(m["format"], "nodkey.grant-v1.vectors");
    assert_eq!(m["spec_draft"], 4);
    let c = &m["constants"];
    assert_eq!(c["typ"], TYP);
    assert_eq!(c["external_aad_tag"], AAD_TAG);
    assert_eq!(c["kid_label"], KID_LABEL);
    assert_eq!(c["request_hash_label"], RQH_LABEL);
    assert_eq!(c["max_grant_bytes"], MAX_GRANT_BYTES as u64);
    assert_eq!(c["max_transport_chars"], MAX_TRANSPORT_CHARS as u64);
    assert_eq!(c["skew_seconds"], MAX_SKEW);
    assert_eq!(c["max_ttl_seconds"], MAX_TTL);

    let wl = workloads(&m);
    let mut regs: BTreeMap<String, Registry> = BTreeMap::new();
    let mut opsets: BTreeMap<String, Operations> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut unvalidated = Vec::new();
    let mut n = Counts::default();

    // Request-hash examples (spec §5.4).
    let ops = operations();
    for ex in m["request_hash_examples"].as_array().unwrap() {
        n.request_hash += 1;
        let req = ops
            .parse_request(
                ex["request"]["op"].as_str().unwrap(),
                params(&ex["request"]["args"]),
            )
            .expect("example request is valid");
        let want = hex(ex["request_hash"].as_str().unwrap());
        if req.request_hash().as_slice() != want.as_slice() {
            failures.push(format!("request_hash example {}", ex["request"]));
        }
    }

    for v in m["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        match v["kind"].as_str().unwrap() {
            "registry" => {
                n.registry += 1;
                let got = match load_registry(v["registry"].as_str().unwrap()) {
                    Ok(_) => "LOAD_OK".to_owned(),
                    Err(code) => code,
                };
                let want = v["expected"].as_str().unwrap();
                if got != want {
                    failures.push(format!("{id}: expected {want}, got {got}"));
                }
            }
            "operations" => {
                n.operations += 1;
                let got = match Operations::load(&read(v["operations"].as_str().unwrap())) {
                    Ok(_) => "LOAD_OK".to_owned(),
                    Err(e) => e.as_str().to_owned(),
                };
                let want = v["expected"].as_str().unwrap();
                if got != want {
                    failures.push(format!("{id}: expected {want}, got {got}"));
                }
            }
            "transport" => {
                n.transport += 1;
                let text = v["text"].as_str().unwrap();
                assert_eq!(text.len() as u64, v["text_len"].as_u64().unwrap(), "{id}");
                let want = v["expected"].as_str().unwrap();
                let got = match decode_transport(Some(text)) {
                    Ok(bytes) => {
                        let expected_bytes = match v["decoded"].as_str() {
                            Some(f) => hex(&read(f)),
                            None => Vec::new(),
                        };
                        if bytes == expected_bytes {
                            "DECODED".to_owned()
                        } else {
                            "DECODED(wrong bytes)".to_owned()
                        }
                    }
                    Err(code) => code.as_str().to_owned(),
                };
                if got != want {
                    failures.push(format!("{id}: expected {want}, got {got}"));
                }
            }
            "grant" => {
                n.grant += 1;
                let reg_file = v["registry"].as_str().unwrap();
                let ops_file = v["operations"].as_str().unwrap();
                if !regs.contains_key(reg_file) {
                    regs.insert(reg_file.into(), load_registry(reg_file).expect(reg_file));
                }
                if !opsets.contains_key(ops_file) {
                    opsets.insert(ops_file.into(), Operations::load(&read(ops_file)).unwrap());
                }
                let ops = &opsets[ops_file];
                let grant = hex(&read(v["grant"].as_str().unwrap()));
                assert_eq!(grant.len() as u64, v["grant_len"].as_u64().unwrap(), "{id}");
                let broker = Broker {
                    registry: &regs[reg_file],
                    operations: ops,
                    workloads: &wl,
                };
                let mut store = ReplayStore::default();
                for (i, s) in v["steps"].as_array().unwrap().iter().enumerate() {
                    n.steps += 1;
                    let revoked = revocations(&s["revoked_before"]);
                    let before = unvalidated.len();
                    let req = request(
                        ops,
                        s["request"]["op"].as_str().unwrap(),
                        params(&s["request"]["args"]),
                        &mut unvalidated,
                    );
                    if unvalidated.len() > before {
                        let last = unvalidated.pop().unwrap();
                        unvalidated.push(format!("{id} step {i}: {last}"));
                    }
                    let bid = BrokerId::new(s["broker_id"].as_str().unwrap()).expect("broker_id");
                    let sub = Submission {
                        now: s["now"].as_u64().unwrap(),
                        broker_id: &bid,
                        peer_wid: s["peer_wid"].as_str().unwrap(),
                        revoked: &revoked,
                        request: &req,
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

    println!("{n:?}, failures: {}", failures.len());
    println!("requests rejected by the strict parser (run unvalidated): {unvalidated:#?}");
    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
    // Draft 2 counts (spec §12.1) plus the Draft 4 additions of spec §17 (MND-01..12, one step
    // each; OPS-21..25); guards against a silently truncated manifest.
    assert_eq!(
        (
            n.grant,
            n.steps,
            n.registry,
            n.operations,
            n.transport,
            n.request_hash
        ),
        (292, 305, 26, 24, 11, 3)
    );
    // Only the vectors that deliberately carry ill-formed requests bypass the strict parser:
    // CON-20..23 (README), and CON-24, whose request is also outside the declaration (its grant
    // fails earlier, at step 7; SPEC_ISSUES.md D2-1).
    assert_eq!(unvalidated.len(), 5, "{unvalidated:#?}");
    for (u, idp) in unvalidated
        .iter()
        .zip(["CON-20", "CON-21", "CON-22", "CON-23", "CON-24"])
    {
        assert!(u.starts_with(idp), "{u}");
    }
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
