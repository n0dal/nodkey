// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Socket I `read_grant` (effect-protocol-v2 §4.2, EP-05).

mod common;

use common::*;
use nodkey_grant::{
    BrokerId, Limits, Operations, ParamValue, Registry, Verified, VerifyContext, decode_transport,
    verify,
};
use serde_json::{Value, json};

async fn read_grant(path: &std::path::Path, ten: &str, sub: &str, wid: &str, rop: Value) -> Value {
    let req = json!({"v":2,"id":"g-r","op":"read_grant","args":{
        "subject": {"ten": ten, "sub": sub}, "wid": wid, "rop": rop}});
    gateway_raw(path, &req.to_string()).await.unwrap()
}

#[tokio::test]
async fn read_grant_signs_knd2_that_a_broker_accepts_for_reads_only() {
    let dir = tmpdir("read");
    let keys = make_key(&dir);
    let broker = FakeBroker::start(&dir, &keys.registry_json).await;
    let run = start_authority(&dir, &keys, &broker.path, Opts::new()).await;

    let r = read_grant(
        &run.gateway_path,
        "globex",
        "user:u-5",
        SHOP,
        json!(["payments.get_order"]),
    )
    .await;
    assert!(is_ok(&r), "{r}");
    let grant = decode_transport(r["result"]["grant"].as_str()).unwrap();

    let registry = Registry::load(&keys.registry_json).unwrap();
    let ops = Operations::load(OPERATIONS).unwrap();
    let broker_id = BrokerId::new(BROKER_ID).unwrap();
    let tenants = vec!["acme".to_owned(), "globex".to_owned()];
    let check = |op: &str, params: Vec<(&str, ParamValue)>| {
        let request = ops
            .parse_request(
                op,
                params.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
            )
            .unwrap();
        let ctx = VerifyContext {
            now: now(),
            broker_id: &broker_id,
            workload: SHOP,
            workload_tenants: &tenants,
            request: &request,
            operations: &ops,
            limits: Limits::default(),
        };
        match verify(&grant, &registry, &ctx) {
            Ok(Verified::Read(g)) => {
                let id = g.identity().clone();
                g.decide(&[]).map(|_| id).map_err(|e| e.as_str())
            }
            Ok(Verified::Write(_)) => Err("write"),
            Err(e) => Err(e.as_str()),
        }
    };
    let id = check(
        "payments.get_order",
        vec![("order_id", ParamValue::Uint(1))],
    )
    .unwrap();
    assert_eq!((id.ten.as_str(), id.sub.as_str()), ("globex", "user:u-5"));
    assert_eq!(id.exp - id.iat, 30);
    assert_eq!(id.nbf, id.iat);
    // Never valid for a write operation (T26).
    let w = check(
        "payments.refund",
        vec![
            ("order_id", ParamValue::Uint(1)),
            ("amount_minor", ParamValue::Uint(1)),
            ("currency", ParamValue::Text("EUR".into())),
            ("charge_id", ParamValue::Text("ch_demoorder0001".into())),
        ],
    );
    assert!(w.is_err());

    // Two read grants get distinct CSPRNG jtis.
    let r2 = read_grant(
        &run.gateway_path,
        "globex",
        "user:u-5",
        SHOP,
        json!(["payments.get_order"]),
    )
    .await;
    assert_ne!(r["result"]["grant"], r2["result"]["grant"]);
}

#[tokio::test]
async fn read_grant_refusals() {
    let dir = tmpdir("readno");
    let keys = make_key(&dir);
    let broker = FakeBroker::start(&dir, &keys.registry_json).await;
    let run = start_authority(&dir, &keys, &broker.path, Opts::new()).await;
    let p = &run.gateway_path;
    let cases = [
        // tenant not registered for the workload
        ("initech", SHOP, json!(["payments.get_order"])),
        // write operation in rop
        ("acme", SHOP, json!(["payments.refund"])),
        // read op declared but not allowed for this workload
        ("acme", SHOP, json!(["ledger.get_balance"])),
        // unknown workload
        (
            "acme",
            "spiffe://nodkey.test/workload/other",
            json!(["payments.get_order"]),
        ),
        // empty, duplicate, wrong type
        ("acme", SHOP, json!([])),
        (
            "acme",
            SHOP,
            json!(["payments.get_order", "payments.get_order"]),
        ),
        ("acme", SHOP, json!("payments.get_order")),
    ];
    for (ten, wid, rop) in cases {
        let r = read_grant(p, ten, "user:u-1", wid, rop.clone()).await;
        assert_eq!(err_code(&r), Some("not_available"), "{ten} {wid} {rop}");
    }
    let r = read_grant(p, "acme", "bad sub", SHOP, json!(["payments.get_order"])).await;
    assert_eq!(err_code(&r), Some("not_available"));
}

#[tokio::test]
async fn au_r_03_enrolled_workload_reads_only_for_its_principal() {
    let dir = tmpdir("readenr");
    let keys = make_key(&dir);
    let broker = FakeBroker::start(&dir, &keys.registry_json).await;
    let run = start_authority(&dir, &keys, &broker.path, Opts::new()).await;
    let p = &run.gateway_path;
    let ok = read_grant(p, "acme", "user:u-17", AGENT, json!(["ledger.get_balance"])).await;
    assert!(is_ok(&ok), "{ok}");
    let other = read_grant(p, "acme", "user:u-18", AGENT, json!(["ledger.get_balance"])).await;
    assert_eq!(err_code(&other), Some("not_available"));
}
