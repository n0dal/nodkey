// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! payments-adapter-v1 Draft 4 §16: `payments.support_refund` grants (PT-45..PT-47, PT-49). Every
//! refusal is checked against a counting TLS server: nothing may reach the provider.

mod common;

use std::sync::atomic::Ordering;

use common::*;
use nodkey_grant::{GrantBuilder, ParamValue};
use nodkey_payments_adapter::orders::OrderRow;
use serde_json::{Value, json};

const AGENT: &str = "spiffe://nodkey.test/workload/support";
const CH: &str = "ch_supportord01";

struct Env {
    f: FakeServer,
    p: P,
    orders: std::sync::Arc<FakeOrders>,
}

async fn env(support: Option<Value>) -> Env {
    let f = FakeServer::start(
        Script::Respond(vec![(ok_response("", ECHO_BODY), 0)]),
        false,
    )
    .await;
    let orders = FakeOrders::standard();
    orders.rows.lock().unwrap().insert(
        4720,
        OrderRow {
            order_id: 4720,
            ten: "acme".into(),
            owner_sub: "c42".into(),
            charge_id: CH.into(),
            currency: "USD".into(),
        },
    );
    let mut o = Opts::new(f.addr);
    o.orders = orders.clone();
    o.support = support;
    let p = start_p(o).await;
    Env { f, p, orders }
}

fn support_cfg() -> Option<Value> {
    Some(json!({"wids": [AGENT], "support_principals": {"acme": ["op_ana"]}}))
}

fn grant(wid: &str, sub: &str, con3: &str) -> GrantBuilder {
    let iat = now();
    GrantBuilder::write("payments.support_refund", 1)
        .issuer(ISS)
        .audience(BROKER)
        .jti(jti())
        .times(iat, iat, iat + 30)
        .workload(wid)
        .tenant("acme")
        .subject(sub)
        .resource(0, ParamValue::Uint(4720))
        .exact(0, ParamValue::Uint(500))
        .exact(1, ParamValue::Text("USD".into()))
        .exact(2, ParamValue::Text(CH.into()))
        .exact(3, ParamValue::Text(con3.into()))
}

impl Env {
    fn sent(&self) -> usize {
        self.f.tcp_accepts.load(Ordering::SeqCst)
    }
    async fn refused(&self, g: &GrantBuilder, what: &str) {
        let before = self.sent();
        let v = self.p.create(&sign(g, SEED)).await;
        assert_eq!(err_code(&v), "grant_refused", "{what}: {v}");
        assert_eq!(
            self.sent(),
            before,
            "{what}: something reached the provider"
        );
    }
    async fn created(&self, g: &GrantBuilder, what: &str) {
        let v = self.p.create(&sign(g, SEED)).await;
        assert_eq!(result_class(&v).0, "created", "{what}: {v}");
    }
}

/// Positive controls: `cfm = 1` and `cfm = 2` with `mid` (the adapter does not evaluate the
/// mandate); the order check is on con3, not on the support principal `sub`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn support_refund_created_with_cfm_1_and_2() {
    let e = env(support_cfg()).await;
    e.created(&grant(AGENT, "op_ana", "c42").confirmed(true), "cfm = 1")
        .await;
    e.created(
        &grant(AGENT, "op_ana", "c42").mandated([7; 16]),
        "cfm = 2 + mid",
    )
    .await;
}

/// PT-45: `sub` ∉ support_principals, `wid` ∉ support.wids, no `support` configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pt45_principal_wid_and_configuration() {
    let e = env(support_cfg()).await;
    e.refused(
        &grant(AGENT, "op_bob", "c42").confirmed(true),
        "sub not a principal",
    )
    .await;
    e.refused(
        &grant(SHOP, "op_ana", "c42").confirmed(true),
        "wid not a support wid",
    )
    .await;
    let none = env(None).await;
    none.refused(
        &grant(AGENT, "op_ana", "c42").confirmed(true),
        "no support configuration",
    )
    .await;
}

/// PT-46: con3 ≠ the order's owner (a broker lying about the customer); con3 = " ". PT-49: owner
/// changed after signing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pt46_pt49_owner_is_con3() {
    let e = env(support_cfg()).await;
    e.refused(&grant(AGENT, "op_ana", "c9").confirmed(true), "con3 lie")
        .await;
    e.refused(
        &grant(AGENT, "op_ana", " ").confirmed(true),
        "reserved con3",
    )
    .await;
    let g = grant(AGENT, "op_ana", "c42").confirmed(true);
    e.orders
        .rows
        .lock()
        .unwrap()
        .get_mut(&4720)
        .unwrap()
        .owner_sub = "c9".into();
    e.refused(&g, "owner changed after signing").await;
}

/// PT-47: `cfm = 0` is refused (grant crate: confirmation required); a `cfm = 2` grant without
/// `mid` cannot be built (format rule, grant-v1 MND-04/05 vectors cover the parse side).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pt47_cfm() {
    let e = env(support_cfg()).await;
    e.refused(&grant(AGENT, "op_ana", "c42").confirmed(false), "cfm = 0")
        .await;
}

/// §16.1: strict `support` member; every tenant configured; no empty lists.
#[test]
fn support_config_refusals() {
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let path = sockdir().join("cfg.sock");
    for bad in [
        json!({"wids": [], "support_principals": {"acme": ["op_ana"]}}),
        json!({"wids": [AGENT], "support_principals": {}}),
        json!({"wids": [AGENT], "support_principals": {"globex": ["op_ana"]}}),
        json!({"wids": [AGENT], "support_principals": {"acme": []}}),
        json!({"wids": [AGENT, AGENT], "support_principals": {"acme": ["op_ana"]}}),
        json!({"wids": [AGENT], "support_principals": {"acme": ["op ana"]}}),
        json!({"wids": [AGENT], "support_principals": {"acme": ["op_ana"]}, "x": 1}),
    ] {
        let mut o = Opts::new(addr);
        o.support = Some(bad.clone());
        assert!(try_build_adapter(&o, &path).is_err(), "{bad}");
    }
    let mut o = Opts::new(addr);
    o.support = support_cfg();
    assert!(try_build_adapter(&o, &path).is_ok());
}
