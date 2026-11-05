// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL integration tests for the broker side of mandates (agent-interface-v1 Draft 2 §3–§4,
//! effect-protocol-v2 Draft 4 §12, ADR-0006 Amendment 3). A fake authority signs with the RFC 8032
//! TEST 1 key (it may sign anything, which is how these tests check that the **broker's** own
//! mandate row bounds delivery and execution); a fake payments adapter answers `adapter.hello` only
//! (refunds are checked up to the T1 reservation). Run with `tests/run-pg-integration.sh`.
//!
//! AT-xx ids refer to agent-interface-v1 §7, Txx to effect-protocol-v2 §12.7.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::*;
use nodkey_broker::v2::config::{RawV2Config, V2Config};
use nodkey_broker::v2::db::Pool;
use nodkey_broker::v2::decls;
use nodkey_broker::v2::ids::{decode_id, encode_id, hex, random16};
use nodkey_broker::v2::service::{Broker, Clock, Delivery, Execution};
use nodkey_broker::v2::wire::{Code, Fail};
use nodkey_grant::{Binding, GrantBuilder, ParamValue, Registry, encode_transport};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const TEN: &str = "shop1";
const ANA: (&str, &str) = ("shop1", "op_ana");
const BOB: (&str, &str) = ("shop1", "op_bob");
const ALICE: &str = "alice@customer.test";

fn ops_text() -> String {
    r#"{"format":"nodkey.operations.v1","operations":[
 {"op":"payments.support_refund","kind":"write","opv":1,"requires_confirmation":true,"mandate_eligible":true,"params":[
  {"name":"order_id","in":"res","key":0,"class":"exact","type":"uint","destination":false},
  {"name":"amount_minor","in":"con","key":0,"class":"exact","type":"uint","destination":false},
  {"name":"currency","in":"con","key":1,"class":"exact","type":"currency","destination":false},
  {"name":"charge_id","in":"con","key":2,"class":"exact","type":"text64","destination":false},
  {"name":"customer_sub","in":"con","key":3,"class":"exact","type":"text64","destination":false}]},
 {"op":"payments.support_get_order","kind":"read","opv":1,"requires_confirmation":false,"params":[
  {"name":"order_id","in":"request","key":null,"class":"owner_scoped","type":"uint","destination":false}]},
 {"op":"messages.send","kind":"write","opv":1,"requires_confirmation":true,"mandate_eligible":true,"params":[
  {"name":"customer_sub","in":"res","key":0,"class":"exact","type":"text64","destination":false},
  {"name":"to","in":"con","key":0,"class":"exact","type":"text256","destination":true},
  {"name":"body","in":"con","key":null,"class":"free","type":"text256","destination":false,"justification":"message content (R-A2)"}]},
 {"op":"mandate.support_ticket","kind":"write","opv":1,"requires_confirmation":true,"params":[
  {"name":"customer_sub","in":"res","key":0,"class":"exact","type":"text64","destination":false},
  {"name":"currency","in":"con","key":0,"class":"exact","type":"currency","destination":false},
  {"name":"refund_max_count","in":"con","key":1,"class":"exact","type":"uint","destination":false},
  {"name":"refund_max_per_call_minor","in":"con","key":2,"class":"exact","type":"uint","destination":false},
  {"name":"refund_max_total_minor","in":"con","key":3,"class":"exact","type":"uint","destination":false},
  {"name":"message_max_count","in":"con","key":4,"class":"exact","type":"uint","destination":false},
  {"name":"valid_for_s","in":"con","key":5,"class":"exact","type":"uint","destination":false},
  {"name":"customer_email","in":"con","key":6,"class":"exact","type":"text256","destination":false}]}]}"#
        .to_string()
}

const AGENT_OPS: &str = r#"["payments.support_refund","messages.send","mandate.support_ticket","payments.support_get_order"]"#;

const AUTH_WL: &str = r#"{"format":"nodkey.workloads.v1","workloads":[
 {"wid":"spiffe://nodkey.test/workload/agent","tenants":["shop1"],"approver_source":{"enrolled":{"ten":"shop1","sub":"op_ana"}},
  "write_ops":["payments.support_refund","messages.send","mandate.support_ticket"],"read_ops":["payments.support_get_order"]},
 {"wid":"spiffe://nodkey.test/workload/agent2","tenants":["shop1"],"approver_source":{"enrolled":{"ten":"shop1","sub":"op_bob"}},
  "write_ops":["payments.support_refund","messages.send","mandate.support_ticket"],"read_ops":["payments.support_get_order"]}],
 "support_principals":{"shop1":["op_ana","op_bob"]},
 "mandate_template":{"template":"mandate.support_ticket","refund_op":"payments.support_refund",
  "read_ops":["payments.support_get_order"],"message_op":"messages.send",
  "ceilings":{"refund_max_count":5,"message_max_count":10,"refund_max_total_minor":{"EUR":10000}}}}"#;

fn config(db: &str, sock: &str, adapter_uid: u32) -> String {
    format!(
        r#"{{"format":"nodkey.broker.v2","profile":"phase3","broker_id":"{BROKER_ID}",
 "auth_origin":"https://auth.nodkey.test","ledger_currency":"EUR",
 "db":{{"host":"unused","port":5432,"dbname":"{db}","user":"nodkey_broker","password_file":"/nonexistent"}},
 "registry_path":"/nonexistent","operations_path":"/nonexistent","authority_workloads_path":"/nonexistent",
 "limits":{{"pending_per_wid":128,"pending_per_approver":128,"proposals_per_min":600,"proposal_burst":600,"status_per_min":600,"pending_lifetime_s":600,"reads_per_min":600,"db_conns_per_wid":4}},
 "gateway":{{"socket_path":"/run/t/gw-broker/broker.sock","uid":20001}},
 "authority":{{"socket_path":"/run/t/au-broker/broker.sock","uid":20002}},
 "payments":{{"adapter_socket":"{sock}","adapter_uid":{adapter_uid},"R_max_s":180,"max_resends":5,"adapter_total_ms":400,
   "budget":{{"max_count_per_day":1000,"limits_minor":{{"EUR":10000000}}}}}},
 "workloads":[
  {{"wid":"{AGENT}","display_name":"support-bot","socket_path":"/run/t/wl/agent/broker.sock","uid":10001,
   "tenants":["shop1"],"approver_source":{{"kind":"enrolled","ten":"shop1","sub":"op_ana"}},"allowed_ops":{AGENT_OPS}}},
  {{"wid":"{AGENT2}","display_name":"support-bot-2","socket_path":"/run/t/wl/agent2/broker.sock","uid":10002,
   "tenants":["shop1"],"approver_source":{{"kind":"enrolled","ten":"shop1","sub":"op_bob"}},"allowed_ops":{AGENT_OPS}}}]}}"#
    )
}

fn my_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    let p = std::env::temp_dir().join(format!(
        "gm-uid-{}-{}",
        std::process::id(),
        hex(&random16().unwrap())
    ));
    std::fs::write(&p, b"").unwrap();
    let u = std::fs::metadata(&p).unwrap().uid();
    let _ = std::fs::remove_file(&p);
    u
}

fn build(db: &str, now: Arc<AtomicU64>, sock: &str, digest_salt: &[u8]) -> Broker {
    let ops_text = ops_text();
    let (ops, names) = decls::load(&ops_text).unwrap();
    let raw = RawV2Config::parse(config(db, sock, my_uid()).as_bytes()).unwrap();
    let cfg = V2Config::from_raw(raw, &ops, &names, 99_999, true).unwrap();
    let m = nodkey_broker::v2::config::check_authority_workloads(AUTH_WL.as_bytes(), &cfg, &ops)
        .unwrap();
    assert!(m.is_some());
    // `digest_salt` simulates a changed workloads file (AT-16: config.digest change).
    let wl = [AUTH_WL.as_bytes(), digest_salt].concat();
    let digest = nodkey_broker::v2::config::config_digest(ops_text.as_bytes(), &wl);
    let registry = Registry::load(&registry_json("active")).unwrap();
    let e = pg_env();
    let pool = Pool::from_config(pg_config(db, "nodkey_broker", &e.broker_pw), 8);
    let control = Pool::from_config(pg_config(db, "nodkey_broker", &e.broker_pw), 16);
    let clock: Clock = {
        let now = now.clone();
        Arc::new(move || now.load(Ordering::SeqCst))
    };
    Broker::new(cfg, registry, ops, names, (pool, control), digest, clock).with_mandates(m)
}

/// A fake adapter that answers `adapter.hello` only (refund execution needs a ready adapter).
async fn start_hello_only(sock: &std::path::Path) {
    let l = nodkey_broker::v2::server::bind_socket(sock).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut r = BufReader::new(r);
                let mut line = String::new();
                if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let req: Value = serde_json::from_str(&line).unwrap();
                let resp = if req["op"] == "adapter.hello" {
                    json!({"v":2,"id":req["id"],"correlation_id":"fake-1","ok":true,"result":
                        {"format":"nodkey.payments-adapter.v1","profile":"simpay","caps":["idem_status"],
                         "idem_kid":"00112233445566ff","r_max_s":180,"deadline_ms":400}})
                } else {
                    json!({"v":2,"id":req["id"],"correlation_id":"fake-1","ok":false,
                           "error":{"code":"invalid_argument","message":"m"}})
                };
                let _ = w.write_all(format!("{resp}\n").as_bytes()).await;
            });
        }
    });
}

struct M {
    h: H,
    sock: PathBuf,
}

async fn setup() -> M {
    let db = fresh_db().await;
    let e = pg_env();
    let su = connect(pg_config(&db, "postgres", &e.super_pw)).await;
    let mut orders = String::from(
        "INSERT INTO nodkey.orders (order_id, ten, owner_sub, charge_id, currency, captured_minor, external_refunded_minor, status) VALUES \
         (101, 'shop1', 'c42', 'ch_order0101aa', 'EUR', 3500, 0, 'captured'), \
         (102, 'shop1', 'c42', 'ch_order0102aa', 'EUR', 3000, 0, 'captured'), \
         (777, 'shop1', 'c9',  'ch_order0777aa', 'EUR', 4000, 0, 'captured'), \
         (103, 'shop1', 'c42', 'ch_order0103aa', 'USD', 3000, 0, 'captured')",
    );
    // Orders 200..215 of c42 for the concurrency test (one in flight per order).
    for i in 200..216 {
        orders.push_str(&format!(
            ", ({i}, 'shop1', 'c42', 'ch_order0{i}bb', 'EUR', 5000, 0, 'captured')"
        ));
    }
    su.batch_execute(&orders).await.unwrap();
    su.batch_execute(
        "INSERT INTO nodkey.customers (ten, sub, email) VALUES \
         ('shop1', 'c42', 'alice@customer.test'), ('shop1', 'c9', 'bob@customer.test')",
    )
    .await
    .unwrap();
    let dir = PathBuf::from(format!("/tmp/gm-{}", &hex(&random16().unwrap())[..10]));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("adapter.sock");
    start_hello_only(&sock).await;
    let now = Arc::new(AtomicU64::new(T0));
    let b = Arc::new(build(&db, now.clone(), sock.to_str().unwrap(), b""));
    b.startup_checks().await.unwrap();
    assert!(b.ensure_adapter().await, "adapter.hello");
    M {
        h: H { b, now, db, su },
        sock,
    }
}

/// Signs a write grant from a `pending.get` record using the loaded declaration; `mid` makes it
/// a `cfm = 2` mandate grant.
fn sign(b: &Broker, rec: &Value, now: u64, mid: Option<[u8; 16]>) -> String {
    let op = rec["op"].as_str().unwrap();
    let decl = b.ops.get(op).unwrap();
    let mut g = GrantBuilder::write(op, 1)
        .issuer(ISS)
        .audience(BROKER_ID)
        .jti(decode_id(rec["pending_id"].as_str().unwrap()).unwrap())
        .times(now, now, now + 30)
        .workload(rec["wid"].as_str().unwrap())
        .tenant(rec["ten"].as_str().unwrap())
        .subject(rec["approver_sub"].as_str().unwrap());
    for p in &decl.params {
        let v = &rec["params"][&p.name];
        let pv = match v {
            Value::String(s) => ParamValue::Text(s.clone()),
            _ => ParamValue::Uint(v.as_u64().unwrap()),
        };
        g = match p.binding {
            Binding::Resource(k) => g.resource(k, pv),
            Binding::Exact(k) => g.exact(k, pv),
            _ => g,
        };
    }
    g = match mid {
        Some(m) => g.mandated(m),
        None => g.confirmed(true),
    };
    encode_transport(&g.sign(&key(KEY_A)).unwrap())
}

impl M {
    fn b(&self) -> &Arc<Broker> {
        &self.h.b
    }
    async fn propose(&self, wid: &str, op: &str, params: Value) -> Result<Value, Fail> {
        let approver = if wid == AGENT { ANA } else { BOB };
        self.b()
            .propose(
                &self.h.wl(wid),
                &obj(json!({"op": op, "params": params, "approver": {"ten": approver.0, "sub": approver.1}})),
            )
            .await
    }
    async fn pid(&self, wid: &str, op: &str, params: Value) -> String {
        self.propose(wid, op, params).await.unwrap()["pending_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    async fn awaiting(&self, wid: &str, pid: &str) -> Value {
        self.h.status(wid, pid).await.unwrap()["awaiting"].clone()
    }
    /// Human approval path: cfm = 1 grant delivered.
    async fn human(&self, pid: &str) -> Delivery {
        let rec = self.h.get(pid).await;
        let g = sign(self.b(), &rec, self.h.now(), None);
        self.h.deliver(pid, &g).await
    }
    async fn mandated(&self, pid: &str, mid: &str) -> Delivery {
        let rec = self.h.get(pid).await;
        let g = sign(self.b(), &rec, self.h.now(), Some(decode_id(mid).unwrap()));
        self.h.deliver(pid, &g).await
    }
    async fn exec(&self, pid: &str) -> Execution {
        self.b()
            .execute(decode_id(pid).unwrap(), "t")
            .await
            .unwrap()
    }
    /// S0: propose, render as the principal, approve (cfm = 1), activate. Returns the mid.
    async fn mandate(
        &self,
        wid: &str,
        cs: &str,
        n: u64,
        per: u64,
        total: u64,
        msgs: u64,
    ) -> String {
        let pid = self
            .pid(
                wid,
                decls::MANDATE_TEMPLATE,
                json!({"customer_sub": cs, "currency": "EUR", "refund_max_count": n,
                       "refund_max_per_call_minor": per, "refund_max_total_minor": total,
                       "message_max_count": msgs, "valid_for_s": 3600}),
            )
            .await;
        let who = if wid == AGENT { ANA } else { BOB };
        self.h.render(&pid, who).await.expect("template render");
        assert_eq!(self.human(&pid).await, Delivery::Accepted);
        assert_eq!(self.exec(&pid).await, Execution::Succeeded);
        pid
    }
    async fn refund(&self, wid: &str, order: u64, amount: u64) -> String {
        self.pid(
            wid,
            decls::SUPPORT_REFUND,
            json!({"order_id": order, "amount_minor": amount, "currency": "EUR"}),
        )
        .await
    }
    async fn message(&self, wid: &str, cs: &str, body: &str) -> String {
        self.pid(
            wid,
            decls::MESSAGES_SEND,
            json!({"customer_sub": cs, "body": body}),
        )
        .await
    }
    async fn counters(&self, mid: &str) -> (i64, i64, i64, String) {
        let r = self
            .h
            .su
            .query_one(
                "SELECT refund_count, refund_total_minor, message_count, state FROM public.mandate WHERE mid = $1",
                &[&decode_id(mid).unwrap().as_slice()],
            )
            .await
            .unwrap();
        (r.get(0), r.get(1), r.get(2), r.get(3))
    }
    async fn candidates(&self) -> Vec<String> {
        let v = self.b().mandate_candidates(&obj(json!({}))).await.unwrap();
        v["pending_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect()
    }
    async fn revoke(&self, mid: &str, subject: (&str, &str)) -> Result<Value, Fail> {
        self.b()
            .mandate_revoke(&obj(
                json!({"mid": mid, "subject": {"ten": subject.0, "sub": subject.1}}),
            ))
            .await
    }
    async fn read(&self, wid: &str, args: Value) -> Result<Value, Fail> {
        self.b()
            .read(&self.h.wl(wid), decls::SUPPORT_GET_ORDER, &obj(args))
            .await
    }
}

/// AT-09, S0–S2, S8: a mandate is approved as a normal confirmed effect and activated; an
/// in-scope refund and message are covered, get `cfm = 2` grants, execute, and update counters.
/// T55: the propose response is identical for covered and uncovered proposals.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn at09_mandated_refund_and_message() {
    let m = setup().await;
    // Before any mandate: confirmation.
    let before = m.refund(AGENT, 101, 2000).await;
    assert_eq!(m.awaiting(AGENT, &before).await, json!("confirmation"));
    let mid = m.mandate(AGENT, "c42", 3, 2500, 5000, 3).await;
    // Template page facts: customer and trusted email.
    let tpl = m.h.get(&mid).await;
    assert_eq!(tpl["params"]["customer_email"], ALICE);
    let r = m
        .propose(
            AGENT,
            decls::SUPPORT_REFUND,
            json!({"order_id":101,"amount_minor":2000,"currency":"EUR"}),
        )
        .await
        .unwrap();
    let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        ["confirm_url", "expires_at", "pending_id"],
        "T55: same shape"
    );
    let pid = r["pending_id"].as_str().unwrap().to_owned();
    assert_eq!(m.awaiting(AGENT, &pid).await, json!("mandate"));
    assert!(m.candidates().await.contains(&pid));
    assert!(!m.candidates().await.contains(&before));
    let rec = m.h.get(&pid).await;
    assert_eq!(rec["params"]["customer_sub"], "c42");
    assert_eq!(rec["params"]["charge_id"], "ch_order0101aa");
    assert_eq!(m.mandated(&pid, &mid).await, Delivery::Accepted);
    assert_eq!(m.exec(&pid).await, Execution::Reserved);
    assert_eq!(m.counters(&mid).await, (1, 2000, 0, "active".into()));
    let st = m.h.status(AGENT, &pid).await.unwrap();
    assert_eq!(st["state"], "EXECUTING");
    assert_eq!(st["awaiting"], Value::Null);
    // S8: message to c42 (recipient resolved by the broker).
    let msg = m.message(AGENT, "c42", "Card details: none").await;
    assert_eq!(m.awaiting(AGENT, &msg).await, json!("mandate"));
    assert_eq!(m.h.get(&msg).await["params"]["to"], ALICE);
    assert_eq!(m.mandated(&msg, &mid).await, Delivery::Accepted);
    assert_eq!(m.exec(&msg).await, Execution::Succeeded);
    assert_eq!(m.counters(&mid).await, (1, 2000, 1, "active".into()));
    let ob =
        m.h.su
            .query_one(
                "SELECT \"to\", body, ten FROM public.outbox WHERE message_id = $1",
                &[&decode_id(&msg).unwrap().as_slice()],
            )
            .await
            .unwrap();
    assert_eq!(
        (
            ob.get::<_, String>(0),
            ob.get::<_, String>(1),
            ob.get::<_, String>(2)
        ),
        (ALICE.into(), "Card details: none".into(), TEN.into())
    );
    // A human (cfm = 1) approval of the uncovered record touches no mandate counter.
    assert_eq!(m.human(&before).await, Delivery::Accepted);
    assert_eq!(
        m.exec(&before).await,
        Execution::Denied("order_busy".into())
    );
    assert_eq!(m.counters(&mid).await, (1, 2000, 1, "active".into()));
}

/// AT-10, AT-11, S3, S7: out-of-scope order/customer, per-call, currency, count and total
/// boundaries all fall back to confirmation; exact boundaries are covered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn at10_at11_coverage_boundaries() {
    let m = setup().await;
    let mid = m.mandate(AGENT, "c42", 3, 2500, 5000, 1).await;
    let conf = json!("confirmation");
    let cov = json!("mandate");
    let p = m.refund(AGENT, 777, 500).await; // c9's order (S3)
    assert_eq!(m.awaiting(AGENT, &p).await, conf);
    assert_eq!(m.h.get(&p).await["params"]["customer_sub"], "c9");
    let p = m.refund(AGENT, 101, 2501).await; // per-call + 1
    assert_eq!(m.awaiting(AGENT, &p).await, conf);
    let p = m.refund(AGENT, 103, 100).await; // USD order, currency EUR proposed → resolved differs
    assert_eq!(
        m.awaiting(AGENT, &p).await,
        cov,
        "currency is the proposal's; order check at T1"
    );
    let p = m
        .pid(
            AGENT,
            decls::SUPPORT_REFUND,
            json!({"order_id":101,"amount_minor":100,"currency":"USD"}),
        )
        .await;
    assert_eq!(m.awaiting(AGENT, &p).await, conf, "currency ≠ mandate's");
    let p = m.refund(AGENT, 99999, 100).await; // nonexistent order: customer_sub " "
    assert_eq!(m.h.get(&p).await["params"]["customer_sub"], " ");
    assert_eq!(m.awaiting(AGENT, &p).await, conf);
    let p = m.message(AGENT, "c9", "hi").await; // S7
    assert_eq!(m.awaiting(AGENT, &p).await, conf);
    // Exactly per-call: covered; run the counters to the edges.
    for (order, amount) in [(200, 2500), (201, 2499)] {
        let p = m.refund(AGENT, order, amount).await;
        assert_eq!(m.awaiting(AGENT, &p).await, cov);
        assert_eq!(m.mandated(&p, &mid).await, Delivery::Accepted);
        assert_eq!(m.exec(&p).await, Execution::Reserved);
    }
    assert_eq!(m.counters(&mid).await.1, 4999);
    let p = m.refund(AGENT, 202, 2).await; // total + 1
    assert_eq!(m.awaiting(AGENT, &p).await, conf);
    // The broker refuses delivery of a grant beyond its own counters (forced by the authority).
    assert_eq!(
        m.mandated(&p, &mid).await,
        Delivery::Rejected("mandate check".into())
    );
    let p = m.refund(AGENT, 202, 1).await; // total exactly
    assert_eq!(m.awaiting(AGENT, &p).await, cov);
    assert_eq!(m.mandated(&p, &mid).await, Delivery::Accepted);
    assert_eq!(m.exec(&p).await, Execution::Reserved);
    assert_eq!(m.counters(&mid).await, (3, 5000, 0, "active".into()));
    let p = m.refund(AGENT, 203, 1).await; // count + 1 and total + 1
    assert_eq!(m.awaiting(AGENT, &p).await, conf);
    // Messages: count 1.
    let p = m.message(AGENT, "c42", "one").await;
    assert_eq!(m.awaiting(AGENT, &p).await, cov);
    assert_eq!(m.mandated(&p, &mid).await, Delivery::Accepted);
    assert_eq!(m.exec(&p).await, Execution::Succeeded);
    let p = m.message(AGENT, "c42", "two").await;
    assert_eq!(m.awaiting(AGENT, &p).await, conf);
}

/// AT-12: 16 concurrent mandated refunds (grants already delivered) exceeding count and total:
/// executed ≤ totals; counters equal the executed effects.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn at12_counters_under_concurrency() {
    let m = setup().await;
    let mid = m.mandate(AGENT, "c42", 5, 2000, 5000, 0).await;
    let mut pids = Vec::new();
    for i in 0..16u64 {
        let p = m.refund(AGENT, 200 + i, 2000).await;
        // Delivery checks the counters as they are now (all zero): every grant is accepted.
        assert_eq!(m.mandated(&p, &mid).await, Delivery::Accepted);
        pids.push(p);
    }
    let mut tasks = Vec::new();
    for p in pids.clone() {
        let b = m.b().clone();
        tasks.push(tokio::spawn(async move {
            b.execute(decode_id(&p).unwrap(), "race").await.unwrap()
        }));
    }
    let mut reserved = 0;
    for t in tasks {
        match t.await.unwrap() {
            Execution::Reserved => reserved += 1,
            Execution::Denied(r) => assert_eq!(r, "mandate"),
            e => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!(reserved, 2, "total 5000 admits two 2000 refunds");
    assert_eq!(m.counters(&mid).await, (2, 4000, 0, "active".into()));
    let n: i64 =
        m.h.su
            .query_one("SELECT count(*) FROM nodkey.payment_effect", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(n, 2);
}

/// AT-15, T57, T58: broker-side revocation stops delivery, execution of already delivered
/// grants, and reads; revoke is idempotent; another subject's or an unknown mid is refused.
/// T56: `mandate.declined` final/non-final and on a non-PENDING record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn at15_t56_t57_t58_revocation() {
    let m = setup().await;
    let mid = m.mandate(AGENT, "c42", 5, 2500, 10000, 5).await;
    assert!(m.read(AGENT, json!({"order_id": 101})).await.is_ok());
    let delivered = m.refund(AGENT, 101, 1000).await;
    assert_eq!(m.mandated(&delivered, &mid).await, Delivery::Accepted);
    let later = m.refund(AGENT, 102, 1000).await;
    assert_eq!(m.awaiting(AGENT, &later).await, json!("mandate"));
    // T57
    let na = |r: Result<Value, Fail>| r.unwrap_err().code;
    assert_eq!(na(m.revoke(&mid, BOB).await), Code::NotAvailable);
    assert_eq!(
        na(m.revoke(&encode_id(&[9; 16]), ANA).await),
        Code::NotAvailable
    );
    assert_eq!(m.revoke(&mid, ANA).await.unwrap(), json!({}));
    assert_eq!(m.revoke(&mid, ANA).await.unwrap(), json!({}));
    assert_eq!(m.counters(&mid).await.3, "revoked");
    // T58: execution after revocation → FAILED/denied, nothing reserved.
    assert_eq!(
        m.exec(&delivered).await,
        Execution::Denied("mandate".into())
    );
    assert_eq!(m.h.state(&delivered).await, "FAILED");
    assert_eq!(m.h.consumed(&delivered).await.as_deref(), Some("DENIED"));
    // T58: delivery after revocation → rejected; the authority then declines finally → DENIED.
    assert_eq!(
        m.mandated(&later, &mid).await,
        Delivery::Rejected("mandate check".into())
    );
    assert_eq!(m.h.state(&later).await, "PENDING");
    m.b()
        .mandate_declined(&obj(json!({"pending_id": later, "final": true})))
        .await
        .unwrap();
    assert_eq!(m.h.state(&later).await, "DENIED");
    // T56: on a non-PENDING record nothing changes.
    m.b()
        .mandate_declined(&obj(json!({"pending_id": later, "final": false})))
        .await
        .unwrap();
    assert_eq!(m.h.state(&later).await, "DENIED");
    assert_eq!(
        m.b()
            .mandate_declined(&obj(
                json!({"pending_id": encode_id(&[3; 16]), "final": false})
            ))
            .await
            .unwrap_err()
            .code,
        Code::NotFound
    );
    // Reads stop (AT-22 revoked); new proposals go to confirmation (S12).
    assert_eq!(
        m.read(AGENT, json!({"order_id": 101}))
            .await
            .unwrap_err()
            .code,
        Code::GrantDenied
    );
    let p = m.refund(AGENT, 102, 100).await;
    assert_eq!(m.awaiting(AGENT, &p).await, json!("confirmation"));
    // T56 non-final: awaiting → confirmation.
    let mid2 = m.mandate(AGENT, "c42", 5, 2500, 10000, 5).await;
    let p = m.refund(AGENT, 200, 100).await;
    assert_eq!(m.awaiting(AGENT, &p).await, json!("mandate"));
    m.b()
        .mandate_declined(&obj(json!({"pending_id": p, "final": false})))
        .await
        .unwrap();
    assert_eq!(m.awaiting(AGENT, &p).await, json!("confirmation"));
    assert!(!m.candidates().await.contains(&p));
    // Mandate list shows both, newest first, with effective states.
    let l = m
        .b()
        .mandate_list(&obj(json!({"subject": {"ten": TEN, "sub": "op_ana"}})))
        .await
        .unwrap();
    let states: Vec<&str> = l["mandates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["state"].as_str().unwrap())
        .collect();
    assert_eq!(states.len(), 2);
    assert!(states.contains(&"active") && states.contains(&"revoked"));
    let _ = mid2;
    let other = m
        .b()
        .mandate_list(&obj(json!({"subject": {"ten": TEN, "sub": "op_bob"}})))
        .await
        .unwrap();
    assert_eq!(other["mandates"], json!([]));
}

/// AT-16: expiry at exp ± 1 s; `revoked_before` for (ten, wid); a `config.digest` change; all make
/// the mandate inactive for coverage, delivery, execution and reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn at16_expiry_revoked_before_config_change() {
    let m = setup().await;
    let mid = m.mandate(AGENT, "c42", 5, 2500, 10000, 5).await;
    let exp: i64 =
        m.h.su
            .query_one(
                "SELECT exp FROM public.mandate WHERE mid = $1",
                &[&decode_id(&mid).unwrap().as_slice()],
            )
            .await
            .unwrap()
            .get(0);
    m.h.set_now(exp as u64 - 1);
    assert!(m.read(AGENT, json!({"order_id": 101})).await.is_ok());
    let p = m.message(AGENT, "c42", "x").await;
    assert_eq!(m.awaiting(AGENT, &p).await, json!("mandate"));
    m.h.set_now(exp as u64);
    assert_eq!(
        m.read(AGENT, json!({"order_id": 101}))
            .await
            .unwrap_err()
            .code,
        Code::GrantDenied
    );
    let p = m.message(AGENT, "c42", "y").await;
    assert_eq!(m.awaiting(AGENT, &p).await, json!("confirmation"));
    assert_eq!(
        m.mandated(&p, &mid).await,
        Delivery::Rejected("mandate check".into())
    );
    // A new mandate after expiry starts at zero (AT-17 second half).
    let mid2 = m.mandate(AGENT, "c42", 5, 2500, 10000, 5).await;
    assert_eq!(m.counters(&mid).await.3, "expired");
    assert_eq!(m.counters(&mid2).await, (0, 0, 0, "active".into()));
    // revoked_before for (ten, wid), strictly after the mandate's iat.
    m.h.set_now(m.h.now() + 10);
    m.h.su
        .execute(
            "INSERT INTO revoked_before (ten, wid, before) VALUES ($1, $2, $3)",
            &[&TEN, &AGENT, &(m.h.now() as i64)],
        )
        .await
        .unwrap();
    assert_eq!(
        m.read(AGENT, json!({"order_id": 101}))
            .await
            .unwrap_err()
            .code,
        Code::GrantDenied
    );
    m.h.su
        .execute("DELETE FROM revoked_before", &[])
        .await
        .unwrap();
    assert!(m.read(AGENT, json!({"order_id": 101})).await.is_ok());
    // config.digest change: a broker started with another workloads file sees it inactive.
    let other = Arc::new(build(
        &m.h.db,
        m.h.now.clone(),
        m.sock.to_str().unwrap(),
        b" ",
    ));
    let wl = other.cfg.workload(AGENT).unwrap().clone();
    assert_eq!(
        other
            .read(
                &wl,
                decls::SUPPORT_GET_ORDER,
                &obj(json!({"order_id": 101}))
            )
            .await
            .unwrap_err()
            .code,
        Code::GrantDenied
    );
}

/// AT-17, T60: no replacement — render, delivery and activation each refuse a second mandate
/// while one is active.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn at17_t60_no_replacement() {
    let tpl = json!({"customer_sub": "c42", "currency": "EUR", "refund_max_count": 1,
                     "refund_max_per_call_minor": 100, "refund_max_total_minor": 100,
                     "message_max_count": 1, "valid_for_s": 600});
    let m = setup().await;
    // Two template records approved (delivered) while none is active; activation of the second
    // must fail.
    let a = m.pid(AGENT, decls::MANDATE_TEMPLATE, tpl.clone()).await;
    let b2 = m.pid(AGENT, decls::MANDATE_TEMPLATE, tpl.clone()).await;
    assert_eq!(m.human(&a).await, Delivery::Accepted);
    assert_eq!(m.human(&b2).await, Delivery::Accepted);
    assert_eq!(m.exec(&a).await, Execution::Succeeded);
    assert!(matches!(m.exec(&b2).await, Execution::Denied(_)));
    assert_eq!(m.h.state(&b2).await, "FAILED");
    // Render and delivery while active.
    let c = m.pid(AGENT, decls::MANDATE_TEMPLATE, tpl.clone()).await;
    assert_eq!(
        m.h.render(&c, ANA).await.unwrap_err().code,
        Code::NotAvailable
    );
    assert_eq!(
        m.human(&c).await,
        Delivery::Rejected("approval check: agent operation".into())
    );
    // Another workload of another principal is unaffected (key is (wid, ten, sub)).
    let d = m.pid(AGENT2, decls::MANDATE_TEMPLATE, tpl.clone()).await;
    assert!(m.h.render(&d, BOB).await.is_ok());
    // After revocation a new mandate is possible.
    m.revoke(&a, ANA).await.unwrap();
    assert!(m.h.render(&c, ANA).await.is_ok());
    assert_eq!(m.human(&c).await, Delivery::Accepted);
    assert_eq!(m.exec(&c).await, Execution::Succeeded);
    assert_eq!(m.counters(&c).await, (0, 0, 0, "active".into()));
}

/// AT-22: reads in scope, out of scope, nonexistent, with a grant member, without a mandate;
/// identical `grant_denied` bodies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn at22_mandate_reads() {
    let m = setup().await;
    assert_eq!(
        m.read(AGENT, json!({"order_id": 101}))
            .await
            .unwrap_err()
            .code,
        Code::GrantDenied
    );
    m.mandate(AGENT, "c42", 5, 2500, 10000, 5).await;
    let v = m.read(AGENT, json!({"order_id": 101})).await.unwrap();
    assert_eq!(
        v,
        json!({"order_id":101,"customer_sub":"c42","currency":"EUR","amount_minor":3500,"refunded_minor":0,"status":"captured"})
    );
    for args in [
        json!({"order_id": 777}),
        json!({"order_id": 424242}),
        json!({"order_id": 101, "grant": "x"}),
        json!({"order_id": "101"}),
    ] {
        assert_eq!(
            m.read(AGENT, args).await.unwrap_err().code,
            Code::GrantDenied
        );
    }
    // AT-07: another workload has no mandate.
    assert_eq!(
        m.read(AGENT2, json!({"order_id": 101}))
            .await
            .unwrap_err()
            .code,
        Code::GrantDenied
    );
}

/// AT-07: a mandate of another workload/principal never covers; a cfm = 2 grant naming it is
/// refused at delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn at07_other_workload_mandate() {
    let m = setup().await;
    let mid = m.mandate(AGENT, "c42", 5, 2500, 10000, 5).await;
    let p = m.refund(AGENT2, 101, 100).await;
    assert_eq!(m.awaiting(AGENT2, &p).await, json!("confirmation"));
    assert_eq!(
        m.mandated(&p, &mid).await,
        Delivery::Rejected("mandate check".into())
    );
    // A cfm = 2 grant whose mid is not a mandate at all.
    let p = m.refund(AGENT, 101, 100).await;
    assert_eq!(
        m.mandated(&p, &encode_id(&[5; 16])).await,
        Delivery::Rejected("mandate check".into())
    );
}

/// AT-10 (email changed), AT-14 (owner changed) between delivery and execution: FAILED/denied,
/// counters unchanged. At propose, a changed email no longer matches the mandate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn at10_at14_trusted_state_changes() {
    let m = setup().await;
    let mid = m.mandate(AGENT, "c42", 5, 2500, 10000, 5).await;
    let msg = m.message(AGENT, "c42", "hello").await;
    assert_eq!(m.mandated(&msg, &mid).await, Delivery::Accepted);
    let refund = m.refund(AGENT, 102, 1000).await;
    assert_eq!(m.mandated(&refund, &mid).await, Delivery::Accepted);
    m.h.su
        .batch_execute("UPDATE nodkey.orders SET owner_sub = 'c9' WHERE order_id = 102")
        .await
        .unwrap();
    assert_eq!(m.exec(&refund).await, Execution::Denied("mandate".into()));
    m.h.su
        .batch_execute(
            "UPDATE nodkey.customers SET email = 'alice2@customer.test' WHERE sub = 'c42'",
        )
        .await
        .unwrap();
    assert_eq!(m.exec(&msg).await, Execution::Denied("mandate".into()));
    assert_eq!(m.counters(&mid).await, (0, 0, 0, "active".into()));
    let n: i64 =
        m.h.su
            .query_one("SELECT count(*) FROM public.outbox", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
    let p = m.message(AGENT, "c42", "again").await;
    assert_eq!(m.h.get(&p).await["params"]["to"], "alice2@customer.test");
    assert_eq!(m.awaiting(AGENT, &p).await, json!("confirmation"));
}

/// AT-13 / C6: an identical repeat under the same mandate needs confirmation, and its page shows
/// the earlier mandated execution.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn at13_identical_repeat() {
    let m = setup().await;
    let mid = m.mandate(AGENT, "c42", 5, 2500, 10000, 5).await;
    let p = m.message(AGENT, "c42", "same").await;
    assert_eq!(m.mandated(&p, &mid).await, Delivery::Accepted);
    assert_eq!(m.exec(&p).await, Execution::Succeeded);
    let q = m.message(AGENT, "c42", "same").await;
    assert_eq!(m.awaiting(AGENT, &q).await, json!("confirmation"));
    let r = m.h.render(&q, ANA).await.unwrap();
    let facts = r["facts"].to_string();
    assert!(
        facts.contains("Identical effect") && facts.contains(&mid),
        "{facts}"
    );
    let other = m.message(AGENT, "c42", "different").await;
    assert_eq!(m.awaiting(AGENT, &other).await, json!("mandate"));
}

/// AT-05, AT-06, AT-20, support principals: arguments the agent may not supply, ceilings,
/// render by a non-principal, uniform `not_available`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn at05_at20_propose_and_render_refusals() {
    let m = setup().await;
    let inv = |r: Result<Value, Fail>| r.unwrap_err().code;
    for (op, params) in [
        (
            decls::SUPPORT_REFUND,
            json!({"order_id":101,"amount_minor":1,"currency":"EUR","customer_sub":"c42"}),
        ),
        (
            decls::SUPPORT_REFUND,
            json!({"order_id":101,"amount_minor":1,"currency":"EUR","charge_id":"ch_order0101aa"}),
        ),
        (
            decls::MESSAGES_SEND,
            json!({"customer_sub":"c42","body":"x","to":"x@evil.example"}),
        ),
        (
            decls::MANDATE_TEMPLATE,
            json!({"customer_sub":"c42","currency":"EUR","refund_max_count":1,
            "refund_max_per_call_minor":1,"refund_max_total_minor":1,"message_max_count":1,"valid_for_s":60,
            "customer_email":"x@evil.example"}),
        ),
        // ceilings: count 6 > 5, total 10001 > 10000, messages 11 > 10, lifetime 3601 / 59,
        // per-call > total, currency without a ceiling
        (
            decls::MANDATE_TEMPLATE,
            json!({"customer_sub":"c42","currency":"EUR","refund_max_count":6,
            "refund_max_per_call_minor":1,"refund_max_total_minor":1,"message_max_count":1,"valid_for_s":60}),
        ),
        (
            decls::MANDATE_TEMPLATE,
            json!({"customer_sub":"c42","currency":"EUR","refund_max_count":1,
            "refund_max_per_call_minor":1,"refund_max_total_minor":10001,"message_max_count":1,"valid_for_s":60}),
        ),
        (
            decls::MANDATE_TEMPLATE,
            json!({"customer_sub":"c42","currency":"EUR","refund_max_count":1,
            "refund_max_per_call_minor":1,"refund_max_total_minor":1,"message_max_count":11,"valid_for_s":60}),
        ),
        (
            decls::MANDATE_TEMPLATE,
            json!({"customer_sub":"c42","currency":"EUR","refund_max_count":1,
            "refund_max_per_call_minor":1,"refund_max_total_minor":1,"message_max_count":1,"valid_for_s":3601}),
        ),
        (
            decls::MANDATE_TEMPLATE,
            json!({"customer_sub":"c42","currency":"EUR","refund_max_count":1,
            "refund_max_per_call_minor":1,"refund_max_total_minor":1,"message_max_count":1,"valid_for_s":59}),
        ),
        (
            decls::MANDATE_TEMPLATE,
            json!({"customer_sub":"c42","currency":"EUR","refund_max_count":1,
            "refund_max_per_call_minor":2,"refund_max_total_minor":1,"message_max_count":1,"valid_for_s":60}),
        ),
        (
            decls::MANDATE_TEMPLATE,
            json!({"customer_sub":"c42","currency":"USD","refund_max_count":1,
            "refund_max_per_call_minor":1,"refund_max_total_minor":1,"message_max_count":1,"valid_for_s":60}),
        ),
    ] {
        assert_eq!(
            inv(m.propose(AGENT, op, params.clone()).await),
            Code::InvalidArgument,
            "{op} {params}"
        );
    }
    // PC-06: naming a mandate.
    let r = m
        .b()
        .propose(
            &m.h.wl(AGENT),
            &obj(json!({"op": decls::MESSAGES_SEND, "params": {"customer_sub":"c42","body":"x"},
                        "approver": {"ten": TEN, "sub": "op_ana"}, "mid": "AAAAAAAAAAAAAAAAAAAAAA"})),
        )
        .await;
    assert_eq!(inv(r), Code::InvalidArgument);
    // AT-06: another approver.
    let r = m
        .b()
        .propose(
            &m.h.wl(AGENT),
            &obj(
                json!({"op": decls::MESSAGES_SEND, "params": {"customer_sub":"c42","body":"x"},
                        "approver": {"ten": TEN, "sub": "op_bob"}}),
            ),
        )
        .await;
    assert_eq!(inv(r), Code::InvalidArgument);
    // Render only for the intended approver.
    let p = m.message(AGENT, "c42", "x").await;
    assert_eq!(
        m.h.render(&p, BOB).await.unwrap_err().code,
        Code::NotAvailable
    );
    let r = m.h.render(&p, ANA).await.unwrap();
    assert!(r["facts"].to_string().contains(ALICE));
    // Unresolved customer: not renderable, not deliverable.
    let p = m.message(AGENT, "c404", "x").await;
    assert_eq!(m.h.get(&p).await["params"]["to"], " ");
    assert_eq!(
        m.h.render(&p, ANA).await.unwrap_err().code,
        Code::NotAvailable
    );
    // pending.list for the principal shows its records only.
    let l = m
        .b()
        .pending_list(&obj(json!({"subject": {"ten": TEN, "sub": "op_ana"}})))
        .await
        .unwrap();
    assert!(
        l["pending"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["pending_id"] == p)
    );
    let l = m
        .b()
        .pending_list(&obj(json!({"subject": {"ten": TEN, "sub": "op_bob"}})))
        .await
        .unwrap();
    assert_eq!(l["pending"], json!([]));
}
