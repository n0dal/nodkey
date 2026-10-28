//! PostgreSQL integration tests for the broker side of payments-adapter-v1 Draft 3, with a FAKE
//! payments adapter on socket P that simulates the adapter outcomes (created, refused, busy,
//! not_sent, ambiguous, lost response, slow response, lies) over a simulated provider ledger.
//! Run with `tests/run-pg-integration.sh` (the tests are `#[ignore]`).

mod common;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use nodkey_broker::v2::config::{RawV2Config, V2Config};
use nodkey_broker::v2::db::Pool;
use nodkey_broker::v2::decls;
use nodkey_broker::v2::ids::{decode_id, encode_id, hex, random16};
use nodkey_broker::v2::payments::{PayOutcome, PayTo};
use nodkey_broker::v2::service::{Broker, Clock, Delivery, Execution};
use nodkey_broker::v2::wire::Code;
use nodkey_grant::{GrantBuilder, ParamValue, Registry, decode_transport, encode_transport};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const CUST: (&str, &str) = ("acme", "user:alice");
const OTHER: (&str, &str) = ("acme", "user:bob");
const KID: &str = "00112233445566ff";

fn ops_v31() -> String {
    OPS_JSON.replace(
        r#"{"name":"currency","in":"con","key":1,"class":"exact","type":"currency","destination":false}]}"#,
        r#"{"name":"currency","in":"con","key":1,"class":"exact","type":"currency","destination":false},
  {"name":"charge_id","in":"con","key":2,"class":"exact","type":"text64","destination":false}]}"#,
    )
}

const AUTH_WL: &str = r#"{"format":"nodkey.workloads.v1","workloads":[
 {"wid":"spiffe://nodkey.test/workload/shop","tenants":["acme"],"approver_source":"named","write_ops":["payments.refund"],"read_ops":["payments.get_order"]}]}"#;

fn config(db: &str, sock: &str, adapter_uid: u32) -> String {
    format!(
        r#"{{"format":"nodkey.broker.v2","profile":"phase3","broker_id":"{BROKER_ID}",
 "auth_origin":"https://auth.nodkey.test","ledger_currency":"EUR",
 "db":{{"host":"unused","port":5432,"dbname":"{db}","user":"nodkey_broker","password_file":"/nonexistent"}},
 "registry_path":"/nonexistent","operations_path":"/nonexistent","authority_workloads_path":"/nonexistent",
 "limits":{{"pending_per_wid":64,"pending_per_approver":64,"proposals_per_min":600,"proposal_burst":600,"status_per_min":600,"pending_lifetime_s":600,"reads_per_min":600,"db_conns_per_wid":2}},
 "gateway":{{"socket_path":"/run/t/gw-broker/broker.sock","uid":20001}},
 "authority":{{"socket_path":"/run/t/au-broker/broker.sock","uid":20002}},
 "payments":{{"adapter_socket":"{sock}","adapter_uid":{adapter_uid},"R_max_s":180,"max_resends":5,"adapter_total_ms":400,
   "budget":{{"max_count_per_day":3,"limits_minor":{{"USD":20000,"EUR":20000,"JPY":20000}}}}}},
 "workloads":[
  {{"wid":"{SHOP}","display_name":"Shop","socket_path":"/run/t/wl/shop/broker.sock","uid":10003,
   "tenants":["acme"],"approver_source":{{"kind":"named"}},"allowed_ops":["payments.refund","payments.get_order"]}}]}}"#
    )
}

fn my_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    // Unique per call: tests run concurrently in one process.
    let p = std::env::temp_dir().join(format!(
        "gp-uid-{}-{}",
        std::process::id(),
        hex(&random16().unwrap())
    ));
    std::fs::write(&p, b"").unwrap();
    let u = std::fs::metadata(&p).unwrap().uid();
    let _ = std::fs::remove_file(&p);
    u
}

fn build(db: &str, now: Arc<AtomicU64>, sock: &str, adapter_uid: u32) -> Broker {
    let ops_text = ops_v31();
    let (ops, names) = decls::load(&ops_text).unwrap();
    let raw = RawV2Config::parse(config(db, sock, adapter_uid).as_bytes()).unwrap();
    let cfg = V2Config::from_raw(raw, &ops, &names, 99_999, true).unwrap();
    nodkey_broker::v2::config::check_authority_workloads(AUTH_WL.as_bytes(), &cfg, &ops).unwrap();
    let digest =
        nodkey_broker::v2::config::config_digest(ops_text.as_bytes(), AUTH_WL.as_bytes());
    let registry = Registry::load(&registry_json("active")).unwrap();
    let e = pg_env();
    let pool = Pool::from_config(pg_config(db, "nodkey_broker", &e.broker_pw), 8);
    let control = Pool::from_config(pg_config(db, "nodkey_broker", &e.broker_pw), 8);
    let clock: Clock = {
        let now = now.clone();
        Arc::new(move || now.load(Ordering::SeqCst))
    };
    Broker::new(cfg, registry, ops, names, (pool, control), digest, clock)
}

// ------------------------------------------------------------------ fake adapter

#[derive(Debug, Clone)]
enum Mode {
    Normal,
    /// Provider commits, the response is lost (connection closed).
    CommitThenDrop,
    /// Provider fails before commit: ambiguous/http_5xx, nothing recorded.
    FailBeforeCommit,
    NotSent,
    Refused(&'static str),
    /// Provider commits but answers refused.
    DenyButCommit(&'static str),
    Busy,
    /// Answers `created` with a different amount and records nothing.
    Lie,
    /// Waits `ms`, then commits and answers (later than the broker's timeout if large).
    Slow(u64),
    /// `ok:false` (the adapter refused the grant; nothing sent).
    GrantRefused,
}

#[derive(Default)]
struct FakeState {
    modes: VecDeque<Mode>,
    /// grant text → refund JSON (the simulated provider ledger).
    ledger: HashMap<String, Value>,
    /// grant texts received with an in-progress override for idem.status.
    in_progress: HashSet<String>,
    settlement: HashMap<String, &'static str>,
    /// Status reported for refunds without an entry in `settlement` (default: as created,
    /// `pending`).
    default_status: Option<&'static str>,
    ops: Vec<String>,
    /// `idem_kid` of every non-hello call, in order.
    kids: Vec<String>,
}

struct Fake {
    state: Mutex<FakeState>,
    creates: AtomicUsize,
    su: tokio_postgres::Client,
    /// The adapter's current `idem_kid` (changes when the "adapter" restarts with another key).
    kid: Mutex<String>,
    /// Test hook: switch to this kid right after answering the next hello.
    rotate_after_hello: Mutex<Option<String>>,
    r_max: u64,
}

impl Fake {
    fn push(&self, m: Mode) {
        self.state.lock().unwrap().modes.push_back(m);
    }
    fn effects(&self) -> usize {
        self.state.lock().unwrap().ledger.len()
    }
    fn creates(&self) -> usize {
        self.creates.load(Ordering::SeqCst)
    }
    fn set_in_progress(&self, on: bool) {
        let mut s = self.state.lock().unwrap();
        if on {
            let keys: Vec<String> = s.ledger.keys().cloned().collect();
            s.in_progress.extend(keys);
            s.in_progress.insert("*".into());
        } else {
            s.in_progress.clear();
        }
    }

    async fn params_of(&self, grant: &str) -> Option<Value> {
        let bytes = decode_transport(Some(grant)).ok()?;
        let r = self
            .su
            .query_opt(
                "SELECT params FROM public.pending_effect WHERE grant_bytes = $1",
                &[&bytes],
            )
            .await
            .ok()??;
        serde_json::from_str(&r.get::<_, String>(0)).ok()
    }

    fn refund(p: &Value, amount_delta: u64) -> Value {
        json!({"id": format!("re_{}", &hex(&random16().unwrap())[..16]), "charge": p["charge_id"],
               "amount_minor": p["amount_minor"].as_u64().unwrap() + amount_delta,
               "currency": p["currency"], "reference": "ref-fake-1", "status": "pending"})
    }

    /// Returns `None` to close the connection without a response.
    fn kid(&self) -> String {
        self.kid.lock().unwrap().clone()
    }
    fn set_kid(&self, k: &str) {
        *self.kid.lock().unwrap() = k.to_owned();
    }

    async fn handle(&self, op: &str, args: &Value) -> Option<Result<Value, &'static str>> {
        self.state.lock().unwrap().ops.push(op.to_owned());
        // Like the adapter (PC-A-01, BP-01): every grant-carrying call must name the loaded
        // key's kid, else it is refused and nothing is sent.
        if op != "adapter.hello" {
            let k = args["idem_kid"].as_str().unwrap_or_default().to_owned();
            self.state.lock().unwrap().kids.push(k.clone());
            if k != self.kid() {
                return Some(Err("idem_kid_mismatch"));
            }
        }
        let grant = args["grant"].as_str().unwrap_or_default().to_owned();
        let amb = |cause: &str| json!({"class":"ambiguous","cause":cause,"reference":"ref-fake-1","anomalies":[]});
        match op {
            "adapter.hello" => {
                let v = json!({"format":"nodkey.payments-adapter.v1","profile":"simpay",
                "caps":["idem_status"],"idem_kid":self.kid(),"r_max_s":self.r_max,"deadline_ms":400});
                if let Some(k) = self.rotate_after_hello.lock().unwrap().take() {
                    self.set_kid(&k);
                }
                Some(Ok(v))
            }
            "refund.create" => {
                self.creates.fetch_add(1, Ordering::SeqCst);
                let p = self.params_of(&grant).await?;
                let mode = self
                    .state
                    .lock()
                    .unwrap()
                    .modes
                    .pop_front()
                    .unwrap_or(Mode::Normal);
                let existing = self.state.lock().unwrap().ledger.get(&grant).cloned();
                let commit = |s: &Self| -> Value {
                    let mut st = s.state.lock().unwrap();
                    st.ledger
                        .entry(grant.clone())
                        .or_insert_with(|| Fake::refund(&p, 0))
                        .clone()
                };
                let created = |r: Value| json!({"class":"created","refund":r,"reference":"ref-fake-1","anomalies":[]});
                Some(Ok(match mode {
                    // Same key: the provider deduplicates and returns the original.
                    _ if existing.is_some() && !matches!(mode, Mode::Lie) => {
                        created(existing.unwrap())
                    }
                    Mode::Normal => created(commit(self)),
                    Mode::CommitThenDrop => {
                        commit(self);
                        return None;
                    }
                    Mode::FailBeforeCommit => amb("http_5xx"),
                    Mode::NotSent => json!({"class":"not_sent","cause":"connect","anomalies":[]}),
                    Mode::Refused(code) => {
                        json!({"class":"refused","code":code,"http":400,"reference":"ref-fake-1","anomalies":[]})
                    }
                    Mode::DenyButCommit(code) => {
                        commit(self);
                        json!({"class":"refused","code":code,"http":400,"reference":"ref-fake-1","anomalies":[]})
                    }
                    Mode::Busy => {
                        json!({"class":"busy","cause":"in_progress","reference":"ref-fake-1","anomalies":[]})
                    }
                    Mode::Lie => created(Fake::refund(&p, 1)),
                    Mode::Slow(ms) => {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        created(commit(self))
                    }
                    Mode::GrantRefused => return Some(Err("grant_refused")),
                }))
            }
            "refund.find" => {
                let st = self.state.lock().unwrap();
                Some(Ok(match st.ledger.get(&grant) {
                    Some(r) => {
                        let mut r = r.clone();
                        if let Some(s) = st.settlement.get(&grant).or(st.default_status.as_ref()) {
                            r["status"] = json!(s);
                        }
                        json!({"class":"found","refunds":[r],"anomalies":[]})
                    }
                    None => json!({"class":"not_found","anomalies":[]}),
                }))
            }
            "refund.get" => {
                let st = self.state.lock().unwrap();
                let id = args["refund_id"].as_str().unwrap_or_default();
                Some(Ok(match st.ledger.get(&grant).filter(|r| r["id"] == id) {
                    Some(r) => {
                        let mut r = r.clone();
                        if let Some(s) = st.settlement.get(&grant).or(st.default_status.as_ref()) {
                            r["status"] = json!(s);
                        }
                        json!({"class":"found","refunds":[r],"anomalies":[]})
                    }
                    None => json!({"class":"not_found","anomalies":[]}),
                }))
            }
            "idem.status" => {
                let st = self.state.lock().unwrap();
                let s = if st.in_progress.contains(&grant) || st.in_progress.contains("*") {
                    "in_progress"
                } else if st.ledger.contains_key(&grant) {
                    "done"
                } else {
                    "none"
                };
                Some(Ok(json!({"state": s, "anomalies": []})))
            }
            _ => Some(Err("invalid_argument")),
        }
    }
}

async fn start_fake(db: &str, sock: &std::path::Path) -> Arc<Fake> {
    let e = pg_env();
    let fake = Arc::new(Fake {
        state: Mutex::new(FakeState::default()),
        creates: AtomicUsize::new(0),
        su: connect(pg_config(db, "postgres", &e.super_pw)).await,
        kid: Mutex::new(KID.into()),
        rotate_after_hello: Mutex::new(None),
        r_max: 180,
    });
    let l = nodkey_broker::v2::server::bind_socket(sock).unwrap();
    let f = fake.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else {
                continue;
            };
            let f = f.clone();
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut r = BufReader::new(r);
                let mut line = String::new();
                if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let req: Value = serde_json::from_str(&line).unwrap();
                let id = req["id"].clone();
                let Some(res) = f.handle(req["op"].as_str().unwrap(), &req["args"]).await else {
                    return; // drop: response lost
                };
                let resp = match res {
                    Ok(v) => json!({"v":2,"id":id,"correlation_id":"fake-1","ok":true,"result":v}),
                    Err(code) => {
                        json!({"v":2,"id":id,"correlation_id":"fake-1","ok":false,"error":{"code":code,"message":"m"}})
                    }
                };
                let _ = w.write_all(format!("{resp}\n").as_bytes()).await;
            });
        }
    });
    fake
}

struct P {
    h: H,
    fake: Arc<Fake>,
    sock: PathBuf,
}

async fn setup() -> P {
    let db = fresh_db().await;
    let e = pg_env();
    let su = connect(pg_config(&db, "postgres", &e.super_pw)).await;
    su.batch_execute(
        "INSERT INTO nodkey.orders (order_id, ten, owner_sub, charge_id, currency, captured_minor, external_refunded_minor, status) VALUES \
         (1001, 'acme', 'user:alice', 'ch_order1001aa', 'USD', 5000, 0, 'captured'), \
         (1002, 'acme', 'user:bob',   'ch_order1002bb', 'USD', 5000, 0, 'captured'), \
         (1003, 'acme', 'user:alice', 'ch_order1003cc', 'USD', 1000, 990, 'partially_refunded'), \
         (1004, 'acme', 'user:alice', 'ch_order1004dd', 'GBP', 5000, 0, 'captured'), \
         (1005, 'acme', 'user:alice', 'ch_order1005ee', 'USD', 100000, 0, 'captured'), \
         (1006, 'acme', 'user:alice', 'ch_order1006ff', 'JPY', 50000, 0, 'captured')",
    )
    .await
    .unwrap();
    let dir = PathBuf::from(format!("/tmp/gp-{}", &hex(&random16().unwrap())[..10]));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("adapter.sock");
    let fake = start_fake(&db, &sock).await;
    let now = Arc::new(AtomicU64::new(T0));
    let b = Arc::new(build(&db, now.clone(), sock.to_str().unwrap(), my_uid()));
    b.startup_checks().await.unwrap();
    assert!(b.ensure_adapter().await, "adapter.hello");
    P {
        h: H { b, now, db, su },
        fake,
        sock,
    }
}

fn sign_refund(
    rec: &Value,
    now: u64,
    key_hex: &str,
    tweak: impl FnOnce(GrantBuilder) -> GrantBuilder,
) -> String {
    let p = &rec["params"];
    let b = GrantBuilder::write("payments.refund", 1)
        .issuer(ISS)
        .audience(BROKER_ID)
        .jti(decode_id(rec["pending_id"].as_str().unwrap()).unwrap())
        .times(now, now, now + 30)
        .workload(rec["wid"].as_str().unwrap())
        .tenant(rec["ten"].as_str().unwrap())
        .subject(rec["approver_sub"].as_str().unwrap())
        .resource(0, ParamValue::Uint(p["order_id"].as_u64().unwrap()))
        .exact(0, ParamValue::Uint(p["amount_minor"].as_u64().unwrap()))
        .exact(1, ParamValue::Text(p["currency"].as_str().unwrap().into()))
        .exact(2, ParamValue::Text(p["charge_id"].as_str().unwrap().into()))
        .confirmed(true);
    encode_transport(&tweak(b).sign(&key(key_hex)).unwrap())
}

impl P {
    async fn propose(
        &self,
        order: u64,
        amount: u64,
        cur: &str,
        approver: (&str, &str),
    ) -> Result<String, nodkey_broker::v2::wire::Fail> {
        let a = obj(
            json!({"op":"payments.refund","params":{"order_id":order,"amount_minor":amount,"currency":cur},
                           "approver":{"ten":approver.0,"sub":approver.1}}),
        );
        self.h
            .b
            .propose(&self.h.wl(SHOP), &a)
            .await
            .map(|v| v["pending_id"].as_str().unwrap().to_owned())
    }
    /// Render as the approver, sign (fake authority, test key), deliver.
    async fn approve(&self, pid: &str) -> Delivery {
        let r = self.h.render(pid, CUST).await.expect("render");
        let rec = self.h.get(pid).await;
        assert_eq!(rec["digest"], r["digest"]);
        let g = sign_refund(&rec, self.h.now(), KEY_A, |b| b);
        self.h.deliver(pid, &g).await
    }
    async fn reserve(&self, order: u64, amount: u64, cur: &str) -> String {
        let pid = self.propose(order, amount, cur, CUST).await.unwrap();
        assert_eq!(self.approve(&pid).await, Delivery::Accepted);
        assert_eq!(
            self.h
                .b
                .execute(decode_id(&pid).unwrap(), "t")
                .await
                .unwrap(),
            Execution::Reserved
        );
        pid
    }
    async fn pay_state(&self, pid: &str) -> Option<(String, Option<String>)> {
        let id = decode_id(pid).unwrap();
        self.h
            .su
            .query_opt(
                "SELECT state, reason FROM nodkey.payment_effect WHERE pending_id = $1",
                &[&id.as_slice()],
            )
            .await
            .unwrap()
            .map(|r| (r.get(0), r.get(1)))
    }
    async fn counters(&self, charge: &str) -> (i64, i64, i64) {
        self.h
            .su
            .query_opt(
                "SELECT succeeded_minor, inflight_minor, unknown_minor FROM nodkey.charge_refund_state WHERE charge_id = $1",
                &[&charge],
            )
            .await
            .unwrap()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .unwrap_or((0, 0, 0))
    }
    async fn outcome(&self, pid: &str) -> Value {
        self.h.status(SHOP, pid).await.unwrap()["outcome"].clone()
    }
    async fn tick_after(&self, secs: u64) -> Vec<([u8; 16], PayOutcome)> {
        self.h.set_now(self.h.now() + secs);
        self.h.b.payments_tick().await.unwrap()
    }
}

// ------------------------------------------------------------------ tests

/// Happy path: propose resolves charge_id; render shows it; T1 reserves; T2/T3 succeed with a
/// confirming GET; counters, budget, status and get_order agree.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn refund_happy_path() {
    let p = setup().await;
    let pid = p.propose(1001, 1250, "USD", CUST).await.unwrap();
    let rec = p.h.get(&pid).await;
    assert_eq!(rec["params"]["charge_id"], "ch_order1001aa");
    assert_eq!(rec["param_types"]["charge_id"], "text64");
    assert_eq!(
        rec["display"],
        json!({"amount_exponent": 2, "currency": "USD"})
    );
    let r = p.h.render(&pid, CUST).await.unwrap();
    let facts = r["facts"].as_array().unwrap();
    assert!(
        facts
            .iter()
            .any(|f| f["label"] == "Charge being refunded" && f["value"] == "ch_order1001aa")
    );
    assert!(
        facts
            .iter()
            .any(|f| f["label"] == "Remaining refundable" && f["value"] == "50.00 USD")
    );
    assert!(
        facts
            .iter()
            .any(|f| f["label"] == "Remaining refund allowance today")
    );
    assert_eq!(p.approve(&pid).await, Delivery::Accepted);
    let id = decode_id(&pid).unwrap();
    assert_eq!(p.h.b.execute(id, "t").await.unwrap(), Execution::Reserved);
    assert_eq!(p.h.state(&pid).await, "EXECUTING");
    assert_eq!(p.counters("ch_order1001aa").await, (0, 1250, 0));
    assert_eq!(p.h.consumed(&pid).await.as_deref(), Some("ACCEPT"));
    let out = p.h.b.dispatch(id).await.unwrap();
    assert!(
        matches!(out, PayOutcome::Applied(PayTo::Succeeded { .. })),
        "{out:?}"
    );
    assert_eq!(p.h.state(&pid).await, "SUCCEEDED");
    assert_eq!(p.counters("ch_order1001aa").await, (1250, 0, 0));
    assert_eq!((p.fake.creates(), p.fake.effects()), (1, 1));
    let o = p.outcome(&pid).await;
    assert_eq!(
        (o["class"].as_str(), &o["reason"]),
        (Some("succeeded"), &Value::Null)
    );
    // A second dispatch does nothing.
    assert_eq!(p.h.b.dispatch(id).await.unwrap(), PayOutcome::Skipped);
    // payments.get_order with a read grant.
    let g = GrantBuilder::read()
        .issuer(ISS)
        .audience(BROKER_ID)
        .jti(random16().unwrap())
        .times(p.h.now(), p.h.now(), p.h.now() + 30)
        .workload(SHOP)
        .tenant("acme")
        .subject("user:alice")
        .read_op("payments.get_order", 1)
        .sign(&key(KEY_A))
        .unwrap();
    let v =
        p.h.b
            .read(
                &p.h.wl(SHOP),
                "payments.get_order",
                &obj(json!({"order_id": 1001, "grant": encode_transport(&g)})),
            )
            .await
            .unwrap();
    assert_eq!(
        v,
        json!({"order_id":1001,"currency":"USD","amount_minor":5000,"refunded_minor":1250,"status":"captured"})
    );
    let e =
        p.h.b
            .read(
                &p.h.wl(SHOP),
                "payments.get_order",
                &obj(json!({"order_id": 1002, "grant": encode_transport(&g)})),
            )
            .await
            .unwrap_err();
    assert_eq!(e.code, Code::GrantDenied);
    // Settlement polling: pending → succeeded.
    let key = p
        .fake
        .state
        .lock()
        .unwrap()
        .ledger
        .keys()
        .next()
        .cloned()
        .unwrap();
    p.fake
        .state
        .lock()
        .unwrap()
        .settlement
        .insert(key, "succeeded");
    p.tick_after(11).await;
    let s: Option<String> =
        p.h.su
            .query_one("SELECT settlement FROM nodkey.payment_effect", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(s.as_deref(), Some("succeeded"));
    let _ = std::fs::remove_dir_all(p.sock.parent().unwrap());
}

/// PT-10 / PT-12: charge_id supplied by the workload, extra members, bad amount forms.
#[tokio::test]
#[ignore]
async fn pt10_pt12_propose_validation() {
    let p = setup().await;
    for params in [
        json!({"order_id":1001,"amount_minor":5,"currency":"USD","charge_id":"ch_order1001aa"}),
        json!({"order_id":1001,"amount_minor":5,"currency":"USD","memo":"x"}),
        json!({"order_id":1001,"amount_minor":0,"currency":"USD"}),
        json!({"order_id":1001,"amount_minor":"5","currency":"USD"}),
        json!({"order_id":1001,"amount_minor":5.0,"currency":"USD"}),
        json!({"order_id":1001,"amount_minor":-5,"currency":"USD"}),
        json!({"order_id":1001,"amount_minor":5,"currency":"usd"}),
        json!({"order_id":1001,"amount_minor":5,"currency":"XXX"}),
        json!({"order_id":"1001","amount_minor":5,"currency":"USD"}),
        json!({"order_id":1001,"amount_minor":5}),
    ] {
        let e = p.h.b.propose(&p.h.wl(SHOP), &obj(json!({"op":"payments.refund","params":params.clone(),"approver":{"ten":"acme","sub":"user:alice"}}))).await.unwrap_err();
        assert_eq!(e.code, Code::InvalidArgument, "{params}");
    }
    assert_eq!(p.fake.creates(), 0);
}

/// T12 / PT-41: proposals for existing, foreign and nonexistent orders look identical; an
/// `unresolved` record is not renderable, not deliverable, and if forced to APPROVED, T1 denies
/// it `not_owner_or_unknown` without creating a charge state row; the workload sees
/// `not_permitted`.
#[tokio::test]
#[ignore]
async fn pt41_unresolved_charge() {
    let p = setup().await;
    let a = p.h.b.propose(&p.h.wl(SHOP), &obj(json!({"op":"payments.refund","params":{"order_id":1001,"amount_minor":5,"currency":"USD"},"approver":{"ten":"acme","sub":"user:alice"}}))).await.unwrap();
    let b = p.h.b.propose(&p.h.wl(SHOP), &obj(json!({"op":"payments.refund","params":{"order_id":9999,"amount_minor":5,"currency":"USD"},"approver":{"ten":"acme","sub":"user:alice"}}))).await.unwrap();
    let c = p.h.b.propose(&p.h.wl(SHOP), &obj(json!({"op":"payments.refund","params":{"order_id":1002,"amount_minor":5,"currency":"USD"},"approver":{"ten":"acme","sub":"user:alice"}}))).await.unwrap();
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(&a), keys(&b));
    assert_eq!(keys(&a), keys(&c));
    let pid = b["pending_id"].as_str().unwrap();
    let rec = p.h.get(pid).await;
    assert_eq!(rec["params"]["charge_id"], "unresolved");
    assert_eq!(
        p.h.render(pid, CUST).await.unwrap_err().code,
        Code::NotAvailable
    );
    // A test-key grant for the unresolved value is rejected at delivery.
    let g = sign_refund(&rec, p.h.now(), KEY_A, |b| b);
    assert!(matches!(p.h.deliver(pid, &g).await, Delivery::Rejected(_)));
    // Forced to APPROVED (attacker J on the broker DB): T1 step 0 denies.
    let id = decode_id(pid).unwrap();
    p.h.su.execute(
        "UPDATE public.pending_effect SET state = 'APPROVED', grant_bytes = $2, grant_exp = $3, state_changed_at = $3 WHERE pending_id = $1",
        &[&id.as_slice(), &decode_transport(Some(&g)).unwrap(), &((p.h.now() + 30) as i64)],
    ).await.unwrap();
    let r = p.h.b.execute(id, "t").await.unwrap();
    assert!(
        matches!(r, Execution::Denied(ref d) if d == "not_owner_or_unknown"),
        "{r:?}"
    );
    let n: i64 =
        p.h.su
            .query_one("SELECT count(*) FROM nodkey.charge_refund_state", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
    let o = p.outcome(pid).await;
    assert_eq!(
        (o["class"].as_str(), o["reason"].as_str()),
        (Some("denied"), Some("not_permitted"))
    );
    assert_eq!(p.fake.creates(), 0);
}

/// PT-01 / PT-34 / PT-20: ownership or status changes after approval → FAILED/denied with the
/// uniform reasons; no adapter call. Render of a foreign order is the uniform error; the reason
/// for a foreign order is always `not_permitted`.
#[tokio::test]
#[ignore]
async fn pt01_pt20_pt34_trusted_facts_at_execution() {
    let p = setup().await;
    // Foreign order: the approver (alice) does not own 1002.
    let f = p.propose(1002, 5, "USD", CUST).await.unwrap();
    assert_eq!(
        p.h.render(&f, CUST).await.unwrap_err().code,
        Code::NotAvailable
    );
    // Bob owns 1002, but the record names alice as approver: not renderable for bob either.
    assert_eq!(
        p.h.render(&f, OTHER).await.unwrap_err().code,
        Code::NotAvailable
    );
    // Ownership changed after approval.
    let pid = p.propose(1001, 100, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&pid).await, Delivery::Accepted);
    p.h.su.execute("UPDATE nodkey.orders SET owner_sub = 'user:mallory', status = 'disputed' WHERE order_id = 1001", &[]).await.unwrap();
    let r = p.h.b.execute(decode_id(&pid).unwrap(), "t").await.unwrap();
    assert!(
        matches!(r, Execution::Denied(ref d) if d == "not_owner_or_unknown"),
        "{r:?}"
    );
    assert_eq!(p.outcome(&pid).await["reason"], "not_permitted");
    // Status changed after approval (owner unchanged).
    p.h.su.execute("UPDATE nodkey.orders SET owner_sub = 'user:alice', status = 'captured' WHERE order_id = 1001", &[]).await.unwrap();
    let pid = p.propose(1001, 100, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&pid).await, Delivery::Accepted);
    p.h.su
        .execute(
            "UPDATE nodkey.orders SET status = 'disputed' WHERE order_id = 1001",
            &[],
        )
        .await
        .unwrap();
    let r = p.h.b.execute(decode_id(&pid).unwrap(), "t").await.unwrap();
    assert!(
        matches!(r, Execution::Denied(ref d) if d == "order_status"),
        "{r:?}"
    );
    assert_eq!(p.outcome(&pid).await["reason"], "not_refundable");
    // Immutable columns.
    for sql in [
        "UPDATE nodkey.orders SET captured_minor = 1 WHERE order_id = 1001",
        "UPDATE nodkey.orders SET charge_id = 'ch_otherchrg1' WHERE order_id = 1001",
        "UPDATE nodkey.orders SET currency = 'EUR' WHERE order_id = 1001",
    ] {
        let e = p.h.su.execute(sql, &[]).await.unwrap_err();
        assert!(format!("{e:?}").contains("immutable"), "{sql}: {e:?}");
    }
    assert_eq!(p.fake.creates(), 0);
}

/// PT-03: currency differs from the order: not renderable, delivery rejected, nothing sent.
#[tokio::test]
#[ignore]
async fn pt03_currency_mismatch() {
    let p = setup().await;
    let pid = p.propose(1001, 1000, "JPY", CUST).await.unwrap();
    assert_eq!(
        p.h.render(&pid, CUST).await.unwrap_err().code,
        Code::NotAvailable
    );
    let rec = p.h.get(&pid).await;
    let g = sign_refund(&rec, p.h.now(), KEY_A, |b| b);
    assert!(matches!(p.h.deliver(&pid, &g).await, Delivery::Rejected(_)));
    assert_eq!(p.fake.creates(), 0);
}

/// PT-11 / PT-05: over remaining, partial remaining, one in flight (incl. UNKNOWN), and two
/// approvals racing for the last amount.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt05_pt11_remaining_and_in_flight() {
    let p = setup().await;
    // 1003: captured 1000, externally refunded 990 → 10 remaining.
    let over = p.propose(1003, 11, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&over).await, Delivery::Accepted);
    let r = p.h.b.execute(decode_id(&over).unwrap(), "t").await.unwrap();
    assert_eq!(r, Execution::Denied("insufficient_refundable".into()));
    assert_eq!(p.outcome(&over).await["reason"], "not_refundable");
    // Two approvals race for the last 10.
    let a = p.propose(1003, 10, "USD", CUST).await.unwrap();
    let b = p.propose(1003, 10, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&a).await, Delivery::Accepted);
    assert_eq!(p.approve(&b).await, Delivery::Accepted);
    let (b1, b2) = (p.h.b.clone(), p.h.b.clone());
    let (ia, ib) = (decode_id(&a).unwrap(), decode_id(&b).unwrap());
    let ta = tokio::spawn(async move { b1.execute(ia, "a").await });
    let tb = tokio::spawn(async move { b2.execute(ib, "b").await });
    let (ra, rb) = (ta.await.unwrap().unwrap(), tb.await.unwrap().unwrap());
    let reserved = [&ra, &rb]
        .iter()
        .filter(|r| ***r == Execution::Reserved)
        .count();
    assert_eq!(reserved, 1, "{ra:?} {rb:?}");
    for (r, pid) in [(&ra, &a), (&rb, &b)] {
        if *r == Execution::Reserved {
            p.h.b.dispatch(decode_id(pid).unwrap()).await.unwrap();
        } else {
            assert!(
                matches!(r, Execution::Denied(d) if d == "order_busy" || d == "insufficient_refundable"),
                "{r:?}"
            );
        }
    }
    assert_eq!(p.fake.effects(), 1);
    assert_eq!(p.counters("ch_order1003cc").await, (10, 0, 0));
    // While a refund is UNKNOWN, another refund on the same charge is denied (order_busy).
    p.fake.push(Mode::CommitThenDrop);
    let u = p.reserve(1001, 100, "USD").await;
    assert!(matches!(
        p.h.b.dispatch(decode_id(&u).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Unknown { .. })
    ));
    let n = p.propose(1001, 100, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&n).await, Delivery::Accepted);
    assert_eq!(
        p.h.b.execute(decode_id(&n).unwrap(), "t").await.unwrap(),
        Execution::Denied("order_busy".into())
    );
    let creates = p.fake.creates();
    assert_eq!(creates, 2, "no adapter call for denied refunds");
}

/// PT-22: budget per customer, currency and UTC day: count limit, amount limit, unconfigured
/// currency, and a new UTC day.
#[tokio::test]
#[ignore]
async fn pt22_budget() {
    let p = setup().await;
    for i in 0..3 {
        let pid = p.reserve(1005, 100 + i, "USD").await;
        p.h.b.dispatch(decode_id(&pid).unwrap()).await.unwrap();
    }
    let fourth = p.propose(1005, 50, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&fourth).await, Delivery::Accepted);
    assert_eq!(
        p.h.b
            .execute(decode_id(&fourth).unwrap(), "t")
            .await
            .unwrap(),
        Execution::Denied("budget".into())
    );
    assert_eq!(p.outcome(&fourth).await["reason"], "limit");
    // Unconfigured currency (GBP).
    let gbp = p.propose(1004, 50, "GBP", CUST).await.unwrap();
    assert_eq!(p.approve(&gbp).await, Delivery::Accepted);
    assert_eq!(
        p.h.b.execute(decode_id(&gbp).unwrap(), "t").await.unwrap(),
        Execution::Denied("budget".into())
    );
    // Next UTC day: allowed again, but the amount limit (200.00) still applies per day.
    let next_day = (p.h.now() / 86_400 + 1) * 86_400;
    p.h.set_now(next_day);
    let big = p.propose(1005, 20_001, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&big).await, Delivery::Accepted);
    assert_eq!(
        p.h.b.execute(decode_id(&big).unwrap(), "t").await.unwrap(),
        Execution::Denied("budget".into())
    );
    let ok = p.reserve(1005, 20_000, "USD").await;
    assert!(matches!(
        p.h.b.dispatch(decode_id(&ok).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Succeeded { .. })
    ));
    // JPY (exponent 0): limit 20000 = ¥20,000.
    let jpy = p.reserve(1006, 20_000, "JPY").await;
    assert!(matches!(
        p.h.b.dispatch(decode_id(&jpy).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Succeeded { .. })
    ));
    let spent: i64 = p
        .h
        .su
        .query_one(
            "SELECT sum(spent_minor)::bigint FROM nodkey.refund_budget WHERE currency = 'USD'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(spent, 100 + 101 + 102 + 20_000);
    // The budget never decreases.
    assert!(
        p.h.su
            .execute("UPDATE nodkey.refund_budget SET spent_minor = 0", &[])
            .await
            .is_err()
    );
}

/// T3: not_sent on the first call → FAILED/not_sent, released; a refusal or adapter refusal →
/// UNKNOWN (+ alarm); busy three times → UNKNOWN.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn t3_classification() {
    let p = setup().await;
    p.fake.push(Mode::NotSent);
    let a = p.reserve(1005, 10, "USD").await;
    assert_eq!(
        p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Failed { reason: "not_sent" })
    );
    assert_eq!(p.h.state(&a).await, "FAILED");
    assert_eq!(
        p.pay_state(&a).await,
        Some(("FAILED".into(), Some("not_sent".into())))
    );
    let o = p.outcome(&a).await;
    assert_eq!(
        (o["class"].as_str(), o["reason"].as_str()),
        (Some("failed"), Some("not_executed"))
    );
    assert_eq!(p.counters("ch_order1005ee").await, (0, 0, 0));
    // Refused by the provider for a refund the broker proved valid → UNKNOWN, not FAILED.
    p.fake.push(Mode::Refused("charge_already_refunded"));
    let b = p.reserve(1001, 10, "USD").await;
    assert_eq!(
        p.h.b.dispatch(decode_id(&b).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Unknown { reason: "refused" })
    );
    let o = p.outcome(&b).await;
    assert_eq!(
        (o["class"].as_str(), &o["reason"]),
        (Some("unknown"), &Value::Null)
    );
    // Adapter refuses the grant (ok:false) → UNKNOWN.
    p.fake.push(Mode::GrantRefused);
    let c = p.reserve(1006, 10, "JPY").await;
    assert_eq!(
        p.h.b.dispatch(decode_id(&c).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Unknown {
            reason: "grant_refused"
        })
    );
    assert_eq!(p.fake.effects(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn t3_busy_three_times() {
    let p = setup().await;
    for _ in 0..3 {
        p.fake.push(Mode::Busy);
    }
    let a = p.reserve(1005, 10, "USD").await;
    assert_eq!(
        p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Unknown { reason: "busy" })
    );
    assert_eq!(p.fake.creates(), 3);
    // Lies are never success: a `created` echo with another amount → UNKNOWN.
    p.fake.push(Mode::Lie);
    let b = p.reserve(1001, 10, "USD").await;
    assert_eq!(
        p.h.b.dispatch(decode_id(&b).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Unknown {
            reason: "ambiguous"
        })
    );
    assert_ne!(p.h.state(&b).await, "SUCCEEDED");
}

/// PT-06 / PT-08 / PT-16: committed but response lost (or refused-but-committed) → UNKNOWN;
/// the reconciler's lookup resolves SUCCEEDED without a resend; ledger 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt06_lost_response_resolved_by_lookup() {
    let p = setup().await;
    p.fake.push(Mode::CommitThenDrop);
    let a = p.reserve(1001, 300, "USD").await;
    assert!(matches!(
        p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Unknown { .. })
    ));
    assert_eq!(p.counters("ch_order1001aa").await, (0, 0, 300));
    assert_eq!(
        p.outcome(&a).await,
        json!({"class":"unknown","receipt_id":null,"reason":null})
    );
    // Not due yet.
    assert!(p.h.b.payments_tick().await.unwrap().is_empty());
    let out = p.tick_after(11).await;
    assert!(
        matches!(
            out.as_slice(),
            [(_, PayOutcome::Applied(PayTo::Succeeded { .. }))]
        ),
        "{out:?}"
    );
    assert_eq!(p.h.state(&a).await, "SUCCEEDED");
    assert_eq!((p.fake.creates(), p.fake.effects()), (1, 1));
    assert_eq!(p.counters("ch_order1001aa").await, (300, 0, 0));
    let resends: i32 =
        p.h.su
            .query_one("SELECT resends FROM nodkey.payment_effect", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(resends, 0);
    // deny_but_commit: refused + committed → UNKNOWN + alarm → lookup → SUCCEEDED.
    p.fake.push(Mode::DenyButCommit("amount_too_large"));
    let b = p.reserve(1005, 50, "USD").await;
    assert!(matches!(
        p.h.b.dispatch(decode_id(&b).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Unknown { reason: "refused" })
    ));
    p.tick_after(11).await;
    assert_eq!(p.h.state(&b).await, "SUCCEEDED");
    assert_eq!(p.fake.effects(), 2);
}

/// PT-09: failure before commit → UNKNOWN; lookup not_found; idem `none` in round 1 → one
/// same-key resend → SUCCEEDED; ledger 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt09_same_key_resend() {
    let p = setup().await;
    p.fake.push(Mode::FailBeforeCommit);
    let a = p.reserve(1001, 200, "USD").await;
    assert!(matches!(
        p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Unknown { .. })
    ));
    assert_eq!(p.fake.effects(), 0);
    let out = p.tick_after(11).await;
    assert!(
        matches!(
            out.as_slice(),
            [(_, PayOutcome::Applied(PayTo::Succeeded { .. }))]
        ),
        "{out:?}"
    );
    assert_eq!((p.fake.creates(), p.fake.effects()), (2, 1));
    let resends: i32 =
        p.h.su
            .query_one("SELECT resends FROM nodkey.payment_effect", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(resends, 1);
}

/// PT-07: slow commit beyond the timeout → UNKNOWN; idem `in_progress` → no resend; later the
/// lookup finds it → SUCCEEDED; ledger 1. Also `none` after round 1 stops resending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt07_in_progress_never_resends() {
    let p = setup().await;
    // Slow but does not commit before the broker gives up: model as in-progress at the provider.
    p.fake.push(Mode::FailBeforeCommit);
    let a = p.reserve(1001, 200, "USD").await;
    p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap();
    p.fake.set_in_progress(true);
    p.tick_after(11).await; // round 1: in_progress → wait, next check in 60 s
    assert_eq!(p.fake.creates(), 1, "no resend while in progress");
    p.fake.set_in_progress(false);
    // Round 2 (still before the resend deadline) and `none`: stop resending, operator_required.
    p.tick_after(60).await;
    assert_eq!(p.fake.creates(), 1);
    let (stopped, reason): (bool, Option<String>) = {
        let r =
            p.h.su
                .query_one(
                    "SELECT resend_stopped, reason FROM nodkey.payment_effect",
                    &[],
                )
                .await
                .unwrap();
        (r.get(0), r.get(1))
    };
    assert!(stopped);
    assert_eq!(reason.as_deref(), Some("operator_required"));
    // A real slow commit (Slow > timeout) is later found by lookup.
    p.fake.push(Mode::Slow(3000));
    let b = p.reserve(1005, 10, "USD").await;
    assert!(matches!(
        p.h.b.dispatch(decode_id(&b).unwrap()).await.unwrap(),
        PayOutcome::Applied(PayTo::Unknown { .. })
    ));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    p.tick_after(11).await;
    assert_eq!(p.h.state(&b).await, "SUCCEEDED");
    assert_eq!(p.fake.effects(), 1);
}

/// PT-15: UNKNOWN past `resend_deadline` (iat + R_max − 60) → no create; lookups only; after
/// 7 days `operator_required`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt15_no_resend_after_deadline() {
    let p = setup().await;
    p.fake.push(Mode::FailBeforeCommit);
    let a = p.reserve(1001, 200, "USD").await;
    p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap();
    p.tick_after(121).await; // past iat + 180 − 60
    assert_eq!(p.fake.creates(), 1, "no resend after the deadline");
    p.tick_after(8 * 86_400).await;
    let reason: Option<String> =
        p.h.su
            .query_one("SELECT reason FROM nodkey.payment_effect", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(reason.as_deref(), Some("operator_required"));
    assert_eq!(p.h.state(&a).await, "UNKNOWN");
    assert_eq!(p.fake.creates(), 1);
}

/// PT-21: crash after T1 (RESERVED never dispatched) → FAILED/not_dispatched after 30 s; a
/// DISPATCHED row whose lease expired → UNKNOWN/lost_response; the reconciler then resolves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt21_crash_recovery() {
    let p = setup().await;
    let a = p.reserve(1001, 100, "USD").await;
    assert!(p.h.b.payments_tick().await.unwrap().is_empty());
    let out = p.tick_after(31).await;
    assert!(
        matches!(
            out.as_slice(),
            [(
                _,
                PayOutcome::Applied(PayTo::Failed {
                    reason: "not_dispatched"
                })
            )]
        ),
        "{out:?}"
    );
    assert_eq!(p.outcome(&a).await["reason"], "not_executed");
    assert_eq!(p.fake.creates(), 0);
    // DISPATCHED with an expired lease (the dispatcher died after the request was sent).
    let b = p.reserve(1005, 100, "USD").await;
    let id = decode_id(&b).unwrap();
    p.h.su.execute(
        "UPDATE nodkey.payment_effect SET state = 'DISPATCHED', dispatched_at = $2, lease_until = $2 WHERE pending_id = $1",
        &[&id.as_slice(), &(p.h.now() as i64)],
    ).await.unwrap();
    let out = p.tick_after(1).await;
    assert!(
        out.iter().any(|(_, o)| *o
            == PayOutcome::Applied(PayTo::Unknown {
                reason: "lost_response"
            })),
        "{out:?}"
    );
    // Nothing reached the provider: lookup not_found, idem none in round 1 → resend once.
    p.tick_after(11).await;
    assert_eq!(p.h.state(&b).await, "SUCCEEDED");
    assert_eq!(p.fake.effects(), 1);
}

/// PT-33: a dispatcher whose lease is lost (recovery moved the row to UNKNOWN) discards its late
/// result; at most one call in flight; ledger 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt33_lease_discards_late_result() {
    let p = setup().await;
    let a = p.reserve(1001, 100, "USD").await;
    let id = decode_id(&a).unwrap();
    // Late T3: the row is already UNKNOWN when the dispatcher applies its result.
    p.h.su.execute("UPDATE nodkey.payment_effect SET state = 'DISPATCHED', dispatched_at = 0, lease_until = 0 WHERE pending_id = $1", &[&id.as_slice()]).await.unwrap();
    let out = p.tick_after(1).await;
    assert!(out.iter().any(|(_, o)| *o
        == PayOutcome::Applied(PayTo::Unknown {
            reason: "lost_response"
        })));
    let late =
        p.h.b
            .apply(
                &id,
                "DISPATCHED",
                &PayTo::Succeeded {
                    refund_id: "re_abcdefgh12".into(),
                    settlement: nodkey_broker::v2::adapter::RefundStatus::Succeeded,
                },
                true,
                None,
                "",
            )
            .await
            .unwrap();
    assert!(!late, "late result discarded");
    // A reconciler round while another holder has a live lease is skipped.
    p.h.su.execute("UPDATE nodkey.payment_effect SET lease_owner = '\\x00000000000000000000000000000001', lease_until = $2, next_check_at = 0 WHERE pending_id = $1",
        &[&id.as_slice(), &((p.h.now() + 1000) as i64)]).await.unwrap();
    assert_eq!(p.h.b.reconcile(id).await.unwrap(), PayOutcome::Skipped);
    assert_eq!(p.fake.creates(), 0);
}

/// PT-36: K_idem rotated while a row is non-final → payment processing refused (alarm);
/// approved refunds are not executed. PT-24 (broker side): an adapter peer with the wrong uid is
/// never used.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt24_pt36_adapter_identity() {
    let p = setup().await;
    p.fake.push(Mode::CommitThenDrop);
    let a = p.reserve(1001, 100, "USD").await;
    p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap();
    // A restarted broker meets an adapter with another idem_kid.
    p.h.su
        .execute(
            "UPDATE nodkey.payment_effect SET idem_kid = 'ffffffffffffffff'",
            &[],
        )
        .await
        .ok();
    let id = decode_id(&a).unwrap();
    // (the frozen column cannot change: the trigger refuses)
    let kid: String =
        p.h.su
            .query_one(
                "SELECT idem_kid FROM nodkey.payment_effect WHERE pending_id = $1",
                &[&id.as_slice()],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(kid, KID);
    // A broker whose adapter reports another kid.
    let s3 = p.sock.with_file_name("adapter3.sock");
    let e = pg_env();
    let f3 = Arc::new(Fake {
        state: Mutex::new(FakeState::default()),
        creates: AtomicUsize::new(0),
        su: connect(pg_config(&p.h.db, "postgres", &e.super_pw)).await,
        kid: Mutex::new("ffffffffffffffff".into()),
        rotate_after_hello: Mutex::new(None),
        r_max: 180,
    });
    {
        let l = nodkey_broker::v2::server::bind_socket(&s3).unwrap();
        let f = f3.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else {
                    continue;
                };
                let f = f.clone();
                tokio::spawn(async move {
                    let (r, mut w) = s.into_split();
                    let mut r = BufReader::new(r);
                    let mut line = String::new();
                    if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let req: Value = serde_json::from_str(&line).unwrap();
                    if let Some(Ok(v)) = f.handle(req["op"].as_str().unwrap(), &req["args"]).await {
                        let resp = json!({"v":2,"id":req["id"],"correlation_id":"fake-3","ok":true,"result":v});
                        let _ = w.write_all(format!("{resp}\n").as_bytes()).await;
                    }
                });
            }
        });
    }
    let b3 = build(&p.h.db, p.h.now.clone(), s3.to_str().unwrap(), my_uid());
    assert!(!b3.ensure_adapter().await, "non-final row with another kid");
    let pid = p.propose(1005, 10, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&pid).await, Delivery::Accepted);
    assert_eq!(
        b3.execute(decode_id(&pid).unwrap(), "t").await.unwrap(),
        Execution::Unverified("payments_not_ready")
    );
    // Wrong adapter uid: hello is never accepted.
    let b4 = build(
        &p.h.db,
        p.h.now.clone(),
        p.sock.to_str().unwrap(),
        my_uid() + 1,
    );
    assert!(!b4.ensure_adapter().await);
    assert_eq!(f3.creates(), 0);
}

/// PT-37: get_order.refunded_minor = external + succeeded only (not UNKNOWN or in flight).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt37_get_order_refunded() {
    let p = setup().await;
    let a = p.reserve(1005, 100, "USD").await;
    p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap();
    p.fake.push(Mode::FailBeforeCommit);
    // A second refund needs the first one settled in our model (one in flight); next day budget ok.
    let b = p.reserve(1003, 5, "USD").await;
    p.h.b.dispatch(decode_id(&b).unwrap()).await.unwrap();
    let g = GrantBuilder::read()
        .issuer(ISS)
        .audience(BROKER_ID)
        .jti(random16().unwrap())
        .times(p.h.now(), p.h.now(), p.h.now() + 30)
        .workload(SHOP)
        .tenant("acme")
        .subject("user:alice")
        .read_op("payments.get_order", 1)
        .sign(&key(KEY_A))
        .unwrap();
    let rd = |o: u64| obj(json!({"order_id": o, "grant": encode_transport(&g)}));
    let v =
        p.h.b
            .read(&p.h.wl(SHOP), "payments.get_order", &rd(1005))
            .await
            .unwrap();
    assert_eq!(v["refunded_minor"], 100);
    let v =
        p.h.b
            .read(&p.h.wl(SHOP), "payments.get_order", &rd(1003))
            .await
            .unwrap();
    assert_eq!(v["refunded_minor"], 990, "UNKNOWN excluded");
}

/// A session as `nodkey_shop_operator` (the real operator role; BP-02). The role is given a
/// login and the per-run test password, and `CONNECT` on the test database.
async fn operator(p: &P) -> tokio_postgres::Client {
    static LOGIN: tokio::sync::Mutex<bool> = tokio::sync::Mutex::const_new(false);
    let e = pg_env();
    {
        let mut done = LOGIN.lock().await;
        if !*done {
            p.h.su
                .batch_execute(&format!(
                    "ALTER ROLE nodkey_shop_operator LOGIN PASSWORD '{}'",
                    e.broker_pw
                ))
                .await
                .unwrap();
            *done = true;
        }
    }
    p.h.su
        .batch_execute(&format!(
            "GRANT CONNECT ON DATABASE {} TO nodkey_shop_operator",
            p.h.db
        ))
        .await
        .unwrap();
    let c = connect(pg_config(&p.h.db, "nodkey_shop_operator", &e.broker_pw)).await;
    let who: String = c
        .query_one("SELECT current_user::text", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(who, "nodkey_shop_operator");
    c
}

/// PT-39: counters forced out of step are rejected at commit; an operator owner change racing
/// T1 serializes on the charge lock and T1 sees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt39_counters_and_operator_race() {
    let p = setup().await;
    let a = p.reserve(1005, 100, "USD").await;
    let _ = a;
    let e = p.h.su.execute("UPDATE nodkey.charge_refund_state SET inflight_minor = 0 WHERE charge_id = 'ch_order1005ee'", &[]).await.unwrap_err();
    assert!(format!("{e:?}").contains("out of step"), "{e:?}");
    // Operator transaction (as nodkey_shop_operator, BP-02) holds the charge lock while it
    // changes the owner.
    let mut op = operator(&p).await;
    let pid = p.propose(1001, 10, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&pid).await, Delivery::Accepted);
    let tx = op.transaction().await.unwrap();
    tx.execute(
        "UPDATE nodkey.orders SET owner_sub = 'user:bob' WHERE order_id = 1001",
        &[],
    )
    .await
    .unwrap();
    let b = p.h.b.clone();
    let id = decode_id(&pid).unwrap();
    let t = tokio::spawn(async move { b.execute(id, "race").await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    tx.commit().await.unwrap();
    let r = t.await.unwrap().unwrap();
    assert_eq!(r, Execution::Denied("not_owner_or_unknown".into()));
}

/// PT-30 / PT-31 (database part): unique charge ids; the broker role cannot write or lock
/// orders, create objects or temp tables; its search_path is empty.
#[tokio::test]
#[ignore]
async fn pt30_pt31_database_privileges() {
    let p = setup().await;
    let e = p.h.su.execute(
        "INSERT INTO nodkey.orders VALUES (2001,'acme','user:x','ch_order1001aa','USD',10,0,'captured')", &[]).await.unwrap_err();
    assert!(
        format!("{e:?}").contains("unique") || format!("{e:?}").contains("23505"),
        "{e:?}"
    );
    let env = pg_env();
    let br = connect(pg_config(&p.h.db, "nodkey_broker", &env.broker_pw)).await;
    let sp: String = br.query_one("SHOW search_path", &[]).await.unwrap().get(0);
    assert!(sp == "\"\"" || sp.is_empty(), "{sp}");
    for sql in [
        "INSERT INTO nodkey.orders VALUES (2002,'acme','user:x','ch_neworder22','USD',10,0,'captured')",
        "UPDATE nodkey.orders SET status = 'refunded' WHERE order_id = 1001",
        "SELECT 1 FROM nodkey.orders WHERE order_id = 1001 FOR UPDATE",
        "DELETE FROM nodkey.payment_effect",
        "UPDATE nodkey.payment_effect SET amount_minor = 1",
        "DELETE FROM nodkey.refund_budget",
        "CREATE TABLE nodkey.orders2 (x int)",
        "CREATE TABLE public.orders (x int)",
        "CREATE TEMP TABLE orders (x int)",
        "CREATE VIEW nodkey.v AS SELECT 1",
        "SELECT 1 FROM orders",
    ] {
        assert!(br.execute(sql, &[]).await.is_err(), "{sql}");
    }
    // GRANT without the grant option is only a warning in PostgreSQL; assert it granted nothing.
    let _ = br
        .execute("GRANT UPDATE ON nodkey.orders TO nodkey_broker", &[])
        .await;
    let _ = br
        .execute("GRANT SELECT ON nodkey.orders TO PUBLIC", &[])
        .await;
    assert!(
        br.execute(
            "UPDATE nodkey.orders SET status = 'refunded' WHERE order_id = 1001",
            &[]
        )
        .await
        .is_err()
    );
    let pub_sel: bool =
        p.h.su
            .query_one(
                "SELECT has_table_privilege('public', 'nodkey.orders', 'SELECT')",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    assert!(!pub_sel);
    let n: i64 = br
        .query_one("SELECT count(*) FROM nodkey.orders", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 6);
}

/// PT-04: one grant delivered 50× concurrently with execution and recovery → one row, one
/// provider refund.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn pt04_concurrent_delivery() {
    let p = setup().await;
    let pid = p.propose(1001, 700, "USD", CUST).await.unwrap();
    let rec = p.h.get(&pid).await;
    let g = sign_refund(&rec, p.h.now(), KEY_A, |b| b);
    let id = decode_id(&pid).unwrap();
    let mut tasks = Vec::new();
    for i in 0..50 {
        let (b, g, pid) = (p.h.b.clone(), g.clone(), pid.clone());
        tasks.push(tokio::spawn(async move {
            let _ = b
                .deliver(&obj(json!({"pending_id": pid, "grant": g})))
                .await;
            if b.execute(id, &format!("c{i}")).await == Ok(Execution::Reserved) {
                let _ = b.dispatch(id).await;
            }
            if i % 10 == 0 {
                // Like the recovery loop: a reserved refund is dispatched by the caller.
                if let Ok(out) = b.recovery_tick().await {
                    for (pid, r) in out {
                        if r == Ok(Execution::Reserved) {
                            let _ = b.dispatch(pid).await;
                        }
                    }
                }
                let _ = b.payments_tick().await;
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let n: i64 =
        p.h.su
            .query_one("SELECT count(*) FROM nodkey.payment_effect", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(n, 1);
    assert_eq!(p.h.state(&pid).await, "SUCCEEDED");
    assert_eq!((p.fake.creates(), p.fake.effects()), (1, 1));
    assert_eq!(p.counters("ch_order1001aa").await, (700, 0, 0));
}

/// PT-23: settlement `failed` after success → alarm, amount stays encumbered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn pt23_late_settlement_failure() {
    let p = setup().await;
    let a = p.reserve(1001, 100, "USD").await;
    p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap();
    let key = p
        .fake
        .state
        .lock()
        .unwrap()
        .ledger
        .keys()
        .next()
        .cloned()
        .unwrap();
    p.fake
        .state
        .lock()
        .unwrap()
        .settlement
        .insert(key, "failed");
    p.tick_after(11).await;
    let s: Option<String> =
        p.h.su
            .query_one("SELECT settlement FROM nodkey.payment_effect", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(s.as_deref(), Some("failed"));
    assert_eq!(
        p.counters("ch_order1001aa").await,
        (100, 0, 0),
        "still encumbered"
    );
    assert_eq!(p.h.state(&a).await, "SUCCEEDED");
    let _ = encode_id(&[0; 16]);
}

/// Row columns read by the settlement tests.
async fn settle_row(p: &P, pid: &str) -> (String, Option<String>, Option<String>, Option<i64>) {
    let id = decode_id(pid).unwrap();
    let r =
        p.h.su
            .query_one(
                "SELECT state, settlement, anomaly, next_check_at FROM nodkey.payment_effect WHERE pending_id = $1",
                &[&id.as_slice()],
            )
            .await
            .unwrap();
    (r.get(0), r.get(1), r.get(2), r.get(3))
}

fn set_provider_status(p: &P, status: &'static str) {
    let mut st = p.fake.state.lock().unwrap();
    let keys: Vec<String> = st.ledger.keys().cloned().collect();
    assert!(!keys.is_empty() || status == "succeeded");
    for k in keys {
        st.settlement.insert(k, status);
    }
}

fn ops_since(p: &P, n: usize) -> Vec<String> {
    p.fake.state.lock().unwrap().ops[n..].to_vec()
}

/// DEMOP-F06 / §7.3 post-success watch: a refund whose settlement went pending → succeeded is
/// still re-checked (lookup only); a later `failed` is recorded with anomaly
/// `settlement_reversed`, the row stays `SUCCEEDED`, the amount stays encumbered, nothing is
/// re-sent, and `failed` is final.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn f06_reversal_after_success_is_recorded_without_resend() {
    let p = setup().await;
    let a = p.reserve(1001, 100, "USD").await;
    p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap();
    assert_eq!(
        settle_row(&p, &a).await.1.as_deref(),
        Some("pending"),
        "the fake creates pending refunds"
    );
    set_provider_status(&p, "succeeded");
    p.tick_after(11).await;
    let (state, settlement, anomaly, next) = settle_row(&p, &a).await;
    assert_eq!(
        (state.as_str(), settlement.as_deref(), anomaly),
        ("SUCCEEDED", Some("succeeded"), None)
    );
    let next = next.expect("post-success watch scheduled");
    assert_eq!(
        next,
        i64::try_from(p.h.now()).unwrap() + 60,
        "watch round 1"
    );
    // Not due yet: no call.
    let n0 = p.fake.state.lock().unwrap().ops.len();
    p.tick_after(30).await;
    assert!(!ops_since(&p, n0).iter().any(|o| o == "refund.get"));
    // The provider reverses the settled refund.
    set_provider_status(&p, "failed");
    p.tick_after(31).await;
    let (state, settlement, anomaly, next) = settle_row(&p, &a).await;
    assert_eq!(
        (
            state.as_str(),
            settlement.as_deref(),
            anomaly.as_deref(),
            next
        ),
        (
            "SUCCEEDED",
            Some("failed"),
            Some("settlement_reversed"),
            None
        )
    );
    assert_eq!(
        p.counters("ch_order1001aa").await,
        (100, 0, 0),
        "still encumbered"
    );
    assert_eq!(p.h.state(&a).await, "SUCCEEDED");
    let calls = ops_since(&p, n0);
    assert!(calls.iter().any(|o| o == "refund.get"), "{calls:?}");
    assert!(
        calls
            .iter()
            .all(|o| o == "refund.get" || o == "adapter.hello"),
        "lookup only: {calls:?}"
    );
    assert_eq!(
        (p.fake.creates(), p.fake.effects()),
        (1, 1),
        "never re-dispatched"
    );
    // `failed` is final: no further checks, and the provider cannot "un-fail" it.
    set_provider_status(&p, "succeeded");
    let n1 = p.fake.state.lock().unwrap().ops.len();
    for _ in 0..3 {
        p.tick_after(2 * 86_400).await;
    }
    assert!(!ops_since(&p, n1).iter().any(|o| o == "refund.get"));
    assert_eq!(settle_row(&p, &a).await.1.as_deref(), Some("failed"));
    // The DB guard enforces the same: failed is final, succeeded never goes back to pending.
    let id = decode_id(&a).unwrap();
    for to in ["succeeded", "pending"] {
        assert!(
            p.h.su
                .execute(
                    "UPDATE nodkey.payment_effect SET settlement = $2 WHERE pending_id = $1",
                    &[&id.as_slice(), &to],
                )
                .await
                .is_err(),
            "failed -> {to}"
        );
    }
    let _ = std::fs::remove_dir_all(p.sock.parent().unwrap());
}

/// DEMOP-F06: a refund confirmed `succeeded` at dispatch enters the watch at once; the watch
/// ends at `dispatched_at + settlement_watch_s` (default 30 days) and a reversal reported after
/// the window is not observed (published residual); `succeeded → pending` is refused by the DB.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn f06_watch_is_bounded() {
    let p = setup().await;
    let a = p.reserve(1001, 200, "USD").await;
    // The provider reports the refund `succeeded` already on the confirming GET (like simpay).
    p.fake.state.lock().unwrap().default_status = Some("succeeded");
    let id = decode_id(&a).unwrap();
    p.h.b.dispatch(id).await.unwrap();
    let (_, settlement, _, next) = settle_row(&p, &a).await;
    assert_eq!(settlement.as_deref(), Some("succeeded"));
    assert_eq!(
        next,
        Some(i64::try_from(p.h.now()).unwrap() + 10),
        "watch starts at dispatch"
    );
    p.tick_after(11).await;
    let dispatched: i64 =
        p.h.su
            .query_one(
                "SELECT dispatched_at FROM nodkey.payment_effect WHERE pending_id = $1",
                &[&id.as_slice()],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(settle_row(&p, &a).await.1.as_deref(), Some("succeeded"));
    // Walk the watch: checks keep happening while the window is open.
    let n0 = p.fake.state.lock().unwrap().ops.len();
    for _ in 0..10 {
        p.tick_after(86_400).await;
    }
    let gets = ops_since(&p, n0)
        .iter()
        .filter(|o| *o == "refund.get")
        .count();
    assert!(gets >= 5, "watch keeps checking: {gets}");
    // Jump past the window: one last round finds the window closed and stops.
    let end = u64::try_from(dispatched).unwrap() + 30 * 86_400;
    p.h.set_now(end + 1);
    p.h.b.payments_tick().await.unwrap();
    let (_, settlement, _, next) = settle_row(&p, &a).await;
    assert_eq!((settlement.as_deref(), next), (Some("succeeded"), None));
    set_provider_status(&p, "failed");
    let n1 = p.fake.state.lock().unwrap().ops.len();
    p.tick_after(86_400).await;
    assert!(
        !ops_since(&p, n1).iter().any(|o| o == "refund.get"),
        "no check after the window"
    );
    assert_eq!(settle_row(&p, &a).await.1.as_deref(), Some("succeeded"));
    assert_eq!(p.fake.creates(), 1);
    assert!(
        p.h.su
            .execute(
                "UPDATE nodkey.payment_effect SET settlement = 'pending' WHERE pending_id = $1",
                &[&id.as_slice()],
            )
            .await
            .is_err(),
        "succeeded -> pending refused"
    );
    let _ = std::fs::remove_dir_all(p.sock.parent().unwrap());
}

/// DEMOP-F07 / PT-31 / PA-17: PostgreSQL lets any role `ALTER ROLE` its own session defaults,
/// so `search_path` is not the control. The control is: every broker/adapter statement is
/// schema-qualified, every function pins `search_path`, and no Nodkey login role has `CREATE`
/// on any schema nor `CREATE` or `TEMPORARY` on any database, so no object that could shadow a
/// qualified name can be created.
#[tokio::test]
#[ignore]
async fn f07_no_create_or_temp_anywhere() {
    let p = setup().await;
    let env = pg_env();
    let br = connect(pg_config(&p.h.db, "nodkey_broker", &env.broker_pw)).await;
    // The residual, stated: the role can change its own default (rolled back here).
    br.batch_execute("BEGIN; ALTER ROLE nodkey_broker SET search_path = 'public'; ROLLBACK;")
        .await
        .expect("PostgreSQL allows ALTER ROLE on one's own session defaults");
    // Even with a non-empty session search_path, nothing can be created to shadow a name.
    br.batch_execute("SET search_path = public, nodkey")
        .await
        .unwrap();
    for sql in [
        "CREATE VIEW public.orders AS SELECT 1 AS order_id",
        "CREATE TABLE public.payment_effect (x int)",
        "CREATE TEMP TABLE orders (x int)",
        "CREATE FUNCTION public.nodkey_is_id(t text, n integer) RETURNS boolean LANGUAGE sql RETURN true",
        "CREATE SCHEMA evil",
    ] {
        assert!(br.execute(sql, &[]).await.is_err(), "{sql}");
    }
    let roles = [
        "nodkey_broker",
        "nodkey_payments_adapter",
        "nodkey_shop_operator",
    ];
    {
        // Database privileges across the cluster; hold the creation lock so that no test
        // database is observed between its CREATE and its REVOKE.
        let _g = CREATE_LOCK.lock().await;
        for r in roles {
            let dbs: Vec<String> =
                p.h.su
                    .query(
                        "SELECT datname FROM pg_catalog.pg_database \
                         WHERE pg_catalog.has_database_privilege($1, oid, 'CREATE') \
                            OR pg_catalog.has_database_privilege($1, oid, 'TEMPORARY')",
                        &[&r],
                    )
                    .await
                    .unwrap()
                    .iter()
                    .map(|x| x.get(0))
                    .collect();
            assert!(dbs.is_empty(), "{r} has CREATE/TEMPORARY on {dbs:?}");
        }
    }
    // Schema privileges in the broker's database and in the demo database `ledger`.
    for db in [p.h.db.clone(), "ledger".to_owned()] {
        let su = connect(pg_config(&db, "postgres", &env.super_pw)).await;
        for r in roles {
            let schemas: Vec<String> = su
                .query(
                    "SELECT nspname::text FROM pg_catalog.pg_namespace \
                     WHERE pg_catalog.has_schema_privilege($1, oid, 'CREATE')",
                    &[&r],
                )
                .await
                .unwrap()
                .iter()
                .map(|x| x.get(0))
                .collect();
            assert!(schemas.is_empty(), "{db}: {r} has CREATE on {schemas:?}");
            let attrs: (bool, bool, bool) = su
                .query_one(
                    "SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_catalog.pg_roles WHERE rolname = $1",
                    &[&r],
                )
                .await
                .map(|x| (x.get(0), x.get(1), x.get(2)))
                .unwrap();
            assert_eq!(attrs, (false, false, false), "{r}");
        }
        // Every function in the Nodkey schemas pins search_path.
        let unpinned: Vec<String> = su
            .query(
                "SELECT p.oid::regprocedure::text FROM pg_catalog.pg_proc p \
                 JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
                 WHERE n.nspname IN ('public','nodkey') \
                   AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}')) c WHERE c LIKE 'search_path=%')",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|x| x.get(0))
            .collect();
        assert!(
            unpinned.is_empty(),
            "{db}: functions without a pinned search_path: {unpinned:?}"
        );
    }
    let _ = std::fs::remove_dir_all(p.sock.parent().unwrap());
}

/// BP-02: operator updates of the trusted facts, made AS `nodkey_shop_operator` (not the
/// superuser), commit — on a charge that has no `charge_refund_state` row yet (the trigger
/// creates it; the deferred counter check then runs at the operator's COMMIT) and on one that
/// has. The operator still cannot touch the broker-owned tables.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bp02_operator_updates_as_operator_role() {
    let p = setup().await;
    let op = operator(&p).await;
    let rows: i64 = p
        .h
        .su
        .query_one(
            "SELECT count(*) FROM nodkey.charge_refund_state WHERE charge_id = 'ch_order1002bb'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 0, "fresh charge");
    for sql in [
        "UPDATE nodkey.orders SET status = 'disputed' WHERE order_id = 1002",
        "UPDATE nodkey.orders SET owner_sub = 'user:carol' WHERE order_id = 1002",
        "UPDATE nodkey.orders SET external_refunded_minor = 100 WHERE order_id = 1004",
    ] {
        op.batch_execute(sql)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    }
    // Explicit transaction: the deferred check runs at this COMMIT.
    op.batch_execute(
        "BEGIN; UPDATE nodkey.orders SET status = 'canceled' WHERE order_id = 1006; COMMIT",
    )
    .await
    .unwrap();
    let st: String =
        p.h.su
            .query_one(
                "SELECT status FROM nodkey.orders WHERE order_id = 1002",
                &[],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(st, "disputed");
    // A charge with an existing state row and an open effect.
    let a = p.reserve(1005, 100, "USD").await;
    op.batch_execute(
        "UPDATE nodkey.orders SET external_refunded_minor = 50 WHERE order_id = 1005",
    )
    .await
    .unwrap();
    p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap();
    assert_eq!(p.h.state(&a).await, "SUCCEEDED");
    op.batch_execute(
        "UPDATE nodkey.orders SET status = 'partially_refunded' WHERE order_id = 1005",
    )
    .await
    .unwrap();
    // The trusted facts are what T1 sees next: 1002 is disputed.
    let pid = p.propose(1001, 10, "USD", CUST).await.unwrap();
    let _ = pid;
    // The operator has no path to the broker-owned state.
    for sql in [
        "UPDATE nodkey.charge_refund_state SET inflight_minor = 0",
        "INSERT INTO nodkey.charge_refund_state (charge_id) VALUES ('ch_operator0001')",
        "SELECT * FROM nodkey.payment_effect",
        "UPDATE nodkey.payment_effect SET state = 'FAILED'",
        "SELECT nodkey.charge_counters_check()",
        "UPDATE nodkey.orders SET captured_minor = 1 WHERE order_id = 1001",
    ] {
        assert!(
            op.batch_execute(sql).await.is_err(),
            "operator allowed: {sql}"
        );
    }
    assert_eq!(p.counters("ch_order1005ee").await, (100, 0, 0));
}

/// BP-01 (reviewer scenario): a row is UNKNOWN under K1; the adapter alone restarts with a
/// rotated K_idem (K2) while the broker keeps running. The broker re-learns the kid before the
/// round, refuses payment processing (alarm) and makes no call for the row: no lookup under K2,
/// no resend. When the operator restores K1, the row is reconciled under K1 (the kid it was
/// dispatched with) and resolves with exactly one refund.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bp01_adapter_restart_with_rotated_key_never_resends() {
    let p = setup().await;
    p.fake.push(Mode::FailBeforeCommit);
    let a = p.reserve(1001, 200, "USD").await;
    p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap();
    assert_eq!(p.pay_state(&a).await.unwrap().0, "UNKNOWN");
    assert_eq!((p.fake.creates(), p.fake.effects()), (1, 0));
    let calls_before = p.fake.state.lock().unwrap().kids.len();
    // Adapter-only restart with K2.
    p.fake.set_kid("ffffffffffffffff");
    let out = p.tick_after(11).await;
    assert!(out.is_empty(), "{out:?}");
    assert!(
        !p.h.b.ensure_adapter().await,
        "not ready while a K1 row is open"
    );
    assert_eq!(
        p.h.b.reconcile(decode_id(&a).unwrap()).await.unwrap(),
        PayOutcome::Skipped
    );
    assert_eq!(
        p.fake.state.lock().unwrap().kids.len(),
        calls_before,
        "no call for the row under K2"
    );
    assert_eq!((p.fake.creates(), p.fake.effects()), (1, 0));
    // New refunds are not executed meanwhile.
    let pid = p.propose(1005, 10, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&pid).await, Delivery::Accepted);
    assert_eq!(
        p.h.b.execute(decode_id(&pid).unwrap(), "t").await.unwrap(),
        Execution::Unverified("payments_not_ready")
    );
    // The operator restores K1: the row resolves under K1 with one refund.
    p.fake.set_kid(KID);
    let out = p.tick_after(11).await;
    assert!(
        out.iter()
            .any(|(_, o)| matches!(o, PayOutcome::Applied(PayTo::Succeeded { .. }))),
        "{out:?}"
    );
    assert_eq!(p.h.state(&a).await, "SUCCEEDED");
    assert_eq!(p.fake.effects(), 1);
    let kids = p.fake.state.lock().unwrap().kids.clone();
    assert!(kids.iter().all(|k| k == KID), "{kids:?}");
}

/// BP-01: a row reserved under K1 is not dispatched when the adapter now reports K2 (the
/// broker re-runs hello before the dispatch); nothing is sent and the row fails as never
/// dispatched. A call that names a stale kid is refused by the adapter (nothing sent) and the
/// row stays UNKNOWN with an alarm, never FAILED.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bp01_dispatch_rechecks_the_kid() {
    let p = setup().await;
    let a = p.reserve(1001, 100, "USD").await;
    p.fake.set_kid("ffffffffffffffff");
    assert_eq!(
        p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap(),
        PayOutcome::Skipped
    );
    assert_eq!(p.fake.creates(), 0);
    let out = p.tick_after(31).await;
    assert!(
        out.iter().any(|(_, o)| *o
            == PayOutcome::Applied(PayTo::Failed {
                reason: "not_dispatched"
            })),
        "{out:?}"
    );
    assert_eq!(p.fake.creates(), 0);
    // Key restored; then the adapter rotates between hello and the create: refused, UNKNOWN.
    p.fake.set_kid(KID);
    assert!(p.h.b.ensure_adapter().await);
    let b = p.reserve(1005, 100, "USD").await;
    let id = decode_id(&b).unwrap();
    // The fake rotates right after it has answered the dispatcher's hello.
    *p.fake.rotate_after_hello.lock().unwrap() = Some("eeeeeeeeeeeeeeee".into());
    let out = p.h.b.dispatch(id).await.unwrap();
    assert_eq!(
        out,
        PayOutcome::Applied(PayTo::Unknown {
            reason: "key_mismatch"
        })
    );
    assert_eq!(p.fake.effects(), 0);
    assert_eq!(p.h.state(&b).await, "UNKNOWN");
}

/// BP-03: a dispatcher that waits for a call slot past its lease re-checks the lease after
/// the wait and sends nothing once recovery has moved the row on (at most one call in flight
/// per row).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bp03_lease_rechecked_after_slot_wait() {
    let p = setup().await;
    let a = p.reserve(1001, 100, "USD").await;
    let id = decode_id(&a).unwrap();
    let rt = p.h.b.payments.as_ref().unwrap();
    let held = rt.calls.acquire_many(8).await.unwrap();
    let b = p.h.b.clone();
    let d = tokio::spawn(async move { b.dispatch(id).await });
    // The dispatcher has committed T2 and now waits for a slot.
    for _ in 0..100 {
        if p.pay_state(&a).await.unwrap().0 == "DISPATCHED" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let lease = p.h.b.cfg.payments.as_ref().unwrap().lease_dispatch_s();
    let out = p.tick_after(lease + 1).await;
    assert!(out.iter().any(|(_, o)| *o
        == PayOutcome::Applied(PayTo::Unknown {
            reason: "lost_response"
        })));
    drop(held);
    assert_eq!(d.await.unwrap().unwrap(), PayOutcome::Discarded);
    assert_eq!(p.fake.creates(), 0, "the late dispatcher sent nothing");
}

/// BP-04: Phase 3 recovery never waits for the adapter: with a slow adapter, `recovery_tick`
/// executes an approved refund (T1) and returns without any adapter call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bp04_recovery_tick_does_not_call_the_adapter() {
    let p = setup().await;
    p.fake.push(Mode::Slow(5000));
    let pid = p.propose(1001, 100, "USD", CUST).await.unwrap();
    assert_eq!(p.approve(&pid).await, Delivery::Accepted);
    let t = std::time::Instant::now();
    let out = p.h.b.recovery_tick().await.unwrap();
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert!(out.iter().any(|(_, r)| *r == Ok(Execution::Reserved)));
    assert_eq!(p.fake.creates(), 0);
}

/// BP-05 + BP-08: one row whose transition fails (the provider "confirms" it with a refund id
/// that already confirmed another row; the UNIQUE index rejects it) does not stop the tick: the
/// other row resolves, the failing row stays UNKNOWN and is backed off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bp05_bp08_one_failing_row_does_not_stop_the_tick() {
    let p = setup().await;
    let a = p.reserve(1001, 100, "USD").await;
    p.h.b.dispatch(decode_id(&a).unwrap()).await.unwrap();
    assert_eq!(p.h.state(&a).await, "SUCCEEDED");
    let ra: String =
        p.h.su
            .query_one(
                "SELECT provider_refund_id FROM nodkey.payment_effect WHERE pending_id = $1",
                &[&decode_id(&a).unwrap().as_slice()],
            )
            .await
            .unwrap()
            .get(0);
    p.fake.push(Mode::FailBeforeCommit);
    let b = p.reserve(1005, 100, "USD").await;
    p.h.b.dispatch(decode_id(&b).unwrap()).await.unwrap();
    p.fake.push(Mode::CommitThenDrop);
    let c = p.reserve(1006, 100, "JPY").await;
    p.h.b.dispatch(decode_id(&c).unwrap()).await.unwrap();
    // The provider reports row B as refunded with row A's refund id.
    let grant_b: Vec<u8> =
        p.h.su
            .query_one(
                "SELECT grant_bytes FROM public.pending_effect WHERE pending_id = $1",
                &[&decode_id(&b).unwrap().as_slice()],
            )
            .await
            .unwrap()
            .get(0);
    let params_b = p.fake.params_of(&encode_transport(&grant_b)).await.unwrap();
    let mut fake_b = Fake::refund(&params_b, 0);
    fake_b["id"] = json!(ra);
    p.fake
        .state
        .lock()
        .unwrap()
        .ledger
        .insert(encode_transport(&grant_b), fake_b);
    let out = p.tick_after(11).await;
    assert_eq!(p.h.state(&c).await, "SUCCEEDED", "{out:?}");
    assert_eq!(p.h.state(&b).await, "UNKNOWN");
    let next: Option<i64> =
        p.h.su
            .query_one(
                "SELECT next_check_at FROM nodkey.payment_effect WHERE pending_id = $1",
                &[&decode_id(&b).unwrap().as_slice()],
            )
            .await
            .unwrap()
            .get(0);
    assert!(next.unwrap() >= (p.h.now() + 60) as i64, "backed off");
}
