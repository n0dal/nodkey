// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Test fixtures: a fake broker (socket A), a fake gateway client (socket I), and an in-process
//! authority wired to temporary Unix sockets.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use nodkey_authority::broker_client::BrokerClient;
use nodkey_authority::config::{Workloads, config_digest};
use nodkey_authority::digest::{PendingRecord, hex};
use nodkey_authority::key::{keygen, load_signing_key};
use nodkey_authority::server::{Authority, Clock, Settings, system_clock};
use nodkey_authority::store::Store;
use nodkey_grant::{
    BrokerId, Limits, Operations, ParamValue, Registry, Verified, VerifyContext, decode_transport,
    verify,
};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

pub const ISSUER: &str = "nodkey.authority.test";
pub const BROKER_ID: &str = "nodkey.broker.payments-test";
pub const SHOP: &str = "spiffe://nodkey.test/workload/shop";
pub const AGENT: &str = "spiffe://nodkey.test/workload/agent";

pub const OPERATIONS: &str = r#"{"format":"nodkey.operations.v1","operations":[
{"op":"payments.refund","kind":"write","opv":1,"requires_confirmation":true,"params":[
 {"name":"order_id","in":"res","key":0,"class":"exact","type":"uint","destination":false},
 {"name":"amount_minor","in":"con","key":0,"class":"exact","type":"uint","destination":false},
 {"name":"currency","in":"con","key":1,"class":"exact","type":"currency","destination":false},
 {"name":"charge_id","in":"con","key":2,"class":"exact","type":"text64","destination":false}]},
{"op":"ledger.transfer","kind":"write","opv":1,"requires_confirmation":true,"params":[
 {"name":"from","in":"res","key":0,"class":"exact","type":"account_id","destination":false},
 {"name":"to","in":"con","key":0,"class":"exact","type":"account_id","destination":true},
 {"name":"amount_minor","in":"con","key":1,"class":"exact","type":"uint","destination":false}]},
{"op":"test.note","kind":"write","opv":1,"requires_confirmation":true,"params":[
 {"name":"order_id","in":"res","key":0,"class":"exact","type":"uint","destination":false},
 {"name":"note","in":"con","key":null,"class":"free","type":"text64","destination":false,"justification":"test-only free text"}]},
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
 {"name":"body","in":"con","key":null,"class":"free","type":"text256","destination":false,"justification":"message content"}]},
{"op":"mandate.support_ticket","kind":"write","opv":1,"requires_confirmation":true,"params":[
 {"name":"customer_sub","in":"res","key":0,"class":"exact","type":"text64","destination":false},
 {"name":"currency","in":"con","key":0,"class":"exact","type":"currency","destination":false},
 {"name":"refund_max_count","in":"con","key":1,"class":"exact","type":"uint","destination":false},
 {"name":"refund_max_per_call_minor","in":"con","key":2,"class":"exact","type":"uint","destination":false},
 {"name":"refund_max_total_minor","in":"con","key":3,"class":"exact","type":"uint","destination":false},
 {"name":"message_max_count","in":"con","key":4,"class":"exact","type":"uint","destination":false},
 {"name":"valid_for_s","in":"con","key":5,"class":"exact","type":"uint","destination":false},
 {"name":"customer_email","in":"con","key":6,"class":"exact","type":"text256","destination":false}]},
{"op":"payments.get_order","kind":"read","opv":1,"requires_confirmation":false,"params":[
 {"name":"order_id","in":"request","key":null,"class":"owner_scoped","type":"uint","destination":false}]},
{"op":"ledger.get_balance","kind":"read","opv":1,"requires_confirmation":false,"params":[
 {"name":"account","in":"request","key":null,"class":"owner_scoped","type":"account_id","destination":false}]}
]}"#;

pub const WORKLOADS: &str = r#"{"format":"nodkey.workloads.v1","workloads":[
{"wid":"spiffe://nodkey.test/workload/shop","tenants":["acme","globex"],"approver_source":"named",
 "write_ops":["payments.refund","test.note"],"read_ops":["payments.get_order"]},
{"wid":"spiffe://nodkey.test/workload/agent","tenants":["acme"],"approver_source":{"enrolled":{"ten":"acme","sub":"user:u-17"}},
 "write_ops":["ledger.transfer"],"read_ops":["ledger.get_balance"]},
{"wid":"spiffe://nodkey.test/workload/support","tenants":["shop1"],"approver_source":{"enrolled":{"ten":"shop1","sub":"op_ana"}},
 "write_ops":["payments.support_refund","messages.send","mandate.support_ticket"],"read_ops":["payments.support_get_order"]}
],
"support_principals":{"shop1":["op_ana"]},
"mandate_template":{"template":"mandate.support_ticket","refund_op":"payments.support_refund",
 "read_ops":["payments.support_get_order"],"message_op":"messages.send",
 "ceilings":{"refund_max_count":5,"message_max_count":10,"refund_max_total_minor":{"EUR":10000}}}}"#;

pub const SUPPORT: &str = "spiffe://nodkey.test/workload/support";

pub fn tmpdir(name: &str) -> PathBuf {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b).unwrap();
    // Short base path: Unix socket paths are limited to ~104 bytes on macOS.
    let d = PathBuf::from("/tmp").join(format!("gla-{name}-{}", hex(&b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn random_pid() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).unwrap();
    nodkey_grant::encode_transport(&b)
}

/// A refund record (named `shop` workload), as the broker's `pending.get` would return it.
pub fn refund_record(pid: &str, sub: &str, amount: u64, expires_at: u64) -> Map<String, Value> {
    json!({
        "pending_id": pid, "broker_id": BROKER_ID, "wid": SHOP, "ten": "acme",
        "approver_sub": sub, "op": "payments.refund", "opv": 1,
        "params": {"order_id": 9821, "amount_minor": amount, "currency": "EUR", "charge_id": "ch_demoorder0001"},
        "param_types": {"order_id": "uint", "amount_minor": "uint", "currency": "currency", "charge_id": "text64"},
        "created_at": expires_at.saturating_sub(600), "expires_at": expires_at,
        "display": {"amount_exponent": 2, "currency": "EUR"}
    })
    .as_object()
    .unwrap()
    .clone()
}

pub fn transfer_record(pid: &str, sub: &str, expires_at: u64) -> Map<String, Value> {
    json!({
        "pending_id": pid, "broker_id": BROKER_ID, "wid": AGENT, "ten": "acme",
        "approver_sub": sub, "op": "ledger.transfer", "opv": 1,
        "params": {"from": "alice", "to": "bob", "amount_minor": 12500},
        "param_types": {"from": "account_id", "to": "account_id", "amount_minor": "uint"},
        "created_at": expires_at.saturating_sub(600), "expires_at": expires_at,
        "display": {"amount_exponent": 2, "currency": "EUR"}
    })
    .as_object()
    .unwrap()
    .clone()
}

pub fn digest_of(rec: &Map<String, Value>) -> String {
    hex(&PendingRecord::from_json(rec, &[]).unwrap().digest())
}

// ------------------------------------------------------------------ fake broker

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliverMode {
    /// Verify the grant like a broker (grant-v1 §7.2 + decide) and apply §4.3.
    Accept,
    /// Answer `unavailable` without applying.
    Unavailable,
    /// Never answer `grant.deliver` (the connection stays open).
    Hang,
    /// Apply like `Accept`, then close the connection without answering (lost response).
    ApplyAndDrop,
}

#[derive(Debug)]
pub struct BrokerRecord {
    pub json: Map<String, Value>,
    pub state: String,
    /// Overrides the `digest` member returned by `pending.get` (a lying broker).
    pub digest_override: Option<String>,
    pub grant: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct FakeBrokerState {
    pub records: HashMap<String, BrokerRecord>,
    pub mode: DeliverMode,
    pub config_digest: [u8; 32],
    /// Every `grant.deliver` received: (pending_id, grant bytes).
    pub deliveries: Vec<(String, Vec<u8>)>,
    /// `grant.deliver` results returned: "accepted" / "rejected" / "expired".
    pub results: Vec<String>,
    pub pending_gets: usize,
    pub registry_json: String,
    /// Fail the first N deliveries with `unavailable` before applying `mode`.
    pub fail_first: usize,
    /// Close a connection idle for this long (the real broker's `READ_TIMEOUT`, DEMO2-F02).
    pub idle_close: Option<Duration>,
    /// Connections accepted.
    pub connections: usize,
    /// Close the connection on every `pending.get` without answering.
    pub drop_pending_get: bool,
    /// `mandate.candidates` answer.
    pub candidates: Vec<String>,
    /// `mandate.declined` calls received: (pending_id, final).
    pub declined: Vec<(String, bool)>,
    /// Reject every delivery of a `cfm = 2` grant (a broker-side revocation).
    pub reject_mandated: bool,
    /// Verified `cfm = 2` deliveries: (pending_id, mid).
    pub mandated: Vec<(String, [u8; 16])>,
}

pub type Shared = Arc<StdMutex<FakeBrokerState>>;

pub struct FakeBroker {
    pub path: PathBuf,
    pub state: Shared,
}

impl FakeBroker {
    pub async fn start(dir: &Path, registry_json: &str) -> FakeBroker {
        let sockdir = dir.join("au-broker");
        std::fs::create_dir_all(&sockdir).unwrap();
        let path = sockdir.join("broker.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let state = Arc::new(StdMutex::new(FakeBrokerState {
            records: HashMap::new(),
            mode: DeliverMode::Accept,
            config_digest: config_digest(OPERATIONS.as_bytes(), WORKLOADS.as_bytes()),
            deliveries: vec![],
            results: vec![],
            pending_gets: 0,
            registry_json: registry_json.to_owned(),
            fail_first: 0,
            idle_close: None,
            connections: 0,
            drop_pending_get: false,
            candidates: vec![],
            declined: vec![],
            reject_mandated: false,
            mandated: vec![],
        }));
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    return;
                };
                let st = st.clone();
                st.lock().unwrap().connections += 1;
                tokio::spawn(async move { serve_broker_conn(s, st).await });
            }
        });
        FakeBroker { path, state }
    }

    pub fn add(&self, rec: Map<String, Value>, state: &str) {
        let pid = rec["pending_id"].as_str().unwrap().to_owned();
        self.state.lock().unwrap().records.insert(
            pid,
            BrokerRecord {
                json: rec,
                state: state.to_owned(),
                digest_override: None,
                grant: None,
            },
        );
    }

    pub fn deliveries(&self) -> Vec<(String, Vec<u8>)> {
        self.state.lock().unwrap().deliveries.clone()
    }

    pub fn set_mode(&self, m: DeliverMode) {
        self.state.lock().unwrap().mode = m;
    }

    pub fn record_state(&self, pid: &str) -> String {
        self.state.lock().unwrap().records[pid].state.clone()
    }
}

fn reply(id: &Value, result: Result<Value, &str>) -> Value {
    match result {
        Ok(r) => json!({"v":2,"id":id,"correlation_id":"br-1","ok":true,"result":r}),
        Err(code) => {
            json!({"v":2,"id":id,"correlation_id":"br-1","ok":false,"error":{"code":code,"message":"x"}})
        }
    }
}

/// Broker-side verification of a delivered grant (what the real broker does in §4.3 step 3).
fn broker_verify(st: &FakeBrokerState, rec: &Map<String, Value>, grant: &[u8]) -> bool {
    broker_check(st, rec, grant).0
}

/// The `mid` of a delivered grant that verifies with `cfm = 2`.
fn broker_verify_mid(
    st: &FakeBrokerState,
    rec: &Map<String, Value>,
    grant: &[u8],
) -> Option<[u8; 16]> {
    match broker_check(st, rec, grant) {
        (true, m) => m,
        _ => None,
    }
}

fn broker_check(
    st: &FakeBrokerState,
    rec: &Map<String, Value>,
    grant: &[u8],
) -> (bool, Option<[u8; 16]>) {
    let registry = Registry::load(&st.registry_json).unwrap();
    let ops = Operations::load(OPERATIONS).unwrap();
    let broker_id = BrokerId::new(BROKER_ID).unwrap();
    let mut params = std::collections::BTreeMap::new();
    for (k, v) in rec["params"].as_object().unwrap() {
        let pv = match v {
            Value::Number(n) => ParamValue::Uint(n.as_u64().unwrap()),
            Value::String(s) => ParamValue::Text(s.clone()),
            _ => return (false, None),
        };
        params.insert(k.clone(), pv);
    }
    let Ok(request) = ops.parse_request(rec["op"].as_str().unwrap(), params) else {
        return (false, None);
    };
    let wid = rec["wid"].as_str().unwrap();
    let tenants = vec![rec["ten"].as_str().unwrap().to_owned()];
    let ctx = VerifyContext {
        now: now(),
        broker_id: &broker_id,
        workload: wid,
        workload_tenants: &tenants,
        request: &request,
        operations: &ops,
        limits: Limits::default(),
    };
    match verify(grant, &registry, &ctx) {
        Ok(Verified::Write(w)) => {
            let id = w.identity().clone();
            let mid = w.mandate_id();
            let jti_ok =
                nodkey_grant::encode_transport(&id.jti) == rec["pending_id"].as_str().unwrap();
            let sub_ok = id.sub == rec["approver_sub"].as_str().unwrap();
            (jti_ok && sub_ok && w.decide(&[]).is_ok(), mid)
        }
        _ => (false, None),
    }
}

fn handle_broker(st: &mut FakeBrokerState, req: &Map<String, Value>) -> Option<(Value, bool)> {
    let id = req["id"].clone();
    let args = req["args"].as_object().unwrap();
    match req["op"].as_str().unwrap() {
        "config.digest" => Some((
            reply(&id, Ok(json!({"digest": hex(&st.config_digest)}))),
            false,
        )),
        "pending.get" => {
            st.pending_gets += 1;
            let pid = args["pending_id"].as_str().unwrap();
            let Some(r) = st.records.get(pid) else {
                return Some((reply(&id, Err("not_found")), false));
            };
            if st.drop_pending_get {
                return Some((reply(&id, Err("unavailable")), true));
            }
            let mut res = r.json.clone();
            let digest = r
                .digest_override
                .clone()
                .unwrap_or_else(|| digest_of(&r.json));
            res.insert("state".into(), json!(r.state));
            res.insert("digest".into(), json!(digest));
            Some((reply(&id, Ok(Value::Object(res))), false))
        }
        "mandate.candidates" => {
            Some((reply(&id, Ok(json!({"pending_ids": st.candidates}))), false))
        }
        "mandate.declined" => {
            let pid = args["pending_id"].as_str().unwrap().to_owned();
            st.declined
                .push((pid.clone(), args["final"].as_bool().unwrap()));
            if args["final"] == true
                && let Some(r) = st.records.get_mut(&pid)
                && r.state == "PENDING"
            {
                r.state = "DENIED".into();
            }
            Some((reply(&id, Ok(json!({}))), false))
        }
        "grant.deliver" => {
            let pid = args["pending_id"].as_str().unwrap().to_owned();
            let grant = decode_transport(args["grant"].as_str()).unwrap();
            st.deliveries.push((pid.clone(), grant.clone()));
            let mid = st
                .records
                .get(&pid)
                .and_then(|r| broker_verify_mid(st, &r.json, &grant));
            if let Some(m) = mid {
                st.mandated.push((pid.clone(), m));
            }
            if st.reject_mandated && mid.is_some() {
                st.results.push("rejected".into());
                return Some((reply(&id, Ok(json!({"status": "rejected"}))), false));
            }
            if st.fail_first > 0 {
                st.fail_first -= 1;
                return Some((reply(&id, Err("unavailable")), false));
            }
            let mode = st.mode;
            match mode {
                DeliverMode::Unavailable => return Some((reply(&id, Err("unavailable")), false)),
                DeliverMode::Hang => return None,
                DeliverMode::Accept | DeliverMode::ApplyAndDrop => {}
            }
            let status = {
                let verified = st
                    .records
                    .get(&pid)
                    .map(|r| broker_verify(st, &r.json, &grant))
                    .unwrap_or(false);
                match st.records.get_mut(&pid) {
                    None => "rejected",
                    Some(r) if r.state == "APPROVED" && r.grant.as_deref() == Some(&grant[..]) => {
                        "accepted"
                    }
                    Some(r) if r.state != "PENDING" => "expired",
                    Some(_) if !verified => "rejected",
                    Some(r) => {
                        r.state = "APPROVED".into();
                        r.grant = Some(grant);
                        "accepted"
                    }
                }
            };
            st.results.push(status.to_owned());
            Some((
                reply(&id, Ok(json!({"status": status}))),
                mode == DeliverMode::ApplyAndDrop,
            ))
        }
        _ => Some((reply(&id, Err("unknown_operation")), false)),
    }
}

async fn serve_broker_conn(s: UnixStream, st: Shared) {
    let (r, mut w) = s.into_split();
    let mut lines = BufReader::new(r).lines();
    loop {
        let idle = st.lock().unwrap().idle_close;
        let next = match idle {
            Some(d) => match tokio::time::timeout(d, lines.next_line()).await {
                Ok(n) => n,
                Err(_) => return, // idle: close, like the real broker
            },
            None => lines.next_line().await,
        };
        let Ok(Some(line)) = next else {
            return;
        };
        let req: Map<String, Value> = serde_json::from_str(&line).unwrap();
        let out = handle_broker(&mut st.lock().unwrap(), &req);
        match out {
            None => {
                // Hang: keep the connection open, never answer.
                std::future::pending::<()>().await;
            }
            Some((_, true)) => return, // applied, response lost
            Some((resp, false)) => {
                let mut b = resp.to_string().into_bytes();
                b.push(b'\n');
                if w.write_all(&b).await.is_err() {
                    return;
                }
            }
        }
    }
}

// ------------------------------------------------------------------ authority

pub struct Keys {
    pub key_path: PathBuf,
    pub registry_json: String,
}

pub fn make_key(dir: &Path) -> Keys {
    let key_path = dir.join("authority.key");
    let registry_json = keygen(&key_path, ISSUER, 1, 4_000_000_000).unwrap();
    Keys {
        key_path,
        registry_json,
    }
}

pub struct Opts {
    pub gateway_uid: u32,
    pub broker_uid: u32,
    pub ttl: u64,
    pub skew: u64,
    pub reply_timeout: Duration,
    pub clock: Clock,
}

impl Opts {
    pub fn new() -> Opts {
        let uid = nodkey_authority::own_uid().unwrap();
        Opts {
            gateway_uid: uid,
            broker_uid: uid,
            ttl: 30,
            skew: 5,
            reply_timeout: Duration::from_secs(10),
            clock: system_clock(),
        }
    }
}

pub struct Running {
    pub authority: Arc<Authority>,
    pub gateway_path: PathBuf,
    pub task: tokio::task::JoinHandle<()>,
}

pub async fn start_authority(dir: &Path, keys: &Keys, broker_path: &Path, o: Opts) -> Running {
    let uid = nodkey_authority::own_uid().unwrap();
    let ops = Operations::load(OPERATIONS).unwrap();
    let wl = Workloads::load(WORKLOADS.as_bytes(), &ops).unwrap();
    let key = load_signing_key(&keys.key_path, uid).unwrap();
    let store = Store::open(&dir.join("issuance.log"), uid).unwrap();
    let broker = BrokerClient::new(
        broker_path.to_owned(),
        o.broker_uid,
        config_digest(OPERATIONS.as_bytes(), WORKLOADS.as_bytes()),
        Duration::from_secs(2),
    );
    let settings = Settings {
        issuer: ISSUER.into(),
        broker_id: BROKER_ID.into(),
        gateway_uid: o.gateway_uid,
        grant_ttl_secs: o.ttl,
        skew_secs: o.skew,
        approve_reply_timeout: o.reply_timeout,
        retry_interval: Duration::from_millis(50),
        ledger_currency: "EUR".into(),
    };
    let authority = Authority::new(settings, ops, wl, key, store, broker, o.clock);
    let gwdir = dir.join("gw-authority");
    std::fs::create_dir_all(&gwdir).unwrap();
    let gateway_path = gwdir.join("authority.sock");
    let _ = std::fs::remove_file(&gateway_path);
    let listener = UnixListener::bind(&gateway_path).unwrap();
    let task = tokio::spawn(authority.clone().serve(listener));
    Running {
        authority,
        gateway_path,
        task,
    }
}

// ------------------------------------------------------------------ fake gateway

/// Sends one raw line on socket I; returns the response, or None if the connection was closed
/// without a response.
pub async fn gateway_raw(path: &Path, line: &str) -> Option<Value> {
    let s = UnixStream::connect(path).await.ok()?;
    let (r, mut w) = s.into_split();
    let _ = w.write_all(format!("{line}\n").as_bytes()).await;
    let mut lines = BufReader::new(r).lines();
    match tokio::time::timeout(Duration::from_secs(60), lines.next_line()).await {
        Ok(Ok(Some(l))) => Some(serde_json::from_str(&l).unwrap()),
        _ => None,
    }
}

pub async fn gateway_raw_owned(path: PathBuf, line: String) -> Option<Value> {
    gateway_raw(&path, &line).await
}

pub async fn approve(path: &Path, pid: &str, digest: &str, ten: &str, sub: &str) -> Value {
    let req = json!({"v":2,"id":"g-1","op":"approve","args":{
        "pending_id": pid, "digest_shown": digest, "subject": {"ten": ten, "sub": sub}}});
    gateway_raw(path, &req.to_string()).await.unwrap()
}

pub fn is_ok(v: &Value) -> bool {
    v["ok"] == json!(true)
}

pub fn err_code(v: &Value) -> Option<&str> {
    v["error"]["code"].as_str()
}
