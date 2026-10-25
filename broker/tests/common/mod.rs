//! Integration-test harness: a real PostgreSQL (see `tests/run-pg-integration.sh`) initialized
//! with the demo's own initdb scripts, one fresh database per test (copied from the `ledger`
//! template), a controllable clock, a fake authority that signs with the RFC 8032 TEST 1 key
//! through `nodkey_grant::GrantBuilder`, and a fake gateway that recomputes the digest.
//!
//! TEST-ONLY key material: RFC 8032 §7.1 secrets are public.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nodkey_broker::v2::config::{RawV2Config, V2Config, WorkloadReg};
use nodkey_broker::v2::db::Pool;
use nodkey_broker::v2::decls;
use nodkey_broker::v2::digest::PendingFields;
use nodkey_broker::v2::ids::{decode_id, hex, random16};
use nodkey_broker::v2::service::{Broker, Clock, Delivery};
use nodkey_broker::v2::wire::Fail;
use nodkey_grant::{GrantBuilder, ParamValue, Registry, SigningKey, encode_transport};
use serde_json::{Map, Value, json};
use tokio_postgres::{Client, NoTls};

pub const T0: u64 = 1_790_000_000; // inside the test key's validity window (2026)
pub const BROKER_ID: &str = "nodkey.broker.test";
pub const ISS: &str = "nodkey.authority.test";
pub const AGENT: &str = "spiffe://nodkey.test/workload/agent";
pub const AGENT2: &str = "spiffe://nodkey.test/workload/agent2";
pub const SHOP: &str = "spiffe://nodkey.test/workload/shop";

pub const KEY_A: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
pub const KEY_B: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

pub fn registry_json(status: &str) -> String {
    format!(
        r#"{{"format":"nodkey.grant-keys.v1","keys":[{{"kid":"4fcf41a3bf742ec7db96e0aaa5047e3a","alg":"Ed25519",
        "public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","iss":"{ISS}",
        "purpose":"grant","not_before":1767225600,"not_after":1798761600,"status":"{status}"}}]}}"#
    )
}

pub const OPS_JSON: &str = r#"{"format":"nodkey.operations.v1","operations":[
 {"op":"ledger.transfer","kind":"write","opv":1,"requires_confirmation":true,"params":[
  {"name":"from","in":"res","key":0,"class":"exact","type":"account_id","destination":false},
  {"name":"to","in":"con","key":0,"class":"exact","type":"account_id","destination":true},
  {"name":"amount_minor","in":"con","key":1,"class":"exact","type":"uint","destination":false}]},
 {"op":"payments.refund","kind":"write","opv":1,"requires_confirmation":true,"params":[
  {"name":"order_id","in":"res","key":0,"class":"exact","type":"uint","destination":false},
  {"name":"amount_minor","in":"con","key":0,"class":"exact","type":"uint","destination":false},
  {"name":"currency","in":"con","key":1,"class":"exact","type":"currency","destination":false}]},
 {"op":"ledger.get_balance","kind":"read","opv":1,"requires_confirmation":false,"params":[
  {"name":"account","in":"request","key":null,"class":"owner_scoped","type":"account_id","destination":false}]},
 {"op":"payments.get_order","kind":"read","opv":1,"requires_confirmation":false,"params":[
  {"name":"order_id","in":"request","key":null,"class":"owner_scoped","type":"uint","destination":false}]}]}"#;

pub fn key(hexseed: &str) -> SigningKey {
    let b: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hexseed[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    SigningKey::from_bytes(&b.try_into().unwrap())
}

pub struct PgEnv {
    pub host: String,
    pub port: u16,
    pub super_pw: String,
    pub broker_pw: String,
}

/// Connection settings from the environment set by `tests/run-pg-integration.sh`.
pub fn pg_env() -> PgEnv {
    let v = |k: &str| {
        std::env::var(k).unwrap_or_else(|_| {
            panic!(
                "{k} not set: run broker/tests/run-pg-integration.sh (these tests need PostgreSQL)"
            )
        })
    };
    PgEnv {
        host: v("NODKEY_PG_HOST"),
        port: v("NODKEY_PG_PORT").parse().unwrap(),
        super_pw: v("NODKEY_PG_SUPER_PASSWORD"),
        broker_pw: v("NODKEY_PG_BROKER_PASSWORD"),
    }
}

pub fn pg_config(db: &str, user: &str, pw: &str) -> tokio_postgres::Config {
    let e = pg_env();
    let mut c = tokio_postgres::Config::new();
    c.host(&e.host)
        .port(e.port)
        .dbname(db)
        .user(user)
        .password(pw);
    c
}

pub async fn connect(cfg: tokio_postgres::Config) -> Client {
    let (client, conn) = cfg.connect(NoTls).await.expect("connect");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

static CREATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A fresh database copied from the initialized `ledger` template.
pub async fn fresh_db() -> String {
    let e = pg_env();
    let name = format!("t_{}", &hex(&random16().unwrap())[..16]);
    let _g = CREATE_LOCK.lock().await;
    let su = connect(pg_config("postgres", "postgres", &e.super_pw)).await;
    for stmt in [
        format!("CREATE DATABASE {name} TEMPLATE ledger"),
        format!("REVOKE ALL ON DATABASE {name} FROM PUBLIC"),
        format!("GRANT CONNECT ON DATABASE {name} TO nodkey_broker"),
    ] {
        su.batch_execute(&stmt).await.expect("create database");
    }
    name
}

pub struct H {
    pub b: Arc<Broker>,
    pub now: Arc<AtomicU64>,
    pub db: String,
    pub su: Client,
}

pub fn config_json(db: &str) -> String {
    format!(
        r#"{{"format":"nodkey.broker.v2","profile":"phase3","broker_id":"{BROKER_ID}",
 "auth_origin":"https://auth.nodkey.test","ledger_currency":"EUR",
 "db":{{"host":"unused","port":5432,"dbname":"{db}","user":"nodkey_broker","password_file":"/nonexistent"}},
 "registry_path":"/nonexistent","operations_path":"/nonexistent","authority_workloads_path":"/nonexistent",
 "gateway":{{"socket_path":"/run/t/gw-broker/broker.sock","uid":20001}},
 "authority":{{"socket_path":"/run/t/au-broker/broker.sock","uid":20002}},
 "workloads":[
  {{"wid":"{AGENT}","display_name":"Budget agent","socket_path":"/run/t/wl/agent/broker.sock","uid":10001,
   "tenants":["acme"],"approver_source":{{"kind":"enrolled","ten":"acme","sub":"user:alice"}},"allowed_ops":["ledger.transfer","ledger.get_balance"]}},
  {{"wid":"{AGENT2}","display_name":"Second agent","socket_path":"/run/t/wl/agent2/broker.sock","uid":10002,
   "tenants":["acme"],"approver_source":{{"kind":"enrolled","ten":"acme","sub":"user:bob"}},"allowed_ops":["ledger.transfer","ledger.get_balance"]}},
  {{"wid":"{SHOP}","display_name":"Shop","socket_path":"/run/t/wl/shop/broker.sock","uid":10003,
   "tenants":["acme"],"approver_source":{{"kind":"named"}},"allowed_ops":["ledger.get_balance"]}}]}}"#
    )
}

/// The authority's copy of the registrations (`nodkey.workloads.v1`, authority README).
pub const AUTH_WORKLOADS: &str = r#"{"format":"nodkey.workloads.v1","workloads":[
 {"wid":"spiffe://nodkey.test/workload/agent","tenants":["acme"],"approver_source":{"enrolled":{"ten":"acme","sub":"user:alice"}},"write_ops":["ledger.transfer"],"read_ops":["ledger.get_balance"]},
 {"wid":"spiffe://nodkey.test/workload/agent2","tenants":["acme"],"approver_source":{"enrolled":{"ten":"acme","sub":"user:bob"}},"write_ops":["ledger.transfer"],"read_ops":["ledger.get_balance"]},
 {"wid":"spiffe://nodkey.test/workload/shop","tenants":["acme"],"approver_source":"named","write_ops":[],"read_ops":["ledger.get_balance"]}]}"#;

pub fn build_broker(db: &str, now: Arc<AtomicU64>, registry_status: &str) -> Broker {
    let (ops, names) = decls::load(OPS_JSON).unwrap();
    let raw = RawV2Config::parse(config_json(db).as_bytes()).unwrap();
    let cfg = V2Config::from_raw(raw, &ops, &names, 99_999, true).unwrap();
    nodkey_broker::v2::config::check_authority_workloads(AUTH_WORKLOADS.as_bytes(), &cfg, &ops)
        .unwrap();
    let digest =
        nodkey_broker::v2::config::config_digest(OPS_JSON.as_bytes(), AUTH_WORKLOADS.as_bytes());
    let registry = Registry::load(&registry_json(registry_status)).unwrap();
    let e = pg_env();
    let pool = Pool::from_config(pg_config(db, "nodkey_broker", &e.broker_pw), 8);
    let clock: Clock = {
        let now = now.clone();
        Arc::new(move || now.load(Ordering::SeqCst))
    };
    Broker::new(cfg, registry, ops, names, pool, digest, clock)
}

pub async fn harness() -> H {
    let db = fresh_db().await;
    let e = pg_env();
    let su = connect(pg_config(&db, "postgres", &e.super_pw)).await;
    su.batch_execute(
        "INSERT INTO account_owner VALUES ('alice','acme','user:alice'), ('bob','acme','user:bob'), \
         ('carol','globex','user:carol'), ('dave','acme','user:alice')",
    )
    .await
    .unwrap();
    let now = Arc::new(AtomicU64::new(T0));
    let b = Arc::new(build_broker(&db, now.clone(), "active"));
    b.startup_checks().await.expect("startup");
    H { b, now, db, su }
}

impl H {
    pub fn set_now(&self, t: u64) {
        self.now.store(t, Ordering::SeqCst);
    }
    pub fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
    pub fn wl(&self, wid: &str) -> WorkloadReg {
        self.b.cfg.workload(wid).unwrap().clone()
    }

    pub async fn propose_transfer(
        &self,
        wid: &str,
        from: &str,
        to: &str,
        amount: u64,
        approver: (&str, &str),
    ) -> Result<String, Fail> {
        let a = obj(
            json!({"op":"ledger.transfer","params":{"from":from,"to":to,"amount_minor":amount},
                           "approver":{"ten":approver.0,"sub":approver.1}}),
        );
        self.b
            .propose(&self.wl(wid), &a)
            .await
            .map(|v| v["pending_id"].as_str().unwrap().to_owned())
    }

    pub async fn status(&self, wid: &str, pid: &str) -> Result<Value, Fail> {
        self.b
            .status(&self.wl(wid), &obj(json!({"pending_id": pid})))
            .await
    }

    pub async fn get(&self, pid: &str) -> Value {
        self.b
            .pending_get(&obj(json!({"pending_id": pid})))
            .await
            .unwrap()
    }

    /// Fake authority (§4.2): fetches the record read-only, checks state, expiry, its own
    /// digest against the shown digest and the broker's, and the subject; signs from the record
    /// only. Returns the transport text (not yet delivered).
    pub async fn authority_sign(
        &self,
        pid: &str,
        digest_shown: &str,
        subject: (&str, &str),
    ) -> Option<String> {
        let rec = self
            .b
            .pending_get(&obj(json!({"pending_id": pid})))
            .await
            .ok()?;
        let now = self.now();
        if rec["state"] != "PENDING" || now >= rec["expires_at"].as_u64()? {
            return None;
        }
        let mut fields = rec.clone();
        let fo = fields.as_object_mut()?;
        fo.remove("state");
        fo.remove("digest");
        let own = hex(&PendingFields::from_json(&fields).ok()?.digest().ok()?);
        if own != digest_shown || own != rec["digest"].as_str()? {
            return None;
        }
        if rec["ten"] != subject.0 || rec["approver_sub"] != subject.1 {
            return None;
        }
        Some(sign_from_record(&rec, now, KEY_A, |b| b))
    }

    pub async fn deliver(&self, pid: &str, grant: &str) -> Delivery {
        self.b
            .deliver(&obj(json!({"pending_id": pid, "grant": grant})))
            .await
    }

    /// Fake gateway render (§4.1) for `subject`; recomputes the digest from the response.
    pub async fn render(&self, pid: &str, subject: (&str, &str)) -> Result<Value, Fail> {
        let v = self
            .b
            .render(&obj(
                json!({"pending_id": pid, "subject": {"ten": subject.0, "sub": subject.1}}),
            ))
            .await?;
        let mut f = Map::new();
        for k in [
            "pending_id",
            "broker_id",
            "wid",
            "ten",
            "approver_sub",
            "op",
            "opv",
            "params",
            "param_types",
            "created_at",
            "expires_at",
            "display",
        ] {
            f.insert(k.into(), v["record"][k].clone());
        }
        let d = hex(&PendingFields::from_json(&Value::Object(f))
            .unwrap()
            .digest()
            .unwrap());
        assert_eq!(d, v["digest"].as_str().unwrap(), "gateway digest recompute");
        Ok(v)
    }

    /// Full happy path up to delivery: render as the approver, authority approve, deliver.
    pub async fn approve(&self, pid: &str, subject: (&str, &str)) -> Delivery {
        let r = self.render(pid, subject).await.expect("render");
        let g = self
            .authority_sign(pid, r["digest"].as_str().unwrap(), subject)
            .await
            .expect("sign");
        self.deliver(pid, &g).await
    }

    pub async fn balance(&self, acct: &str) -> i64 {
        self.su
            .query_one("SELECT balance_cents FROM accounts WHERE id = $1", &[&acct])
            .await
            .unwrap()
            .get(0)
    }

    pub async fn consumed(&self, pid: &str) -> Option<String> {
        let jti = decode_id(pid).unwrap();
        self.su
            .query_opt(
                "SELECT outcome FROM consumed_grant WHERE iss = $1 AND jti = $2",
                &[&ISS, &jti.as_slice()],
            )
            .await
            .unwrap()
            .map(|r| r.get(0))
    }

    pub async fn transfers_for(&self, pid: &str) -> i64 {
        self.su
            .query_one(
                "SELECT count(*) FROM transfers WHERE idempotency_key = $1",
                &[&pid],
            )
            .await
            .unwrap()
            .get(0)
    }

    pub async fn state(&self, pid: &str) -> String {
        let id = decode_id(pid).unwrap();
        self.su
            .query_one(
                "SELECT state FROM pending_effect WHERE pending_id = $1",
                &[&id.as_slice()],
            )
            .await
            .unwrap()
            .get(0)
    }
}

/// Signs a write grant from a `pending.get` record, letting `tweak` change the builder.
pub fn sign_from_record(
    rec: &Value,
    now: u64,
    key_hex: &str,
    tweak: impl FnOnce(GrantBuilder) -> GrantBuilder,
) -> String {
    let p = &rec["params"];
    let b = GrantBuilder::write(rec["op"].as_str().unwrap(), 1)
        .issuer(ISS)
        .audience(rec["broker_id"].as_str().unwrap())
        .jti(decode_id(rec["pending_id"].as_str().unwrap()).unwrap())
        .times(now, now, now + 30)
        .workload(rec["wid"].as_str().unwrap())
        .tenant(rec["ten"].as_str().unwrap())
        .subject(rec["approver_sub"].as_str().unwrap())
        .resource(0, ParamValue::Text(p["from"].as_str().unwrap().into()))
        .exact(0, ParamValue::Text(p["to"].as_str().unwrap().into()))
        .exact(1, ParamValue::Uint(p["amount_minor"].as_u64().unwrap()))
        .confirmed(true);
    encode_transport(&tweak(b).sign(&key(key_hex)).unwrap())
}

pub fn read_grant(now: u64, wid: &str, ten: &str, sub: &str, key_hex: &str) -> String {
    let g = GrantBuilder::read()
        .issuer(ISS)
        .audience(BROKER_ID)
        .jti(random16().unwrap())
        .times(now, now, now + 30)
        .workload(wid)
        .tenant(ten)
        .subject(sub)
        .read_op("ledger.get_balance", 1)
        .sign(&key(key_hex))
        .unwrap();
    encode_transport(&g)
}

pub fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(o) => o,
        _ => panic!("not an object"),
    }
}
