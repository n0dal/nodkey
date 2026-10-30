// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Test harness: a real simpay process (built from `tools/simpay`, TLS with its `gen-test-ca`
//! certificates), an in-process adapter served on a socket P in a temporary directory, a fake
//! broker client, a grant issuer, scriptable TLS servers for byte-level HTTP faults, and a log
//! capture for byte searches.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use nodkey_grant::{GrantBuilder, ParamValue, Registry, SigningKey, derive_kid, encode_transport};
use nodkey_payments_adapter::config::parse_config;
use nodkey_payments_adapter::derive::IdemKey;
use nodkey_payments_adapter::orders::{BoxFut, OrderRow, OrderView};
use nodkey_payments_adapter::provider::ApiKey;
use nodkey_payments_adapter::server::{Adapter, bind_socket, serve};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

pub const ACCT: &str = "acct_demomerchant01";
pub const RK: &str = "rk_sim_DEMOrefundsWriteChargesRead";
pub const CH_USD: &str = "ch_demoorder0001";
pub const CH_JPY: &str = "ch_demoorder0002";
pub const CH_EUR_PENDING: &str = "ch_demoorder0003";
pub const ISS: &str = "nodkey.authority.test";
pub const BROKER: &str = "broker.demo-p";
pub const SHOP: &str = "spiffe://nodkey.test/workload/shop";
pub const SEED: [u8; 32] = [0x11; 32];
pub const SEED_REVOKED: [u8; 32] = [0x22; 32];
pub const SEED_SHORT: [u8; 32] = [0x33; 32];
pub const SEED_FOREIGN: [u8; 32] = [0x44; 32];
pub const KIDEM: [u8; 32] = [0x5a; 32];
pub const SERVER_NAME: &str = "simpay.test";

static N: AtomicUsize = AtomicUsize::new(0);

pub fn uniq() -> usize {
    N.fetch_add(1, Ordering::SeqCst)
}

pub fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn tmpdir(tag: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{tag}-{}-{}",
        std::process::id(),
        uniq()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Short directory for Unix sockets (sun_path is 104 bytes on macOS).
pub fn sockdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("gpa{}-{}", std::process::id(), uniq()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------- log capture

static LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn sink(line: &str) {
    LOGS.lock().unwrap().push(line.to_owned());
}

pub fn capture_logs() {
    let _ = nodkey_payments_adapter::log::set_sink(sink);
}

pub fn logs() -> Vec<String> {
    LOGS.lock().unwrap().clone()
}

// ---------------------------------------------------------------- simpay

pub fn simpay_bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let manifest = repo().join("tools/simpay/Cargo.toml");
        let st = Command::new(env!("CARGO"))
            .args(["build", "--release", "--quiet", "--manifest-path"])
            .arg(&manifest)
            .status()
            .expect("cargo build simpay");
        assert!(st.success(), "building tools/simpay failed");
        repo().join("tools/simpay/target/release/simpay")
    })
}

pub struct Certs {
    pub dir: PathBuf,
}

impl Certs {
    pub fn ca(&self) -> PathBuf {
        self.dir.join("simpay-TEST-ONLY-ca.crt")
    }
    pub fn cert(&self) -> PathBuf {
        self.dir.join("simpay-TEST-ONLY-server.crt")
    }
    pub fn key(&self) -> PathBuf {
        self.dir.join("simpay-TEST-ONLY-server.key")
    }
    pub fn wrong_host(&self) -> (PathBuf, PathBuf) {
        (
            self.dir.join("simpay-TEST-ONLY-MALICIOUS-wrong-host.crt"),
            self.dir.join("simpay-TEST-ONLY-MALICIOUS-wrong-host.key"),
        )
    }
    pub fn expired(&self) -> (PathBuf, PathBuf) {
        (
            self.dir.join("simpay-TEST-ONLY-MALICIOUS-expired.crt"),
            self.dir.join("simpay-TEST-ONLY-MALICIOUS-expired.key"),
        )
    }
}

fn gen_ca(tag: &str) -> Certs {
    let dir = tmpdir(tag).join("certs");
    let st = Command::new(simpay_bin())
        .args(["gen-test-ca", "--out"])
        .arg(&dir)
        .args(["--dns-name", SERVER_NAME, "--malicious-certs"])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    Certs { dir }
}

/// The pinned test CA (with a server certificate for `simpay.test` and the malicious ones).
pub fn certs() -> &'static Certs {
    static C: OnceLock<Certs> = OnceLock::new();
    C.get_or_init(|| gen_ca("ca"))
}

/// A second, unrelated test CA (wrong-CA case).
pub fn foreign_certs() -> &'static Certs {
    static C: OnceLock<Certs> = OnceLock::new();
    C.get_or_init(|| gen_ca("foreign"))
}

pub enum Tls {
    Good,
    Plain,
    Files(PathBuf, PathBuf),
}

pub struct Simpay {
    child: Child,
    pub api: SocketAddr,
    pub admin: SocketAddr,
}

impl Drop for Simpay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn simpay_config(retention: u64) -> Value {
    json!({
        "api_listen": "127.0.0.1:0", "admin_listen": "127.0.0.1:0", "seed": "adapter-tests",
        "clock": {"mode": "system"}, "idempotency_retention_s": retention,
        "fixture": {
            "accounts": [{"id": ACCT, "keys": [
                {"secret": RK, "permissions": {"refunds": "write", "charges": "read"},
                 "allowed_cidrs": ["127.0.0.0/8"]},
                {"secret": "rk_sim_OTHERSOURCEONLY0001", "permissions": {"refunds": "write"},
                 "allowed_cidrs": ["10.0.0.0/8"]}]}],
            "charges": [
                {"id": CH_USD, "account": ACCT, "amount_minor": 5000, "currency": "usd"},
                {"id": CH_JPY, "account": ACCT, "amount_minor": 1000, "currency": "jpy"},
                {"id": CH_EUR_PENDING, "account": ACCT, "amount_minor": 12000, "currency": "eur",
                 "refund_initial_status": "pending"}
            ]
        }
    })
}

impl Simpay {
    pub fn start(tls: Tls) -> Simpay {
        let dir = tmpdir("simpay");
        let cfg = dir.join("config.json");
        std::fs::write(&cfg, simpay_config(86_400).to_string()).unwrap();
        let mut cmd = Command::new(simpay_bin());
        cmd.arg("--config").arg(&cfg);
        match tls {
            Tls::Good => {
                cmd.arg("--tls-cert").arg(certs().cert());
                cmd.arg("--tls-key").arg(certs().key());
            }
            Tls::Files(c, k) => {
                cmd.arg("--tls-cert").arg(c).arg("--tls-key").arg(k);
            }
            Tls::Plain => {}
        }
        let mut child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let (mut api, mut admin) = (None, None);
        while api.is_none() || admin.is_none() {
            let l = lines.next().expect("simpay exited early").unwrap();
            let addr = |l: &str| {
                let i = l.find("listening on ").unwrap() + "listening on ".len();
                l[i..].split_whitespace().next().unwrap().parse().unwrap()
            };
            if l.contains("api listening on") {
                api = Some(addr(&l));
            } else if l.contains("admin (fault control) listening on") {
                admin = Some(addr(&l));
            }
        }
        std::thread::spawn(move || for _ in lines {});
        Simpay {
            child,
            api: api.unwrap(),
            admin: admin.unwrap(),
        }
    }

    /// Plain-HTTP admin call (`Connection: close`).
    pub fn admin(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut s = TcpStream::connect(self.admin).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let b = body.map(|v| v.to_string()).unwrap_or_default();
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nHost: admin\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        )
        .unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        let text = String::from_utf8_lossy(&out).to_string();
        let status: u16 = text[9..12].parse().unwrap();
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        (status, serde_json::from_str(body).unwrap_or(Value::Null))
    }

    pub fn faults(&self, rules: Value) {
        let (s, v) = self.admin("PUT", "/admin/faults", Some(json!({"rules": rules})));
        assert_eq!(s, 200, "{v}");
    }

    pub fn malicious(&self, on: bool) {
        let (s, _) = self.admin("PUT", "/admin/malicious", Some(json!({"enabled": on})));
        assert_eq!(s, 200);
    }

    /// `(refund_count, refund_sum)` for a charge from `GET /admin/ledger`.
    pub fn ledger(&self, charge: &str) -> (u64, u64) {
        let (_, v) = self.admin("GET", "/admin/ledger", None);
        let ch = find_charge(&v, charge).unwrap_or(Value::Null);
        (
            ch["refund_count"].as_u64().unwrap_or(0),
            ch["refund_sum"].as_u64().unwrap_or(0),
        )
    }

    pub fn total_refunds(&self) -> u64 {
        let (_, v) = self.admin("GET", "/admin/ledger", None);
        let mut n = 0;
        walk(&v, &mut |o| {
            if let Some(c) = o.get("refund_count").and_then(Value::as_u64) {
                n += c;
            }
        });
        n
    }
}

fn walk(v: &Value, f: &mut dyn FnMut(&serde_json::Map<String, Value>)) {
    match v {
        Value::Object(o) => {
            f(o);
            for x in o.values() {
                walk(x, f);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| walk(x, f)),
        _ => {}
    }
}

fn find_charge(v: &Value, charge: &str) -> Option<Value> {
    let mut out = None;
    walk(v, &mut |o| {
        if out.is_none()
            && o.get("refund_count").is_some()
            && (o.get("charge").and_then(Value::as_str) == Some(charge)
                || o.get("id").and_then(Value::as_str) == Some(charge))
        {
            out = Some(Value::Object(o.clone()));
        }
    });
    if out.is_none()
        && let Some(o) = v.get("charges").and_then(|c| c.get(charge))
    {
        out = Some(o.clone());
    }
    out
}

// ---------------------------------------------------------------- grants

pub fn key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

fn key_entry(seed: [u8; 32], nb: u64, na: u64, status: &str) -> Value {
    let pk = key(seed).verifying_key().to_bytes();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    json!({"kid": hex(&derive_kid(&pk)), "alg": "Ed25519", "public_key": hex(&pk), "iss": ISS,
           "purpose": "grant", "not_before": nb, "not_after": na, "status": status})
}

/// Registry: the active key, a revoked key, and a key whose window ends 1000 s ago.
pub fn registry() -> Registry {
    let t = now();
    let doc = json!({"format": "nodkey.grant-keys.v1", "keys": [
        key_entry(SEED, 1_735_689_600, 4_102_444_800, "active"),
        key_entry(SEED_REVOKED, 1_735_689_600, 4_102_444_800, "revoked"),
        key_entry(SEED_SHORT, t - 100_000, t - 1000, "active"),
    ]});
    Registry::load(&doc.to_string()).expect("registry")
}

pub struct G {
    pub b: GrantBuilder,
    pub seed: [u8; 32],
}

pub fn jti() -> [u8; 16] {
    let n = uniq() as u64;
    let mut j = [0u8; 16];
    j[..8].copy_from_slice(&(std::process::id() as u64).to_be_bytes());
    j[8..].copy_from_slice(&n.to_be_bytes());
    j
}

/// A valid refund grant for `order_id` 4711 → `CH_USD`, 500 USD minor units, issued now.
pub fn refund_grant(amount: u64, currency: &str, charge: &str, iat: u64) -> GrantBuilder {
    GrantBuilder::write("payments.refund", 1)
        .issuer(ISS)
        .audience(BROKER)
        .jti(jti())
        .times(iat, iat, iat + 30)
        .workload(SHOP)
        .tenant("acme")
        .subject("user:u-17")
        .resource(0, ParamValue::Uint(4711))
        .exact(0, ParamValue::Uint(amount))
        .exact(1, ParamValue::Text(currency.into()))
        .exact(2, ParamValue::Text(charge.into()))
        .confirmed(true)
}

pub fn sign(b: &GrantBuilder, seed: [u8; 32]) -> String {
    encode_transport(&b.sign(&key(seed)).expect("sign"))
}

// ---------------------------------------------------------------- orders

#[derive(Default)]
pub struct FakeOrders {
    pub rows: Mutex<HashMap<u64, OrderRow>>,
    pub down: std::sync::atomic::AtomicBool,
}

impl FakeOrders {
    pub fn standard() -> Arc<FakeOrders> {
        let f = FakeOrders::default();
        for (id, ch, cur) in [
            (4711, CH_USD, "USD"),
            (4712, CH_JPY, "JPY"),
            (4713, CH_EUR_PENDING, "EUR"),
        ] {
            f.rows.lock().unwrap().insert(
                id,
                OrderRow {
                    order_id: id,
                    ten: "acme".into(),
                    owner_sub: "user:u-17".into(),
                    charge_id: ch.into(),
                    currency: cur.into(),
                },
            );
        }
        Arc::new(f)
    }
}

impl OrderView for FakeOrders {
    fn fetch(&self, id: u64) -> BoxFut<'_, Result<Option<OrderRow>, &'static str>> {
        let r = if self.down.load(Ordering::SeqCst) {
            Err("db_connect")
        } else {
            Ok(self.rows.lock().unwrap().get(&id).cloned())
        };
        Box::pin(async move { r })
    }
}

// ---------------------------------------------------------------- adapter on socket P

pub struct Opts {
    pub addr: SocketAddr,
    pub ca: PathBuf,
    pub caps: Vec<&'static str>,
    pub total_ms: u64,
    pub connect_ms: u64,
    pub r_max_s: u64,
    pub broker_uid: Option<u32>,
    pub tenants: Vec<&'static str>,
    pub orders: Arc<dyn OrderView>,
    pub max_concurrent: usize,
    pub key: &'static str,
    pub kidem: [u8; 32],
    pub idem_key_not_before: u64,
    /// §16.1 `support` member (absent when `None`).
    pub support: Option<Value>,
}

impl Opts {
    pub fn new(addr: SocketAddr) -> Opts {
        Opts {
            addr,
            ca: certs().ca(),
            caps: vec!["idem_status"],
            total_ms: 10_000,
            connect_ms: 2_000,
            r_max_s: 43_200,
            broker_uid: None,
            tenants: vec!["acme"],
            orders: FakeOrders::standard(),
            max_concurrent: 8,
            key: RK,
            kidem: KIDEM,
            idem_key_not_before: 1_704_067_200,
            support: None,
        }
    }
}

pub fn my_uid() -> u32 {
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    use std::os::unix::fs::MetadataExt;
    let _ = a;
    std::fs::metadata(std::env::temp_dir()).unwrap();
    let p = std::env::temp_dir().join(format!("gpa-uid-{}-{}", std::process::id(), uniq()));
    std::fs::write(&p, b"").unwrap();
    let u = std::fs::metadata(&p).unwrap().uid();
    let _ = std::fs::remove_file(&p);
    u
}

pub struct P {
    pub path: PathBuf,
    pub adapter: Arc<Adapter>,
}

pub fn adapter_config(o: &Opts, sock: &Path) -> Value {
    let mut v = adapter_config_base(o, sock);
    if let Some(s) = &o.support {
        v["support"] = s.clone();
    }
    v
}

fn adapter_config_base(o: &Opts, sock: &Path) -> Value {
    json!({"format": "nodkey.payments-adapter.v1", "socket_path": sock.display().to_string(),
        "broker_uid": o.broker_uid.unwrap_or_else(my_uid), "broker_id": BROKER, "wid": SHOP,
        "tenants": o.tenants, "R_max_s": o.r_max_s, "registry_path": "/etc/nodkey-adapter/keys.json",
        "db": {"socket_dir": "/run/pg-adapter", "db_uid": 70, "dbname": "ledger",
               "user": "nodkey_payments_adapter", "password_file": "/run/secrets/db"},
        "provider": {"profile": "simpay", "account": ACCT, "addr": o.addr.to_string(),
            "server_name": SERVER_NAME, "ca_file": "/etc/nodkey-adapter/ca.crt",
            "key_file": "/run/secrets/simpay", "idem_key_file": "/run/secrets/kidem",
            "idem_key_not_before": o.idem_key_not_before, "retention_s": 86400, "resend_margin_s": 7200, "caps": o.caps},
        "limits": {"connect_ms": o.connect_ms, "total_ms": o.total_ms, "max_head": 16384,
                   "max_body": 65536, "max_concurrent": o.max_concurrent}})
}

pub fn build_adapter(o: &Opts, sock: &Path) -> Adapter {
    try_build_adapter(o, sock).expect("build adapter")
}

pub fn try_build_adapter(o: &Opts, sock: &Path) -> Result<Adapter, String> {
    let cfg = parse_config(adapter_config(o, sock).to_string().as_bytes())?;
    let ca = nodkey_payments_adapter::config::parse_ca(&std::fs::read(&o.ca).unwrap()).unwrap();
    nodkey_payments_adapter::build(
        cfg,
        registry(),
        ca,
        ApiKey::new(zeroize::Zeroizing::new(o.key.to_string())),
        IdemKey::new(o.kidem),
        o.orders.clone(),
    )
}

pub async fn start_p(o: Opts) -> P {
    capture_logs();
    let dir = sockdir();
    let path = dir.join("adapter.sock");
    let adapter = Arc::new(build_adapter(&o, &path));
    let l = bind_socket(&path).unwrap();
    tokio::spawn(serve(l, adapter.clone()));
    P { path, adapter }
}

impl P {
    /// Fake broker client: one request per connection; `None` if the adapter closed without a
    /// response.
    pub async fn raw(&self, line: &[u8]) -> Option<Value> {
        let mut s = tokio::net::UnixStream::connect(&self.path).await.unwrap();
        let _ = s.write_all(line).await;
        let mut r = tokio::io::BufReader::new(s);
        let mut out = String::new();
        match tokio::time::timeout(Duration::from_secs(30), r.read_line(&mut out)).await {
            Ok(Ok(n)) if n > 0 => {
                // Strict: exactly one line, then EOF.
                let mut rest = Vec::new();
                let _ = r.read_to_end(&mut rest).await;
                assert!(rest.is_empty(), "more than one response line");
                Some(serde_json::from_str(&out).expect("response is JSON"))
            }
            _ => None,
        }
    }

    /// Sends one request. Like the broker, every call that carries a grant also carries the
    /// adapter's current `idem_kid` unless the test sets one itself.
    pub async fn call(&self, op: &str, mut args: Value) -> Value {
        if let Some(o) = args.as_object_mut()
            && o.contains_key("grant")
            && !o.contains_key("idem_kid")
        {
            o.insert("idem_kid".into(), json!(self.adapter.idem.kid()));
        }
        let id = format!("r{}", uniq());
        let line = json!({"v": 2, "id": id, "op": op, "args": args}).to_string() + "\n";
        let v = self.raw(line.as_bytes()).await.expect("response");
        assert_eq!(v["id"], json!(id), "response id must equal request id");
        assert_eq!(v["v"], json!(2));
        v
    }

    pub async fn create(&self, grant: &str) -> Value {
        self.call("refund.create", json!({"grant": grant})).await
    }
}

pub fn result_class(v: &Value) -> (&str, &str) {
    assert_eq!(v["ok"], json!(true), "{v}");
    (
        v["result"]["class"].as_str().unwrap(),
        v["result"]["cause"]
            .as_str()
            .or(v["result"]["code"].as_str())
            .unwrap_or(""),
    )
}

pub fn err_code(v: &Value) -> &str {
    assert_eq!(v["ok"], json!(false), "{v}");
    v["error"]["code"].as_str().unwrap()
}

// ---------------------------------------------------------------- scriptable TLS server

/// What the fake server does after the handshake. `{charge}`, `{amount}`, `{reference}` in the
/// script are replaced from the request (so echoes can be made exact), then `{BODYLEN}`.
#[derive(Clone)]
pub enum Script {
    /// Write these chunks (with substitutions), sleeping `ms` between them, then close.
    Respond(Vec<(String, u64)>),
    /// Accept TCP but never answer the TLS handshake.
    StallHandshake,
    /// Write this text, then never write again; count the connection in `closed` once the
    /// client closes it (EOF or error on read).
    StallUntilClosed(String),
}

pub struct FakeServer {
    pub addr: SocketAddr,
    pub tcp_accepts: Arc<AtomicUsize>,
    pub requests: Arc<AtomicUsize>,
    /// Connections the client closed (only for [`Script::StallUntilClosed`]).
    pub closed: Arc<AtomicUsize>,
}

pub fn tls_server_config(v12_only: bool) -> rustls::ServerConfig {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_file_iter(certs().cert())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(certs_key()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = if v12_only {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap()
}

fn certs_key() -> PathBuf {
    certs().key()
}

/// Substitutes request values, then `{BODYLEN}` with the length of the text after the blank
/// line that ends its head.
fn subst(s: &str, req: &HashMap<String, String>) -> String {
    let mut s = s.to_string();
    for k in ["charge", "amount", "reference"] {
        s = s.replace(
            &format!("{{{k}}}"),
            req.get(k).map(String::as_str).unwrap_or(""),
        );
    }
    // The body is what follows the blank line after the `{BODYLEN}` header.
    let Some(at) = s.find("{BODYLEN}") else {
        return s;
    };
    let body_len = s[at..]
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.len())
        .unwrap_or(0);
    s.replace("{BODYLEN}", &body_len.to_string())
}

async fn read_request<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
) -> Option<HashMap<String, String>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
    let cl: usize = head
        .lines()
        .find_map(|l| {
            l.strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap_or(0))
        })
        .unwrap_or(0);
    while buf.len() < head_end + cl {
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = &buf[head_end..];
    Some(
        form_urlencoded::parse(body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
    )
}

impl FakeServer {
    pub async fn start(script: Script, v12_only: bool) -> FakeServer {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server_config(v12_only)));
        let tcp_accepts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let (ta, rq, cl) = (tcp_accepts.clone(), requests.clone(), closed.clone());
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = l.accept().await else {
                    return;
                };
                ta.fetch_add(1, Ordering::SeqCst);
                let (acceptor, script, rq, cl) =
                    (acceptor.clone(), script.clone(), rq.clone(), cl.clone());
                tokio::spawn(async move {
                    match script {
                        Script::StallHandshake => {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            drop(tcp);
                        }
                        Script::Respond(chunks) => {
                            let Ok(mut tls) = acceptor.accept(tcp).await else {
                                return;
                            };
                            let Some(req) = read_request(&mut tls).await else {
                                return;
                            };
                            rq.fetch_add(1, Ordering::SeqCst);
                            for (c, ms) in chunks {
                                let text = subst(&c, &req);
                                if tls.write_all(text.as_bytes()).await.is_err() {
                                    return;
                                }
                                let _ = tls.flush().await;
                                if ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(ms)).await;
                                }
                            }
                            let _ = tls.shutdown().await;
                        }
                        Script::StallUntilClosed(text) => {
                            let Ok(mut tls) = acceptor.accept(tcp).await else {
                                return;
                            };
                            let Some(req) = read_request(&mut tls).await else {
                                return;
                            };
                            rq.fetch_add(1, Ordering::SeqCst);
                            let _ = tls.write_all(subst(&text, &req).as_bytes()).await;
                            let _ = tls.flush().await;
                            let mut tmp = [0u8; 256];
                            loop {
                                match tls.read(&mut tmp).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(_) => {}
                                }
                            }
                            cl.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
            }
        });
        FakeServer {
            addr,
            tcp_accepts,
            requests,
            closed,
        }
    }
}

/// A valid refund body echoing the request.
pub const ECHO_BODY: &str = r#"{"id":"re_FAKE00000001","object":"refund","amount":{amount},"charge":"{charge}","currency":"usd","status":"succeeded","reference":"{reference}"}"#;

/// `HTTP/1.1 200` with a JSON body; `extra` are additional header lines (each ending in CRLF).
pub fn ok_response(extra: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{extra}Content-Length: {{BODYLEN}}\r\nConnection: close\r\n\r\n{body}"
    )
}
