//! Test harness: a fake upstream app, fake broker (socket G) and fake authority (socket I), a raw
//! HTTP/1.1-over-TLS client, and a gateway started on 127.0.0.1:0 in the production `files` TLS mode
//! with a test certificate (generated once per test process).
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use nodkey_gateway::config::{
    self, Config, Limits, ReadRoute, SessionConfig, TlsConfig, Upstream,
};
use nodkey_gateway::util::{b64url, hex_lower, now_secs, random_bytes};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener};

pub const APP: &str = "app.localhost";
pub const AUTH: &str = "auth.localhost";
pub const APP_ORIGIN: &str = "https://app.localhost";
pub const AUTH_ORIGIN: &str = "https://auth.localhost";

pub struct TestCert {
    pub cert_pem: PathBuf,
    pub key_pem: PathBuf,
    pub client: Arc<rustls::ClientConfig>,
}

/// One self-signed certificate for both test host names, shared by every harness in the process.
pub fn test_cert() -> &'static TestCert {
    static CERT: std::sync::OnceLock<TestCert> = std::sync::OnceLock::new();
    CERT.get_or_init(|| {
        let ck = rcgen::generate_simple_self_signed(vec![APP.to_owned(), AUTH.to_owned()]).unwrap();
        let dir = tmpdir();
        let cert_pem = dir.join("cert.pem");
        let key_pem = dir.join("key.pem");
        std::fs::write(&cert_pem, ck.cert.pem()).unwrap();
        std::fs::write(&key_pem, ck.signing_key.serialize_pem()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ck.cert.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TestCert {
            cert_pem,
            key_pem,
            client: Arc::new(client),
        }
    })
}

/// The uid that owns files this process creates (the fake broker and authority run as it).
pub fn my_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(&test_cert().cert_pem).unwrap().uid()
}

/// TLS connection to the gateway with SNI `sni`.
pub async fn tls_connect(
    addr: SocketAddr,
    sni: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    tokio_rustls::TlsConnector::from(test_cert().client.clone())
        .connect(
            rustls::pki_types::ServerName::try_from(sni.to_owned()).unwrap(),
            tcp,
        )
        .await
        .unwrap()
}

/// SNI for a request head: the auth host if its first `Host` line names it, else the app host.
fn sni_for(head: &str) -> &'static str {
    let host = head
        .lines()
        .find_map(|l| l.strip_prefix("Host: "))
        .unwrap_or("");
    if host.starts_with(AUTH) { AUTH } else { APP }
}
/// Size of the fake upstream's `/big` response.
pub const BIG: usize = 4 << 20;
pub const WID: &str = "spiffe://nodkey.test/workload/shop";

/// What the fake upstream saw.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub op: String,
    pub args: Value,
}

#[derive(Debug, Clone)]
pub struct Rec {
    pub record: Value,
    pub state: String,
    pub digest: String,
    pub display_name: String,
    pub approver_source: String,
    /// If set, the broker reports this digest instead of the true one (tamper test).
    pub lie_digest: Option<String>,
}

#[derive(Debug, Default)]
pub struct World {
    pub upstream: Vec<Seen>,
    pub broker_calls: Vec<Call>,
    pub authority_calls: Vec<Call>,
    pub records: HashMap<String, Rec>,
    /// `mandate.list` answer per subject `"ten/sub"` (effect-protocol-v2 §12.3).
    pub mandates: HashMap<String, Vec<Value>>,
    /// While true, the fake broker closes `mandate.revoke` connections without answering.
    pub broker_revoke_down: bool,
    /// `"G:<op>"` / `"I:<op>"` in arrival order (revoke ordering, §12.6).
    pub order: Vec<String>,
}

pub type Shared = Arc<Mutex<World>>;

pub struct Harness {
    pub addr: SocketAddr,
    pub world: Shared,
    pub dir: PathBuf,
    pub gw: nodkey_gateway::server::Running,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.gw.task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("glgw-{}", hex_lower(&random_bytes::<6>().unwrap())));
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn new_pid() -> String {
    b64url(&random_bytes::<16>().unwrap())
}

/// A `payments.refund` record proposed by the shop for (`acme`, `sub`).
pub fn refund_record(pid: &str, sub: &str, amount: u64) -> Value {
    let now = now_secs();
    json!({
        "pending_id": pid, "broker_id": "nodkey.broker.payments-test", "wid": WID, "ten": "acme",
        "approver_sub": sub, "op": "payments.refund", "opv": 1,
        "params": {"order_id": 9821, "amount_minor": amount, "currency": "EUR"},
        "param_types": {"order_id": "uint", "amount_minor": "uint", "currency": "currency"},
        "created_at": now, "expires_at": now + 600,
        "display": {"amount_exponent": 2, "currency": "EUR"}
    })
}

pub fn digest_of(record: &Value) -> String {
    let r: nodkey_gateway::digest::PendingRecord =
        serde_json::from_value(record.clone()).unwrap();
    hex_lower(&nodkey_gateway::digest::check(r).unwrap().digest)
}

pub fn add_record(world: &Shared, record: Value, state: &str) -> String {
    let pid = record["pending_id"].as_str().unwrap().to_owned();
    let digest = digest_of(&record);
    world.lock().unwrap().records.insert(
        pid.clone(),
        Rec {
            record,
            state: state.to_owned(),
            digest: digest.clone(),
            display_name: "Demo Shop".into(),
            approver_source: "named".into(),
            lie_digest: None,
        },
    );
    digest
}

async fn fake_upstream(world: Shared) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let world = world.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let world = world.clone();
                        async move {
                            let method = req.method().to_string();
                            let target = req.uri().to_string();
                            let headers: Vec<(String, String)> = req
                                .headers()
                                .iter()
                                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("?").to_owned()))
                                .collect();
                            let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
                            world.lock().unwrap().upstream.push(Seen {
                                method,
                                target: target.clone(),
                                headers,
                                body,
                            });
                            let mut r =
                                hyper::Response::new(Full::new(Bytes::from("hello from app")));
                            let h = r.headers_mut();
                            h.insert("content-type", "text/html".parse().unwrap());
                            if target.starts_with("/dupct") {
                                h.append("content-type", "text/plain".parse().unwrap());
                            }
                            if target.starts_with("/big") {
                                *r.body_mut() = Full::new(Bytes::from(vec![b'x'; BIG]));
                            }
                            let h = r.headers_mut();
                            if target.starts_with("/headers") {
                                for (k, v) in [
                                    ("set-cookie", "PHPSESSID=abc; Path=/; HttpOnly"),
                                    (
                                        "set-cookie",
                                        "__Host-nodkey_session=evil; Path=/; Secure; HttpOnly",
                                    ),
                                    (
                                        "set-cookie",
                                        "__HOST-NODKEY_SESSION=evil2; Path=/; Secure",
                                    ),
                                    ("set-cookie", "PHPSESSID=tossed; Domain=localhost; Path=/"),
                                    ("set-cookie", "tracking=1; Path=/"),
                                    ("service-worker-allowed", "/"),
                                    ("access-control-allow-origin", "*"),
                                    ("access-control-allow-credentials", "true"),
                                    ("cache-control", "public, max-age=3600"),
                                    ("expires", "Thu, 01 Dec 2094 16:00:00 GMT"),
                                    ("x-custom", "1"),
                                    ("nodkey-grant", "forged"),
                                    ("content-security-policy", "default-src 'self'"),
                                    ("location", "/next"),
                                    ("clear-site-data", "\"cookies\""),
                                ] {
                                    h.append(k, v.parse().unwrap());
                                }
                            }
                            Ok::<_, std::convert::Infallible>(r)
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    addr
}

async fn serve_lines(l: UnixListener, world: Shared, f: fn(&Shared, &str, &Value) -> Value) {
    loop {
        let Ok((s, _)) = l.accept().await else { return };
        let world = world.clone();
        tokio::spawn(async move {
            let (r, mut w) = s.into_split();
            let mut r = BufReader::new(r);
            let mut line = String::new();
            if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let req: Value = serde_json::from_str(line.trim_end()).unwrap();
            let op = req["op"].as_str().unwrap().to_owned();
            let out = f(&world, &op, &req["args"]);
            if out.get("__drop").is_some() {
                return; // close without a response (peer down / lost answer)
            }
            let mut env = json!({"v": 2, "id": req["id"], "correlation_id": "c-1"});
            match out.get("__error") {
                Some(code) => {
                    env["ok"] = json!(false);
                    env["error"] = json!({"code": code, "message": "static"});
                }
                None => {
                    env["ok"] = json!(true);
                    env["result"] = out;
                }
            }
            let mut bytes = serde_json::to_vec(&env).unwrap();
            bytes.push(b'\n');
            let _ = w.write_all(&bytes).await;
        });
    }
}

fn broker(world: &Shared, op: &str, args: &Value) -> Value {
    let mut w = world.lock().unwrap();
    w.broker_calls.push(Call {
        op: op.into(),
        args: args.clone(),
    });
    let na = json!({"__error": "not_available"});
    let subject = format!(
        "{}/{}",
        args["subject"]["ten"].as_str().unwrap_or(""),
        args["subject"]["sub"].as_str().unwrap_or("")
    );
    match op {
        "pending.list" => {
            let pending: Vec<Value> = w
                .records
                .values()
                .filter(|r| {
                    r.state == "PENDING"
                        && format!("{}/{}", r.record["ten"].as_str().unwrap(), r.record["approver_sub"].as_str().unwrap()) == subject
                })
                .map(|r| json!({"pending_id": r.record["pending_id"], "op": r.record["op"],
                                "created_at": r.record["created_at"], "expires_at": r.record["expires_at"]}))
                .collect();
            return json!({"pending": pending});
        }
        "mandate.list" => {
            return json!({"mandates": w.mandates.get(&subject).cloned().unwrap_or_default()});
        }
        "mandate.revoke" => {
            if w.broker_revoke_down {
                return json!({"__drop": true});
            }
            w.order.push("G:mandate.revoke".into());
            let mid = args["mid"].clone();
            let Some(list) = w.mandates.get_mut(&subject) else {
                return na;
            };
            let Some(m) = list.iter_mut().find(|m| m["mid"] == mid) else {
                return na;
            };
            m["state"] = json!("revoked");
            return json!({});
        }
        _ => {}
    }
    let pid = args["pending_id"].as_str().unwrap_or("");
    let Some(rec) = w.records.get_mut(pid) else {
        return na;
    };
    let subj_ok = args["subject"]["ten"] == rec.record["ten"]
        && args["subject"]["sub"] == rec.record["approver_sub"];
    if !subj_ok {
        return na;
    }
    match op {
        "pending.render" => json!({
            "record": rec.record, "digest": rec.lie_digest.clone().unwrap_or(rec.digest.clone()),
            "state": rec.state,
            "facts": [{"label": "Captured amount", "value": "100.00 EUR"},
                      {"label": "Order owner", "value": "you"}],
            "context": {"pending_from_workload_for_subject": 1, "recent_identical": [],
                        "other_open_on_resource": [], "workload_display_name": rec.display_name,
                        "approver_source": rec.approver_source}
        }),
        "pending.deny" => {
            if args["digest"] == json!(rec.digest) && rec.state == "PENDING" {
                rec.state = "DENIED".into();
                json!({})
            } else {
                na
            }
        }
        _ => json!({"__error": "unknown_operation"}),
    }
}

pub const FAKE_GRANT: &str = "0oRDoQEmoQRCAAFYAA";

fn authority(world: &Shared, op: &str, args: &Value) -> Value {
    let mut w = world.lock().unwrap();
    w.authority_calls.push(Call {
        op: op.into(),
        args: args.clone(),
    });
    match op {
        "approve" => {
            let pid = args["pending_id"].as_str().unwrap_or("");
            match w.records.get_mut(pid) {
                Some(r)
                    if r.state == "PENDING"
                        && args["digest_shown"] == json!(r.digest)
                        && args["subject"]["sub"] == r.record["approver_sub"] =>
                {
                    r.state = "APPROVED".into();
                    json!({})
                }
                _ => json!({"__error": "not_available"}),
            }
        }
        "read_grant" => json!({"grant": FAKE_GRANT}),
        "mandate.revoke" => {
            w.order.push("I:mandate.revoke".into());
            json!({})
        }
        _ => json!({"__error": "unknown_operation"}),
    }
}

pub fn base_config(dir: &std::path::Path, upstream: SocketAddr) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: TlsConfig::Files {
            cert_pem: test_cert().cert_pem.clone(),
            key_pem: test_cert().key_pem.clone(),
        },
        app_origin: APP_ORIGIN.into(),
        auth_origin: AUTH_ORIGIN.into(),
        upstream: Upstream::Tcp(upstream),
        app_wid: WID.into(),
        read_routes: vec![ReadRoute {
            path: "/orders/".into(),
            rop: vec!["payments.get_order".into()],
        }],
        app_cookies: vec!["PHPSESSID".into()],
        broker_socket: dir.join("g.sock"),
        authority_socket: dir.join("i.sock"),
        expected_broker_uid: my_uid(),
        expected_authority_uid: my_uid(),
        dev_local_only: false,
        trusted_proxies: vec![],
        session: SessionConfig::default(),
        limits: Limits::default(),
        test_login: None,
    }
}

pub async fn start_with(mutate: impl FnOnce(&mut Config)) -> Harness {
    let world: Shared = Arc::new(Mutex::new(World::default()));
    let dir = tmpdir();
    let up = fake_upstream(world.clone()).await;
    let gl = UnixListener::bind(dir.join("g.sock")).unwrap();
    let il = UnixListener::bind(dir.join("i.sock")).unwrap();
    tokio::spawn(serve_lines(gl, world.clone(), broker));
    tokio::spawn(serve_lines(il, world.clone(), authority));
    let mut cfg = base_config(&dir, up);
    mutate(&mut cfg);
    let checked = config::check(cfg).expect("config");
    let gw = nodkey_gateway::server::start(checked)
        .await
        .expect("start");
    Harness {
        addr: gw.addr,
        world,
        dir,
        gw,
    }
}

pub async fn start() -> Harness {
    start_with(|_| {}).await
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub raw: Vec<u8>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    /// The `name=value` of the first `Set-Cookie` for `name`.
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.header("set-cookie")
            .into_iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .map(|c| c.split(';').next().unwrap()[name.len() + 1..].to_owned())
    }
    /// Response without the `Date` header, for byte-identity comparisons.
    pub fn without_date(&self) -> (u16, Vec<(String, String)>, Vec<u8>) {
        (
            self.status,
            self.headers
                .iter()
                .filter(|(k, _)| !k.eq_ignore_ascii_case("date"))
                .cloned()
                .collect(),
            self.body.clone(),
        )
    }
}

/// Sends `head` (request line + headers, CRLF-separated, without the final blank line) and `body`.
pub async fn raw(addr: SocketAddr, head: &str, body: &[u8]) -> Resp {
    let mut s = tls_connect(addr, sni_for(head)).await;
    let mut req = head.replace('\n', "\r\n");
    if !body.is_empty() {
        req.push_str(&format!("\r\nContent-Length: {}", body.len()));
    }
    req.push_str("\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    // The gateway may answer (e.g. 413) and close before reading the whole body.
    let _ = s.write_all(body).await;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    parse(&out)
}

pub fn parse(out: &[u8]) -> Resp {
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let head = std::str::from_utf8(&out[..split]).unwrap();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.trim().to_ascii_lowercase(), v.trim().to_owned())
        })
        .collect();
    Resp {
        status,
        headers,
        body: out[split + 4..].to_vec(),
        raw: out.to_vec(),
    }
}

pub async fn get(addr: SocketAddr, host: &str, path: &str, extra: &[&str]) -> Resp {
    let mut head = format!("GET {path} HTTP/1.1\nHost: {host}");
    for e in extra {
        head.push('\n');
        head.push_str(e);
    }
    raw(addr, &head, b"").await
}

pub async fn post_form(
    addr: SocketAddr,
    host: &str,
    path: &str,
    extra: &[&str],
    body: &str,
) -> Resp {
    let mut head = format!(
        "POST {path} HTTP/1.1\nHost: {host}\nContent-Type: application/x-www-form-urlencoded"
    );
    for e in extra {
        head.push('\n');
        head.push_str(e);
    }
    raw(addr, &head, body.as_bytes()).await
}

/// Extracts `name="<field>" value="<v>"` from a rendered page.
pub fn form_value(html: &str, field: &str) -> Option<String> {
    let pat = format!("name=\"{field}\" value=\"");
    let i = html.find(&pat)? + pat.len();
    let j = html[i..].find('"')?;
    Some(html[i..i + j].to_owned())
}

pub const NAV_SAME_ORIGIN: [&str; 3] = [
    "Sec-Fetch-Site: same-origin",
    "Sec-Fetch-Mode: navigate",
    "Sec-Fetch-Dest: document",
];

/// Logs in on the auth origin as test user `idx` (feature `test-login`); returns the session id.
pub async fn login(addr: SocketAddr, idx: usize) -> String {
    let page = get(addr, AUTH, "/login", &[]).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let pre = page
        .cookie("__Host-nodkey_preauth")
        .expect("preauth cookie");
    let csrf = form_value(&page.text(), "csrf").expect("csrf");
    let cookie = format!("Cookie: __Host-nodkey_preauth={pre}");
    let mut extra = NAV_SAME_ORIGIN.to_vec();
    extra.push(&cookie);
    let r = post_form(
        addr,
        AUTH,
        "/login",
        &extra,
        &format!("user={idx}&csrf={csrf}"),
    )
    .await;
    assert_eq!(r.status, 303, "{}", r.text());
    r.cookie("__Host-nodkey_session").expect("session cookie")
}
