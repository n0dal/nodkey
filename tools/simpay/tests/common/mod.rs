// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers: in-process server on ephemeral ports, a raw HTTP client that can
//! observe dropped connections and malformed responses, and a webhook receiver.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use simpay::{Config, Server, StartOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const SK: &str = "sk_sim_0123456789abcdef";
pub const SK_OTHER: &str = "sk_sim_otheraccount00001";
/// refunds: write, charges: read
pub const RK_WRITE: &str = "rk_sim_refundswrite00001";
/// refunds: read
pub const RK_READ: &str = "rk_sim_refundsread000001";
/// charges: read only
pub const RK_CHARGES: &str = "rk_sim_chargesonly000001";
/// unrestricted but only from 10.0.0.0/8
pub const RK_CIDR_BAD: &str = "rk_sim_cidrten0000000001";
/// refunds: write, only from 127.0.0.0/8
pub const RK_CIDR_OK: &str = "rk_sim_cidrloop000000001";

pub const CH_USD: &str = "ch_usd00000001";
pub const CH_JPY: &str = "ch_jpy00000001";
pub const CH_PENDING: &str = "ch_pendingrefund01";
pub const CH_UNPAID: &str = "ch_unpaid0000001";
pub const CH_OTHER: &str = "ch_other00000001";
pub const ACCT: &str = "acct_demo0001";
pub const WHSEC: &str = "whsec_sim_0123456789abcdef";

pub fn base_json() -> Value {
    json!({
        "api_listen": "127.0.0.1:0",
        "admin_listen": "127.0.0.1:0",
        "seed": "test-seed",
        "clock": {"mode": "manual", "start": 1_761_350_400u64},
        "webhook_delivery": {"max_attempts": 3, "retry_base_ms": 20, "timeout_ms": 1000},
        "fixture": {
            "accounts": [
                {"id": ACCT, "keys": [
                    {"secret": SK},
                    {"secret": RK_WRITE, "permissions": {"refunds": "write", "charges": "read"}},
                    {"secret": RK_READ, "permissions": {"refunds": "read"}},
                    {"secret": RK_CHARGES, "permissions": {"charges": "read", "refunds": "none"}},
                    {"secret": RK_CIDR_BAD, "permissions": {"refunds": "write", "charges": "write"},
                     "allowed_cidrs": ["10.0.0.0/8"]},
                    {"secret": RK_CIDR_OK, "permissions": {"refunds": "write"},
                     "allowed_cidrs": ["10.0.0.0/8", "127.0.0.0/8"]}
                ]},
                {"id": "acct_other0001", "keys": [{"secret": SK_OTHER}]}
            ],
            "charges": [
                {"id": CH_USD, "account": ACCT, "amount_minor": 5000, "currency": "usd"},
                {"id": CH_JPY, "account": ACCT, "amount_minor": 1000, "currency": "jpy"},
                {"id": CH_PENDING, "account": ACCT, "amount_minor": 3000, "currency": "eur",
                 "refund_initial_status": "pending"},
                {"id": CH_UNPAID, "account": ACCT, "amount_minor": 3000, "currency": "usd",
                 "status": "pending"},
                {"id": CH_OTHER, "account": "acct_other0001", "amount_minor": 7000, "currency": "usd"}
            ]
        }
    })
}

/// Deep-merges `extra` into `base`.
pub fn merge(base: &mut Value, extra: Value) {
    match (base, extra) {
        (Value::Object(b), Value::Object(e)) => {
            for (k, v) in e {
                merge(b.entry(k).or_insert(Value::Null), v);
            }
        }
        (b, e) => *b = e,
    }
}

pub fn config(extra: Value) -> Config {
    let mut v = base_json();
    merge(&mut v, extra);
    Config::from_json(&v.to_string()).expect("config")
}

pub async fn start(extra: Value) -> Server {
    simpay::start(config(extra), StartOptions::default())
        .await
        .expect("start")
}

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
    pub raw: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&self.body)))
    }
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
    }
    pub fn headers_named(&self, name: &str) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .collect()
    }
    pub fn err_code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClientError {
    /// The server closed the connection without sending a single byte.
    Closed,
    Timeout,
    Io(String),
}

/// Sends raw bytes and reads until EOF.
pub async fn raw(addr: SocketAddr, bytes: &[u8], limit: Duration) -> Result<Vec<u8>, ClientError> {
    let fut = async {
        let mut s = TcpStream::connect(addr)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        s.write_all(bytes)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        let mut out = Vec::new();
        match s.read_to_end(&mut out).await {
            Ok(_) => {}
            Err(e) if out.is_empty() => return Err(ClientError::Io(e.to_string())),
            Err(_) => {}
        }
        if out.is_empty() {
            return Err(ClientError::Closed);
        }
        Ok(out)
    };
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err(ClientError::Timeout),
    }
}

/// Tolerant parser: splits on the first blank line and on CRLF; never rejects.
pub fn parse(raw: Vec<u8>) -> Resp {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header terminator");
    let head = &raw[..split];
    let body = raw[split + 4..].to_vec();
    let mut lines = head.split(|b| *b == b'\n');
    let status_line = String::from_utf8_lossy(lines.next().unwrap()).into_owned();
    // For requests (webhook receiver) the second token is the path; status is then 0.
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|t| t.parse().ok())
        .unwrap_or(0);
    let mut headers = vec![];
    for l in lines {
        let l = l.strip_suffix(b"\r").unwrap_or(l);
        if let Some(i) = l.iter().position(|b| *b == b':') {
            let name = String::from_utf8_lossy(&l[..i]).into_owned();
            let mut v = &l[i + 1..];
            while v.first() == Some(&b' ') {
                v = &v[1..];
            }
            headers.push((name, v.to_vec()));
        }
    }
    Resp {
        status,
        headers,
        body,
        raw,
    }
}

pub async fn request_t(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    limit: Duration,
) -> Result<Resp, ClientError> {
    let mut r = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
    for (n, v) in headers {
        r.push_str(&format!("{n}: {v}\r\n"));
    }
    if !body.is_empty() || method == "POST" || method == "PUT" {
        r.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    r.push_str("\r\n");
    let mut bytes = r.into_bytes();
    bytes.extend_from_slice(body);
    raw(addr, &bytes, limit).await.map(parse)
}

pub async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Resp, ClientError> {
    request_t(addr, method, path, headers, body, Duration::from_secs(10)).await
}

pub async fn refund_t(
    server: &Server,
    key: &str,
    idem: &str,
    params: &str,
    limit: Duration,
) -> Result<Resp, ClientError> {
    let auth = format!("Bearer {key}");
    request_t(
        server.api_addr,
        "POST",
        "/v1/refunds",
        &[
            ("Authorization", &auth),
            ("Idempotency-Key", idem),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        params.as_bytes(),
        limit,
    )
    .await
}

pub async fn refund(server: &Server, key: &str, idem: &str, params: &str) -> Resp {
    refund_t(server, key, idem, params, Duration::from_secs(10))
        .await
        .expect("refund request")
}

pub async fn get(server: &Server, key: &str, path: &str) -> Resp {
    let auth = format!("Bearer {key}");
    request(
        server.api_addr,
        "GET",
        path,
        &[("Authorization", &auth)],
        b"",
    )
    .await
    .expect("get")
}

pub async fn admin(server: &Server, method: &str, path: &str, body: Value) -> Resp {
    let b = if body.is_null() {
        vec![]
    } else {
        body.to_string().into_bytes()
    };
    request(server.admin_addr, method, path, &[], &b)
        .await
        .expect("admin")
}

pub async fn faults(server: &Server, rules: Value) {
    let r = admin(server, "PUT", "/admin/faults", json!({ "rules": rules })).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

pub async fn malicious(server: &Server, on: bool) {
    let r = admin(server, "PUT", "/admin/malicious", json!({ "enabled": on })).await;
    assert_eq!(r.status, 200);
}

pub async fn advance(server: &Server, seconds: u64) {
    let r = admin(
        server,
        "POST",
        "/admin/clock/advance",
        json!({ "seconds": seconds }),
    )
    .await;
    assert_eq!(r.status, 200);
}

/// (refund_count, refund_sum, amount_refunded) for a charge, from the admin ledger.
pub async fn ledger(server: &Server, charge: &str) -> (u64, u64, u64) {
    let l = admin(server, "GET", "/admin/ledger", Value::Null)
        .await
        .json();
    let c = l["charges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == charge)
        .unwrap()
        .clone();
    (
        c["refund_count"].as_u64().unwrap(),
        c["refund_sum"].as_u64().unwrap(),
        c["amount_refunded"].as_u64().unwrap(),
    )
}

pub async fn wait_until<F: FnMut() -> bool>(mut f: F, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f()
}

#[derive(Debug, Clone)]
pub struct Received {
    pub signature: String,
    pub event_id_header: String,
    pub body: Vec<u8>,
}

impl Received {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

pub struct Hook {
    pub addr: SocketAddr,
    pub got: Arc<Mutex<Vec<Received>>>,
}

impl Hook {
    pub fn url(&self) -> String {
        format!("http://{}/hook", self.addr)
    }
    pub fn count(&self) -> usize {
        self.got.lock().unwrap().len()
    }
    pub fn all(&self) -> Vec<Received> {
        self.got.lock().unwrap().clone()
    }
}

/// Webhook receiver answering 500 to the first `fail_first` requests, then 200.
pub async fn hook_server(fail_first: usize) -> Hook {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::new(AtomicUsize::new(0));
    let g = got.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let g = g.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head_end, len) = loop {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (p + 4, len);
                    }
                };
                while buf.len() < head_end + len {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let resp = parse(buf.clone());
                let n = seen.fetch_add(1, Ordering::SeqCst);
                if n >= fail_first {
                    g.lock().unwrap().push(Received {
                        signature: resp.header("simpay-signature").unwrap_or_default(),
                        event_id_header: resp.header("simpay-event-id").unwrap_or_default(),
                        body: buf[head_end..].to_vec(),
                    });
                }
                let status = if n < fail_first {
                    "500 Internal Server Error"
                } else {
                    "200 OK"
                };
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    Hook { addr, got }
}

/// Receiver-side verification, written independently of the simulator's signer:
/// parses `t=…,v1=…`, recomputes HMAC-SHA256 over `t.body`, compares in constant time,
/// and enforces `|now - t| <= tolerance` (tolerance must be non-zero).
pub fn verify(
    secret: &str,
    header: &str,
    body: &[u8],
    now: u64,
    tolerance: u64,
) -> Result<u64, &'static str> {
    assert!(tolerance > 0);
    let mut t = None;
    let mut sigs = vec![];
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", v)) => t = v.parse::<u64>().ok(),
            Some(("v1", v)) => sigs.push(v.to_string()),
            _ => {}
        }
    }
    let t = t.ok_or("no timestamp")?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{t}.").as_bytes());
    mac.update(body);
    let ok = sigs.iter().any(|s| {
        let bytes: Option<Vec<u8>> = (0..s.len())
            .step_by(2)
            .map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
            .collect();
        bytes.is_some_and(|b| mac.clone().verify_slice(&b).is_ok())
    });
    if !ok {
        return Err("bad signature");
    }
    if now.abs_diff(t) > tolerance {
        return Err("stale timestamp");
    }
    Ok(t)
}

pub async fn set_endpoint(server: &Server, url: &str) {
    let r = admin(
        server,
        "PUT",
        &format!("/admin/accounts/{ACCT}/webhook_endpoints"),
        json!({"endpoints": [{"url": url, "secret": WHSEC}]}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

pub async fn now(server: &Server) -> u64 {
    admin(server, "GET", "/admin/clock", Value::Null)
        .await
        .json()["now"]
        .as_u64()
        .unwrap()
}

// ---------------------------------------------------------------- TLS client helpers

use rustls_pki_types::ServerName;
use rustls_pki_types::pem::PemObject;
use std::path::Path;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct TlsClient {
    pub connector: TlsConnector,
    pub name: ServerName<'static>,
}

/// A client that trusts only `ca_pem` and verifies `name`, with the given protocol versions.
pub fn tls_client_versions(
    ca_pem: &Path,
    name: &str,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> TlsClient {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pki_types::CertificateDer::pem_file_iter(ca_pem).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsClient {
        connector: TlsConnector::from(Arc::new(cfg)),
        name: ServerName::try_from(name.to_string()).unwrap(),
    }
}

pub fn tls_client(ca_pem: &Path, name: &str) -> TlsClient {
    tls_client_versions(ca_pem, name, &[&rustls::version::TLS13])
}

/// Like [`raw`], over TLS. A handshake failure is `Io("tls: …")`. An EOF without
/// `close_notify` before any byte arrived is `Closed`.
pub async fn raw_tls(
    addr: SocketAddr,
    tls: &TlsClient,
    bytes: &[u8],
    limit: Duration,
) -> Result<Vec<u8>, ClientError> {
    let fut = async {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        let mut s = tls
            .connector
            .connect(tls.name.clone(), tcp)
            .await
            .map_err(|e| ClientError::Io(format!("tls: {e}")))?;
        s.write_all(bytes)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        let mut out = Vec::new();
        match s.read_to_end(&mut out).await {
            Ok(_) => {}
            Err(e) if out.is_empty() && e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(ClientError::Closed);
            }
            Err(e) if out.is_empty() => return Err(ClientError::Io(e.to_string())),
            Err(_) => {}
        }
        if out.is_empty() {
            return Err(ClientError::Closed);
        }
        Ok(out)
    };
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err(ClientError::Timeout),
    }
}

pub fn build_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut r = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
    for (n, v) in headers {
        r.push_str(&format!("{n}: {v}\r\n"));
    }
    if !body.is_empty() || method == "POST" || method == "PUT" {
        r.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    r.push_str("\r\n");
    let mut bytes = r.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

pub async fn refund_tls_t(
    server: &Server,
    tls: &TlsClient,
    key: &str,
    idem: &str,
    params: &str,
    limit: Duration,
) -> Result<Resp, ClientError> {
    let auth = format!("Bearer {key}");
    let bytes = build_request(
        server.api_addr,
        "POST",
        "/v1/refunds",
        &[
            ("Authorization", &auth),
            ("Idempotency-Key", idem),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        params.as_bytes(),
    );
    raw_tls(server.api_addr, tls, &bytes, limit)
        .await
        .map(parse)
}

pub async fn refund_tls(
    server: &Server,
    tls: &TlsClient,
    key: &str,
    idem: &str,
    params: &str,
) -> Resp {
    refund_tls_t(server, tls, key, idem, params, Duration::from_secs(10))
        .await
        .expect("tls refund")
}

pub async fn get_tls(server: &Server, tls: &TlsClient, key: &str, path: &str) -> Resp {
    let auth = format!("Bearer {key}");
    let bytes = build_request(
        server.api_addr,
        "GET",
        path,
        &[("Authorization", &auth)],
        b"",
    );
    raw_tls(server.api_addr, tls, &bytes, Duration::from_secs(10))
        .await
        .map(parse)
        .expect("tls get")
}
