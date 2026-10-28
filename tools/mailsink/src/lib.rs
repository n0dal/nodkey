//! mailsink: a SIMULATED mail sink for Nodkey Demo A (agent-interface-v1 Draft 2 §3, §5).
//!
//! **It delivers no mail.** `messages.send` is an internal broker effect: one row in the
//! broker-owned `public.outbox`. mailsink polls that table read-only and keeps what it saw in
//! memory, so tests can list "delivered" messages over a local admin endpoint.
//!
//! Trust: none. mailsink is not part of any TCB; Nodkey never reads anything back from it.
//! Local use only: it refuses public bind addresses (see [`check_bind`]).

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const LABEL: &str = "SIMULATED mail sink - delivers no mail";
/// Most messages kept in memory; later ones are counted, not stored.
pub const MAX_MESSAGES: usize = 10_000;
/// Rows read per poll.
pub const BATCH: i64 = 500;
const MAX_HEAD: usize = 8 * 1024;

pub fn log(msg: &str) {
    println!("[mailsink SIMULATOR] {msg}");
}

/// One outbox row as seen by the sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// `message_id` (= the record's `pending_id` bytes), lowercase hex.
    pub message_id: String,
    pub ten: String,
    pub to: String,
    pub body: String,
    pub created_at: i64,
}

impl Message {
    fn json(&self) -> Value {
        json!({"message_id": self.message_id, "ten": self.ten, "to": self.to,
               "body": self.body, "created_at": self.created_at})
    }
}

#[derive(Default)]
struct Inner {
    messages: Vec<Message>,
    ids: HashSet<String>,
    not_stored: u64,
    /// Cursor `(created_at, message_id hex)` of the last row read.
    cursor: Option<(i64, String)>,
    polls_ok: u64,
    last_error: Option<String>,
}

/// In-memory view of what the sink has read. Cheap to clone (shared).
#[derive(Clone, Default)]
pub struct Sink(Arc<Mutex<Inner>>);

impl Sink {
    pub fn new() -> Sink {
        Sink::default()
    }

    /// Adds rows (deduplicated by `message_id`) and advances the cursor.
    pub fn ingest(&self, rows: Vec<Message>) {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for m in rows {
            let key = (m.created_at, m.message_id.clone());
            if g.cursor.as_ref().is_none_or(|c| key > *c) {
                g.cursor = Some(key);
            }
            if !g.ids.insert(m.message_id.clone()) {
                continue;
            }
            if g.messages.len() >= MAX_MESSAGES {
                g.not_stored += 1;
                continue;
            }
            g.messages.push(m);
        }
        g.polls_ok += 1;
        g.last_error = None;
    }

    pub fn poll_failed(&self, e: &str) {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        g.last_error = Some(e.to_owned());
    }

    pub fn cursor(&self) -> Option<(i64, String)> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cursor
            .clone()
    }

    pub fn messages(&self) -> Vec<Message> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .messages
            .clone()
    }

    /// The `GET /messages` body.
    pub fn listing(&self) -> Value {
        let g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        json!({
            "simulator": true,
            "label": LABEL,
            "messages": g.messages.iter().map(Message::json).collect::<Vec<_>>(),
            "not_stored": g.not_stored,
        })
    }

    /// The `GET /healthz` body.
    pub fn health(&self) -> Value {
        let g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        json!({"simulator": true, "label": LABEL, "polls_ok": g.polls_ok,
               "last_error": g.last_error})
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn non_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
}

fn non_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    ip.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
}

/// Bind policy (as simpay's): loopback and private addresses only; the unspecified address only
/// with `--container-bind`; public addresses never.
pub fn check_bind(addr: SocketAddr, container_bind: bool) -> Result<(), String> {
    let ip = canonical_ip(addr.ip());
    if ip.is_unspecified() {
        return if container_bind {
            Ok(())
        } else {
            Err(format!(
                "refusing to bind {addr}: mailsink is a SIMULATOR; pass --container-bind only inside an isolated container network"
            ))
        };
    }
    let ok = match ip {
        IpAddr::V4(v4) => non_public_v4(v4),
        IpAddr::V6(v6) => non_public_v6(v6),
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "refusing to bind {addr}: public address (mailsink is a SIMULATOR; no override)"
        ))
    }
}

fn response(status: &str, body: &Value) -> Vec<u8> {
    let b = body.to_string();
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Mailsink-Simulator: {LABEL}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{b}",
        b.len()
    )
    .into_bytes()
}

async fn read_head(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(buf);
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
    }
}

/// Answers one admin request: `GET /messages`, `GET /healthz`; anything else 404/405/400.
pub fn route(sink: &Sink, head: &[u8]) -> Vec<u8> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => {
            return response(
                "400 Bad Request",
                &json!({"simulator": true, "error": "bad_request"}),
            );
        }
    }
    match (req.method, req.path) {
        (Some("GET"), Some("/messages")) => response("200 OK", &sink.listing()),
        (Some("GET"), Some("/healthz")) => response("200 OK", &sink.health()),
        (Some("GET"), _) => response(
            "404 Not Found",
            &json!({"simulator": true, "error": "not_found"}),
        ),
        _ => response(
            "405 Method Not Allowed",
            &json!({"simulator": true, "error": "method_not_allowed"}),
        ),
    }
}

/// Admin accept loop (one request per connection, 5 s to send the head).
pub async fn serve_admin(listener: TcpListener, sink: Sink) {
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let sink = sink.clone();
        tokio::spawn(async move {
            let head = tokio::time::timeout(Duration::from_secs(5), read_head(&mut s)).await;
            let out = match head {
                Ok(Some(h)) => route(&sink, &h),
                _ => response(
                    "400 Bad Request",
                    &json!({"simulator": true, "error": "bad_request"}),
                ),
            };
            let _ = s.write_all(&out).await;
            let _ = s.shutdown().await;
        });
    }
}

/// The poll query: rows after the cursor, in `(created_at, message_id)` order (bytewise, as the
/// cursor comparison in [`Sink::ingest`]), read-only. Not exercised by the tests (no database).
pub const POLL_SQL: &str = "SELECT encode(message_id, 'hex'), ten, \"to\", body, created_at \
     FROM public.outbox \
     WHERE (created_at, encode(message_id, 'hex') COLLATE \"C\") > ($1, $2 COLLATE \"C\") \
     ORDER BY created_at, encode(message_id, 'hex') COLLATE \"C\" LIMIT $3";

/// Polls `public.outbox` every `every` until the connection fails (the caller reconnects).
pub async fn poll_outbox(client: &tokio_postgres::Client, sink: &Sink, every: Duration) -> String {
    loop {
        let (c_at, c_id) = sink.cursor().unwrap_or((-1, String::new()));
        let rows = match client.query(POLL_SQL, &[&c_at, &c_id, &BATCH]).await {
            Ok(r) => r,
            Err(e) => return e.to_string(),
        };
        let mut batch = Vec::with_capacity(rows.len());
        for r in rows {
            let m = (|| -> Result<Message, tokio_postgres::Error> {
                Ok(Message {
                    message_id: r.try_get(0)?,
                    ten: r.try_get(1)?,
                    to: r.try_get(2)?,
                    body: r.try_get(3)?,
                    created_at: r.try_get(4)?,
                })
            })();
            match m {
                Ok(m) => batch.push(m),
                Err(e) => return e.to_string(),
            }
        }
        let n = batch.len();
        sink.ingest(batch);
        if n > 0 {
            log(&format!("read {n} outbox row(s)"));
        }
        if (n as i64) < BATCH {
            tokio::time::sleep(every).await;
        }
    }
}
