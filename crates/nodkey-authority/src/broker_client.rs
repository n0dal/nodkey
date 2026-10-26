//! Client for socket A (authority → broker): `config.digest`, `pending.get`, `grant.deliver`.
//!
//! One connection, one request in flight at a time. The broker's identity is checked with
//! `SO_PEERCRED` (uid = configured broker uid) and every new connection first compares
//! `config.digest` with the authority's own. Any I/O error, timeout or malformed response drops
//! the connection; the caller sees `Unavailable` (a lost response is indistinguishable from a
//! failure, so `grant.deliver` is retried with the same bytes, §4.2 step 6).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nodkey_grant::encode_transport;
use serde_json::{Map, Value, json};
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;

use crate::digest::{PendingId, PendingRecord, hex, parse_hex_digest};
use crate::log;
use crate::wire::{
    Frame, MAX_LINE, PROTOCOL_VERSION, exact_members, is_request_id, parse_strict_object,
    read_frame, write_line,
};

const STALE_WRITE: &str = "stale connection: write failed";
const STALE_EOF: &str = "stale connection: closed before response";

/// Record states (§3.3).
pub const STATES: [&str; 8] = [
    "PENDING",
    "APPROVED",
    "EXECUTING",
    "SUCCEEDED",
    "FAILED",
    "UNKNOWN",
    "DENIED",
    "EXPIRED",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// The broker answered `not_found`.
    NotFound,
    /// Anything else: connection, timeout, malformed response, other error code.
    Unavailable(&'static str),
}

/// `pending.get` result: the §3.2 fields, `state`, and the broker's `digest`.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub record: PendingRecord,
    pub state: String,
    pub broker_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliverResult {
    Accepted,
    Rejected,
    Expired,
}

#[derive(Debug)]
struct Conn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

#[derive(Debug)]
pub struct BrokerClient {
    path: PathBuf,
    broker_uid: u32,
    config_digest: [u8; 32],
    timeout: Duration,
    conn: Mutex<Option<Conn>>,
    counter: AtomicU64,
}

impl BrokerClient {
    pub fn new(path: PathBuf, broker_uid: u32, config_digest: [u8; 32], timeout: Duration) -> Self {
        BrokerClient {
            path,
            broker_uid,
            config_digest,
            timeout,
            conn: Mutex::new(None),
            counter: AtomicU64::new(0),
        }
    }

    async fn connect(&self) -> Result<Conn, CallError> {
        let stream = tokio::time::timeout(self.timeout, UnixStream::connect(&self.path))
            .await
            .map_err(|_| CallError::Unavailable("connect timeout"))?
            .map_err(|_| CallError::Unavailable("connect failed"))?;
        let cred = stream
            .peer_cred()
            .map_err(|_| CallError::Unavailable("peer_cred"))?;
        if cred.uid() != self.broker_uid {
            log::alarm(
                "broker_peer_uid_mismatch",
                json!({"peer_uid": cred.uid(), "expected_uid": self.broker_uid}),
            );
            return Err(CallError::Unavailable("broker peer uid mismatch"));
        }
        let (r, w) = stream.into_split();
        let mut conn = Conn {
            reader: BufReader::with_capacity(MAX_LINE + 1, r),
            writer: w,
        };
        let res = self.exchange(&mut conn, "config.digest", json!({})).await?;
        exact_members(&res, &["digest"], &[]).map_err(CallError::Unavailable)?;
        let d = res["digest"]
            .as_str()
            .and_then(|s| parse_hex_digest(s).ok())
            .ok_or(CallError::Unavailable("config.digest result"))?;
        if d != self.config_digest {
            log::alarm(
                "config_digest_mismatch",
                json!({"broker": hex(&d), "authority": hex(&self.config_digest)}),
            );
            return Err(CallError::Unavailable("config digest mismatch"));
        }
        Ok(conn)
    }

    /// One request/response on `conn`. Returns the `result` object.
    async fn exchange(
        &self,
        conn: &mut Conn,
        op: &str,
        args: Value,
    ) -> Result<Map<String, Value>, CallError> {
        let id = format!("a-{}", self.counter.fetch_add(1, Ordering::Relaxed));
        let req = json!({"v": PROTOCOL_VERSION, "id": id, "op": op, "args": args});
        if !write_line(&mut conn.writer, &req).await {
            return Err(CallError::Unavailable(STALE_WRITE));
        }
        let mut buf = Vec::new();
        match tokio::time::timeout(
            self.timeout,
            read_frame(&mut conn.reader, MAX_LINE, &mut buf),
        )
        .await
        {
            Ok(Ok(Frame::Line)) => {}
            // Closed before any response byte: typically the broker closed an idle connection.
            Ok(Ok(Frame::Eof)) => return Err(CallError::Unavailable(STALE_EOF)),
            Ok(_) => return Err(CallError::Unavailable("read")),
            Err(_) => return Err(CallError::Unavailable("response timeout")),
        }
        let o = parse_strict_object(&buf).map_err(CallError::Unavailable)?;
        let ok = o.get("ok").and_then(Value::as_bool);
        let body = if ok == Some(true) { "result" } else { "error" };
        exact_members(&o, &["v", "id", "correlation_id", "ok", body], &[])
            .map_err(CallError::Unavailable)?;
        if o["v"].as_u64() != Some(PROTOCOL_VERSION)
            || o["id"].as_str() != Some(id.as_str())
            || !o["correlation_id"].as_str().is_some_and(is_request_id)
        {
            return Err(CallError::Unavailable("response envelope"));
        }
        match ok {
            Some(true) => match &o["result"] {
                Value::Object(m) => Ok(m.clone()),
                _ => Err(CallError::Unavailable("result type")),
            },
            Some(false) => {
                let e = o["error"]
                    .as_object()
                    .ok_or(CallError::Unavailable("error type"))?;
                exact_members(e, &["code", "message"], &[]).map_err(CallError::Unavailable)?;
                match e["code"].as_str() {
                    Some("not_found") => Err(CallError::NotFound),
                    Some("unavailable") => Err(CallError::Unavailable("broker unavailable")),
                    _ => Err(CallError::Unavailable("broker error code")),
                }
            }
            None => Err(CallError::Unavailable("ok type")),
        }
    }

    /// Sends one request. A **reused** connection that turns out to be stale (the write fails, or
    /// the peer closes before any response byte; the broker closes idle connections after its
    /// read timeout) is replaced once by a fresh, re-verified connection and the request is sent
    /// again (DEMO2-F02). This is safe for every socket-A call: `config.digest` and
    /// `pending.get` are read-only, and `grant.deliver` resends the identical, already durable
    /// bytes, which the broker treats idempotently (§4.3 step 2). Nothing is ever re-signed here.
    async fn call(&self, op: &str, args: Value) -> Result<Map<String, Value>, CallError> {
        let mut guard = self.conn.lock().await;
        let mut reused = guard.is_some();
        if !reused {
            *guard = Some(self.connect().await?);
        }
        loop {
            let conn = guard.as_mut().expect("connected above");
            let r = self.exchange(conn, op, args.clone()).await;
            if matches!(r, Err(CallError::Unavailable(_))) {
                // The stream may hold a late response; never reuse it.
                *guard = None;
            }
            match r {
                Err(CallError::Unavailable(why))
                    if reused && (why == STALE_WRITE || why == STALE_EOF) =>
                {
                    log::event("broker_reconnect", json!({"op": op, "detail": why}));
                    reused = false;
                    *guard = Some(self.connect().await?);
                }
                r => return r,
            }
        }
    }

    /// Connects (if needed) and verifies the broker uid and `config.digest`.
    pub async fn check(&self) -> Result<(), CallError> {
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            *guard = Some(self.connect().await?);
        }
        Ok(())
    }

    /// `pending.get{pending_id}`: read-only.
    pub async fn pending_get(&self, pid: &PendingId) -> Result<Fetched, CallError> {
        let res = self
            .call("pending.get", json!({"pending_id": pid.to_text()}))
            .await?;
        let record = PendingRecord::from_json(&res, &["state", "digest"])
            .map_err(|e| CallError::Unavailable(e.0))?;
        let state = res
            .get("state")
            .and_then(Value::as_str)
            .filter(|s| STATES.contains(s))
            .ok_or(CallError::Unavailable("state"))?
            .to_owned();
        let broker_digest = res
            .get("digest")
            .and_then(Value::as_str)
            .and_then(|s| parse_hex_digest(s).ok())
            .ok_or(CallError::Unavailable("digest"))?;
        Ok(Fetched {
            record,
            state,
            broker_digest,
        })
    }

    /// `grant.deliver{pending_id, grant}`.
    pub async fn deliver(&self, pid: &PendingId, grant: &[u8]) -> Result<DeliverResult, CallError> {
        let res = self
            .call(
                "grant.deliver",
                json!({"pending_id": pid.to_text(), "grant": encode_transport(grant)}),
            )
            .await?;
        exact_members(&res, &["status"], &[]).map_err(CallError::Unavailable)?;
        match res["status"].as_str() {
            Some("accepted") => Ok(DeliverResult::Accepted),
            Some("rejected") => Ok(DeliverResult::Rejected),
            Some("expired") => Ok(DeliverResult::Expired),
            _ => Err(CallError::Unavailable("deliver status")),
        }
    }
}
