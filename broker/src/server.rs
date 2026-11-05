// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Per-workload Unix-socket listeners, framing, and request handling.
//!
//! Workload identity is the socket a connection arrives on (each socket lives in a volume
//! mounted into exactly one workload). `SO_PEERCRED` is checked against the configured uid as a
//! second factor. Nothing in the request body can change which workload the broker believes it
//! is serving.

use crate::config::Workload;
use crate::ledger::{Ledger, LedgerError};
use crate::protocol::{self, Deny, ErrorCode, Operation, RequestId};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_REQUESTS_PER_CONNECTION: usize = 256;
pub const MAX_CONNECTIONS_PER_WORKLOAD: usize = 32;

/// Generates correlation ids: a per-process random prefix plus a counter.
pub struct CorrelationIds {
    prefix: String,
    counter: AtomicU64,
}

impl CorrelationIds {
    pub fn new(seed: [u8; 8]) -> Self {
        let prefix = seed.iter().map(|b| format!("{b:02x}")).collect();
        CorrelationIds {
            prefix,
            counter: AtomicU64::new(0),
        }
    }
    pub fn next(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{}-{:08x}", self.prefix, n)
    }
}

pub struct Shared {
    pub ledger: Ledger,
    pub ids: CorrelationIds,
    pub max_request_bytes: usize,
}

/// One structured JSON log line per decision, on stdout.
fn log_decision(entry: Value) {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut obj = json!({"ts_ms": ts_ms as u64, "event": "decision"});
    if let (Some(o), Value::Object(e)) = (obj.as_object_mut(), entry) {
        o.extend(e);
    }
    println!("{obj}");
}

pub fn log_event(event: &str, fields: Value) {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut obj = json!({"ts_ms": ts_ms as u64, "event": event});
    if let (Some(o), Value::Object(e)) = (obj.as_object_mut(), fields) {
        o.extend(e);
    }
    println!("{obj}");
}

#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// A complete line is in the buffer (newline stripped).
    Line,
    /// Clean end of stream before any byte of a new frame.
    Eof,
    /// Stream ended in the middle of a frame.
    Incomplete,
    /// The frame exceeded the limit; the connection must be closed (cannot resynchronise).
    TooLarge,
}

/// Reads one newline-terminated frame of at most `max` bytes (excluding the newline) into `buf`.
/// Never buffers more than `max` bytes of a frame.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    r: &mut R,
    max: usize,
    buf: &mut Vec<u8>,
) -> std::io::Result<Frame> {
    buf.clear();
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok(if buf.is_empty() {
                Frame::Eof
            } else {
                Frame::Incomplete
            });
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if buf.len() + pos > max {
                return Ok(Frame::TooLarge);
            }
            buf.extend_from_slice(&available[..pos]);
            r.consume(pos + 1);
            return Ok(Frame::Line);
        }
        let n = available.len();
        if buf.len() + n > max {
            return Ok(Frame::TooLarge);
        }
        buf.extend_from_slice(available);
        r.consume(n);
    }
}

fn ok_response(id: &RequestId, cid: &str, result: Value) -> Value {
    json!({"v": protocol::PROTOCOL_VERSION, "id": id.as_str(), "correlation_id": cid, "ok": true, "result": result})
}

fn err_response(id: Option<&RequestId>, cid: &str, code: ErrorCode) -> Value {
    json!({
        "v": protocol::PROTOCOL_VERSION,
        "id": id.map(|i| i.as_str()),
        "correlation_id": cid,
        "ok": false,
        "error": {"code": code.as_str(), "message": code.message()}
    })
}

struct PeerInfo {
    uid: u32,
    pid: Option<i32>,
}

/// Handles one request line. Returns the response to send.
async fn handle_line(line: &[u8], wl: &Workload, shared: &Shared, peer: &PeerInfo) -> Value {
    let started = Instant::now();
    let cid = shared.ids.next();
    let base = |op: Option<&str>, decision: &str, code: Option<ErrorCode>, detail: &str| {
        json!({
            "correlation_id": cid,
            "workload": wl.name,
            "peer_uid": peer.uid,
            "peer_pid": peer.pid,
            "op": op,
            "decision": decision,
            "code": code.map(|c| c.as_str()),
            "detail": detail,
            "duration_us": started.elapsed().as_micros() as u64,
        })
    };

    let req = match protocol::parse_request(line) {
        Ok(r) => r,
        Err(f) => {
            log_decision(base(
                f.op_name.as_deref(),
                "deny",
                Some(f.deny.code),
                &f.deny.detail,
            ));
            return err_response(f.id.as_ref(), &cid, f.deny.code);
        }
    };
    let op_name = req.op.kind().wire_name();

    if let Err(d) = wl.authorize(&req.op) {
        log_decision(base(Some(op_name), "deny", Some(d.code), &d.detail));
        return err_response(Some(&req.id), &cid, d.code);
    }

    let mut replayed = false;
    let outcome: Result<Value, Deny> = match &req.op {
        Operation::GetBalance(g) => match shared.ledger.get_balance(&g.account).await {
            Ok(bal) => Ok(json!({"account": g.account.as_str(), "balance_cents": bal})),
            Err(e) => Err(map_ledger_error(e)),
        },
        Operation::Transfer(t) => match shared.ledger.transfer(t, &wl.name, &cid).await {
            Ok(o) => Ok({
                replayed = o.replayed;
                json!({
                "transfer_id": o.transfer_id,
                "from": t.from.as_str(),
                "to": t.to.as_str(),
                "amount_cents": t.amount_cents,
                "from_balance_cents": o.from_balance_cents,
                "replayed": o.replayed,
                })
            }),
            Err(e) => Err(map_ledger_error(e)),
        },
    };

    // Audit: for transfers record the arguments and key on every outcome, and whether the effect
    // is known not to have happened (`effect: "none"`), happened now (`"committed"`), happened
    // earlier under the same key (`"replayed"`), or is unknown (`"unknown"`).
    let add_transfer_fields = |entry: &mut Value, effect: &str| {
        if let (Some(o), Operation::Transfer(t)) = (entry.as_object_mut(), &req.op) {
            o.insert("amount_cents".into(), json!(t.amount_cents));
            o.insert("from".into(), json!(t.from.as_str()));
            o.insert("to".into(), json!(t.to.as_str()));
            o.insert("idempotency_key".into(), json!(t.idempotency_key.as_str()));
            o.insert("effect".into(), json!(effect));
        }
    };
    match outcome {
        Ok(result) => {
            let mut entry = base(Some(op_name), "allow", None, "");
            add_transfer_fields(&mut entry, if replayed { "replayed" } else { "committed" });
            log_decision(entry);
            ok_response(&req.id, &cid, result)
        }
        Err(d) => {
            let (decision, effect) = classify_deny(d.code);
            let mut entry = base(Some(op_name), decision, Some(d.code), &d.detail);
            add_transfer_fields(&mut entry, effect);
            log_decision(entry);
            err_response(Some(&req.id), &cid, d.code)
        }
    }
}

/// Audit classification of a failed operation: (decision, effect). Only `OutcomeUnknown` may
/// leave an effect behind; every other code is returned only when nothing was executed.
fn classify_deny(code: ErrorCode) -> (&'static str, &'static str) {
    match code {
        ErrorCode::OutcomeUnknown => ("unknown", "unknown"),
        ErrorCode::Unavailable => ("unavailable", "none"),
        _ => ("deny", "none"),
    }
}

fn map_ledger_error(e: LedgerError) -> Deny {
    match e {
        LedgerError::UnknownAccount => Deny::new(ErrorCode::UnknownAccount, "account not found"),
        LedgerError::InsufficientFunds => {
            Deny::new(ErrorCode::InsufficientFunds, "balance below amount")
        }
        LedgerError::Overflow => Deny::new(ErrorCode::InvalidArgument, "credit overflow"),
        LedgerError::IdempotencyConflict => Deny::new(
            ErrorCode::IdempotencyConflict,
            "idempotency key reused with different arguments",
        ),
        LedgerError::Unavailable(d) => Deny::new(ErrorCode::Unavailable, d),
        LedgerError::OutcomeUnknown(d) => Deny::new(ErrorCode::OutcomeUnknown, d),
    }
}

async fn write_line(w: &mut (impl AsyncWriteExt + Unpin), v: &Value) -> bool {
    let mut bytes = v.to_string().into_bytes();
    bytes.push(b'\n');
    matches!(
        tokio::time::timeout(WRITE_TIMEOUT, w.write_all(&bytes)).await,
        Ok(Ok(()))
    )
}

async fn handle_connection(stream: UnixStream, wl: Arc<Workload>, shared: Arc<Shared>) {
    let peer = match stream.peer_cred() {
        Ok(c) => PeerInfo {
            uid: c.uid(),
            pid: c.pid(),
        },
        Err(e) => {
            log_event(
                "peer_cred_error",
                json!({"workload": wl.name, "detail": e.to_string()}),
            );
            return;
        }
    };
    let (r, mut w) = stream.into_split();

    if peer.uid != wl.uid {
        let cid = shared.ids.next();
        log_decision(json!({
            "correlation_id": cid, "workload": wl.name, "peer_uid": peer.uid, "peer_pid": peer.pid,
            "op": null, "decision": "deny", "code": ErrorCode::Unauthenticated.as_str(),
            "detail": format!("expected uid {}", wl.uid),
        }));
        let _ = write_line(
            &mut w,
            &err_response(None, &cid, ErrorCode::Unauthenticated),
        )
        .await;
        return;
    }

    let mut reader = BufReader::with_capacity(8192, r);
    let mut buf = Vec::with_capacity(1024);
    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let frame = match tokio::time::timeout(
            READ_TIMEOUT,
            read_frame(&mut reader, shared.max_request_bytes, &mut buf),
        )
        .await
        {
            Ok(Ok(f)) => f,
            Ok(Err(_)) | Err(_) => return,
        };
        let response = match frame {
            Frame::Eof => return,
            Frame::Line => handle_line(&buf, &wl, &shared, &peer).await,
            Frame::Incomplete | Frame::TooLarge => {
                let code = if frame == Frame::TooLarge {
                    ErrorCode::RequestTooLarge
                } else {
                    ErrorCode::MalformedRequest
                };
                let cid = shared.ids.next();
                log_decision(json!({
                    "correlation_id": cid, "workload": wl.name, "peer_uid": peer.uid, "peer_pid": peer.pid,
                    "op": null, "decision": "deny", "code": code.as_str(), "detail": format!("{frame:?}"),
                }));
                let _ = write_line(&mut w, &err_response(None, &cid, code)).await;
                return;
            }
        };
        if !write_line(&mut w, &response).await {
            // The decision (possibly a committed effect) was logged, but the client never saw it.
            log_event(
                "response_not_delivered",
                json!({"workload": wl.name, "correlation_id": response["correlation_id"], "ok": response["ok"]}),
            );
            return;
        }
    }
}

pub async fn serve(listener: UnixListener, wl: Arc<Workload>, shared: Arc<Shared>) {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_WORKLOAD));
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                log_event(
                    "accept_error",
                    json!({"workload": wl.name, "detail": e.to_string()}),
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            // Over the connection limit: refuse (fail closed) rather than queue unboundedly.
            let shared = shared.clone();
            let name = wl.name.clone();
            tokio::spawn(async move {
                let cid = shared.ids.next();
                log_event(
                    "connection_refused",
                    json!({"workload": name, "correlation_id": cid, "detail": "connection limit"}),
                );
                let (_, mut w) = stream.into_split();
                let _ = write_line(&mut w, &err_response(None, &cid, ErrorCode::Unavailable)).await;
            });
            continue;
        };
        let (wl, shared) = (wl.clone(), shared.clone());
        tokio::spawn(async move {
            handle_connection(stream, wl, shared).await;
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn frames(input: &[u8], max: usize) -> Vec<(Frame, Vec<u8>)> {
        // Tiny buffer capacity to exercise frames split across reads.
        let mut r = BufReader::with_capacity(3, input);
        let mut out = vec![];
        let mut buf = vec![];
        loop {
            let f = read_frame(&mut r, max, &mut buf).await.unwrap();
            let stop = f != Frame::Line;
            out.push((f, buf.clone()));
            if stop {
                return out;
            }
        }
    }

    #[tokio::test]
    async fn splits_lines() {
        let f = frames(b"abc\nde\n", 16).await;
        assert_eq!(
            f,
            vec![
                (Frame::Line, b"abc".to_vec()),
                (Frame::Line, b"de".to_vec()),
                (Frame::Eof, vec![])
            ]
        );
    }

    #[tokio::test]
    async fn exact_limit_ok_one_over_rejected() {
        let f = frames(b"12345678\n", 8).await;
        assert_eq!(f[0], (Frame::Line, b"12345678".to_vec()));
        let f = frames(b"123456789\n", 8).await;
        assert_eq!(f[0].0, Frame::TooLarge);
        // No newline at all and over the limit.
        let f = frames(&[b'a'; 100], 8).await;
        assert_eq!(f[0].0, Frame::TooLarge);
    }

    #[tokio::test]
    async fn incomplete_frame_detected() {
        let f = frames(b"abc\nde", 16).await;
        assert_eq!(f[1].0, Frame::Incomplete);
    }

    #[test]
    fn error_response_has_no_detail() {
        let v = err_response(None, "c1", ErrorCode::Unavailable);
        let s = v.to_string();
        assert!(s.contains("\"code\":\"unavailable\""));
        assert!(s.contains("\"id\":null"));
        assert_eq!(v["error"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn ledger_errors_map_to_distinct_codes() {
        assert_eq!(
            map_ledger_error(LedgerError::Unavailable("x".into())).code,
            ErrorCode::Unavailable
        );
        assert_eq!(
            map_ledger_error(LedgerError::OutcomeUnknown("x".into())).code,
            ErrorCode::OutcomeUnknown
        );
        assert_eq!(
            map_ledger_error(LedgerError::IdempotencyConflict).code,
            ErrorCode::IdempotencyConflict
        );
    }

    #[test]
    fn audit_distinguishes_unknown_from_not_executed() {
        assert_eq!(
            classify_deny(ErrorCode::OutcomeUnknown),
            ("unknown", "unknown")
        );
        assert_eq!(
            classify_deny(ErrorCode::Unavailable),
            ("unavailable", "none")
        );
        assert_eq!(
            classify_deny(ErrorCode::IdempotencyConflict),
            ("deny", "none")
        );
        assert_eq!(
            classify_deny(ErrorCode::InsufficientFunds),
            ("deny", "none")
        );
    }

    #[test]
    fn correlation_ids_unique() {
        let ids = CorrelationIds::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let a = ids.next();
        let b = ids.next();
        assert_ne!(a, b);
        assert!(a.starts_with("0102030405060708-"));
    }
}
