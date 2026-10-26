//! Socket P (payments-adapter-v1 §1, §4): the broker is the only client. One strict JSON request
//! line per connection, at most `max_concurrent` connections, 2 s idle timeout, `SO_PEERCRED`
//! uid = `broker_uid` (a mismatch closes without a response and raises an alarm).
//!
//! `ok:false` means no byte of a provider request was written for this call (§1, normative).

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use crate::config::{Cap, Config};
use crate::derive::{Derived, IdemKey};
use crate::grant::{self, GrantInputs, RefundGrant, is_refund_id};
use crate::json::check_strict;
use crate::log::{CorrelationIds, event, now_s};
use crate::orders::{OrderCheck, OrderView, check_order};
use crate::provider::{Call, Provider, form};
use crate::result::{
    Attempt, Exchange, Expected, classify_create, classify_find, classify_get, classify_idem,
};

/// Maximum request line (effect-protocol-v2 §1.2).
pub const MAX_LINE: usize = 8192;
/// Idle timeout for the request line (§1).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Error codes on socket P.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    MalformedRequest,
    UnsupportedVersion,
    RequestTooLarge,
    UnknownOperation,
    GrantRefused,
    Unavailable,
    InvalidArgument,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::MalformedRequest => "malformed_request",
            Code::UnsupportedVersion => "unsupported_version",
            Code::RequestTooLarge => "request_too_large",
            Code::UnknownOperation => "unknown_operation",
            Code::GrantRefused => "grant_refused",
            Code::Unavailable => "unavailable",
            Code::InvalidArgument => "invalid_argument",
        }
    }
    /// Static per code (uniform errors): never derived from input or provider data.
    pub fn message(self) -> &'static str {
        match self {
            Code::MalformedRequest => "request is not a valid request",
            Code::UnsupportedVersion => "protocol version not supported",
            Code::RequestTooLarge => "request exceeds maximum size",
            Code::UnknownOperation => "operation is not served",
            Code::GrantRefused => "grant refused; nothing was sent",
            Code::Unavailable => "unavailable; nothing was sent",
            Code::InvalidArgument => "invalid argument; nothing was sent",
        }
    }
}

/// Everything the adapter needs at runtime. Built once at start-up; immutable afterwards.
pub struct Adapter {
    pub cfg: Config,
    pub grants: GrantInputs,
    pub idem: IdemKey,
    pub provider: Provider,
    pub orders: Arc<dyn OrderView>,
    pub ids: CorrelationIds,
}

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adapter").finish_non_exhaustive()
    }
}

/// Audit fields gathered while handling one request (logged once, no secrets).
#[derive(Default)]
struct Audit {
    op: String,
    jti: Option<String>,
    detail: Option<&'static str>,
    class: Option<&'static str>,
    cause: Option<&'static str>,
    http: Option<u16>,
    sent: bool,
}

type Handled = Result<Value, Code>;

fn ok_response(id: &str, cid: &str, result: Value) -> Value {
    json!({"v": 2, "id": id, "correlation_id": cid, "ok": true, "result": result})
}

fn err_response(id: Option<&str>, cid: &str, code: Code) -> Value {
    json!({"v": 2, "id": id, "correlation_id": cid, "ok": false,
           "error": {"code": code.as_str(), "message": code.message()}})
}

fn is_request_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A parsed envelope: request id, op, args.
type Envelope = (String, String, Map<String, Value>);
/// An envelope error: the request id if it was readable, and the code.
type EnvelopeError = (Option<String>, Code);

/// Envelope `{"v":2,"id","op","args"}` exactly (§2.2 rules).
fn parse_envelope(line: &[u8]) -> Result<Envelope, EnvelopeError> {
    check_strict(line, 4).map_err(|_| (None, Code::MalformedRequest))?;
    let Ok(Value::Object(mut o)) = serde_json::from_slice::<Value>(line) else {
        return Err((None, Code::MalformedRequest));
    };
    if o.len() != 4 || !["v", "id", "op", "args"].iter().all(|k| o.contains_key(*k)) {
        return Err((None, Code::MalformedRequest));
    }
    let id = o["id"]
        .as_str()
        .filter(|s| is_request_id(s))
        .map(str::to_owned)
        .ok_or((None, Code::MalformedRequest))?;
    match o["v"].as_u64() {
        Some(2) => {}
        Some(_) => return Err((Some(id), Code::UnsupportedVersion)),
        None => return Err((Some(id), Code::MalformedRequest)),
    }
    let Some(op) = o["op"].as_str().map(str::to_owned) else {
        return Err((Some(id), Code::MalformedRequest));
    };
    let Some(Value::Object(args)) = o.remove("args") else {
        return Err((Some(id), Code::MalformedRequest));
    };
    Ok((id, op, args))
}

fn exact_args<'a>(args: &'a Map<String, Value>, keys: &[&str]) -> Result<Vec<&'a str>, Code> {
    if args.len() != keys.len() {
        return Err(Code::MalformedRequest);
    }
    keys.iter()
        .map(|k| {
            args.get(*k)
                .and_then(Value::as_str)
                .ok_or(Code::MalformedRequest)
        })
        .collect()
}

impl Adapter {
    fn derived(&self, g: &RefundGrant) -> Derived {
        self.idem
            .derive(&self.cfg.account, &g.op, u64::from(g.opv), &g.iss, &g.jti)
    }

    fn expected(&self, g: &RefundGrant, d: &Derived) -> Expected {
        Expected {
            charge: g.charge_id.clone(),
            amount_minor: g.amount_minor,
            currency: g.currency.clone(),
            reference: d.reference.clone(),
        }
    }

    /// `adapter.hello`.
    pub fn hello(&self) -> Value {
        let caps: Vec<&str> = self.cfg.caps.iter().map(|c| c.as_str()).collect();
        json!({"format": crate::config::FORMAT, "profile": "simpay", "caps": caps,
               "idem_kid": self.idem.kid(), "r_max_s": self.cfg.r_max_s})
    }

    /// `refund.create`: verify (with age), order check, then one provider request built only
    /// from the grant.
    async fn create(&self, grant_text: &str, a: &mut Audit) -> Handled {
        let g = grant::verify_create(&self.grants, grant_text, now_s()).map_err(|r| {
            a.detail = Some(r.0);
            Code::GrantRefused
        })?;
        a.jti = Some(g.jti_hex());
        match check_order(self.orders.as_ref(), &g).await {
            Ok(()) => {}
            Err(OrderCheck::Mismatch) => {
                a.detail = Some("order_mismatch");
                return Err(Code::GrantRefused);
            }
            Err(OrderCheck::Unavailable(d)) => {
                a.detail = Some(d);
                return Err(Code::Unavailable);
            }
        }
        let d = self.derived(&g);
        let amount = g.amount_minor.to_string();
        let lower = g.currency.to_ascii_lowercase();
        let mut pairs = vec![
            ("charge", g.charge_id.as_str()),
            ("amount", amount.as_str()),
            ("reference", d.reference.as_str()),
        ];
        if self.cfg.has(Cap::SendCurrency) {
            pairs.push(("currency", lower.as_str()));
        }
        let call = Call::Create {
            idem_key: d.idem_key.clone(),
            form: form(&pairs),
        };
        let x = self.provider.exchange(&call).await;
        note_exchange(a, &x);
        let att = classify_create(&x, &self.expected(&g, &d));
        a.class = Some(att.class());
        a.cause = att.cause();
        if matches!(att, Attempt::NotSent(_)) {
            a.sent = false;
        }
        Ok(att.to_json(&d.reference))
    }

    /// Lookups: `verify_binding` (no age rule), then one GET built only from the grant.
    async fn lookup(
        &self,
        op: &str,
        grant_text: &str,
        refund_id: Option<&str>,
        a: &mut Audit,
    ) -> Handled {
        if let Some(id) = refund_id
            && !is_refund_id(id)
        {
            a.detail = Some("refund_id_pattern");
            return Err(Code::InvalidArgument);
        }
        let g = grant::verify_lookup(&self.grants, grant_text, now_s()).map_err(|r| {
            a.detail = Some(r.0);
            Code::GrantRefused
        })?;
        a.jti = Some(g.jti_hex());
        let d = self.derived(&g);
        let e = self.expected(&g, &d);
        let pq = match (op, refund_id) {
            ("refund.get", Some(id)) => format!("/v1/refunds/{id}"),
            ("refund.find", _) => format!(
                "/v1/refunds?{}",
                form(&[
                    ("charge", &g.charge_id),
                    ("reference", &d.reference),
                    ("limit", "3")
                ])
            ),
            _ => format!("/v1/idempotency_keys?{}", form(&[("key", &d.idem_key)])),
        };
        let x = self
            .provider
            .exchange(&Call::Get { path_and_query: pq })
            .await;
        note_exchange(a, &x);
        if let Exchange::NotSent(_) = x {
            a.detail = Some("not_sent");
            return Err(Code::Unavailable);
        }
        let (class, cause, v) = match op {
            "refund.find" => {
                let l = classify_find(&x, &e);
                (l.class(), l.cause(), l.to_json())
            }
            "refund.get" => {
                let l = classify_get(&x, &e, refund_id.unwrap_or(""));
                (l.class(), l.cause(), l.to_json())
            }
            _ => {
                let s = classify_idem(&x, &d.idem_key);
                (s.class(), None, s.to_json())
            }
        };
        a.class = Some(class);
        a.cause = cause;
        Ok(v)
    }

    /// Dispatches one request line; returns the response object.
    pub async fn handle_line(&self, line: &[u8]) -> Value {
        let cid = self.ids.next();
        let started = Instant::now();
        let (id, op, args) = match parse_envelope(line) {
            Ok(v) => v,
            Err((id, code)) => {
                event(
                    "p_request",
                    json!({"correlation_id": cid, "outcome": code.as_str()}),
                );
                return err_response(id.as_deref(), &cid, code);
            }
        };
        let mut a = Audit {
            op: op.chars().take(32).collect(),
            ..Default::default()
        };
        let result: Handled = match op.as_str() {
            "adapter.hello" => {
                if args.is_empty() {
                    Ok(self.hello())
                } else {
                    Err(Code::MalformedRequest)
                }
            }
            "refund.create" => match exact_args(&args, &["grant"]) {
                Ok(v) => self.create(v[0], &mut a).await,
                Err(c) => Err(c),
            },
            "refund.find" => match exact_args(&args, &["grant"]) {
                Ok(v) => self.lookup("refund.find", v[0], None, &mut a).await,
                Err(c) => Err(c),
            },
            "refund.get" => match exact_args(&args, &["grant", "refund_id"]) {
                Ok(v) => self.lookup("refund.get", v[0], Some(v[1]), &mut a).await,
                Err(c) => Err(c),
            },
            "idem.status" if self.cfg.has(Cap::IdemStatus) => match exact_args(&args, &["grant"]) {
                Ok(v) => self.lookup("idem.status", v[0], None, &mut a).await,
                Err(c) => Err(c),
            },
            _ => Err(Code::UnknownOperation),
        };
        let outcome = match &result {
            Ok(_) => "ok",
            Err(c) => c.as_str(),
        };
        event(
            "p_request",
            json!({"correlation_id": cid, "op": a.op, "outcome": outcome, "jti": a.jti,
                   "detail": a.detail, "class": a.class, "cause": a.cause, "http": a.http,
                   "provider_request_started": a.sent, "elapsed_ms": started.elapsed().as_millis() as u64}),
        );
        if matches!(result, Err(Code::GrantRefused)) {
            event(
                "alarm",
                json!({"alarm": "grant_refused", "correlation_id": cid, "detail": a.detail}),
            );
        }
        match result {
            Ok(v) => ok_response(&id, &cid, v),
            Err(c) => err_response(Some(&id), &cid, c),
        }
    }
}

fn note_exchange(a: &mut Audit, x: &Exchange) {
    a.sent = !matches!(x, Exchange::NotSent(_));
    if let Exchange::Response { status, .. } = x {
        a.http = Some(*status);
    }
}

/// Reads one `\n`-terminated line of at most `MAX_LINE` bytes.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> Result<bool, Code> {
    loop {
        let avail = r.fill_buf().await.map_err(|_| Code::MalformedRequest)?;
        if avail.is_empty() {
            return if buf.is_empty() {
                Ok(false)
            } else {
                Err(Code::MalformedRequest)
            };
        }
        if let Some(pos) = avail.iter().position(|&b| b == b'\n') {
            if buf.len() + pos > MAX_LINE {
                return Err(Code::RequestTooLarge);
            }
            buf.extend_from_slice(&avail[..pos]);
            r.consume(pos + 1);
            return Ok(true);
        }
        let n = avail.len();
        if buf.len() + n > MAX_LINE {
            return Err(Code::RequestTooLarge);
        }
        buf.extend_from_slice(avail);
        r.consume(n);
    }
}

async fn write_value(w: &mut (impl AsyncWriteExt + Unpin), v: &Value) {
    let mut bytes = v.to_string().into_bytes();
    bytes.push(b'\n');
    let _ = tokio::time::timeout(WRITE_TIMEOUT, async {
        w.write_all(&bytes).await?;
        w.shutdown().await
    })
    .await;
}

async fn handle_connection(stream: UnixStream, adapter: Arc<Adapter>) {
    let uid = match stream.peer_cred() {
        Ok(c) => c.uid(),
        Err(_) => {
            event(
                "alarm",
                json!({"alarm": "peer_cred_unavailable", "socket": "P"}),
            );
            return;
        }
    };
    if uid != adapter.cfg.broker_uid {
        // Close without any response (§1).
        event(
            "alarm",
            json!({"alarm": "peer_uid_mismatch", "socket": "P", "peer_uid": uid,
                   "expected_uid": adapter.cfg.broker_uid}),
        );
        return;
    }
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::with_capacity(MAX_LINE + 1, r);
    let mut buf = Vec::with_capacity(1024);
    let line = tokio::time::timeout(IDLE_TIMEOUT, read_line(&mut reader, &mut buf)).await;
    let resp = match line {
        Err(_) | Ok(Ok(false)) => return,
        Ok(Err(code)) => {
            let cid = adapter.ids.next();
            event(
                "p_request",
                json!({"correlation_id": cid, "outcome": code.as_str()}),
            );
            err_response(None, &cid, code)
        }
        Ok(Ok(true)) => adapter.handle_line(&buf).await,
    };
    write_value(&mut w, &resp).await;
}

/// Accept loop. Connections beyond `max_concurrent` are closed at once (not queued).
pub async fn serve(listener: UnixListener, adapter: Arc<Adapter>) {
    let limit = Arc::new(Semaphore::new(adapter.cfg.max_concurrent));
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            event(
                "p_overload",
                json!({"max_concurrent": adapter.cfg.max_concurrent}),
            );
            drop(stream);
            continue;
        };
        let a = adapter.clone();
        tokio::spawn(async move {
            handle_connection(stream, a).await;
            drop(permit);
        });
    }
}

/// Binds socket P (mode `0660`), removing only a stale socket at the path.
pub fn bind_socket(path: &Path) -> Result<UnixListener, String> {
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if m.file_type().is_socket() {
            std::fs::remove_file(path).map_err(|_| "cannot remove stale socket".to_string())?;
        } else {
            return Err(format!("{} exists and is not a socket", path.display()));
        }
    }
    let l = UnixListener::bind(path).map_err(|_| format!("cannot bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|_| "cannot chmod socket".to_string())?;
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope() {
        assert!(parse_envelope(br#"{"v":2,"id":"r1","op":"x","args":{}}"#).is_ok());
        let code = |s: &str| parse_envelope(s.as_bytes()).unwrap_err().1;
        assert_eq!(
            code(r#"{"v":1,"id":"r1","op":"x","args":{}}"#),
            Code::UnsupportedVersion
        );
        assert_eq!(
            code(r#"{"v":2,"id":"r1","op":"x","args":{},"x":1}"#),
            Code::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":2,"id":"r1","op":"x","op":"y","args":{}}"#),
            Code::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":2,"id":"r 1","op":"x","args":{}}"#),
            Code::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":2,"id":"r1","op":"x","args":[]}"#),
            Code::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":2.0,"id":"r1","op":"x","args":{}}"#),
            Code::MalformedRequest
        );
        assert_eq!(code(r#"[1]"#), Code::MalformedRequest);
        let m: Map<String, Value> = serde_json::from_str(r#"{"grant":"a","x":1}"#).unwrap();
        assert_eq!(exact_args(&m, &["grant"]), Err(Code::MalformedRequest));
        let m: Map<String, Value> = serde_json::from_str(r#"{"grant":1}"#).unwrap();
        assert_eq!(exact_args(&m, &["grant"]), Err(Code::MalformedRequest));
    }
}
