//! Socket P client: broker → payments adapter (payments-adapter-v1 Draft 3 §1, §4).
//!
//! - One request per connection, effect-protocol-v2 framing (strict JSON line ≤ 8 KiB).
//! - The adapter's `SO_PEERCRED` uid must equal the configured `adapter_uid`; otherwise the
//!   connection is closed before any byte is written, and an alarm is raised.
//! - `ok:false` from the adapter means "no byte of a provider request was written". A lost or
//!   late response, a closed connection or an unparseable response is **ambiguous** (§1).
//! - Results are parsed strictly (exact member sets, closed enums). Anything else is ambiguous.
//!   Provider text never reaches the broker: the closed enums carry no free text.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::config::MAX_LINE_BYTES;
use crate::server::{Frame, log_event, read_frame};
use crate::strict_json;

pub const FORMAT: &str = "nodkey.payments-adapter.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refund {
    pub id: String,
    pub charge: String,
    pub amount_minor: u64,
    pub currency: String,
    pub reference: String,
    pub status: RefundStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundStatus {
    Pending,
    Succeeded,
    Failed,
}

impl RefundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RefundStatus::Pending => "pending",
            RefundStatus::Succeeded => "succeeded",
            RefundStatus::Failed => "failed",
        }
    }
}

/// `refund.create` result (§4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    Created { refund: Refund, reference: String },
    Refused { code: String, reference: String },
    Busy { reference: String },
    NotSent,
    Ambiguous { reference: Option<String> },
}

/// `refund.find` / `refund.get` result (§4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Found(Vec<Refund>),
    NotFound,
    Ambiguous,
}

/// `idem.status` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdemState {
    None,
    InProgress,
    Done,
    Ambiguous,
}

/// `adapter.hello` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub profile: String,
    pub caps: Vec<String>,
    pub idem_kid: String,
    pub r_max_s: u64,
    /// The adapter's per-request deadline from receipt (PC-A-02); must be below the broker's
    /// wait for a response.
    pub deadline_ms: u64,
}

impl Hello {
    pub fn has_cap(&self, c: &str) -> bool {
        self.caps.iter().any(|x| x == c)
    }
    /// The provider profile documents deduplication by idempotency key (ADR-0006 7a(1)).
    pub fn dedup_documented(&self) -> bool {
        matches!(self.profile.as_str(), "simpay" | "stripe")
    }
}

/// Outcome of one call on P.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `ok:true`; the `result` object.
    Result(Map<String, Value>),
    /// `ok:false` with a code: the adapter wrote no provider request byte for this call.
    Refused(String),
    /// Nothing was written to the adapter (connect or peer check failed before the request).
    NotDelivered(&'static str),
    /// The request may have reached the adapter; the outcome is unknown.
    Ambiguous(&'static str),
}

const REFUSAL_CODES: [&str; 11] = [
    "amount_too_large",
    "charge_already_refunded",
    "charge_not_refundable",
    "currency_mismatch",
    "resource_missing",
    "parameter_invalid",
    "idempotency_params_mismatch",
    "idempotency_key_invalid",
    "auth_failed",
    "permission_denied",
    "other_4xx",
];
/// Refusal codes that are business refusals (§7.3 step 3).
pub const BUSINESS_REFUSALS: [&str; 5] = [
    "amount_too_large",
    "charge_already_refunded",
    "charge_not_refundable",
    "currency_mismatch",
    "resource_missing",
];
const AMB_CAUSES: [&str; 12] = [
    "timeout",
    "reset_after_send",
    "http_5xx",
    "redirect",
    "bad_status",
    "bad_headers",
    "oversized",
    "bad_json",
    "bad_content_type",
    "echo_mismatch",
    "schema",
    "too_many_matches",
];

fn exact(o: &Map<String, Value>, keys: &[&str]) -> bool {
    o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k))
}

fn s<'a>(o: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    o.get(k).and_then(Value::as_str)
}

fn pattern_id(v: &str, prefix: &str, max: usize) -> bool {
    v.strip_prefix(prefix).is_some_and(|r| {
        (8..=max).contains(&r.len()) && r.bytes().all(|c| c.is_ascii_alphanumeric())
    })
}

/// `^ch_[A-Za-z0-9]{8,61}$` (spec §3.1, PA-19; BP-07).
pub fn is_charge_id(v: &str) -> bool {
    pattern_id(v, "ch_", 61)
}

/// `^re_[A-Za-z0-9]{8,64}$` (spec §5).
pub fn is_refund_id(v: &str) -> bool {
    pattern_id(v, "re_", 64)
}

fn is_reference(v: &str) -> bool {
    (1..=128).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'-'))
}

fn anomalies_ok(o: &Map<String, Value>) -> bool {
    match o.get("anomalies") {
        Some(Value::Array(a)) => {
            a.len() <= 16
                && a.iter().all(|x| {
                    x.as_str()
                        .is_some_and(|x| AMB_CAUSES.contains(&x) || x == "contradicts_request")
                })
        }
        _ => false,
    }
}

pub fn parse_refund(v: &Value) -> Option<Refund> {
    let o = v.as_object()?;
    if !exact(
        o,
        &[
            "id",
            "charge",
            "amount_minor",
            "currency",
            "reference",
            "status",
        ],
    ) {
        return None;
    }
    let id = s(o, "id").filter(|x| is_refund_id(x))?;
    let charge = s(o, "charge").filter(|x| is_charge_id(x))?;
    let amount = o["amount_minor"]
        .as_u64()
        .filter(|n| o["amount_minor"].is_u64() && (1..=999_999_999_999).contains(n))?;
    let currency =
        s(o, "currency").filter(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_uppercase()))?;
    let reference = s(o, "reference").filter(|r| is_reference(r))?;
    let status = match s(o, "status")? {
        "pending" => RefundStatus::Pending,
        "succeeded" => RefundStatus::Succeeded,
        "failed" => RefundStatus::Failed,
        _ => return None,
    };
    Some(Refund {
        id: id.into(),
        charge: charge.into(),
        amount_minor: amount,
        currency: currency.into(),
        reference: reference.into(),
        status,
    })
}

pub fn parse_attempt(o: &Map<String, Value>) -> Option<Attempt> {
    if !anomalies_ok(o) {
        return None;
    }
    let reference = || {
        s(o, "reference")
            .filter(|r| is_reference(r))
            .map(str::to_owned)
    };
    Some(match s(o, "class")? {
        "created" if exact(o, &["class", "refund", "reference", "anomalies"]) => Attempt::Created {
            refund: parse_refund(&o["refund"])?,
            reference: reference()?,
        },
        "refused" if exact(o, &["class", "code", "http", "reference", "anomalies"]) => {
            let code = s(o, "code").filter(|c| REFUSAL_CODES.contains(c))?;
            o["http"].as_u64().filter(|_| o["http"].is_u64())?;
            Attempt::Refused {
                code: code.into(),
                reference: reference()?,
            }
        }
        "busy" if exact(o, &["class", "cause", "reference", "anomalies"]) => {
            s(o, "cause").filter(|c| matches!(*c, "in_progress" | "rate_limited"))?;
            Attempt::Busy {
                reference: reference()?,
            }
        }
        "not_sent" if exact(o, &["class", "cause", "anomalies"]) => {
            s(o, "cause").filter(|c| matches!(*c, "connect" | "tls"))?;
            Attempt::NotSent
        }
        "ambiguous" if exact(o, &["class", "cause", "reference", "anomalies"]) => {
            s(o, "cause").filter(|c| AMB_CAUSES.contains(c))?;
            Attempt::Ambiguous {
                reference: Some(reference()?),
            }
        }
        _ => return None,
    })
}

pub fn parse_lookup(o: &Map<String, Value>) -> Option<Lookup> {
    if !anomalies_ok(o) {
        return None;
    }
    Some(match s(o, "class")? {
        "found" if exact(o, &["class", "refunds", "anomalies"]) => {
            let a = o["refunds"]
                .as_array()
                .filter(|a| !a.is_empty() && a.len() <= 3)?;
            Lookup::Found(a.iter().map(parse_refund).collect::<Option<Vec<_>>>()?)
        }
        "not_found" if exact(o, &["class", "anomalies"]) => Lookup::NotFound,
        "ambiguous" if exact(o, &["class", "cause", "anomalies"]) => {
            s(o, "cause").filter(|c| AMB_CAUSES.contains(c))?;
            Lookup::Ambiguous
        }
        _ => return None,
    })
}

pub fn parse_idem(o: &Map<String, Value>) -> Option<IdemState> {
    if !anomalies_ok(o) {
        return None;
    }
    Some(match s(o, "state")? {
        "none" if exact(o, &["state", "anomalies"]) => IdemState::None,
        "in_progress" if exact(o, &["state", "anomalies"]) => IdemState::InProgress,
        "done" if exact(o, &["state", "anomalies"]) => IdemState::Done,
        "ambiguous" if exact(o, &["state", "cause", "anomalies"]) => {
            s(o, "cause").filter(|c| AMB_CAUSES.contains(c))?;
            IdemState::Ambiguous
        }
        _ => return None,
    })
}

pub fn parse_hello(o: &Map<String, Value>) -> Option<Hello> {
    if !exact(
        o,
        &[
            "format",
            "profile",
            "caps",
            "idem_kid",
            "r_max_s",
            "deadline_ms",
        ],
    ) || s(o, "format")? != FORMAT
    {
        return None;
    }
    let profile = s(o, "profile")
        .filter(|p| (1..=32).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_lowercase()))?;
    let mut caps = Vec::new();
    for c in o["caps"].as_array()? {
        let c = c
            .as_str()
            .filter(|c| matches!(*c, "idem_status" | "send_currency"))?;
        if caps.iter().any(|x| x == c) {
            return None;
        }
        caps.push(c.to_owned());
    }
    let kid = s(o, "idem_kid").filter(|k| {
        k.len() == 16
            && k.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })?;
    let r_max_s = o["r_max_s"].as_u64().filter(|_| o["r_max_s"].is_u64())?;
    let deadline_ms = o["deadline_ms"]
        .as_u64()
        .filter(|n| o["deadline_ms"].is_u64() && *n >= 1)?;
    Some(Hello {
        profile: profile.into(),
        caps,
        idem_kid: kid.into(),
        r_max_s,
        deadline_ms,
    })
}

#[derive(Debug)]
pub struct AdapterClient {
    pub path: PathBuf,
    pub uid: u32,
    pub timeout: Duration,
    counter: AtomicU64,
}

impl AdapterClient {
    pub fn new(path: PathBuf, uid: u32, timeout: Duration) -> Self {
        AdapterClient {
            path,
            uid,
            timeout,
            counter: AtomicU64::new(0),
        }
    }

    pub async fn call(&self, op: &str, args: Value) -> Call {
        let stream =
            match tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&self.path))
                .await
            {
                Ok(Ok(s)) => s,
                _ => return Call::NotDelivered("connect"),
            };
        match stream.peer_cred() {
            Ok(c) if c.uid() == self.uid => {}
            Ok(c) => {
                log_event(
                    "alarm",
                    json!({"kind": "adapter_peer_uid_mismatch", "peer_uid": c.uid(), "expected_uid": self.uid}),
                );
                return Call::NotDelivered("peer uid");
            }
            Err(_) => return Call::NotDelivered("peer_cred"),
        }
        let id = format!("p-{}", self.counter.fetch_add(1, Ordering::Relaxed));
        let req = json!({"v": 2, "id": id, "op": op, "args": args});
        let mut line = req.to_string().into_bytes();
        line.push(b'\n');
        if line.len() > MAX_LINE_BYTES + 1 {
            return Call::NotDelivered("request too large");
        }
        let (r, mut w) = stream.into_split();
        let exchange = async {
            if w.write_all(&line).await.is_err() {
                return Err("write");
            }
            let mut reader = BufReader::with_capacity(MAX_LINE_BYTES + 1, r);
            let mut buf = Vec::new();
            match read_frame(&mut reader, MAX_LINE_BYTES, &mut buf).await {
                Ok(Frame::Line) => Ok(buf),
                _ => Err("read"),
            }
        };
        let buf = match tokio::time::timeout(self.timeout, exchange).await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Call::Ambiguous(e),
            Err(_) => return Call::Ambiguous("timeout"),
        };
        parse_response(&buf, &id)
    }

    pub async fn hello(&self) -> Option<Hello> {
        match self.call("adapter.hello", json!({})).await {
            Call::Result(o) => parse_hello(&o),
            _ => None,
        }
    }
}

/// Strict response envelope: `{"v":2,"id","correlation_id","ok","result"|"error":{"code","message"}}`.
pub fn parse_response(buf: &[u8], id: &str) -> Call {
    if strict_json::check_strict(buf).is_err() {
        return Call::Ambiguous("response json");
    }
    let Ok(Value::Object(o)) = serde_json::from_slice::<Value>(buf) else {
        return Call::Ambiguous("response type");
    };
    let ok = o.get("ok").and_then(Value::as_bool);
    let body = if ok == Some(true) { "result" } else { "error" };
    let corr_ok = s(&o, "correlation_id").is_some_and(|c| {
        (1..=64).contains(&c.len())
            && c.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    });
    if !exact(&o, &["v", "id", "correlation_id", "ok", body])
        || o["v"].as_u64() != Some(2)
        || s(&o, "id") != Some(id)
        || !corr_ok
    {
        return Call::Ambiguous("response envelope");
    }
    match (ok, &o[body]) {
        (Some(true), Value::Object(r)) => Call::Result(r.clone()),
        (Some(false), Value::Object(e)) if exact(e, &["code", "message"]) => match s(e, "code") {
            Some(c)
                if (1..=32).contains(&c.len())
                    && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') =>
            {
                Call::Refused(c.to_owned())
            }
            _ => Call::Ambiguous("error code"),
        },
        _ => Call::Ambiguous("response body"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn refund() -> Value {
        json!({"id":"re_abcdefgh12","charge":"ch_demoorder0001","amount_minor":500,"currency":"USD",
               "reference":"ref-1","status":"succeeded"})
    }

    #[test]
    fn attempt_parsing_is_strict() {
        let ok =
            obj(json!({"class":"created","refund":refund(),"reference":"ref-1","anomalies":[]}));
        assert!(matches!(parse_attempt(&ok), Some(Attempt::Created { .. })));
        for bad in [
            json!({"class":"created","refund":refund(),"reference":"ref-1"}),
            json!({"class":"created","refund":refund(),"reference":"ref-1","anomalies":[],"msg":"x"}),
            json!({"class":"created","refund":refund(),"reference":"ref 1","anomalies":[]}),
            json!({"class":"created","refund":refund(),"reference":"ref-1","anomalies":["free text"]}),
            json!({"class":"refused","code":"provider says no","http":400,"reference":"r","anomalies":[]}),
            json!({"class":"refused","code":"amount_too_large","http":-1,"reference":"r","anomalies":[]}),
            json!({"class":"busy","cause":"other","reference":"r","anomalies":[]}),
            json!({"class":"not_sent","cause":"dns","anomalies":[]}),
            json!({"class":"success","anomalies":[]}),
        ] {
            assert_eq!(parse_attempt(&obj(bad.clone())), None, "{bad}");
        }
        let mut r = refund();
        r["amount_minor"] = json!(0);
        assert_eq!(parse_refund(&r), None);
        let mut r = refund();
        r["id"] = json!("re_x");
        assert_eq!(parse_refund(&r), None);
        let mut r = refund();
        r["note"] = json!("hi");
        assert_eq!(parse_refund(&r), None);
        assert_eq!(
            parse_attempt(&obj(
                json!({"class":"not_sent","cause":"tls","anomalies":[]})
            )),
            Some(Attempt::NotSent)
        );
    }

    #[test]
    fn lookup_hello_idem() {
        assert_eq!(
            parse_lookup(&obj(json!({"class":"not_found","anomalies":[]}))),
            Some(Lookup::NotFound)
        );
        assert!(parse_lookup(&obj(json!({"class":"found","refunds":[],"anomalies":[]}))).is_none());
        assert!(matches!(
            parse_lookup(&obj(
                json!({"class":"found","refunds":[refund()],"anomalies":[]})
            )),
            Some(Lookup::Found(_))
        ));
        assert_eq!(
            parse_idem(&obj(json!({"state":"done","anomalies":[]}))),
            Some(IdemState::Done)
        );
        assert_eq!(parse_idem(&obj(json!({"state":"done"}))), None);
        let h = obj(
            json!({"format":FORMAT,"profile":"simpay","caps":["idem_status"],"idem_kid":"0123456789abcdef","r_max_s":180,"deadline_ms":400}),
        );
        let h = parse_hello(&h).unwrap();
        assert!(h.has_cap("idem_status") && h.dedup_documented());
        assert_eq!(h.deadline_ms, 400);
        assert!(parse_hello(&obj(json!({"format":FORMAT,"profile":"simpay","caps":["x"],"idem_kid":"0123456789abcdef","r_max_s":180,"deadline_ms":400}))).is_none());
        assert!(parse_hello(&obj(json!({"format":FORMAT,"profile":"simpay","caps":[],"idem_kid":"0123456789ABCDEF","r_max_s":180,"deadline_ms":400}))).is_none());
        // Draft 3 hello without deadline_ms is refused.
        assert!(parse_hello(&obj(json!({"format":FORMAT,"profile":"simpay","caps":[],"idem_kid":"0123456789abcdef","r_max_s":180}))).is_none());
    }

    #[test]
    fn response_envelope() {
        let r = br#"{"v":2,"id":"p-1","correlation_id":"c1","ok":true,"result":{"a":1}}"#;
        assert!(matches!(parse_response(r, "p-1"), Call::Result(_)));
        assert!(matches!(parse_response(r, "p-2"), Call::Ambiguous(_)));
        let e = br#"{"v":2,"id":"p-1","correlation_id":"c1","ok":false,"error":{"code":"grant_refused","message":"m"}}"#;
        assert_eq!(
            parse_response(e, "p-1"),
            Call::Refused("grant_refused".into())
        );
        let dup = br#"{"v":2,"id":"p-1","id":"p-1","correlation_id":"c1","ok":true,"result":{}}"#;
        assert!(matches!(parse_response(dup, "p-1"), Call::Ambiguous(_)));
        let extra = br#"{"v":2,"id":"p-1","correlation_id":"c1","ok":true,"result":{},"x":1}"#;
        assert!(matches!(parse_response(extra, "p-1"), Call::Ambiguous(_)));
    }

    #[test]
    fn id_patterns() {
        assert!(is_charge_id("ch_demoorder0001"));
        for bad in [
            "unresolved",
            "ch_x",
            "ch_abc/def12",
            "ch_abcdefgh?x=1",
            "ch_",
            "CH_abcdefgh",
        ] {
            assert!(!is_charge_id(bad), "{bad}");
        }
        // BP-07: 8..=61 characters after the prefix.
        assert!(is_charge_id(&format!("ch_{}", "a".repeat(61))));
        assert!(!is_charge_id(&format!("ch_{}", "a".repeat(62))));
        assert!(!is_charge_id("ch_abcdefg"));
        assert!(is_refund_id(&format!("re_{}", "a".repeat(64))));
        assert!(!is_refund_id(&format!("re_{}", "a".repeat(65))));
    }
}
