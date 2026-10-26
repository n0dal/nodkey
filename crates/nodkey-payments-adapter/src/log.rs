//! Structured logs: one JSON object per line on stdout. Callers pass only closed-enum values,
//! integers, ids and correlation ids; never secrets, idempotency keys, provider text or headers.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

pub fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

static SINK: OnceLock<fn(&str)> = OnceLock::new();

/// Redirects log lines (default: stdout). Settable once per process; the binary never calls it.
/// Tests use it to byte-search every log line for secrets and provider text.
pub fn set_sink(f: fn(&str)) -> bool {
    SINK.set(f).is_ok()
}

pub fn event(event: &str, fields: Value) {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut obj = json!({"ts_ms": ts_ms, "component": "payments-adapter", "event": event});
    if let (Some(o), Value::Object(e)) = (obj.as_object_mut(), fields) {
        o.extend(e);
    }
    match SINK.get() {
        Some(f) => f(&obj.to_string()),
        None => println!("{obj}"),
    }
}

/// Correlation ids `<prefix>-<counter>`; the prefix differs per process start.
#[derive(Debug)]
pub struct CorrelationIds {
    prefix: String,
    counter: AtomicU64,
}

impl CorrelationIds {
    pub fn new() -> CorrelationIds {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        CorrelationIds {
            prefix: format!("pa{:x}{:x}", t, std::process::id()),
            counter: AtomicU64::new(0),
        }
    }
    pub fn next(&self) -> String {
        format!(
            "{}-{:08x}",
            self.prefix,
            self.counter.fetch_add(1, Ordering::Relaxed)
        )
    }
}

impl Default for CorrelationIds {
    fn default() -> Self {
        Self::new()
    }
}
