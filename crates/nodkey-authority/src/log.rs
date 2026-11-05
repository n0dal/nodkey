// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Structured JSON log lines on stdout. Callers never pass key material or grant bytes; fields
//! are identifiers, digests, codes and static reasons only.

use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn event(event: &str, fields: Value) {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut obj = json!({"ts_ms": ts_ms, "event": event});
    if let (Some(o), Value::Object(e)) = (obj.as_object_mut(), fields) {
        o.extend(e);
    }
    // AU-R-06: never panic on a closed or broken stdout (`println!` would); a lost log line
    // must not abort a task between a durable insert and its delivery.
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{obj}");
}

/// An event that needs operator attention (§4.2 step 4 "raises an alarm", §4.3 match failures).
pub fn alarm(event_name: &str, mut fields: Value) {
    if let Value::Object(o) = &mut fields {
        o.insert("alarm".into(), Value::Bool(true));
    }
    event(event_name, fields);
}
