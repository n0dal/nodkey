// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Client for the agent's broker socket W (effect-protocol-v2 §2.2, §2.3).
//!
//! One connection per call: connect, check the listener's uid, send one envelope, read one line,
//! close. The broker closes idle connections after 10 s, so a fresh connection avoids any stale
//! state; every call here is either read-only (`effect.status`, reads) or creates a new record
//! (`effect.propose`), and none is retried by this client.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::json::{self, J};

/// Largest broker request line (broker `MAX_LINE_BYTES`, effect-protocol-v2 §1.2).
pub const MAX_REQUEST: usize = 8 * 1024;
/// Largest broker response line accepted.
pub const MAX_RESPONSE: usize = 64 * 1024;

/// Client-facing broker error codes (effect-protocol-v2 §2.6). Anything else is `unavailable`.
pub const CODES: [&str; 10] = [
    "malformed_request",
    "unsupported_version",
    "request_too_large",
    "unknown_operation",
    "operation_not_permitted",
    "invalid_argument",
    "limit_exceeded",
    "not_found",
    "grant_denied",
    "unavailable",
];

/// Outcome of one call.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// `ok: true`; the `result` object.
    Ok(J),
    /// `ok: false`; the error code, mapped onto [`CODES`].
    Err(&'static str),
}

pub struct BrokerClient {
    path: PathBuf,
    uid: u32,
    timeout: Duration,
    next: AtomicU64,
}

fn known(code: &str) -> &'static str {
    CODES
        .iter()
        .find(|c| **c == code)
        .copied()
        .unwrap_or("unavailable")
}

impl BrokerClient {
    pub fn new(path: PathBuf, uid: u32, timeout: Duration) -> BrokerClient {
        BrokerClient {
            path,
            uid,
            timeout,
            next: AtomicU64::new(1),
        }
    }

    /// Sends `{v:2, id, op, args}` and returns the broker's answer. Transport failures, a wrong
    /// listener uid, a malformed or mismatched response are all `Err("unavailable")`.
    pub async fn call(&self, op: &str, args: Value) -> Reply {
        let id = format!("mcp-{}", self.next.fetch_add(1, Ordering::Relaxed));
        let line = json!({"v": 2, "id": id, "op": op, "args": args}).to_string();
        if line.len() > MAX_REQUEST {
            return Reply::Err("request_too_large");
        }
        match tokio::time::timeout(self.timeout, self.exchange(line)).await {
            Ok(Some(resp)) => parse_reply(&resp, &id),
            _ => Reply::Err("unavailable"),
        }
    }

    async fn exchange(&self, mut line: String) -> Option<Vec<u8>> {
        let stream = UnixStream::connect(&self.path).await.ok()?;
        if stream.peer_cred().ok()?.uid() != self.uid {
            return None;
        }
        let (r, mut w) = stream.into_split();
        line.push('\n');
        w.write_all(line.as_bytes()).await.ok()?;
        let mut reader = BufReader::new(r).take(MAX_RESPONSE as u64 + 1);
        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).await.ok()?;
        if buf.pop() != Some(b'\n') {
            return None;
        }
        Some(buf)
    }
}

fn parse_reply(line: &[u8], id: &str) -> Reply {
    let Ok(v) = json::parse(line) else {
        return Reply::Err("unavailable");
    };
    if v.get("v").and_then(J::as_uint) != Some(2) || v.get("id").and_then(J::as_str) != Some(id) {
        return Reply::Err("unavailable");
    }
    match (v.get("ok"), v.get("result"), v.get("error")) {
        (Some(J::Bool(true)), Some(r @ J::Obj(_)), None) => Reply::Ok(r.clone()),
        (Some(J::Bool(false)), None, Some(e)) => match e.get("code").and_then(J::as_str) {
            Some(c) => Reply::Err(known(c)),
            None => Reply::Err("unavailable"),
        },
        _ => Reply::Err("unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_parsing() {
        let ok = br#"{"v":2,"id":"mcp-1","correlation_id":"c","ok":true,"result":{"a":1}}"#;
        assert!(matches!(parse_reply(ok, "mcp-1"), Reply::Ok(_)));
        assert_eq!(parse_reply(ok, "mcp-2"), Reply::Err("unavailable"));
        let e = br#"{"v":2,"id":"mcp-1","correlation_id":"c","ok":false,"error":{"code":"grant_denied","message":"x"}}"#;
        assert_eq!(parse_reply(e, "mcp-1"), Reply::Err("grant_denied"));
        let odd = br#"{"v":2,"id":"mcp-1","ok":false,"error":{"code":"made_up","message":"x"}}"#;
        assert_eq!(parse_reply(odd, "mcp-1"), Reply::Err("unavailable"));
        let dup = br#"{"v":2,"id":"mcp-1","ok":true,"ok":false,"result":{}}"#;
        assert_eq!(parse_reply(dup, "mcp-1"), Reply::Err("unavailable"));
        let both = br#"{"v":2,"id":"mcp-1","ok":true,"result":{},"error":{"code":"x"}}"#;
        assert_eq!(parse_reply(both, "mcp-1"), Reply::Err("unavailable"));
    }
}
