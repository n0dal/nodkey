// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Framing and strict JSON shared by sockets I (gateway → authority) and A (authority → broker).
//!
//! effect-protocol-v2 §1.2: one strict JSON object per line; duplicate, unknown and wrongly typed
//! members are rejected; lines are at most 8 KiB; the v1 timeouts apply.

use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt};

pub const PROTOCOL_VERSION: u64 = 2;
/// Maximum line length in bytes, excluding the newline (§1.2).
pub const MAX_LINE: usize = 8 * 1024;
/// v1 broker timeouts (`broker/src/server.rs`).
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Parses `input` as exactly one JSON object, rejecting duplicate keys at any depth.
pub fn parse_strict_object(input: &[u8]) -> Result<Map<String, Value>, &'static str> {
    let mut de = serde_json::Deserializer::from_slice(input);
    NoDup::deserialize(&mut de).map_err(|_| "invalid or duplicate-key JSON")?;
    de.end().map_err(|_| "trailing data")?;
    match serde_json::from_slice::<Value>(input) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err("not a JSON object"),
    }
}

/// Requires the object's member set to be exactly `required` plus any subset of `optional`.
pub fn exact_members(
    o: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), &'static str> {
    for k in o.keys() {
        if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
            return Err("unknown member");
        }
    }
    if required.iter().any(|k| !o.contains_key(*k)) {
        return Err("missing member");
    }
    Ok(())
}

/// Request/response id: 1..=64 of `[A-Za-z0-9._-]` (§2.2).
pub fn is_request_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

struct NoDup;

impl<'de> Deserialize<'de> for NoDup {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDupVisitor)
    }
}

struct NoDupVisitor;

impl<'de> Visitor<'de> for NoDupVisitor {
    type Value = NoDup;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_i64<E>(self, _: i64) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_u64<E>(self, _: u64) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_f64<E>(self, _: f64) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_str<E>(self, _: &str) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_unit<E>(self) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NoDup, A::Error> {
        while seq.next_element::<NoDup>()?.is_some() {}
        Ok(NoDup)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NoDup, A::Error> {
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            map.next_value::<NoDup>()?;
        }
        Ok(NoDup)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Line,
    Eof,
    Incomplete,
    TooLarge,
}

/// Reads one newline-terminated frame of at most `max` bytes into `buf` (newline stripped).
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

/// Writes one JSON line with the write timeout. Returns false on failure or timeout.
pub async fn write_line(w: &mut (impl AsyncWriteExt + Unpin), v: &Value) -> bool {
    let mut bytes = v.to_string().into_bytes();
    bytes.push(b'\n');
    if bytes.len() > MAX_LINE + 1 {
        return false;
    }
    matches!(
        tokio::time::timeout(WRITE_TIMEOUT, w.write_all(&bytes)).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_object() {
        assert!(parse_strict_object(br#"{"a":1}"#).is_ok());
        assert!(parse_strict_object(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_strict_object(br#"{"a":{"b":1,"b":1}}"#).is_err());
        assert!(parse_strict_object(br#"[1]"#).is_err());
        assert!(parse_strict_object(br#"{"a":1} {}"#).is_err());
    }

    #[tokio::test]
    async fn frame_limits() {
        let mut ok = vec![b'a'; MAX_LINE];
        ok.push(b'\n');
        let mut r = tokio::io::BufReader::new(&ok[..]);
        let mut buf = vec![];
        assert_eq!(
            read_frame(&mut r, MAX_LINE, &mut buf).await.unwrap(),
            Frame::Line
        );
        let big = vec![b'a'; MAX_LINE + 1];
        let mut r = tokio::io::BufReader::new(&big[..]);
        assert_eq!(
            read_frame(&mut r, MAX_LINE, &mut buf).await.unwrap(),
            Frame::TooLarge
        );
    }
}
