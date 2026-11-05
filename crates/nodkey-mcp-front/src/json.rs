// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! A small strict JSON parser (RFC 8259) for messages that cross the front.
//!
//! Why not `serde_json::Value` directly: it keeps the last of duplicate members, and it loses the
//! lexical form of numbers (`1.0`, `1e3`, `-0` and `1` become indistinguishable or are coerced).
//! agent-interface-v1 §2.4 requires rejecting both. This parser:
//! - rejects duplicate member names at any depth (compared after unescaping);
//! - keeps every number as its exact source text ([`J::Num`]); [`J::as_uint`] accepts only
//!   `0|[1-9][0-9]*` up to 2^53 − 1;
//! - rejects lone surrogates, unescaped control characters, trailing data, and nesting deeper
//!   than [`MAX_DEPTH`].
//!
//! Input size is bounded by the callers (64 KiB per line).

use serde_json::{Map, Value};

/// Maximum nesting depth of arrays and objects.
pub const MAX_DEPTH: usize = 32;

/// 2^53 − 1, the largest `uint` (grant-v1 §6.2).
pub const MAX_UINT: u64 = 9_007_199_254_740_991;

/// A parsed JSON value. Objects keep member order; names are unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum J {
    Null,
    Bool(bool),
    /// The number's exact source text.
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn get(&self, k: &str) -> Option<&J> {
        match self {
            J::Obj(m) => m.iter().find(|(n, _)| n == k).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            J::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&[(String, J)]> {
        match self {
            J::Obj(m) => Some(m),
            _ => None,
        }
    }

    /// A non-negative integer written without sign, fraction, exponent or leading zero, at most
    /// 2^53 − 1. Anything else is `None` (no coercion).
    pub fn as_uint(&self) -> Option<u64> {
        let J::Num(t) = self else { return None };
        let b = t.as_bytes();
        if b.is_empty() || b.len() > 16 || !b.iter().all(u8::is_ascii_digit) {
            return None;
        }
        if b.len() > 1 && b[0] == b'0' {
            return None;
        }
        t.parse::<u64>().ok().filter(|n| *n <= MAX_UINT)
    }

    /// Converts to `serde_json::Value`. Numbers must be `uint`s (see [`J::as_uint`]); any other
    /// number makes the conversion fail, so nothing is coerced.
    pub fn to_value(&self) -> Option<Value> {
        Some(match self {
            J::Null => Value::Null,
            J::Bool(b) => Value::Bool(*b),
            J::Num(_) => Value::from(self.as_uint()?),
            J::Str(s) => Value::String(s.clone()),
            J::Arr(a) => Value::Array(a.iter().map(J::to_value).collect::<Option<_>>()?),
            J::Obj(m) => {
                let mut o = Map::new();
                for (k, v) in m {
                    o.insert(k.clone(), v.to_value()?);
                }
                Value::Object(o)
            }
        })
    }
}

/// Why a document was rejected (for tests and logs; never sent to a peer verbatim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub &'static str);

/// Parses exactly one JSON value from `input` (surrounding whitespace allowed).
pub fn parse(input: &[u8]) -> Result<J, ParseError> {
    let text = std::str::from_utf8(input).map_err(|_| ParseError("invalid utf-8"))?;
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(ParseError("trailing data"));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.i += 1;
        }
    }

    fn lit(&mut self, word: &[u8], v: J) -> Result<J, ParseError> {
        if self.s[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(ParseError("invalid literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<J, ParseError> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(J::Str(self.string()?)),
            Some(b't') => self.lit(b"true", J::Bool(true)),
            Some(b'f') => self.lit(b"false", J::Bool(false)),
            Some(b'n') => self.lit(b"null", J::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(ParseError("unexpected character")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<J, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError("too deep"));
        }
        self.i += 1;
        let mut members: Vec<(String, J)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(J::Obj(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(ParseError("expected member name"));
            }
            let k = self.string()?;
            if members.iter().any(|(n, _)| *n == k) {
                return Err(ParseError("duplicate member name"));
            }
            self.ws();
            if self.peek() != Some(b':') {
                return Err(ParseError("expected ':'"));
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth)?;
            members.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(J::Obj(members));
                }
                _ => return Err(ParseError("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<J, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError("too deep"));
        }
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(J::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(J::Arr(items));
                }
                _ => return Err(ParseError("expected ',' or ']'")),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while let Some(b'0'..=b'9') = self.peek() {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<J, ParseError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if let Some(b'0'..=b'9') = self.peek() {
                    return Err(ParseError("leading zero"));
                }
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(ParseError("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err(ParseError("invalid fraction"));
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.i += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(ParseError("invalid exponent"));
            }
        }
        // The slice is ASCII by construction.
        let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| ParseError("number"))?;
        Ok(J::Num(text.to_owned()))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let h = self
            .s
            .get(self.i..self.i + 4)
            .ok_or(ParseError("short \\u escape"))?;
        let mut n = 0u32;
        for &c in h {
            let d = (c as char)
                .to_digit(16)
                .ok_or(ParseError("bad \\u escape"))?;
            n = n * 16 + d;
        }
        self.i += 4;
        Ok(n)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            // Input is valid UTF-8 and we stopped on an ASCII byte, so this is a char boundary.
            out.push_str(
                std::str::from_utf8(&self.s[start..self.i]).map_err(|_| ParseError("utf-8"))?,
            );
            match self.peek() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let e = self.peek().ok_or(ParseError("unterminated escape"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(ParseError("lone surrogate"));
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(ParseError("lone surrogate"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(ParseError("lone surrogate"));
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or(ParseError("bad code point"))?);
                        }
                        _ => return Err(ParseError("bad escape")),
                    }
                }
                Some(_) => return Err(ParseError("control character in string")),
                None => return Err(ParseError("unterminated string")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_keeps_number_text() {
        let v = parse(br#" {"a":[1,-2,3.5,1e3,0,null,true,"x\u00e9\ud83d\ude00"]} "#).unwrap();
        let a = v.get("a").unwrap();
        let J::Arr(items) = a else { panic!() };
        assert_eq!(items[0].as_uint(), Some(1));
        assert_eq!(items[1], J::Num("-2".into()));
        assert_eq!(items[3], J::Num("1e3".into()));
        assert_eq!(items[4].as_uint(), Some(0));
        assert_eq!(items[7].as_str(), Some("x\u{e9}\u{1F600}"));
    }

    #[test]
    fn uint_rules() {
        for (t, ok) in [
            ("0", Some(0)),
            ("9007199254740991", Some(MAX_UINT)),
            ("9007199254740992", None),
            ("1.0", None),
            ("1e3", None),
            ("-0", None),
            ("-1", None),
            ("10000000000000000000", None),
        ] {
            assert_eq!(parse(t.as_bytes()).unwrap().as_uint(), ok, "{t}");
        }
    }

    #[test]
    fn rejections() {
        for bad in [
            &b"01"[..],
            b"{\"a\":1,\"a\":2}",
            b"{\"a\":1,\"\\u0061\":2}",
            b"{\"a\":{\"b\":1,\"b\":1}}",
            b"[1,]",
            b"{\"a\":1,}",
            b"\"\\ud800\"",
            b"\"\\udc00\"",
            b"\"a\x01\"",
            b"\"\xff\"",
            b"{} {}",
            b"1.",
            b".5",
            b"1e",
            b"+1",
            b"nul",
            b"'a'",
            b"",
        ] {
            assert!(parse(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let deep = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
        assert!(parse(deep.as_bytes()).is_err());
        let ok = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        assert!(parse(ok.as_bytes()).is_ok());
    }
}
