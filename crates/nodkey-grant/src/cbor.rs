//! Strict, bounded decoder and canonical encoder for the CBOR subset of spec §4.
//!
//! Accepted subset: unsigned integers (major 0), negative integers (major 1, only where the
//! profile allows), byte strings (2), text strings (3), arrays (4) and maps (5), all with definite
//! lengths and shortest-form heads. Tags (6) and major type 7 (floats, simple values, `break`) are
//! always rejected. Map keys must be in strictly increasing bytewise order of their encodings.
//!
//! The decoder never allocates more than the input can justify (C9) and recurses at most
//! `max_depth` levels (C10), so its work is linear in the input length.

use std::fmt;

/// A decoded CBOR item borrowing from the input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    Uint(u64),
    /// Negative integer `-1 - n`, stored as `n`.
    Nint(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Value<'a>>),
    Map(Vec<(Value<'a>, Value<'a>)>),
}

/// Which item is being decoded (spec §4.2).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Profile {
    pub allow_negative: bool,
    pub max_depth: usize,
}

pub(crate) const ENVELOPE: Profile = Profile {
    allow_negative: true,
    max_depth: 4,
};
pub(crate) const HEADER: Profile = Profile {
    allow_negative: true,
    max_depth: 1,
};
pub(crate) const PAYLOAD: Profile = Profile {
    allow_negative: false,
    max_depth: 3,
};

/// Decoding failure. The rule that failed is kept for diagnostics only; every failure maps to the
/// single error code of the item being decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// C1: input ends inside an item, or is empty.
    Truncated,
    /// C1: bytes remain after the item.
    TrailingBytes,
    /// C2: a head is not in shortest form.
    NonMinimal,
    /// C3/C4: indefinite length or reserved additional information.
    BadAdditionalInfo,
    /// C5: major type 7.
    MajorType7,
    /// C6: a tag.
    Tag,
    /// Negative integer where the profile forbids it.
    Negative,
    /// C7: text string is not UTF-8.
    InvalidUtf8,
    /// C8: map keys not strictly increasing.
    KeyOrder,
    /// C9: declared length exceeds remaining input.
    LengthExceedsInput,
    /// C10: nesting too deep.
    TooDeep,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Decodes exactly one item that consumes all of `input` (C1).
pub(crate) fn decode(input: &[u8], profile: Profile) -> Result<Value<'_>, DecodeError> {
    let mut d = Decoder {
        buf: input,
        pos: 0,
        profile,
    };
    let v = d.item(0)?;
    if d.pos != input.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(v)
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    profile: Profile,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self.buf.get(self.pos).ok_or(DecodeError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], DecodeError> {
        // C9: checked before any use of `n` as a size.
        if n > self.remaining() as u64 {
            return Err(DecodeError::LengthExceedsInput);
        }
        let n = n as usize;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn uint_be(&mut self, width: usize) -> Result<u64, DecodeError> {
        if width > self.remaining() {
            return Err(DecodeError::Truncated);
        }
        let mut v: u64 = 0;
        for _ in 0..width {
            v = (v << 8) | u64::from(self.byte()?);
        }
        Ok(v)
    }

    /// Reads a head; returns (major type, argument).
    fn head(&mut self) -> Result<(u8, u64), DecodeError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major == 7 {
            return Err(DecodeError::MajorType7);
        }
        if major == 6 {
            return Err(DecodeError::Tag);
        }
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = self.uint_be(1)?;
                if v < 24 {
                    return Err(DecodeError::NonMinimal);
                }
                v
            }
            25 => {
                let v = self.uint_be(2)?;
                if v <= 0xff {
                    return Err(DecodeError::NonMinimal);
                }
                v
            }
            26 => {
                let v = self.uint_be(4)?;
                if v <= 0xffff {
                    return Err(DecodeError::NonMinimal);
                }
                v
            }
            27 => {
                let v = self.uint_be(8)?;
                if v <= 0xffff_ffff {
                    return Err(DecodeError::NonMinimal);
                }
                v
            }
            _ => return Err(DecodeError::BadAdditionalInfo),
        };
        Ok((major, arg))
    }

    fn item(&mut self, depth: usize) -> Result<Value<'a>, DecodeError> {
        let (major, arg) = self.head()?;
        match major {
            0 => Ok(Value::Uint(arg)),
            1 => {
                if self.profile.allow_negative {
                    Ok(Value::Nint(arg))
                } else {
                    Err(DecodeError::Negative)
                }
            }
            2 => Ok(Value::Bytes(self.take(arg)?)),
            3 => {
                let raw = self.take(arg)?;
                core::str::from_utf8(raw)
                    .map(Value::Text)
                    .map_err(|_| DecodeError::InvalidUtf8)
            }
            4 => {
                let depth = self.enter(depth, arg, 1)?;
                // Bounded by the remaining input (checked in `enter`).
                let mut items = Vec::with_capacity(arg as usize);
                for _ in 0..arg {
                    items.push(self.item(depth)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let depth = self.enter(depth, arg, 2)?;
                let mut entries = Vec::with_capacity(arg as usize);
                let mut prev_key: Option<&'a [u8]> = None;
                for _ in 0..arg {
                    let start = self.pos;
                    let k = self.item(depth)?;
                    let key_bytes = &self.buf[start..self.pos];
                    if let Some(p) = prev_key {
                        if p >= key_bytes {
                            return Err(DecodeError::KeyOrder);
                        }
                    }
                    prev_key = Some(key_bytes);
                    let v = self.item(depth)?;
                    entries.push((k, v));
                }
                Ok(Value::Map(entries))
            }
            // Majors 6 and 7 were rejected in `head`.
            _ => Err(DecodeError::Tag),
        }
    }

    /// Checks depth (C10) and that `count` elements of at least `min_bytes` each can fit (C9).
    fn enter(&self, depth: usize, count: u64, min_bytes: u64) -> Result<usize, DecodeError> {
        let depth = depth + 1;
        if depth > self.profile.max_depth {
            return Err(DecodeError::TooDeep);
        }
        if count.saturating_mul(min_bytes) > self.remaining() as u64 {
            return Err(DecodeError::LengthExceedsInput);
        }
        Ok(depth)
    }
}

/// Encoding failure (only possible for maps with duplicate keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DuplicateKey;

/// Writes a shortest-form head.
pub(crate) fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Encodes `v` with the core deterministic encoding (RFC 8949 §4.2.1): shortest heads, definite
/// lengths, map entries sorted by the bytewise order of their encoded keys.
pub(crate) fn encode(v: &Value<'_>, out: &mut Vec<u8>) -> Result<(), DuplicateKey> {
    match v {
        Value::Uint(n) => write_head(out, 0, *n),
        Value::Nint(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            write_head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for i in items {
                encode(i, out)?;
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let mut kb = Vec::new();
                encode(k, &mut kb)?;
                let mut vb = Vec::new();
                encode(val, &mut vb)?;
                encoded.push((kb, vb));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(DuplicateKey);
            }
            write_head(out, 5, encoded.len() as u64);
            for (kb, vb) in encoded {
                out.extend_from_slice(&kb);
                out.extend_from_slice(&vb);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(b: &[u8]) -> Result<Value<'_>, DecodeError> {
        decode(b, ENVELOPE)
    }

    #[test]
    fn shortest_form_enforced() {
        assert_eq!(dec(&[0x18, 0x01]), Err(DecodeError::NonMinimal));
        assert_eq!(dec(&[0x18, 0x18]), Ok(Value::Uint(24)));
        assert_eq!(dec(&[0x19, 0x00, 0xff]), Err(DecodeError::NonMinimal));
        assert_eq!(dec(&[0x1a, 0, 0, 0xff, 0xff]), Err(DecodeError::NonMinimal));
        assert_eq!(
            dec(&[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]),
            Err(DecodeError::NonMinimal)
        );
        assert_eq!(
            dec(&[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
            Ok(Value::Uint(1 << 32))
        );
        assert_eq!(dec(&[0x98, 0x04, 0, 0, 0, 0]), Err(DecodeError::NonMinimal));
        assert_eq!(dec(&[0x78, 0x01, b'a']), Err(DecodeError::NonMinimal));
    }

    #[test]
    fn indefinite_reserved_and_major7_rejected() {
        for b in [0x5f, 0x7f, 0x9f, 0xbf, 0x1f] {
            assert_eq!(dec(&[b, 0xff]), Err(DecodeError::BadAdditionalInfo));
        }
        for b in [0x1c, 0x1d, 0x1e] {
            assert_eq!(dec(&[b]), Err(DecodeError::BadAdditionalInfo));
        }
        for b in [0xf4, 0xf5, 0xf6, 0xf7, 0xf9, 0xfa, 0xfb, 0xff, 0xe0] {
            assert_eq!(
                dec(&[b, 0, 0, 0, 0, 0, 0, 0, 0]),
                Err(DecodeError::MajorType7)
            );
        }
        assert_eq!(dec(&[0xc1, 0x00]), Err(DecodeError::Tag));
        assert_eq!(dec(&[0xd2, 0x80]), Err(DecodeError::Tag));
    }

    #[test]
    fn bounds_and_trailing() {
        assert_eq!(dec(&[]), Err(DecodeError::Truncated));
        assert_eq!(dec(&[0x00, 0x00]), Err(DecodeError::TrailingBytes));
        assert_eq!(
            dec(&[0x5a, 0xff, 0xff, 0xff, 0xff]),
            Err(DecodeError::LengthExceedsInput)
        );
        assert_eq!(
            dec(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(DecodeError::LengthExceedsInput)
        );
        assert_eq!(dec(&[0x19, 0x01]), Err(DecodeError::Truncated));
        assert_eq!(dec(&[0x62, 0xc3, 0x28]), Err(DecodeError::InvalidUtf8));
    }

    #[test]
    fn key_order_and_depth() {
        assert!(dec(&[0xa2, 0x00, 0x00, 0x01, 0x00]).is_ok());
        assert_eq!(
            dec(&[0xa2, 0x01, 0x00, 0x00, 0x00]),
            Err(DecodeError::KeyOrder)
        );
        assert_eq!(
            dec(&[0xa2, 0x00, 0x00, 0x00, 0x00]),
            Err(DecodeError::KeyOrder)
        );
        // Shorter text key sorts first: "b" (0x61 0x62) < "aa" (0x62 0x61 0x61).
        assert!(dec(&[0xa2, 0x61, b'b', 0x00, 0x62, b'a', b'a', 0x00]).is_ok());
        assert_eq!(decode(&[0x81, 0x80], HEADER), Err(DecodeError::TooDeep));
        assert!(decode(&[0x81, 0x81, 0x80], PAYLOAD).is_ok());
        assert_eq!(
            decode(&[0x81, 0x81, 0x81, 0x80], PAYLOAD),
            Err(DecodeError::TooDeep)
        );
        assert_eq!(decode(&[0x20], PAYLOAD), Err(DecodeError::Negative));
        assert_eq!(decode(&[0x32], HEADER), Ok(Value::Nint(18)));
    }

    #[test]
    fn encode_round_trip_sorted() {
        let v = Value::Map(vec![
            (Value::Uint(10), Value::Text("x")),
            (Value::Uint(1), Value::Nint(18)),
            (Value::Uint(4), Value::Bytes(&[1, 2])),
        ]);
        let mut out = Vec::new();
        encode(&v, &mut out).unwrap();
        assert_eq!(out, [0xa3, 0x01, 0x32, 0x04, 0x42, 1, 2, 0x0a, 0x61, b'x']);
        assert!(decode(&out, HEADER).is_ok());
        let dup = Value::Map(vec![
            (Value::Uint(1), Value::Uint(1)),
            (Value::Uint(1), Value::Uint(2)),
        ]);
        assert_eq!(encode(&dup, &mut Vec::new()), Err(DuplicateKey));
        for n in [
            0u64,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            1 << 32,
            u64::MAX,
        ] {
            let mut b = Vec::new();
            write_head(&mut b, 0, n);
            assert_eq!(decode(&b, PAYLOAD), Ok(Value::Uint(n)));
        }
    }
}
