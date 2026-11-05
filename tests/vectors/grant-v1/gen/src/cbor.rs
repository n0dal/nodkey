// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Minimal CBOR encoder (deterministic by construction unless the caller injects raw bytes) and a
//! strict decoder implementing the Nodkey-Grant v1 decoding rules (spec §4.1):
//! RFC 8949 §4.2.1 core deterministic encoding, definite lengths only, no major type 7
//! (floats, simple values, break), optional negative integers and tags, bounded depth,
//! no trailing bytes, map keys strictly increasing in bytewise order of their encodings.

/// Encodes a CBOR head with the shortest argument encoding.
pub fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    if n < 24 {
        vec![m | n as u8]
    } else if n <= 0xff {
        vec![m | 24, n as u8]
    } else if n <= 0xffff {
        let mut v = vec![m | 25];
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![m | 26];
        v.extend_from_slice(&(n as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![m | 27];
        v.extend_from_slice(&n.to_be_bytes());
        v
    }
}

pub fn uint(n: u64) -> Vec<u8> {
    head(0, n)
}

/// Encodes a negative integer `n` (< 0).
pub fn nint(n: i64) -> Vec<u8> {
    assert!(n < 0);
    head(1, (-1 - n) as u64)
}

pub fn bstr(b: &[u8]) -> Vec<u8> {
    let mut v = head(2, b.len() as u64);
    v.extend_from_slice(b);
    v
}

pub fn tstr(s: &str) -> Vec<u8> {
    let mut v = head(3, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    v
}

pub fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = head(4, items.len() as u64);
    for i in items {
        v.extend_from_slice(i);
    }
    v
}

/// Encodes a map with entries in the given order (no sorting; caller controls canonicality).
pub fn map_raw(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut v = head(5, entries.len() as u64);
    for (k, val) in entries {
        v.extend_from_slice(k);
        v.extend_from_slice(val);
    }
    v
}

/// Encodes a map with entries sorted by the bytewise order of the encoded keys (RFC 8949 §4.2.1).
pub fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut e = entries.to_vec();
    e.sort_by(|a, b| a.0.cmp(&b.0));
    for w in e.windows(2) {
        assert!(w[0].0 != w[1].0, "duplicate key in canonical map");
    }
    map_raw(&e)
}

pub fn tag(t: u64, inner: &[u8]) -> Vec<u8> {
    let mut v = head(6, t);
    v.extend_from_slice(inner);
    v
}

#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Uint(u64),
    /// Negative integer with value `-1 - n`.
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Item>),
    Map(Vec<(Item, Item)>),
}

#[derive(Clone, Copy)]
pub struct Rules {
    pub allow_nint: bool,
    /// Maximum container nesting depth; a top-level array or map is depth 1.
    pub max_depth: usize,
}

struct Dec<'a> {
    b: &'a [u8],
    pos: usize,
    rules: Rules,
}

impl<'a> Dec<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        let x = *self.b.get(self.pos).ok_or("truncated")?;
        self.pos += 1;
        Ok(x)
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], String> {
        // Never allocate or slice from a declared length before checking it against the input.
        let remaining = (self.b.len() - self.pos) as u64;
        if n > remaining {
            return Err("declared length exceeds input".into());
        }
        let s = &self.b[self.pos..self.pos + n as usize];
        self.pos += n as usize;
        Ok(s)
    }

    /// Reads a head; returns (major, argument). Rejects non-minimal and indefinite encodings.
    fn head(&mut self) -> Result<(u8, u64), String> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major == 7 {
            return Err("major type 7 (float/simple/break) forbidden".into());
        }
        let n = match ai {
            0..=23 => ai as u64,
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err("non-minimal argument".into());
                }
                v
            }
            25 => {
                let s = self.take(2)?;
                let v = u16::from_be_bytes([s[0], s[1]]) as u64;
                if v <= 0xff {
                    return Err("non-minimal argument".into());
                }
                v
            }
            26 => {
                let s = self.take(4)?;
                let v = u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64;
                if v <= 0xffff {
                    return Err("non-minimal argument".into());
                }
                v
            }
            27 => {
                let s = self.take(8)?;
                let v = u64::from_be_bytes(s.try_into().unwrap());
                if v <= 0xffff_ffff {
                    return Err("non-minimal argument".into());
                }
                v
            }
            31 => return Err("indefinite length forbidden".into()),
            _ => return Err("reserved additional information".into()),
        };
        Ok((major, n))
    }

    fn item(&mut self, depth: usize) -> Result<Item, String> {
        let (major, n) = self.head()?;
        match major {
            0 => Ok(Item::Uint(n)),
            1 => {
                if self.rules.allow_nint {
                    Ok(Item::Nint(n))
                } else {
                    Err("negative integer forbidden".into())
                }
            }
            2 => Ok(Item::Bytes(self.take(n)?.to_vec())),
            3 => {
                let s = self.take(n)?;
                let t = std::str::from_utf8(s).map_err(|_| "invalid UTF-8")?;
                Ok(Item::Text(t.to_owned()))
            }
            4 => {
                if depth + 1 > self.rules.max_depth {
                    return Err("nesting too deep".into());
                }
                // Each element takes at least one byte; reject impossible counts before allocating.
                if n > (self.b.len() - self.pos) as u64 {
                    return Err("declared length exceeds input".into());
                }
                let mut v = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    v.push(self.item(depth + 1)?);
                }
                Ok(Item::Array(v))
            }
            5 => {
                if depth + 1 > self.rules.max_depth {
                    return Err("nesting too deep".into());
                }
                if n > (self.b.len() - self.pos) as u64 / 2 {
                    return Err("declared length exceeds input".into());
                }
                let mut v = Vec::with_capacity(n as usize);
                let mut prev: Option<&[u8]> = None;
                for _ in 0..n {
                    let start = self.pos;
                    let k = self.item(depth + 1)?;
                    let kbytes = &self.b[start..self.pos];
                    if let Some(p) = prev
                        && kbytes <= p {
                            return Err("map keys not in strictly increasing bytewise order (or duplicate)".into());
                        }
                    prev = Some(kbytes);
                    let val = self.item(depth + 1)?;
                    v.push((k, val));
                }
                Ok(Item::Map(v))
            }
            6 => Err("tag forbidden".into()),
            _ => unreachable!(),
        }
    }
}

/// Strictly decodes exactly one data item occupying all of `input`.
pub fn decode(input: &[u8], rules: Rules) -> Result<Item, String> {
    let mut d = Dec { b: input, pos: 0, rules };
    let it = d.item(0)?;
    if d.pos != input.len() {
        return Err("trailing bytes".into());
    }
    Ok(it)
}

#[cfg(test)]
mod tests {
    use super::*;
    const R: Rules = Rules { allow_nint: true, max_depth: 4 };

    #[test]
    fn rejects_non_minimal_and_indefinite() {
        assert!(decode(&[0x18, 0x01], R).is_err());
        assert!(decode(&[0x19, 0x00, 0xff], R).is_err());
        assert!(decode(&[0x9f, 0xff], R).is_err());
        assert!(decode(&[0xbf, 0xff], R).is_err());
        assert!(decode(&[0xf9, 0x00, 0x00], R).is_err());
        assert!(decode(&[0xc1, 0x01], R).is_err());
        assert!(decode(&[0x01, 0x00], R).is_err());
        assert!(decode(&[0x5a, 0xff, 0xff, 0xff, 0xff], R).is_err());
    }

    #[test]
    fn rejects_unsorted_and_duplicate_keys() {
        assert!(decode(&[0xa2, 0x01, 0x00, 0x00, 0x00], R).is_err());
        assert!(decode(&[0xa2, 0x01, 0x00, 0x01, 0x00], R).is_err());
        assert_eq!(
            decode(&[0xa2, 0x00, 0x00, 0x01, 0x00], R).unwrap(),
            Item::Map(vec![(Item::Uint(0), Item::Uint(0)), (Item::Uint(1), Item::Uint(0))])
        );
    }

    #[test]
    fn roundtrip_heads() {
        for n in [0u64, 23, 24, 255, 256, 65535, 65536, 0xffff_ffff, 0x1_0000_0000, u64::MAX] {
            assert_eq!(decode(&uint(n), R).unwrap(), Item::Uint(n));
        }
    }
}
