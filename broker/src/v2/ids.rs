// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Identifiers: `pending_id` and `receipt_id` are 16 bytes from the OS CSPRNG, written as
//! canonical unpadded base64url (22 characters). Parsing is canonical: aliases with non-zero
//! trailing bits are rejected, never normalized (spec §3.2 key 0).

use std::io::Read;

/// 16 bytes from the operating system CSPRNG.
pub fn random16() -> std::io::Result<[u8; 16]> {
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

pub fn encode_id(b: &[u8; 16]) -> String {
    nodkey_grant::encode_transport(b)
}

/// Canonical decode of a 22-character base64url id. `None` for any other text.
pub fn decode_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 22 {
        return None;
    }
    let v = nodkey_grant::decode_transport(Some(s)).ok()?;
    <[u8; 16]>::try_from(v.as_slice()).ok()
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// Exactly 64 lowercase hex characters (spec §3.2 "Hex digest"). Uppercase is rejected.
pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

/// An ID per grant-v1 §5.1: bytes 0x21–0x7E, length 1..=max.
pub fn is_id(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| (0x21..=0x7e).contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_roundtrip_and_canonical() {
        let b = [
            0xfb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let s = encode_id(&b);
        assert_eq!(s, "-xEiM0RVZneImaq7zN3u_w");
        assert_eq!(decode_id(&s), Some(b));
        // Alias with a non-zero trailing bit (DG-07).
        assert_eq!(decode_id("-xEiM0RVZneImaq7zN3u_x"), None);
        for bad in [
            "",
            "-xEiM0RVZneImaq7zN3u_",
            "-xEiM0RVZneImaq7zN3u_w=",
            "-xEiM0RVZneImaq7zN3u_ww",
            "+xEiM0RVZneImaq7zN3u_w",
            "-xEiM0RVZneImaq7zN3u/w",
            " xEiM0RVZneImaq7zN3u_w",
        ] {
            assert_eq!(decode_id(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn random_ids_differ() {
        assert_ne!(random16().unwrap(), random16().unwrap());
    }

    #[test]
    fn hex_rules() {
        let d = [0xabu8; 32];
        let h = hex(&d);
        assert_eq!(parse_hex32(&h), Some(d));
        assert_eq!(parse_hex32(&h.to_uppercase()), None);
        assert_eq!(parse_hex32(&h[..62]), None);
        assert_eq!(parse_hex32(&format!("{h}0")), None);
        assert_eq!(parse_hex32(&h.replace('a', "g")), None);
    }

    #[test]
    fn id_grammar() {
        assert!(is_id("user:u-17", 256));
        assert!(!is_id("", 256));
        assert!(!is_id("a b", 256));
        assert!(!is_id("user:u-\u{e9}", 256));
        assert!(!is_id(&"a".repeat(129), 128));
        assert!(is_id(&"a".repeat(128), 128));
    }
}
