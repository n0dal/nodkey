// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Small helpers: CSPRNG, canonical base64url, lowercase hex, time, HTML escaping, ID grammars.

use std::time::{SystemTime, UNIX_EPOCH};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Fills `buf` from the operating-system CSPRNG. Failure is fatal for the caller's operation
/// (returns `None`); nothing falls back to a weaker source.
pub fn random_bytes<const N: usize>() -> Option<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).ok()?;
    Some(b)
}

/// Unpadded base64url (RFC 4648 §5) of `bytes`.
pub fn b64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let (mut acc, mut n) = (0u32, 0u32);
    for x in bytes {
        acc = (acc << 8) | u32::from(*x);
        n += 8;
        while n >= 6 {
            n -= 6;
            out.push(B64[((acc >> n) & 63) as usize] as char);
            acc &= (1 << n) - 1;
        }
    }
    if n > 0 {
        out.push(B64[((acc << (6 - n)) & 63) as usize] as char);
    }
    out
}

/// Canonical unpadded base64url decode (grant-v1 §2 rules): alphabet only, no padding, the unused
/// trailing bits are zero, and the length is not `1 mod 4`. Non-canonical text is rejected.
pub fn b64url_decode_canonical(s: &str) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 {
        return None;
    }
    let (mut acc, mut n) = (0u32, 0u32);
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.bytes() {
        let v = B64.iter().position(|x| *x == c)? as u32;
        acc = (acc << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
            acc &= (1 << n) - 1;
        }
    }
    if acc != 0 {
        return None;
    }
    Some(out)
}

/// A canonical pending id: exactly 22 characters decoding canonically to 16 bytes.
pub fn decode_pending_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 22 {
        return None;
    }
    b64url_decode_canonical(s)?.try_into().ok()
}

pub fn hex_lower(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// Exactly 64 lowercase hex characters (spec §3.2 "Hex digest"); anything else is rejected.
pub fn parse_digest_hex(s: &str) -> Option<[u8; 32]> {
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
    for (i, pair) in b.chunks_exact(2).enumerate() {
        out[i] = (nib(pair[0])? << 4) | nib(pair[1])?;
    }
    Some(out)
}

/// Constant-time equality for fixed-size secrets and digests.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Unix seconds (floor). A clock before 1970 is treated as 0, which makes every expiry check fail
/// closed (nothing is "not yet expired" relative to a far-future record unless it truly is).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Spec §3.2 / grant-v1 §5.1 ID: 1..=max bytes of 0x21..=0x7E.
pub fn is_id(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| (0x21..=0x7e).contains(&c))
}

/// grant-v1 §5.1 operation name: `[a-z0-9_.]{1,64}`.
pub fn is_op_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'.')
}

/// Parameter / display key name: `[a-z0-9_]{1,64}`.
pub fn is_param_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Escapes text for HTML element content and double- or single-quoted attribute values.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// `YYYY-MM-DD HH:MM:SS UTC` for Unix seconds (proleptic Gregorian; Howard Hinnant's
/// days-to-civil algorithm).
pub fn fmt_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Formats `minor` units with `exponent` decimal places (display key 11 only).
pub fn fmt_amount(minor: u64, exponent: u64) -> Option<String> {
    if exponent > 18 {
        return None;
    }
    if exponent == 0 {
        return Some(minor.to_string());
    }
    let p = 10u64.pow(exponent as u32);
    Some(format!(
        "{}.{:0width$}",
        minor / p,
        minor % p,
        width = exponent as usize
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip_and_canonical() {
        let id = [
            0xfbu8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let s = b64url(&id);
        assert_eq!(s, "-xEiM0RVZneImaq7zN3u_w");
        assert_eq!(decode_pending_id(&s), Some(id));
        assert_eq!(decode_pending_id("-xEiM0RVZneImaq7zN3u_x"), None);
        assert_eq!(decode_pending_id("-xEiM0RVZneImaq7zN3u_w="), None);
        assert_eq!(decode_pending_id("+xEiM0RVZneImaq7zN3u_w"), None);
        assert_eq!(b64url(&[0u8; 32]).len(), 43);
    }

    #[test]
    fn hex_rules() {
        let h = "920744baca72aba5050f061410f1b55d0d201e3dad6862dfd40956ee5082dddc";
        let d = parse_digest_hex(h).unwrap();
        assert_eq!(hex_lower(&d), h);
        assert!(parse_digest_hex(&h.to_uppercase()).is_none());
        assert!(parse_digest_hex(&h[..62]).is_none());
    }

    #[test]
    fn formatting() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_utc(1_792_886_400), "2026-10-25 00:00:00 UTC");
        assert_eq!(fmt_amount(1250, 2).unwrap(), "12.50");
        assert_eq!(fmt_amount(5, 3).unwrap(), "0.005");
        assert_eq!(fmt_amount(1250, 0).unwrap(), "1250");
        assert_eq!(
            esc("<a href='x'>&\""),
            "&lt;a href=&#39;x&#39;&gt;&amp;&quot;"
        );
    }
}
