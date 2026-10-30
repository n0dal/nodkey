// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Character-class and hex helpers.

/// Spec §5.1 ID: 1..=max bytes, each in 0x21..=0x7E.
pub(crate) fn is_id(b: &[u8], max: usize) -> bool {
    !b.is_empty() && b.len() <= max && b.iter().all(|c| (0x21..=0x7e).contains(c))
}

/// Spec §5.1 operation name: `[a-z0-9_.]{1,64}`.
pub(crate) fn is_op_name(b: &[u8]) -> bool {
    !b.is_empty()
        && b.len() <= 64
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'.')
}

/// Spec §5.3 text value in `res`/`con`: 0..=256 bytes of 0x20..=0x7E.
pub(crate) fn is_value_text(b: &[u8]) -> bool {
    b.len() <= 256 && b.iter().all(|c| (0x20..=0x7e).contains(c))
}

pub(crate) fn hex_lower(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// Lowercase hex only; `None` on odd length, uppercase, or any other character.
pub(crate) fn parse_hex_lower(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    b.chunks_exact(2)
        .map(|p| Some((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert!(is_id(b"spiffe://x/y", 256));
        assert!(!is_id(b"", 10));
        assert!(!is_id(b"a b", 10));
        assert!(!is_id(&[b'a'; 11], 10));
        assert!(is_op_name(b"ledger.get_balance"));
        assert!(!is_op_name(b"Ledger"));
        assert!(!is_op_name(b""));
        assert!(is_value_text(b""));
        assert!(is_value_text(b"a b"));
        assert!(!is_value_text(b"a\n"));
        assert_eq!(parse_hex_lower("0aff"), Some(vec![0x0a, 0xff]));
        assert_eq!(parse_hex_lower("0AFF"), None);
        assert_eq!(parse_hex_lower("0"), None);
        assert_eq!(hex_lower(&[0x0a, 0xff]), "0aff");
    }
}
