// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Strict-JSON helpers (spec §8.2): integers must match `0|[1-9][0-9]*` and be ≤ 2^53 − 1.

use serde_json::value::RawValue;

use crate::MAX_TIME;

/// Parses a JSON integer token under the spec's grammar; `None` for anything else (sign,
/// fraction, exponent, leading zero, string, null, out of range).
pub(crate) fn json_uint(raw: &RawValue) -> Option<u64> {
    let t = raw.get().as_bytes();
    let canonical =
        t == b"0" || (matches!(t.first(), Some(b'1'..=b'9')) && t.iter().all(u8::is_ascii_digit));
    if !canonical || t.len() > 16 {
        return None;
    }
    let mut n: u64 = 0;
    for d in t {
        n = n * 10 + u64::from(d - b'0');
    }
    (n <= MAX_TIME).then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Option<u64> {
        let raw: &RawValue = serde_json::from_str(s).unwrap();
        json_uint(raw)
    }

    #[test]
    fn integer_grammar() {
        assert_eq!(p("0"), Some(0));
        assert_eq!(p("1767225600"), Some(1_767_225_600));
        assert_eq!(p("9007199254740991"), Some(MAX_TIME));
        for bad in [
            "9007199254740992",
            "-1",
            "-0",
            "1.0",
            "1e3",
            "1.7672256e9",
            "\"1\"",
            "null",
            "99999999999999999999",
        ] {
            assert_eq!(p(bad), None, "{bad}");
        }
    }
}
