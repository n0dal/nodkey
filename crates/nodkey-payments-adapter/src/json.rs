// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Strict JSON pre-validation (payments-adapter-v1 §6.1; the broker's `strict_json` rules).
//!
//! Accepts exactly one JSON value (surrounding whitespace allowed) with no duplicate object keys at
//! any depth (compared after unescaping), nesting depth ≤ `max_depth`, and numbers only as
//! non-negative integers that fit `u64` (no sign, fraction or exponent). `serde_json` keeps the
//! last of duplicate keys, so two parsers could disagree on a document; rejecting duplicates
//! removes that ambiguity before any typed reading happens.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

/// Returns `Ok(())` if `input` satisfies the rules above.
/// The document is not strict JSON (no detail: callers map it to a closed code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotStrict;

pub fn check_strict(input: &[u8], max_depth: usize) -> Result<(), NotStrict> {
    let mut de = serde_json::Deserializer::from_slice(input);
    Strict {
        depth: 0,
        max: max_depth,
    }
    .deserialize(&mut de)
    .map_err(|_| NotStrict)?;
    de.end().map_err(|_| NotStrict)
}

#[derive(Clone, Copy)]
struct Strict {
    depth: usize,
    max: usize,
}

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl Strict {
    fn deeper<E: de::Error>(self) -> Result<Strict, E> {
        if self.depth + 1 > self.max {
            return Err(E::custom("too deep"));
        }
        Ok(Strict {
            depth: self.depth + 1,
            max: self.max,
        })
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("strict JSON")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Err(E::custom("negative integer"))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Err(E::custom("not an integer"))
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let inner = self.deeper()?;
        while seq.next_element_seed(inner)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let inner = self.deeper()?;
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("duplicate key"));
            }
            map.next_value_seed(inner)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::check_strict;

    #[test]
    fn accepts_plain_documents() {
        assert!(check_strict(br#"{"a":1,"b":[true,null,"x",{"c":0}]}"#, 8).is_ok());
        assert!(check_strict(b" {\"a\":18446744073709551615}\n", 8).is_ok());
        assert!(check_strict(br#"[{"a":1},{"a":2}]"#, 8).is_ok());
    }

    #[test]
    fn rejects_duplicates_at_any_depth_and_after_unescaping() {
        assert!(check_strict(br#"{"a":1,"a":2}"#, 8).is_err());
        assert!(check_strict(br#"{"x":[{"amount":1,"amount":2}]}"#, 8).is_err());
        assert!(check_strict(br#"{"op":1,"op":2}"#, 8).is_err());
    }

    #[test]
    fn rejects_non_u64_numbers() {
        for doc in [
            &br#"{"a":-1}"#[..],
            br#"{"a":1.0}"#,
            br#"{"a":1e3}"#,
            br#"{"a":18446744073709551616}"#,
            br#"{"a":1e400}"#,
        ] {
            assert!(
                check_strict(doc, 8).is_err(),
                "{}",
                String::from_utf8_lossy(doc)
            );
        }
    }

    #[test]
    fn enforces_depth() {
        let ok = "[".repeat(8) + &"]".repeat(8);
        let bad = "[".repeat(9) + &"]".repeat(9);
        assert!(check_strict(ok.as_bytes(), 8).is_ok());
        assert!(check_strict(bad.as_bytes(), 8).is_err());
        let huge = "[".repeat(100_000) + &"]".repeat(100_000);
        assert!(check_strict(huge.as_bytes(), 8).is_err());
    }

    #[test]
    fn rejects_syntax_errors_trailing_data_and_invalid_utf8() {
        for doc in [
            &b""[..],
            b"{",
            br#"{"a":1} x"#,
            br#"{"a":1,}"#,
            b"{\"a\":\"\xff\"}",
            b"not json",
        ] {
            assert!(check_strict(doc, 8).is_err());
        }
    }
}
