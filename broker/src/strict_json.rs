//! Strict JSON pre-validation.
//!
//! `serde_json` silently keeps the *last* value when an object contains the same key twice
//! (when deserializing into `Value`/maps). Two parsers that disagree on which duplicate wins
//! are a classic request-smuggling primitive, so the broker rejects any document that contains
//! a duplicate key at any depth before typed parsing happens.
//!
//! Keys are compared after JSON unescaping, so `"a"` and `"a"` are duplicates.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;

/// Returns `Ok(())` if `input` is exactly one syntactically valid JSON value (surrounding
/// whitespace allowed) with no duplicate object keys at any depth.
pub fn check_strict(input: &[u8]) -> Result<(), String> {
    let mut de = serde_json::Deserializer::from_slice(input);
    NoDup::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())
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

#[cfg(test)]
mod tests {
    use super::check_strict;

    #[test]
    fn accepts_valid_documents() {
        assert!(check_strict(br#"{"a":1,"b":{"c":[1,2,{"d":null}]}}"#).is_ok());
        assert!(check_strict(b"  {\"a\":true}\n").is_ok());
        // Same key in sibling objects is not a duplicate.
        assert!(check_strict(br#"[{"a":1},{"a":2}]"#).is_ok());
        assert!(check_strict(br#"{"a":{"a":1}}"#).is_ok());
    }

    #[test]
    fn rejects_top_level_duplicate() {
        let e = check_strict(br#"{"a":1,"a":2}"#).unwrap_err();
        assert!(e.contains("duplicate"), "{e}");
    }

    #[test]
    fn rejects_nested_duplicate() {
        assert!(check_strict(br#"{"args":{"amount_cents":1,"amount_cents":999}}"#).is_err());
        assert!(check_strict(br#"{"x":[{"k":1,"k":1}]}"#).is_err());
    }

    #[test]
    fn rejects_duplicate_after_unescaping() {
        assert!(check_strict(br#"{"op":"a","op":"b"}"#).is_err());
    }

    #[test]
    fn rejects_syntax_errors_and_trailing_data() {
        assert!(check_strict(b"").is_err());
        assert!(check_strict(b"{").is_err());
        assert!(check_strict(br#"{"a":1} {"a":2}"#).is_err());
        assert!(check_strict(br#"{"a":1,}"#).is_err());
        assert!(check_strict(br#"{'a':1}"#).is_err());
        assert!(check_strict(b"{\"a\":NaN}").is_err());
    }

    #[test]
    fn rejects_invalid_utf8_in_strings() {
        assert!(check_strict(b"{\"a\":\"\xff\"}").is_err());
    }

    #[test]
    fn rejects_excessive_nesting() {
        let deep = "[".repeat(1000) + &"]".repeat(1000);
        assert!(check_strict(deep.as_bytes()).is_err());
    }
}
