//! Strict JSON helpers: maps that reject duplicate keys, and uint/text scalars.
//!
//! `serde_json` maps keep the last of duplicate keys; derived structs already reject duplicate and
//! (with `deny_unknown_fields`) unknown members. Every map read from a peer goes through
//! [`StrictMap`].

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};

/// Largest integer value accepted anywhere: 2^53 − 1.
pub const MAX_UINT: u64 = (1 << 53) - 1;

/// A JSON object whose duplicate keys are an error.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StrictMap<V>(pub BTreeMap<String, V>);

impl<'de, V: Deserialize<'de>> Deserialize<'de> for StrictMap<V> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V2<V>(std::marker::PhantomData<V>);
        impl<'de, V: Deserialize<'de>> Visitor<'de> for V2<V> {
            type Value = StrictMap<V>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object without duplicate keys")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
                let mut out = BTreeMap::new();
                while let Some(k) = m.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    let v = m.next_value()?;
                    out.insert(k, v);
                }
                Ok(StrictMap(out))
            }
        }
        d.deserialize_map(V2(std::marker::PhantomData))
    }
}

impl<V: Serialize> Serialize for StrictMap<V> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

/// A JSON value that is either a non-negative integer ≤ 2^53 − 1 or a string. Floats, negative
/// numbers, booleans, nulls, arrays and objects are rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scalar {
    Uint(u64),
    Text(String),
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct SV;
        impl Visitor<'_> for SV {
            type Value = Scalar;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an integer 0..=2^53-1 or a string")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Scalar, E> {
                if v <= MAX_UINT {
                    Ok(Scalar::Uint(v))
                } else {
                    Err(E::custom("integer out of range"))
                }
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Scalar, E> {
                if v >= 0 {
                    self.visit_u64(v as u64)
                } else {
                    Err(E::custom("negative integer"))
                }
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Scalar, E> {
                Ok(Scalar::Text(v.to_owned()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Scalar, E> {
                Ok(Scalar::Text(v))
            }
        }
        d.deserialize_any(SV)
    }
}

impl Serialize for Scalar {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Scalar::Uint(n) => s.serialize_u64(*n),
            Scalar::Text(t) => s.serialize_str(t),
        }
    }
}

/// A uint ≤ 2^53 − 1.
pub fn de_uint<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let v = u64::deserialize(d)?;
    if v > MAX_UINT {
        return Err(de::Error::custom("integer out of range"));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_rejected() {
        assert!(serde_json::from_str::<StrictMap<Scalar>>(r#"{"a":1,"a":2}"#).is_err());
        let m: StrictMap<Scalar> = serde_json::from_str(r#"{"a":1,"b":"x"}"#).unwrap();
        assert_eq!(m.0.len(), 2);
    }

    #[test]
    fn scalar_rules() {
        assert!(serde_json::from_str::<Scalar>("1.0").is_err());
        assert!(serde_json::from_str::<Scalar>("-1").is_err());
        assert!(serde_json::from_str::<Scalar>("9007199254740992").is_err());
        assert!(serde_json::from_str::<Scalar>("true").is_err());
        assert!(serde_json::from_str::<Scalar>("null").is_err());
        assert_eq!(
            serde_json::from_str::<Scalar>("9007199254740991").unwrap(),
            Scalar::Uint(MAX_UINT)
        );
    }
}
