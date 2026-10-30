// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Key registry (spec §8): strict JSON loading with every load-time check of §8.3.

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::KID_LABEL;
use crate::error::{RegistryError, RegistryErrorCode};
use crate::json::json_uint;
use crate::text::{hex_lower, is_id, parse_hex_lower};

/// COSE algorithm identifier of Ed25519 (RFC 9864); the only algorithm in v1.
pub const ALG_ED25519: i64 = -19;

/// `kid = SHA-256("nodkey.kid.v1" || 0x00 || public_key)[0..16]` (spec §8.1).
pub fn derive_kid(public_key: &[u8; 32]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(KID_LABEL.as_bytes());
    h.update([0u8]);
    h.update(public_key);
    let d = h.finalize();
    let mut kid = [0u8; 16];
    kid.copy_from_slice(&d[..16]);
    kid
}

/// Registry status of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Revoked,
}

/// One validated registry entry.
#[derive(Debug, Clone)]
pub struct KeyEntry {
    kid: [u8; 16],
    key: VerifyingKey,
    iss: String,
    not_before: u64,
    not_after: u64,
    status: KeyStatus,
}

impl KeyEntry {
    pub fn kid(&self) -> &[u8; 16] {
        &self.kid
    }
    pub fn public_key(&self) -> &VerifyingKey {
        &self.key
    }
    pub fn iss(&self) -> &str {
        &self.iss
    }
    pub fn not_before(&self) -> u64 {
        self.not_before
    }
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
    pub fn status(&self) -> KeyStatus {
        self.status
    }
    /// The entry's COSE algorithm (always Ed25519 in v1).
    pub fn alg(&self) -> i64 {
        ALG_ED25519
    }
}

/// A loaded, fully validated key registry.
#[derive(Debug, Clone)]
pub struct Registry {
    by_kid: BTreeMap<[u8; 16], KeyEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistry<'a> {
    #[serde(borrow)]
    format: &'a str,
    #[serde(borrow)]
    keys: Vec<&'a RawValue>,
}

/// Strings are borrowed `&str`: serde_json refuses to borrow a string containing an escape, so
/// escaped values are rejected (review GC-06). Integers are taken raw and checked against the
/// §8.2 grammar.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry<'a> {
    #[serde(borrow)]
    kid: &'a str,
    #[serde(borrow)]
    alg: &'a str,
    #[serde(borrow)]
    public_key: &'a str,
    #[serde(borrow)]
    iss: &'a str,
    #[serde(borrow)]
    purpose: &'a str,
    #[serde(borrow)]
    not_before: &'a RawValue,
    #[serde(borrow)]
    not_after: &'a RawValue,
    #[serde(borrow)]
    status: &'a str,
}

fn err(code: RegistryErrorCode, entry: Option<usize>) -> RegistryError {
    RegistryError { code, entry }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl Registry {
    /// Parses and validates a registry document (spec §8.2, §8.3). Entries are checked in file
    /// order; the first failure aborts the load (the broker must refuse to start).
    ///
    /// Document-level failures (not JSON, duplicate/unknown/missing members, wrong types, string
    /// escapes, non-canonical integers, wrong `format`, empty `keys`) and entry member failures
    /// (including the `kid` format) are `registry_entry_invalid`.
    pub fn load(json: &str) -> Result<Registry, RegistryError> {
        use RegistryErrorCode::*;
        let raw: RawRegistry<'_> =
            serde_json::from_str(json).map_err(|_| err(EntryInvalid, None))?;
        if raw.format != "nodkey.grant-keys.v1" || raw.keys.is_empty() {
            return Err(err(EntryInvalid, None));
        }
        let mut by_kid: BTreeMap<[u8; 16], KeyEntry> = BTreeMap::new();
        for (i, raw_entry) in raw.keys.iter().enumerate() {
            let at = Some(i);
            // Strict per-entry parse from the raw text, so duplicate members are detected.
            let e: RawEntry<'_> =
                serde_json::from_str(raw_entry.get()).map_err(|_| err(EntryInvalid, at))?;
            let status = match e.status {
                "active" => KeyStatus::Active,
                "revoked" => KeyStatus::Revoked,
                _ => return Err(err(EntryInvalid, at)),
            };
            let (Some(not_before), Some(not_after)) =
                (json_uint(e.not_before), json_uint(e.not_after))
            else {
                return Err(err(EntryInvalid, at));
            };
            if e.alg != "Ed25519"
                || e.purpose != "grant"
                || !is_id(e.iss.as_bytes(), 128)
                || not_before >= not_after
                || !is_lower_hex(e.kid, 32)
            {
                return Err(err(EntryInvalid, at));
            }

            // public_key: 64 lowercase hex, a curve point, canonically encoded.
            let pk: [u8; 32] = parse_hex_lower(e.public_key)
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
                .ok_or(err(KeyInvalid, at))?;
            let key = VerifyingKey::from_bytes(&pk).map_err(|_| err(KeyInvalid, at))?;
            let point = key.to_edwards();
            if point.compress().to_bytes() != pk {
                return Err(err(KeyInvalid, at));
            }
            // Order exactly L (spec §8.3): not small order and torsion-free.
            if point.is_small_order() || !point.is_torsion_free() {
                return Err(err(KeyWeak, at));
            }

            let kid = derive_kid(&pk);
            if e.kid != hex_lower(&kid) {
                return Err(err(KidMismatch, at));
            }
            // Same public key implies same kid, so one map covers both rules.
            if by_kid.contains_key(&kid) {
                return Err(err(DuplicateKey, at));
            }
            by_kid.insert(
                kid,
                KeyEntry {
                    kid,
                    key,
                    iss: e.iss.to_owned(),
                    not_before,
                    not_after,
                    status,
                },
            );
        }
        Ok(Registry { by_kid })
    }

    /// Looks up an entry by kid.
    pub fn get(&self, kid: &[u8; 16]) -> Option<&KeyEntry> {
        self.by_kid.get(kid)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.by_kid.len()
    }

    /// Always false for a loaded registry (`keys` must be non-empty).
    pub fn is_empty(&self) -> bool {
        self.by_kid.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC8032_TEST1_PK: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn doc(entries: &[String]) -> String {
        format!(
            r#"{{"format":"nodkey.grant-keys.v1","keys":[{}]}}"#,
            entries.join(",")
        )
    }

    fn entry(pk: &str, kid: &str) -> String {
        format!(
            r#"{{"kid":"{kid}","alg":"Ed25519","public_key":"{pk}","iss":"i","purpose":"grant","not_before":1,"not_after":2,"status":"active"}}"#
        )
    }

    fn kid_of(pk_hex: &str) -> String {
        let pk: [u8; 32] = parse_hex_lower(pk_hex).unwrap().try_into().unwrap();
        hex_lower(&derive_kid(&pk))
    }

    #[test]
    fn spec_example_kid() {
        assert_eq!(kid_of(RFC8032_TEST1_PK), "c1044a5f9c337b6a1d0f01b9cc1fc9c9");
        let r = Registry::load(&doc(&[entry(RFC8032_TEST1_PK, &kid_of(RFC8032_TEST1_PK))]));
        assert_eq!(r.unwrap().len(), 1);
    }

    #[test]
    fn duplicate_member_rejected() {
        let e = entry(RFC8032_TEST1_PK, &kid_of(RFC8032_TEST1_PK))
            .replace(r#""iss":"i","#, r#""iss":"i","iss":"j","#);
        assert_eq!(
            Registry::load(&doc(&[e])).unwrap_err().code,
            RegistryErrorCode::EntryInvalid
        );
        let top = r#"{"format":"nodkey.grant-keys.v1","format":"nodkey.grant-keys.v1","keys":[]}"#;
        assert_eq!(
            Registry::load(top).unwrap_err().code,
            RegistryErrorCode::EntryInvalid
        );
    }

    #[test]
    fn escapes_and_integer_grammar_rejected() {
        let good = entry(RFC8032_TEST1_PK, &kid_of(RFC8032_TEST1_PK));
        for (from, to) in [
            (r#""status":"active""#, r#""status":"\u0061ctive""#),
            (r#""not_before":1"#, r#""not_before":-0"#),
            (r#""not_before":1"#, r#""not_before":1.0"#),
            (r#""not_after":2"#, r#""not_after":9007199254740992"#),
        ] {
            assert!(good.contains(from));
            let e = good.replace(from, to);
            assert_eq!(
                Registry::load(&doc(&[e])).unwrap_err().code,
                RegistryErrorCode::EntryInvalid,
                "{to}"
            );
        }
    }

    #[test]
    fn mixed_order_key_is_weak() {
        // A + T where T is the order-2 point (0, -1): torsion component, not small order.
        use ed25519_dalek::VerifyingKey;
        let a: [u8; 32] = parse_hex_lower(RFC8032_TEST1_PK)
            .unwrap()
            .try_into()
            .unwrap();
        let p = VerifyingKey::from_bytes(&a).unwrap().to_edwards();
        let mut t2 = [0u8; 32];
        t2[0] = 0xec;
        t2[1..31].fill(0xff);
        t2[31] = 0x7f; // y = p - 1 = -1
        let t = VerifyingKey::from_bytes(&t2).unwrap().to_edwards();
        assert!(t.is_small_order());
        let mixed = (p + t).compress().to_bytes();
        let mixed_hex = hex_lower(&mixed);
        let r = Registry::load(&doc(&[entry(&mixed_hex, &kid_of(&mixed_hex))]));
        assert_eq!(r.unwrap_err().code, RegistryErrorCode::KeyWeak);
    }
}
