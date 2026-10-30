// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! T28/T37: the authority's digest code against tests/vectors/effect-v2/digest-vectors.json
//! (DG-01..DG-12), which were produced by an independent generator and cross-checked in Python.

use nodkey_authority::digest::{PendingRecord, hex};
use serde_json::Value;

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/vectors/effect-v2/digest-vectors.json"
);

#[test]
fn digest_vectors_all() {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
    assert_eq!(doc["format"], "nodkey.effect-v2.digest-vectors");
    assert_eq!(doc["label"], "nodkey.pending.v1");
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 12);
    let (mut accepted, mut rejected) = (0, 0);
    for v in vectors {
        let id = v["id"].as_str().unwrap();
        let rec = v["record"].as_object().unwrap();
        let parsed = PendingRecord::from_json(rec, &[]);
        if v.get("expected").and_then(Value::as_str) == Some("reject") {
            assert!(parsed.is_err(), "{id}: must be rejected");
            rejected += 1;
        } else {
            let r = parsed.unwrap_or_else(|e| panic!("{id}: rejected: {e:?}"));
            assert_eq!(
                hex(&r.cbor()),
                v["cbor_hex"].as_str().unwrap(),
                "{id}: cbor"
            );
            assert_eq!(
                hex(&r.digest()),
                v["digest"].as_str().unwrap(),
                "{id}: digest"
            );
            accepted += 1;
        }
    }
    assert_eq!((accepted, rejected), (8, 4));
}
