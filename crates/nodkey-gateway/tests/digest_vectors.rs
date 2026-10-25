//! T28/T37 (gateway part): the gateway's digest code against tests/vectors/effect-v2.

use nodkey_gateway::digest::{PendingRecord, check, encode_record};
use nodkey_gateway::util::hex_lower;

#[test]
fn dg_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/effect-v2/digest-vectors.json"
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let vectors = v["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 10);
    let (mut acc, mut rej) = (0, 0);
    for t in vectors {
        let id = t["id"].as_str().unwrap();
        let parsed: Result<PendingRecord, _> = serde_json::from_value(t["record"].clone());
        if t.get("expected").and_then(|e| e.as_str()) == Some("reject") {
            let rejected = match parsed {
                Err(_) => true,
                Ok(r) => check(r).is_err(),
            };
            assert!(rejected, "{id} must be rejected");
            rej += 1;
        } else {
            let r = parsed.unwrap_or_else(|e| panic!("{id}: {e}"));
            let (m, _) = encode_record(&r).unwrap_or_else(|e| panic!("{id}: {e:?}"));
            assert_eq!(hex_lower(&m), t["cbor_hex"].as_str().unwrap(), "{id} cbor");
            assert_eq!(
                hex_lower(&check(r).unwrap().digest),
                t["digest"].as_str().unwrap(),
                "{id} digest"
            );
            acc += 1;
        }
    }
    eprintln!("digest vectors: {acc} accepted as expected, {rej} rejected as expected");
}

#[test]
fn duplicate_param_key_rejected() {
    let s = r#"{"pending_id":"-xEiM0RVZneImaq7zN3u_w","broker_id":"b","wid":"w","ten":"t","approver_sub":"s",
      "op":"payments.refund","opv":1,"params":{"order_id":1,"order_id":2},"param_types":{"order_id":"uint"},
      "created_at":1,"expires_at":2,"display":{}}"#;
    assert!(serde_json::from_str::<PendingRecord>(s).is_err());
}
