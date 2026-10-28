//! Fuzz target: grant verification on arbitrary bytes.
//!
//! Input layout: byte 0 selects the request (see common::pick_request); byte 1 bit 0 selects
//! the input form (0 = raw COSE bytes, 1 = transport text through `decode_transport`); the rest
//! is the grant.
//!
//! Properties checked: no panic / timeout / OOM; and (SI-07, as in tests/robustness.rs) a grant
//! that the verifier authorizes must be byte-identical to a published vector, because the fuzzer
//! holds no signing key and Ed25519 `verify_strict` is not malleable.
#![no_main]

#[path = "common.rs"]
mod common;

use nodkey_grant::decode_transport;
use libfuzzer_sys::fuzz_target;

/// Harness control, checked once: the published accepted vector ACC-01 must be authorized for
/// request 0 (its own request). If not, the fixture is broken and every run would be vacuous.
fn control(f: &common::Fixture) {
    static DONE: std::sync::Once = std::sync::Once::new();
    DONE.call_once(|| {
        let acc01 = include_str!("../../../../tests/vectors/grant-v1/grants/ACC-01-valid-transfer.hex");
        let g: Vec<u8> = (0..acc01.trim().len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&acc01.trim()[i..i + 2], 16).unwrap())
            .collect();
        assert!(common::decide(f, &g, common::pick_request(f, 0)), "harness control failed");
    });
}

fuzz_target!(|data: &[u8]| {
    let f = common::fixture();
    control(f);
    let (sel, mode, rest) = match data {
        [s, m, rest @ ..] => (*s, *m, rest),
        _ => return,
    };
    let req = common::pick_request(f, sel);
    let grant: Vec<u8> = if mode & 1 == 1 {
        let Ok(text) = std::str::from_utf8(rest) else { return };
        match decode_transport(Some(text)) {
            Ok(g) => g,
            Err(_) => return,
        }
    } else {
        rest.to_vec()
    };
    if common::decide(f, &grant, req) {
        assert!(
            f.vector_grants.contains(&grant),
            "authorized a grant that is not a published vector"
        );
    }
});
