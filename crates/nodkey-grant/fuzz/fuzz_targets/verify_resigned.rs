// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: payload decoding and schema/decision code behind the signature check.
//!
//! Input layout: byte 0 selects the request; the rest is a candidate COSE payload, which is
//! wrapped in the fixed protected header and signed with published RFC 8032 test key A (the
//! vectors' active key), so mutated payloads reach steps 6-9 and W12/W13.
//!
//! Property checked: no panic / timeout / OOM. Re-signed grants are genuinely signed, so
//! acceptance is not a finding by itself.
#![no_main]

#[path = "common.rs"]
mod common;

use ed25519_dalek::Signer;
use nodkey_grant::{AAD_TAG, SigningKey, TYP, derive_kid};
use libfuzzer_sys::fuzz_target;

/// RFC 8032 section 7.1 TEST 1 secret seed (published test key "A" in the vectors manifest).
const SEED_A: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fn bstr(out: &mut Vec<u8>, b: &[u8]) {
    match b.len() {
        n if n < 24 => out.push(0x40 | n as u8),
        n if n < 256 => out.extend_from_slice(&[0x58, n as u8]),
        n => out.extend_from_slice(&[0x59, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(b);
}

/// Same construction as `sign_raw` in crates/nodkey-grant/tests/robustness.rs.
fn sign_raw(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let kid = derive_kid(&key.verifying_key().to_bytes());
    let mut protected = vec![0xa3, 0x01, 0x32, 0x04, 0x50];
    protected.extend_from_slice(&kid);
    protected.extend_from_slice(&[0x10, 0x78, 0x1f]);
    protected.extend_from_slice(TYP.as_bytes());
    let mut aad = AAD_TAG.as_bytes().to_vec();
    aad.push(0);
    aad.extend_from_slice(common::BROKER.as_bytes());
    let mut msg = vec![0x84, 0x6a];
    msg.extend_from_slice(b"Signature1");
    bstr(&mut msg, &protected);
    bstr(&mut msg, &aad);
    bstr(&mut msg, payload);
    let sig = key.sign(&msg).to_bytes();
    let mut g = vec![0xd2, 0x84];
    bstr(&mut g, &protected);
    g.push(0xa0);
    bstr(&mut g, payload);
    bstr(&mut g, &sig);
    g
}

fuzz_target!(|data: &[u8]| {
    let f = common::fixture();
    let Some((sel, payload)) = data.split_first() else { return };
    if payload.len() > 4096 {
        return;
    }
    let req = common::pick_request(f, *sel);
    let key = SigningKey::from_bytes(&SEED_A);
    let _ = common::decide(f, &sign_raw(&key, payload), req);
});
