//! Fuzz-style smoke tests without `cargo fuzz`: the verifier is fed truncated, mutated, extended
//! and random variants of every vector and must never panic. Mutated payloads are also re-signed
//! with test key A so that the post-signature decoder and schema code is exercised.
//!
//! Any panic fails the test. In addition, no mutation of an accepted grant may be accepted
//! (SI-07: one byte sequence, one meaning).

mod common;

use std::collections::HashMap;

use common::*;
use nodkey_grant::{
    AAD_TAG, Operations, ParamValue, Params, Registry, SigningKey, Skew, TYP, VerifyContext,
    decode_transport, derive_kid, verify,
};

struct Fixture {
    registry: Registry,
    ops: Operations,
    wl: HashMap<String, Vec<String>>,
    grants: Vec<(String, Vec<u8>, bool)>,
}

fn fixture() -> Fixture {
    let m = manifest();
    let mut grants = Vec::new();
    for v in m["vectors"].as_array().unwrap() {
        if v["kind"] != "grant" {
            continue;
        }
        let g = hex(
            &std::fs::read_to_string(vectors_dir().join(v["grant"].as_str().unwrap())).unwrap(),
        );
        let accepted = v["steps"][0]["expected"] == "ACCEPT";
        grants.push((v["id"].as_str().unwrap().to_owned(), g, accepted));
    }
    Fixture {
        registry: load_registry("registry.json").unwrap(),
        ops: operations(&m),
        wl: workloads(&m),
        grants,
    }
}

fn transfer_params() -> Params {
    Params::from([
        ("from".into(), ParamValue::Text("alice".into())),
        ("to".into(), ParamValue::Text("bob".into())),
        ("amount_cents".into(), ParamValue::Uint(12500)),
    ])
}

fn check(f: &Fixture, g: &[u8], p: &Params) -> bool {
    let ctx = VerifyContext {
        now: 1_792_886_410,
        audience: BROKER,
        workload: APP1,
        workload_tenants: &f.wl[APP1],
        requested_op: "ledger.transfer",
        requested_params: p,
        operations: &f.ops,
        skew: Skew::default(),
    };
    verify(g, &f.registry, &ctx).is_ok()
}

fn mutations(g: &[u8], r: &mut Rng) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for len in 0..g.len() {
        out.push(g[..len].to_vec());
    }
    for i in 0..g.len() {
        for x in [0x01u8, 0x80, 0xff] {
            let mut m = g.to_vec();
            m[i] ^= x;
            out.push(m);
        }
        for b in [
            0x00u8, 0x17, 0x18, 0x1b, 0x1f, 0x3f, 0x5b, 0x7f, 0x9f, 0xbb, 0xbf, 0xd2, 0xf6, 0xfb,
        ] {
            if g[i] != b {
                let mut m = g.to_vec();
                m[i] = b;
                out.push(m);
            }
        }
    }
    for _ in 0..64 {
        let mut m = g.to_vec();
        let at = r.below(m.len() as u64 + 1) as usize;
        m.insert(at, r.byte());
        out.push(m);
        if g.is_empty() {
            continue;
        }
        let mut m = g.to_vec();
        for _ in 0..1 + r.below(8) {
            let i = r.below(m.len() as u64) as usize;
            m[i] = r.byte();
        }
        if m != g {
            out.push(m);
        }
    }
    out
}

#[test]
fn mutated_vectors_never_panic_and_never_accept() {
    let f = fixture();
    let p = transfer_params();
    let mut r = Rng(0x1234_5678_9abc_def1);
    let mut n = 0usize;
    for (id, g, accepted) in &f.grants {
        for m in mutations(g, &mut r) {
            n += 1;
            let ok = check(&f, &m, &p);
            if *accepted && m != *g {
                assert!(!ok, "mutation of {id} accepted: {}", m.len());
            }
        }
    }
    println!("mutated inputs checked: {n}");
    assert!(n > 100_000);
}

#[test]
fn random_bytes_never_panic() {
    let f = fixture();
    let p = transfer_params();
    let mut r = Rng(42);
    for _ in 0..20_000 {
        let len = r.below(300) as usize;
        let mut g: Vec<u8> = (0..len).map(|_| r.byte()).collect();
        if r.below(2) == 0 && !g.is_empty() {
            g[0] = 0xd2; // get past the tag check more often
        }
        assert!(!check(&f, &g, &p));
    }
    // Over-long and deeply nested inputs.
    assert!(!check(&f, &vec![0x81; 5000], &p));
    let mut nested = vec![0xd2];
    nested.extend(std::iter::repeat_n(0x81, 2000));
    assert!(!check(&f, &nested, &p));
}

#[test]
fn transport_decoder_never_panics() {
    let mut r = Rng(7);
    const CHARS: &[u8] = b"ABCxyz019-_+/= \n\x00\xc3";
    for _ in 0..20_000 {
        let len = r.below(40) as usize;
        let bytes: Vec<u8> = (0..len)
            .map(|_| CHARS[r.below(CHARS.len() as u64) as usize])
            .collect();
        let s = String::from_utf8_lossy(&bytes);
        let _ = decode_transport(Some(&s));
    }
}

/// Splits a vector shaped `d2 84 <protected bstr> a0 <payload bstr> <sig bstr>` and returns the
/// payload, or `None` if the vector does not have that shape.
fn payload_of(g: &[u8]) -> Option<Vec<u8>> {
    if g.get(..4)? != [0xd2, 0x84, 0x58, 0x37] || *g.get(59)? != 0xa0 {
        return None;
    }
    let (len, start) = match *g.get(60)? {
        0x58 => (*g.get(61)? as usize, 62),
        0x59 => (u16::from_be_bytes([*g.get(61)?, *g.get(62)?]) as usize, 63),
        _ => return None,
    };
    g.get(start..start + len).map(<[u8]>::to_vec)
}

/// Test-only envelope over an arbitrary payload, signed with key A. (The library's issuer
/// refuses to sign non-conforming payloads, which is exactly what this needs.)
fn sign_raw(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let kid = derive_kid(&key.verifying_key().to_bytes());
    let mut protected = vec![0xa3, 0x01, 0x32, 0x04, 0x50];
    protected.extend_from_slice(&kid);
    protected.extend_from_slice(&[0x10, 0x78, 0x1f]);
    protected.extend_from_slice(TYP.as_bytes());
    fn bstr(out: &mut Vec<u8>, b: &[u8]) {
        match b.len() {
            n if n < 24 => out.push(0x40 | n as u8),
            n if n < 256 => out.extend_from_slice(&[0x58, n as u8]),
            n => out.extend_from_slice(&[0x59, (n >> 8) as u8, n as u8]),
        }
        out.extend_from_slice(b);
    }
    let mut aad = AAD_TAG.as_bytes().to_vec();
    aad.push(0);
    aad.extend_from_slice(BROKER.as_bytes());
    let mut msg = vec![0x84, 0x6a];
    msg.extend_from_slice(b"Signature1");
    bstr(&mut msg, &protected);
    bstr(&mut msg, &aad);
    bstr(&mut msg, payload);
    use ed25519_dalek::Signer;
    let sig = key.sign(&msg).to_bytes();
    let mut g = vec![0xd2, 0x84];
    bstr(&mut g, &protected);
    g.push(0xa0);
    bstr(&mut g, payload);
    bstr(&mut g, &sig);
    g
}

#[test]
fn resigned_mutated_payloads_never_panic() {
    let f = fixture();
    let p = transfer_params();
    let key = signing_key(SEED_A);
    let mut r = Rng(0xdead_beef);

    // Control: re-signing an unmodified accepted payload is accepted (the harness is sound).
    let acc01 = &f
        .grants
        .iter()
        .find(|(id, ..)| id.starts_with("ACC-01"))
        .unwrap()
        .1;
    let pl = payload_of(acc01).unwrap();
    assert!(check(&f, &sign_raw(&key, &pl), &p));

    // Re-signed mutations are genuinely signed grants, so some (e.g. a changed jti) are
    // legitimately accepted; the property checked here is only "no panic".
    let mut n = 0usize;
    for (_, g, _) in &f.grants {
        let Some(pl) = payload_of(g) else { continue };
        for m in mutations(&pl, &mut r).into_iter().step_by(13) {
            n += 1;
            let _ = check(&f, &sign_raw(&key, &m), &p);
        }
    }
    println!("re-signed mutated payloads checked: {n}");
    assert!(n > 20_000);
}
