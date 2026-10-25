//! Issuer round trips: GrantBuilder -> sign -> verify, byte-exact reproduction of a committed
//! vector, and randomized property checks (deterministic PRNG, no proptest dependency).

mod common;

use std::collections::HashMap;

use common::*;
use nodkey_grant::{
    GrantBuilder, GrantError, GrantKind, ParamValue, Params, Registry, Skew, VerifyContext,
    decode_transport, encode_transport, verify,
};

struct Env {
    registry: Registry,
    ops: nodkey_grant::Operations,
    wl: HashMap<String, Vec<String>>,
}

fn env() -> Env {
    let m = manifest();
    Env {
        registry: load_registry("registry.json").unwrap(),
        ops: operations(&m),
        wl: workloads(&m),
    }
}

const IAT: u64 = 1_792_886_400;

fn transfer(to: &str, amount: u64) -> Params {
    Params::from([
        ("from".into(), ParamValue::Text("alice".into())),
        ("to".into(), ParamValue::Text(to.into())),
        ("amount_cents".into(), ParamValue::Uint(amount)),
    ])
}

fn transfer_grant(jti: [u8; 16], nbf: u64, exp: u64) -> GrantBuilder {
    GrantBuilder::write("ledger.transfer", 1)
        .issuer("nodkey.authority.test")
        .audience(BROKER)
        .jti(jti)
        .times(IAT, nbf, exp)
        .workload(APP1)
        .tenant("acme")
        .subject("user:u-17")
        .resource(0, ParamValue::Text("alice".into()))
        .exact(0, ParamValue::Text("bob".into()))
        .exact(1, ParamValue::Uint(12500))
        .confirmed(true)
}

fn ctx<'a>(e: &'a Env, now: u64, op: &'a str, p: &'a Params) -> VerifyContext<'a> {
    VerifyContext {
        now,
        audience: BROKER,
        workload: APP1,
        workload_tenants: &e.wl[APP1],
        requested_op: op,
        requested_params: p,
        operations: &e.ops,
        skew: Skew::default(),
    }
}

fn vector_jti(id: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"nodkey.test.jti");
    h.update([0u8]);
    h.update(id.as_bytes());
    h.finalize()[..16].try_into().unwrap()
}

/// The builder reproduces the committed ACC-01 grant byte for byte (search over the unknown
/// nbf/exp only), which cross-checks the canonical encoder against the vector generator's.
#[test]
fn builder_reproduces_acc01_bytes() {
    let want = hex(&std::fs::read_to_string(
        vectors_dir().join("grants/ACC-01-valid-transfer.hex"),
    )
    .unwrap());
    let key = signing_key(SEED_A);
    // The jti label is the short id ("ACC-01"), not the manifest id (SPEC_ISSUES.md SI-6).
    let jti = vector_jti("ACC-01");
    let mut found = false;
    'outer: for nbf in IAT..=IAT + 5 {
        for exp in nbf + 1..=nbf + 30 {
            if transfer_grant(jti, nbf, exp).sign(&key).unwrap() == want {
                found = true;
                break 'outer;
            }
        }
    }
    assert!(found, "builder output never matched ACC-01");
}

#[test]
fn write_round_trip_and_bindings() {
    let e = env();
    let key = signing_key(SEED_A);
    let g = transfer_grant([7; 16], IAT, IAT + 30).sign(&key).unwrap();
    let p = transfer("bob", 12500);
    let v = verify(&g, &e.registry, &ctx(&e, IAT + 10, "ledger.transfer", &p)).unwrap();
    assert_eq!(v.kind(), GrantKind::Write);
    assert!(v.must_consume());
    assert_eq!(v.jti(), &[7; 16]);
    assert_eq!(v.iss(), "nodkey.authority.test");
    assert_eq!((v.op(), v.opv()), ("ledger.transfer", 1));
    assert_eq!((v.tenant(), v.subject()), ("acme", "user:u-17"));

    // Transport round trip.
    let t = encode_transport(&g);
    assert_eq!(decode_transport(Some(&t)).unwrap(), g);

    // A verified-but-denied write grant carries its identity for §7.3 recording.
    let bad = transfer("mallory", 12500);
    let r = verify(&g, &e.registry, &ctx(&e, IAT + 10, "ledger.transfer", &bad)).unwrap_err();
    assert_eq!(r.code, GrantError::ConstraintMismatch);
    assert_eq!(r.verified.as_ref().unwrap().jti, [7; 16]);

    // An unverified failure carries none.
    let r = verify(&g, &e.registry, &ctx(&e, IAT + 100, "ledger.transfer", &p)).unwrap_err();
    assert_eq!(r.code, GrantError::Expired);
    assert!(r.verified.is_none());
}

#[test]
fn read_round_trip() {
    let e = env();
    let g = GrantBuilder::read()
        .issuer("nodkey.authority.test")
        .audience(BROKER)
        .jti([1; 16])
        .times(IAT, IAT, IAT + 30)
        .workload(APP1)
        .tenant("acme")
        .subject("user:u-17")
        .read_op("ledger.get_balance", 1)
        .read_op("ledger.list_transfers", 1)
        .sign(&signing_key(SEED_A))
        .unwrap();
    let p = Params::from([("account".into(), ParamValue::Text("alice".into()))]);
    for op in ["ledger.get_balance", "ledger.list_transfers"] {
        let v = verify(&g, &e.registry, &ctx(&e, IAT + 1, op, &p)).unwrap();
        assert!(!v.must_consume());
        assert_eq!(v.op(), op);
    }
    let r = verify(&g, &e.registry, &ctx(&e, IAT + 1, "ledger.transfer", &p)).unwrap_err();
    assert_eq!(r.code, GrantError::KindMismatch);
}

#[test]
fn builder_refuses_nonconforming_grants() {
    let key = signing_key(SEED_A);
    let ok = || transfer_grant([0; 16], IAT, IAT + 30);
    assert!(ok().sign(&key).is_ok());
    assert!(ok().times(IAT, IAT, IAT + 31).sign(&key).is_err());
    assert!(ok().times(IAT, IAT - 1, IAT + 10).sign(&key).is_err());
    assert!(ok().times(IAT, IAT, IAT).sign(&key).is_err());
    assert!(ok().tenant("ac me").sign(&key).is_err());
    assert!(ok().tenant("").sign(&key).is_err());
    assert!(ok().subject(&"x".repeat(257)).sign(&key).is_err());
    assert!(ok().resource(16, ParamValue::Uint(1)).sign(&key).is_err());
    assert!(
        ok().exact(2, ParamValue::Text("a\n".into()))
            .sign(&key)
            .is_err()
    );
    assert!(ok().read_op("ledger.get_balance", 1).sign(&key).is_err());
    assert!(
        GrantBuilder::write("Ledger.Transfer", 1)
            .sign(&key)
            .is_err()
    );
    let read = GrantBuilder::read()
        .issuer("i")
        .audience("a")
        .jti([0; 16])
        .times(1, 1, 2)
        .workload("w")
        .tenant("t")
        .subject("s");
    assert!(read.clone().sign(&key).is_err(), "empty rop");
    assert!(read.clone().read_op("x", 0).sign(&key).is_err(), "opv 0");
    assert!(
        read.clone()
            .confirmed(true)
            .read_op("x", 1)
            .sign(&key)
            .is_err()
    );
    assert!(read.read_op("x", 1).sign(&key).is_ok());
    // Oversized grants are refused rather than emitted.
    let big = ok().workload(&"w".repeat(256)).subject(&"s".repeat(256));
    let big = (0..16u8).fold(big, |b, k| b.resource(k, ParamValue::Text("r".repeat(100))));
    assert!(big.sign(&key).is_err());
}

fn rand_id(r: &mut Rng, max: usize) -> String {
    let len = 1 + r.below(max as u64) as usize;
    (0..len)
        .map(|_| (0x21 + r.below(0x7e - 0x21 + 1) as u8) as char)
        .collect()
}

/// Property: any conforming test.hold grant (random IDs, times, bound, currency, account)
/// verifies for any request within its bindings, and is denied with the exact code when one
/// binding is exceeded.
#[test]
fn property_random_test_hold_grants() {
    let e = env();
    let key = signing_key(SEED_A);
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    for i in 0..300 {
        let sub = rand_id(&mut r, 256);
        let nbf = IAT + r.below(5);
        let exp = nbf + 1 + r.below(30);
        let bound = r.next() >> r.below(64);
        let account: String = (0..1 + r.below(32))
            .map(|_| b"abcdefghijklmnopqrstuvwxyz0123456789_"[r.below(37) as usize] as char)
            .collect();
        let currency: String = (0..3).map(|_| (b'A' + r.below(26) as u8) as char).collect();
        let g = GrantBuilder::write("test.hold", 1)
            .issuer("nodkey.authority.test")
            .audience(BROKER)
            .jti([i as u8; 16])
            .times(IAT, nbf, exp)
            .workload(APP1)
            .tenant("acme")
            .subject(&sub)
            .resource(0, ParamValue::Text(account.clone()))
            .bounded(0, bound)
            .exact(1, ParamValue::Text(currency.clone()))
            .sign(&key)
            .unwrap();
        let amount = if bound == 0 {
            0
        } else {
            r.below(bound) + r.below(2)
        };
        let memo: String = (0..r.below(65))
            .map(|_| (0x20 + r.below(95) as u8) as char)
            .collect();
        let mut p = Params::from([
            ("account".into(), ParamValue::Text(account.clone())),
            ("amount_cents".into(), ParamValue::Uint(amount.min(bound))),
            ("currency".into(), ParamValue::Text(currency.clone())),
            ("memo".into(), ParamValue::Text(memo)),
        ]);
        let now = nbf + r.below(exp - nbf);
        let v = verify(&g, &e.registry, &ctx(&e, now, "test.hold", &p));
        assert!(v.is_ok(), "iteration {i}: {v:?}");
        assert_eq!(v.unwrap().subject(), sub);

        if bound < u64::MAX {
            p.insert("amount_cents".into(), ParamValue::Uint(bound + 1));
            let err = verify(&g, &e.registry, &ctx(&e, now, "test.hold", &p)).unwrap_err();
            assert_eq!(err.code, GrantError::BoundExceeded);
            p.insert("amount_cents".into(), ParamValue::Uint(bound));
        }
        p.insert("currency".into(), ParamValue::Text("ZZZ".into()));
        if currency != "ZZZ" {
            let err = verify(&g, &e.registry, &ctx(&e, now, "test.hold", &p)).unwrap_err();
            assert_eq!(err.code, GrantError::ConstraintMismatch);
        }
        let err = verify(&g, &e.registry, &ctx(&e, exp + 5, "test.hold", &p)).unwrap_err();
        assert_eq!(err.code, GrantError::Expired);
    }
}

/// The scheduler key cannot be used for user operations, and vice versa (spec D-9).
#[test]
fn role_separation() {
    let e = env();
    let p = transfer("bob", 12500);
    let g = transfer_grant([3; 16], IAT, IAT + 30)
        .issuer("nodkey.scheduler.test")
        .sign(&signing_key(SEED_E))
        .unwrap();
    let err = verify(&g, &e.registry, &ctx(&e, IAT + 1, "ledger.transfer", &p)).unwrap_err();
    assert_eq!(err.code, GrantError::IssuerNotPermitted);
}
