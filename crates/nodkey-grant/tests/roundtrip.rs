//! Issuer round trips (GrantBuilder -> sign -> verify), byte-exact reproduction of a committed
//! vector, API-binding tests for review findings GC-01/GC-02, and randomized property checks
//! (deterministic PRNG, no proptest dependency).

mod common;

use std::collections::HashMap;

use common::*;
use nodkey_grant::{
    Authorized, GrantBuilder, GrantError, GrantKind, Limits, Operations, ParamValue, Params,
    Registry, Request, RequestError, Verified, VerifyContext, WriteGrant, decode_transport,
    encode_transport, verify,
};

struct Env {
    registry: Registry,
    ops: Operations,
    wl: HashMap<String, Vec<String>>,
    bid: nodkey_grant::BrokerId,
}

fn env() -> Env {
    Env {
        registry: load_registry("registry.json").unwrap(),
        ops: operations(),
        wl: workloads(&manifest()),
        bid: broker_id(),
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

fn transfer_grant(jti: [u8; 16], exp: u64) -> GrantBuilder {
    GrantBuilder::write("ledger.transfer", 1)
        .issuer("nodkey.authority.test")
        .audience(BROKER)
        .jti(jti)
        .times(IAT, IAT, exp)
        .workload(APP1)
        .tenant("acme")
        .subject("user:u-17")
        .resource(0, ParamValue::Text("alice".into()))
        .exact(0, ParamValue::Text("bob".into()))
        .exact(1, ParamValue::Uint(12500))
        .confirmed(true)
}

fn ctx<'a>(e: &'a Env, now: u64, req: &'a Request) -> VerifyContext<'a> {
    VerifyContext {
        now,
        broker_id: &e.bid,
        workload: APP1,
        workload_tenants: &e.wl[APP1],
        request: req,
        operations: &e.ops,
        limits: Limits::default(),
    }
}

fn write<'a>(e: &'a Env, g: &[u8], now: u64, req: &'a Request) -> WriteGrant<'a> {
    match verify(g, &e.registry, &ctx(e, now, req)).unwrap() {
        Verified::Write(w) => w,
        Verified::Read(_) => panic!("expected a write grant"),
    }
}

fn decide_write<'a>(
    e: &'a Env,
    g: &[u8],
    now: u64,
    req: &'a Request,
) -> Result<Authorized<'a>, GrantError> {
    write(e, g, now, req).decide(&[])
}

/// The builder reproduces the committed ACC-01 grant byte for byte (jti taken from the grant,
/// as the vectors README recommends), cross-checking the canonical encoder.
#[test]
fn builder_reproduces_acc01_bytes() {
    let want = hex(&read("grants/ACC-01-valid-transfer.hex"));
    let at = want.windows(2).position(|w| w == [0x03, 0x50]).unwrap() + 2;
    let jti: [u8; 16] = want[at..at + 16].try_into().unwrap();
    let got = transfer_grant(jti, IAT + 30)
        .sign(&signing_key(SEED_A))
        .unwrap();
    assert_eq!(got, want);
}

#[test]
fn write_round_trip_binds_the_checked_request() {
    let e = env();
    let g = transfer_grant([7; 16], IAT + 30)
        .sign(&signing_key(SEED_A))
        .unwrap();
    let req = e
        .ops
        .parse_request("ledger.transfer", transfer("bob", 12500))
        .unwrap();
    let w = write(&e, &g, IAT + 10, &req);
    assert_eq!(w.identity().kind, GrantKind::Write);
    // W10 record carries the hash of exactly the validated request (GC-02).
    let c = w.consumption();
    assert_eq!(
        (c.iss.as_str(), c.jti, c.exp),
        ("nodkey.authority.test", [7; 16], IAT + 30)
    );
    assert_eq!(&c.request_hash, req.request_hash());
    let a = w.decide(&[]).unwrap();
    assert_eq!((a.op(), a.opv()), ("ledger.transfer", 1));
    assert_eq!(a.params(), req.params());
    assert_eq!(a.request_hash(), req.request_hash());

    // Transport round trip.
    assert_eq!(decode_transport(Some(&encode_transport(&g))).unwrap(), g);

    // A verified write grant denied at W12 is an Err of `decide` (the broker records it).
    let bad = e
        .ops
        .parse_request("ledger.transfer", transfer("mallory", 12500))
        .unwrap();
    assert_eq!(
        decide_write(&e, &g, IAT + 10, &bad).unwrap_err(),
        GrantError::ConstraintMismatch
    );
    // Unverified failures never reach the consumption stage.
    assert_eq!(
        verify(&g, &e.registry, &ctx(&e, IAT + 100, &req)).unwrap_err(),
        GrantError::Expired
    );
}

/// GC-01: the strict request parser rejects undeclared, missing and ill-typed parameters,
/// including free and owner-scoped ones, so they can never reach verification or effect code.
#[test]
fn request_parser_is_strict() {
    let ops = operations();
    let hold = |memo: ParamValue| {
        Params::from([
            ("account".into(), ParamValue::Text("alice".into())),
            ("amount_cents".into(), ParamValue::Uint(1)),
            ("currency".into(), ParamValue::Text("EUR".into())),
            ("memo".into(), memo),
        ])
    };
    assert!(
        ops.parse_request("test.hold", hold(ParamValue::Text("rent".into())))
            .is_ok()
    );
    assert!(matches!(
        ops.parse_request("test.hold", hold(ParamValue::Uint(1))),
        Err(RequestError::InvalidValue(_))
    ));
    assert!(matches!(
        ops.parse_request("test.hold", hold(ParamValue::Text("\n".repeat(5000)))),
        Err(RequestError::InvalidValue(_))
    ));
    let mut extra = hold(ParamValue::Text("rent".into()));
    extra.insert("to".into(), ParamValue::Text("mallory".into()));
    assert!(matches!(
        ops.parse_request("test.hold", extra),
        Err(RequestError::UnknownParameter(_))
    ));
    let mut missing = hold(ParamValue::Text("rent".into()));
    missing.remove("memo");
    assert!(matches!(
        ops.parse_request("test.hold", missing),
        Err(RequestError::MissingParameter(_))
    ));
    assert_eq!(
        ops.parse_request("ledger.delete", Params::new()),
        Err(RequestError::UnknownOperation)
    );
    let big = transfer("bob", 1 << 53);
    assert!(matches!(
        ops.parse_request("ledger.transfer", big),
        Err(RequestError::InvalidValue(_))
    ));
    let owner = Params::from([("account".into(), ParamValue::Text("Alice".into()))]);
    assert!(matches!(
        ops.parse_request("ledger.get_balance", owner),
        Err(RequestError::InvalidValue(_))
    ));
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
        .read_op("test.peek", 1)
        .sign(&signing_key(SEED_A))
        .unwrap();
    let p = Params::from([("account".into(), ParamValue::Text("alice".into()))]);
    for op in ["ledger.get_balance", "test.peek"] {
        let req = e.ops.parse_request(op, p.clone()).unwrap();
        let Verified::Read(r) = verify(&g, &e.registry, &ctx(&e, IAT + 1, &req)).unwrap() else {
            panic!("read grant")
        };
        let a = r.decide(&[]).unwrap();
        assert_eq!((a.op(), a.tenant(), a.subject()), (op, "acme", "user:u-17"));
    }
    let req = e
        .ops
        .parse_request("ledger.transfer", transfer("bob", 1))
        .unwrap();
    let Verified::Read(r) = verify(&g, &e.registry, &ctx(&e, IAT + 1, &req)).unwrap() else {
        panic!("read grant")
    };
    assert_eq!(r.decide(&[]).unwrap_err(), GrantError::KindMismatch);
}

#[test]
fn builder_refuses_nonconforming_grants() {
    let key = signing_key(SEED_A);
    let ok = || transfer_grant([0; 16], IAT + 30);
    assert!(ok().sign(&key).is_ok());
    assert!(ok().times(IAT, IAT, IAT + 31).sign(&key).is_err());
    assert!(
        ok().times(IAT, IAT + 6, IAT + 10).sign(&key).is_err(),
        "nbf - iat > skew"
    );
    assert!(
        ok().times(IAT, IAT + 1, IAT + 31).sign(&key).is_err(),
        "exp - iat > 30"
    );
    assert!(ok().times(IAT, IAT - 1, IAT + 10).sign(&key).is_err());
    assert!(ok().times(IAT, IAT, IAT).sign(&key).is_err());
    assert!(ok().times(u64::MAX, u64::MAX, u64::MAX).sign(&key).is_err());
    assert!(ok().tenant("ac me").sign(&key).is_err());
    assert!(ok().tenant("").sign(&key).is_err());
    assert!(ok().subject(&"x".repeat(257)).sign(&key).is_err());
    assert!(ok().resource(16, ParamValue::Uint(1)).sign(&key).is_err());
    assert!(ok().exact(2, ParamValue::Uint(1 << 53)).sign(&key).is_err());
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
    let big = ok().workload(&"w".repeat(256)).subject(&"s".repeat(256));
    let big = (0..16u8).fold(big, |b, k| b.resource(k, ParamValue::Text("r".repeat(100))));
    assert!(big.sign(&key).is_err(), "over 2048 bytes");
}

fn rand_id(r: &mut Rng, max: usize) -> String {
    let len = 1 + r.below(max as u64) as usize;
    (0..len)
        .map(|_| (0x21 + r.below(0x7e - 0x21 + 1) as u8) as char)
        .collect()
}

/// Property: any conforming test.hold grant (random subject, times, bound, currency, account)
/// is authorized for any request within its bindings, and is denied with the exact code when a
/// binding is exceeded or the grant has expired.
#[test]
fn property_random_test_hold_grants() {
    let e = env();
    let key = signing_key(SEED_A);
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    for i in 0..300 {
        let sub = rand_id(&mut r, 256);
        let nbf = IAT + r.below(6);
        let exp = nbf + 1 + r.below(IAT + 30 - nbf);
        let bound = (r.next() >> r.below(64)) & ((1 << 53) - 1);
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
        let memo: String = (0..r.below(65))
            .map(|_| (0x20 + r.below(95) as u8) as char)
            .collect();
        let mk = |amount: u64, cur: &str| {
            e.ops
                .parse_request(
                    "test.hold",
                    Params::from([
                        ("account".into(), ParamValue::Text(account.clone())),
                        ("amount_cents".into(), ParamValue::Uint(amount)),
                        ("currency".into(), ParamValue::Text(cur.into())),
                        ("memo".into(), ParamValue::Text(memo.clone())),
                    ]),
                )
                .unwrap()
        };
        let now = nbf + r.below(exp - nbf);
        let req = mk(r.below(bound + 1), &currency);
        let a = decide_write(&e, &g, now, &req);
        assert!(a.is_ok(), "iteration {i}: {a:?}");
        assert_eq!(a.unwrap().identity().sub, sub);
        if bound < (1 << 53) - 1 {
            let req = mk(bound + 1, &currency);
            assert_eq!(
                decide_write(&e, &g, now, &req).unwrap_err(),
                GrantError::BoundExceeded
            );
        }
        if currency != "ZZZ" {
            let req = mk(bound, "ZZZ");
            assert_eq!(
                decide_write(&e, &g, now, &req).unwrap_err(),
                GrantError::ConstraintMismatch
            );
        }
        let req = mk(bound, &currency);
        assert_eq!(
            verify(&g, &e.registry, &ctx(&e, exp + 5, &req)).unwrap_err(),
            GrantError::Expired
        );
    }
}
