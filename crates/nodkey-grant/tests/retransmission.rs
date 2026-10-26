//! `verify_retransmission` (payments-adapter-v1 Draft 2 §3.1): the adapter's non-consuming check.

mod common;

use common::*;
use nodkey_grant::{
    Binding, BrokerId, CLOCK_FLOOR, GrantBuilder, GrantError, Limits, OpKind, OperationDecl,
    Operations, ParamDecl, ParamType, ParamValue, Params, RMax, Registry, RetransmissionContext,
    RetransmissionError, SigningKey, Verified, VerifyContext, verify, verify_retransmission,
};

const SEED_B: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const SEED_C: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
const SEED_D: &str = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";
const ISS: &str = "nodkey.authority.test";
const SHOP: &str = "spiffe://nodkey.test/workload/shop";
const IAT: u64 = 1_792_886_400;
const RMAX: u64 = 43_200;

fn p(name: &str, binding: Binding, ty: ParamType) -> ParamDecl {
    ParamDecl {
        name: name.into(),
        binding,
        ty,
        destination: false,
        justification: None,
    }
}

/// `payments.refund` as declared in effect-protocol-v2 Draft 3.1 (operation table; compiled into the adapter),
/// plus a second write op and a read op to exercise mismatches.
fn ops() -> Operations {
    let refund = OperationDecl {
        name: "payments.refund".into(),
        kind: OpKind::Write,
        opv: 1,
        requires_confirmation: true,
        params: vec![
            p("order_id", Binding::Resource(0), ParamType::Uint),
            p("amount_minor", Binding::Exact(0), ParamType::Uint),
            p("currency", Binding::Exact(1), ParamType::Currency),
            p("charge_id", Binding::Exact(2), ParamType::Text64),
        ],
    };
    let other = OperationDecl {
        name: "payments.other".into(),
        ..refund.clone()
    };
    let bounded = OperationDecl {
        name: "payments.bounded".into(),
        params: vec![
            p("order_id", Binding::Resource(0), ParamType::Uint),
            p("amount_minor", Binding::Bounded(0), ParamType::Uint),
        ],
        ..refund.clone()
    };
    let read = OperationDecl {
        name: "payments.get_order".into(),
        kind: OpKind::Read,
        opv: 1,
        requires_confirmation: false,
        params: vec![p("order_id", Binding::OwnerScoped, ParamType::Uint)],
    };
    Operations::new(vec![refund, other, bounded, read]).unwrap()
}

struct Env {
    registry: Registry,
    ops: Operations,
    bid: BrokerId,
    tenants: Vec<String>,
}

fn env() -> Env {
    Env {
        registry: load_registry("registry.json").unwrap(),
        ops: ops(),
        bid: broker_id(),
        tenants: vec!["acme".into()],
    }
}

fn ctx(e: &Env) -> RetransmissionContext<'_> {
    RetransmissionContext::new(
        &e.registry,
        &e.bid,
        SHOP,
        &e.tenants,
        &e.ops,
        "payments.refund",
        Limits::default(),
    )
    .unwrap()
}

fn rmax() -> RMax {
    RMax::new(RMAX, 86_400, 7_200).unwrap()
}

fn refund(iat: u64) -> GrantBuilder {
    GrantBuilder::write("payments.refund", 1)
        .issuer(ISS)
        .audience(BROKER)
        .jti([9; 16])
        .times(iat, iat, iat + 30)
        .workload(SHOP)
        .tenant("acme")
        .subject("user:u-17")
        .resource(0, ParamValue::Uint(4711))
        .exact(0, ParamValue::Uint(1250))
        .exact(1, ParamValue::Text("EUR".into()))
        .exact(2, ParamValue::Text("ch_ABCDEFGH12".into()))
        .confirmed(true)
}

fn key(seed: &str) -> SigningKey {
    signing_key(seed)
}

fn check(e: &Env, b: GrantBuilder, seed: &str, now: u64) -> Result<(), RetransmissionError> {
    let g = b.sign(&key(seed)).unwrap();
    verify_retransmission(&ctx(e), &g, now, rmax()).map(|_| ())
}

fn grant_err(code: GrantError) -> Result<(), RetransmissionError> {
    Err(RetransmissionError::Grant(code))
}

#[test]
fn accepts_and_returns_idempotency_identity_and_signed_values() {
    let e = env();
    let g = refund(IAT).sign(&key(SEED_A)).unwrap();
    let a = verify_retransmission(&ctx(&e), &g, IAT + 10, rmax()).unwrap();
    assert_eq!(a.idempotency_identity(), (ISS, &[9u8; 16]));
    assert_eq!((a.op(), a.opv(), a.iat()), ("payments.refund", 1, IAT));
    assert_eq!((a.tenant(), a.subject()), ("acme", "user:u-17"));
    let want = Params::from([
        ("order_id".into(), ParamValue::Uint(4711)),
        ("amount_minor".into(), ParamValue::Uint(1250)),
        ("currency".into(), ParamValue::Text("EUR".into())),
        ("charge_id".into(), ParamValue::Text("ch_ABCDEFGH12".into())),
    ]);
    assert_eq!(a.params(), &want);
    // Non-consuming: the same bytes verify again.
    assert!(verify_retransmission(&ctx(&e), &g, IAT + 20, rmax()).is_ok());
}

#[test]
fn expired_but_young_is_accepted_and_broker_path_still_rejects() {
    let e = env();
    let g = refund(IAT).sign(&key(SEED_A)).unwrap();
    let now = IAT + 30 + 5 + 3600; // far past exp + skew
    assert!(verify_retransmission(&ctx(&e), &g, now, rmax()).is_ok());
    // The broker's consuming path is unchanged: expired.
    let req = e
        .ops
        .parse_request(
            "payments.refund",
            Params::from([
                ("order_id".into(), ParamValue::Uint(4711)),
                ("amount_minor".into(), ParamValue::Uint(1250)),
                ("currency".into(), ParamValue::Text("EUR".into())),
                ("charge_id".into(), ParamValue::Text("ch_ABCDEFGH12".into())),
            ]),
        )
        .unwrap();
    let tenants = e.tenants.clone();
    let vctx = VerifyContext {
        now,
        broker_id: &e.bid,
        workload: SHOP,
        workload_tenants: &tenants,
        request: &req,
        operations: &e.ops,
        limits: Limits::default(),
    };
    assert!(matches!(
        verify(&g, &e.registry, &vctx),
        Err(GrantError::Expired)
    ));
    let vctx_young = VerifyContext {
        now: IAT + 1,
        ..vctx
    };
    assert!(matches!(
        verify(&g, &e.registry, &vctx_young),
        Ok(Verified::Write(_))
    ));
}

#[test]
fn age_cap_boundaries() {
    let e = env();
    assert_eq!(check(&e, refund(IAT), SEED_A, IAT + RMAX), Ok(()));
    assert_eq!(
        check(&e, refund(IAT), SEED_A, IAT + RMAX + 1),
        Err(RetransmissionError::AgeExceeded)
    );
    assert_eq!(
        check(&e, refund(IAT), SEED_A, IAT + 10 * RMAX),
        Err(RetransmissionError::AgeExceeded)
    );
}

#[test]
fn future_iat_rejected_beyond_skew() {
    let e = env();
    let now = IAT;
    assert_eq!(check(&e, refund(now + 5), SEED_A, now), Ok(()));
    assert_eq!(
        check(&e, refund(now + 6), SEED_A, now),
        grant_err(GrantError::NotYetValid)
    );
    assert_eq!(
        check(&e, refund(now + 86_400), SEED_A, now),
        grant_err(GrantError::NotYetValid)
    );
}

#[test]
fn every_binding_mismatch_rejected() {
    use GrantError::*;
    let e = env();
    let now = IAT + 10;
    let cases: Vec<(&str, GrantBuilder, &str, Result<(), RetransmissionError>)> = vec![
        (
            "issuer",
            refund(IAT).issuer("nodkey.other"),
            SEED_A,
            grant_err(IssuerMismatch),
        ),
        // aud is bound twice: the signature uses this adapter's broker_id as external_aad.
        (
            "audience",
            refund(IAT).audience("nodkey.broker.other"),
            SEED_A,
            grant_err(SignatureInvalid),
        ),
        (
            "workload",
            refund(IAT).workload(APP1),
            SEED_A,
            grant_err(WorkloadMismatch),
        ),
        (
            "tenant",
            refund(IAT).tenant("globex"),
            SEED_A,
            grant_err(TenantMismatch),
        ),
        (
            "cfm",
            refund(IAT).confirmed(false),
            SEED_A,
            grant_err(ConfirmationRequired),
        ),
        (
            "op",
            retarget("payments.other", 1),
            SEED_A,
            grant_err(OpMismatch),
        ),
        (
            "opv",
            retarget("payments.refund", 2),
            SEED_A,
            grant_err(OpvUnsupported),
        ),
        (
            "res type",
            refund(IAT).resource(0, ParamValue::Text("4711".into())),
            SEED_A,
            grant_err(OpSchemaInvalid),
        ),
        (
            "extra res",
            refund(IAT).resource(1, ParamValue::Uint(1)),
            SEED_A,
            grant_err(OpSchemaInvalid),
        ),
        (
            "extra con",
            refund(IAT).exact(3, ParamValue::Uint(1)),
            SEED_A,
            grant_err(OpSchemaInvalid),
        ),
        (
            "bounded class",
            refund(IAT).bounded(0, 1250),
            SEED_A,
            grant_err(OpSchemaInvalid),
        ),
        (
            "currency type",
            refund(IAT).exact(1, ParamValue::Text("eur".into())),
            SEED_A,
            grant_err(OpSchemaInvalid),
        ),
        (
            "charge type",
            refund(IAT).exact(2, ParamValue::Uint(7)),
            SEED_A,
            grant_err(OpSchemaInvalid),
        ),
        ("unknown key", refund(IAT), SEED_B, grant_err(UnknownKid)),
        ("revoked key", refund(IAT), SEED_C, grant_err(KeyRevoked)),
    ];
    for (name, b, seed, want) in cases {
        assert_eq!(check(&e, b, seed, now), want, "{name}");
    }
    // Missing con key: build without charge_id.
    let missing = GrantBuilder::write("payments.refund", 1)
        .issuer(ISS)
        .audience(BROKER)
        .jti([9; 16])
        .times(IAT, IAT, IAT + 30)
        .workload(SHOP)
        .tenant("acme")
        .subject("user:u-17")
        .resource(0, ParamValue::Uint(4711))
        .exact(0, ParamValue::Uint(1250))
        .exact(1, ParamValue::Text("EUR".into()))
        .confirmed(true);
    assert_eq!(check(&e, missing, SEED_A, now), grant_err(OpSchemaInvalid));
    // Tampered signature.
    let mut g = refund(IAT).sign(&key(SEED_A)).unwrap();
    let last = g.len() - 1;
    g[last] ^= 1;
    assert_eq!(
        verify_retransmission(&ctx(&e), &g, now, rmax()).map(|_| ()),
        grant_err(SignatureInvalid)
    );
}

/// The refund grant with another op/opv but the same bindings.
fn retarget(op: &str, opv: u16) -> GrantBuilder {
    GrantBuilder::write(op, opv)
        .issuer(ISS)
        .audience(BROKER)
        .jti([9; 16])
        .times(IAT, IAT, IAT + 30)
        .workload(SHOP)
        .tenant("acme")
        .subject("user:u-17")
        .resource(0, ParamValue::Uint(4711))
        .exact(0, ParamValue::Uint(1250))
        .exact(1, ParamValue::Text("EUR".into()))
        .exact(2, ParamValue::Text("ch_ABCDEFGH12".into()))
        .confirmed(true)
}

#[test]
fn read_grant_rejected() {
    let e = env();
    let read = GrantBuilder::read()
        .issuer(ISS)
        .audience(BROKER)
        .jti([9; 16])
        .times(IAT, IAT, IAT + 30)
        .workload(SHOP)
        .tenant("acme")
        .subject("user:u-17")
        .read_op("payments.refund", 1);
    assert_eq!(
        check(&e, read, SEED_A, IAT + 1),
        grant_err(GrantError::KindMismatch)
    );
}

#[test]
fn key_window_is_evaluated_at_iat() {
    // Key D is valid [1735689600, 1767225600).
    let e = env();
    let iat = 1_767_225_000;
    // Signed inside D's window, resent after the window ended: accepted.
    assert_eq!(check(&e, refund(iat), SEED_D, iat + 3_600), Ok(()));
    // iat outside D's window: rejected even though `now` is irrelevant.
    let late = 1_767_225_600;
    assert_eq!(
        check(&e, refund(late), SEED_D, late + 1),
        grant_err(GrantError::KeyInactive)
    );
}

#[test]
fn clock_floor() {
    let e = env();
    let iat = CLOCK_FLOOR - 100;
    assert_eq!(
        check(&e, refund(iat), SEED_A, CLOCK_FLOOR - 1),
        Err(RetransmissionError::ClockBelowFloor)
    );
}

#[test]
fn r_max_start_up_rule() {
    assert!(RMax::new(43_200, 86_400, 7_200).is_some());
    assert!(RMax::new(79_199, 86_400, 7_200).is_some());
    assert!(
        RMax::new(79_200, 86_400, 7_200).is_none(),
        "R_max = retention - margin"
    );
    assert!(RMax::new(1, 100, 100).is_none(), "margin = retention");
    assert!(RMax::new(1, 100, 200).is_none());
    assert!(RMax::new(0, 86_400, 7_200).is_none());
    assert!(RMax::new(180, 300, 60).is_some(), "test profile");
}

#[test]
fn context_refuses_non_derivable_or_read_operations() {
    let e = env();
    let mk = |op: &str| {
        RetransmissionContext::new(
            &e.registry,
            &e.bid,
            SHOP,
            &e.tenants,
            &e.ops,
            op,
            Limits::default(),
        )
        .is_some()
    };
    assert!(mk("payments.refund"));
    assert!(!mk("payments.get_order"), "read op");
    assert!(!mk("payments.bounded"), "bounded value is not in the grant");
    assert!(!mk("payments.unknown"));
}
