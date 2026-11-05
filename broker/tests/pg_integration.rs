// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL integration tests for protocol v2. Run with `tests/run-pg-integration.sh`
//! (they are `#[ignore]` so that a plain `cargo test` does not need a database).
//! Each test uses its own database copied from the initialized `ledger` template.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use nodkey_broker::v2::ids::{decode_id, encode_id};
use nodkey_broker::v2::server::{Channel, Server, serve};
use nodkey_broker::v2::service::{Delivery, Execution};
use nodkey_broker::v2::wire::Code;
use serde_json::{Value, json};

const ALICE: (&str, &str) = ("acme", "user:alice");
const BOB: (&str, &str) = ("acme", "user:bob");

async fn approved_transfer(h: &H, amount: u64) -> String {
    let pid = h
        .propose_transfer(AGENT, "alice", "bob", amount, ALICE)
        .await
        .unwrap();
    assert_eq!(h.approve(&pid, ALICE).await, Delivery::Accepted);
    pid
}

/// Happy path: propose → render → authority approve → deliver → execute → SUCCEEDED.
#[tokio::test]
#[ignore]
async fn full_flow_succeeds_once() {
    let h = harness().await;
    let pid = h
        .propose_transfer(AGENT, "alice", "bob", 1250, ALICE)
        .await
        .unwrap();
    assert_eq!(pid.len(), 22);
    let st = h.status(AGENT, &pid).await.unwrap();
    assert_eq!(st["state"], "PENDING");
    assert_eq!(st["outcome"], serde_json::Value::Null);
    let r = h.render(&pid, ALICE).await.unwrap();
    assert_eq!(
        r["record"]["display"],
        json!({"amount_exponent": 2, "currency": "EUR"})
    );
    assert_eq!(
        r["facts"][1],
        json!({"label": "Balance of from", "value": "1000.00 EUR"})
    );
    assert_eq!(
        r["facts"][2],
        json!({"label": "To", "value": "not owned by you"})
    );
    assert_eq!(r["context"]["approver_source"], "enrolled");
    assert_eq!(h.approve(&pid, ALICE).await, Delivery::Accepted);
    assert_eq!(h.state(&pid).await, "APPROVED");
    let pidb = decode_id(&pid).unwrap();
    assert_eq!(h.b.execute(pidb, "t").await.unwrap(), Execution::Succeeded);
    // A second attempt (e.g. the recovery loop) is a no-op.
    assert_eq!(
        h.b.execute(pidb, "t").await.unwrap(),
        Execution::NotApproved
    );
    assert_eq!(h.balance("alice").await, 100000 - 1250);
    assert_eq!(h.balance("bob").await, 50000 + 1250);
    assert_eq!(h.transfers_for(&pid).await, 1);
    assert_eq!(h.consumed(&pid).await.as_deref(), Some("ACCEPT"));
    let st = h.status(AGENT, &pid).await.unwrap();
    assert_eq!(st["state"], "SUCCEEDED");
    assert_eq!(st["outcome"]["class"], "succeeded");
    assert!(decode_id(st["outcome"]["receipt_id"].as_str().unwrap()).is_some());
    // The status response never contains the approver, facts, grant or params. `awaiting` is
    // effect-protocol-v2 Draft 4 §12.2 (null outside PENDING).
    let keys: Vec<_> = st.as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        ["awaiting", "expires_at", "outcome", "pending_id", "state"],
        "{keys:?}"
    );
    assert_eq!(st["awaiting"], Value::Null);
}

/// W14 denial (insufficient funds): FAILED/denied, consumed DENIED, no effect.
#[tokio::test]
#[ignore]
async fn execution_denial_is_recorded_atomically() {
    let h = harness().await;
    let pid = approved_transfer(&h, 100_001).await;
    let r = h.b.execute(decode_id(&pid).unwrap(), "t").await.unwrap();
    assert!(
        matches!(r, Execution::Denied(ref d) if d == "insufficient funds"),
        "{r:?}"
    );
    assert_eq!(h.state(&pid).await, "FAILED");
    assert_eq!(h.consumed(&pid).await.as_deref(), Some("DENIED"));
    assert_eq!(h.transfers_for(&pid).await, 0);
    assert_eq!(h.balance("alice").await, 100000);
    let st = h.status(AGENT, &pid).await.unwrap();
    assert_eq!(st["outcome"]["class"], "denied");
}

/// T02: an enrolled workload naming another approver; other propose-time syntax errors.
#[tokio::test]
#[ignore]
async fn t02_propose_validation() {
    let h = harness().await;
    let e = h
        .propose_transfer(AGENT, "alice", "bob", 5, BOB)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InvalidArgument);
    for (from, to, amt) in [
        ("alice", "alice", 5),
        ("alice", "bob", 0),
        ("Alice", "bob", 5),
    ] {
        let e = h
            .propose_transfer(AGENT, from, to, amt, ALICE)
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::InvalidArgument, "{from} {to} {amt}");
    }
    h.set_now(h.now() + 120);
    let wl = h.wl(AGENT);
    for args in [
        json!({"op":"ledger.transfer","params":{"from":"alice","to":"bob","amount_minor":"5"},"approver":{"ten":"acme","sub":"user:alice"}}),
        json!({"op":"ledger.transfer","params":{"from":"alice","to":"bob","amount_minor":5.0},"approver":{"ten":"acme","sub":"user:alice"}}),
        json!({"op":"ledger.transfer","params":{"from":"alice","to":"bob","amount_minor":9007199254740992u64},"approver":{"ten":"acme","sub":"user:alice"}}),
        json!({"op":"ledger.transfer","params":{"from":"alice","to":"bob"},"approver":{"ten":"acme","sub":"user:alice"}}),
        json!({"op":"ledger.transfer","params":{"from":"alice","to":"bob","amount_minor":5,"memo":"x"},"approver":{"ten":"acme","sub":"user:alice"}}),
        json!({"op":"ledger.transfer","params":{"from":"alice","to":"bob","amount_minor":5},"approver":{"ten":"acme"}}),
        json!({"op":"ledger.get_balance","params":{"account":"alice"},"approver":{"ten":"acme","sub":"user:alice"}}),
        json!({"op":"ledger.drop","params":{},"approver":{"ten":"acme","sub":"user:alice"}}),
        json!({"op":"ledger.transfer","params":{"from":"alice","to":"bob","amount_minor":5},"approver":{"ten":"acme","sub":"user:alice"},"grant":"x"}),
    ] {
        h.set_now(h.now() + 6); // proposal rate: 10/min
        let e = h.b.propose(&wl, &obj(args.clone())).await.unwrap_err();
        assert_eq!(e.code, Code::InvalidArgument, "{args}");
    }
    // Named workloads cannot propose destination operations (and it is not in their allowlist).
    let e = h
        .b
        .propose(&h.wl(SHOP), &obj(json!({"op":"ledger.transfer","params":{"from":"alice","to":"bob","amount_minor":5},"approver":{"ten":"acme","sub":"user:alice"}})))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InvalidArgument);
}

/// The legacy (Phase 3) payments.refund declaration is loadable but never executable; payments
/// operations are not in this workload's allowlist.
#[tokio::test]
#[ignore]
async fn payments_not_implemented_in_phase3() {
    let h = harness().await;
    let e = h
        .b
        .propose(&h.wl(AGENT), &obj(json!({"op":"payments.refund","params":{"order_id":1,"amount_minor":1,"currency":"EUR"},"approver":{"ten":"acme","sub":"user:alice"}})))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (
            Code::OperationNotPermitted,
            "not_implemented_legacy_declaration"
        )
    );
    let e =
        h.b.read(
            &h.wl(AGENT),
            "payments.get_order",
            &obj(json!({"order_id": 1, "grant": "x"})),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (Code::OperationNotPermitted, "op not allowed")
    );
}

/// T09: re-proposals create new records; immutable columns cannot be changed (privileges for
/// the broker role, trigger for any role); the state machine rejects undeclared transitions.
#[tokio::test]
#[ignore]
async fn t09_immutability() {
    let h = harness().await;
    let a = h
        .propose_transfer(AGENT, "alice", "bob", 7, ALICE)
        .await
        .unwrap();
    let b = h
        .propose_transfer(AGENT, "alice", "bob", 7, ALICE)
        .await
        .unwrap();
    assert_ne!(a, b);
    let id = decode_id(&a).unwrap();
    // Broker role: no UPDATE privilege on immutable columns.
    let e = pg_env();
    let br = connect(pg_config(&h.db, "nodkey_broker", &e.broker_pw)).await;
    let err = br
        .execute(
            "UPDATE public.pending_effect SET params = '{}' WHERE pending_id = $1",
            &[&id.as_slice()],
        )
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("permission denied"), "{err:?}");
    assert!(
        br.execute("DELETE FROM public.pending_effect", &[])
            .await
            .is_err()
    );
    assert!(
        br.execute("DELETE FROM public.consumed_grant", &[])
            .await
            .is_err()
    );
    assert!(
        br.execute(
            "INSERT INTO public.account_owner VALUES ('carol','acme','user:alice')",
            &[]
        )
        .await
        .is_err()
    );
    // Superuser: the trigger rejects it.
    for sql in [
        "UPDATE pending_effect SET params = '{\"x\":1}', state = 'DENIED', outcome_class = 'denied', receipt_id = '\\x00112233445566778899aabbccddeeff' WHERE pending_id = $1",
        "UPDATE pending_effect SET digest = '\\x0000000000000000000000000000000000000000000000000000000000000000' WHERE pending_id = $1",
        "UPDATE pending_effect SET state = 'SUCCEEDED', outcome_class = 'succeeded', receipt_id = '\\x00112233445566778899aabbccddeeff' WHERE pending_id = $1",
    ] {
        let err = h.su.execute(sql, &[&id.as_slice()]).await.unwrap_err();
        assert!(
            format!("{err:?}").contains("pending_effect:"),
            "{sql}: {err:?}"
        );
    }
    assert_eq!(h.state(&a).await, "PENDING");
}

/// T10 (broker side): render of a nonexistent, foreign-subject, expired, or non-canonical id
/// and for a subject that fails the approval check: one indistinguishable failure.
#[tokio::test]
#[ignore]
async fn t10_t01_render_uniform() {
    let h = harness().await;
    let pid = h
        .propose_transfer(AGENT, "alice", "bob", 5, ALICE)
        .await
        .unwrap();
    let old = h
        .propose_transfer(AGENT, "alice", "bob", 6, ALICE)
        .await
        .unwrap();
    let unknown = encode_id(&[7u8; 16]);
    let mut failures = vec![
        h.render(&unknown, ALICE).await.unwrap_err(),
        h.render(&pid, BOB).await.unwrap_err(),
        h.render(&pid, ("globex", "user:alice")).await.unwrap_err(),
        h.render(&pid, ("acme", "user:Alice")).await.unwrap_err(),
    ];
    let e = h
        .b
        .render(&obj(json!({"pending_id": format!("{}x", &pid[..21]), "subject": {"ten":"acme","sub":"user:alice"}})))
        .await
        .unwrap_err();
    failures.push(e);
    // Ownership of `from` moved away from the approver: approval check fails at render.
    h.su.execute(
        "UPDATE account_owner SET owner_sub = 'user:bob' WHERE account_id = 'alice'",
        &[],
    )
    .await
    .unwrap();
    failures.push(h.render(&pid, ALICE).await.unwrap_err());
    h.su.execute(
        "UPDATE account_owner SET owner_sub = 'user:alice' WHERE account_id = 'alice'",
        &[],
    )
    .await
    .unwrap();
    // Expired (lazy expiry at render): still shown to the approver with its state, no other.
    h.set_now(T0 + 601);
    let r = h.render(&old, ALICE).await.unwrap();
    assert_eq!(r["state"], "EXPIRED");
    failures.push(h.render(&old, BOB).await.unwrap_err());
    for f in &failures {
        assert_eq!(f.code, Code::NotAvailable);
    }
    let body = |c: Code| nodkey_broker::v2::wire::err_response(None, "c", c).to_string();
    assert_eq!(
        body(failures[0].code),
        body(failures[failures.len() - 1].code)
    );
}

/// T11: effect.status from another workload, unknown, non-canonical: identical not_found.
#[tokio::test]
#[ignore]
async fn t11_status_not_found_identical() {
    let h = harness().await;
    let pid = h
        .propose_transfer(AGENT, "alice", "bob", 5, ALICE)
        .await
        .unwrap();
    let mut alias = pid.clone().into_bytes();
    // Flip a trailing bit of the last character to make a non-canonical alias.
    let last = alias.len() - 1;
    alias[last] = if alias[last] == b'A' { b'B' } else { b'A' };
    let alias = String::from_utf8(alias).unwrap();
    for (wid, id) in [
        (AGENT2, pid.as_str()),
        (AGENT, encode_id(&[9u8; 16]).as_str()),
        (AGENT, alias.as_str()),
        (AGENT, "short"),
        (AGENT, ""),
    ] {
        let e = h.status(wid, id).await.unwrap_err();
        assert_eq!(e.code, Code::NotFound, "{wid} {id}");
    }
    assert!(h.status(AGENT, &pid).await.is_ok());
}

/// T12 (ledger analogue): proposals for existing and nonexistent accounts look identical.
#[tokio::test]
#[ignore]
async fn t12_propose_does_not_reveal_state() {
    let h = harness().await;
    let a = h.b.propose(&h.wl(AGENT), &obj(json!({"op":"ledger.transfer","params":{"from":"alice","to":"bob","amount_minor":5},"approver":{"ten":"acme","sub":"user:alice"}}))).await.unwrap();
    let b = h.b.propose(&h.wl(AGENT), &obj(json!({"op":"ledger.transfer","params":{"from":"nosuch","to":"nobody","amount_minor":5},"approver":{"ten":"acme","sub":"user:alice"}}))).await.unwrap();
    let shape = |v: &serde_json::Value| {
        let mut k: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(shape(&a), shape(&b));
    assert_eq!(a["expires_at"], b["expires_at"]);
    assert_eq!(
        a["confirm_url"].as_str().unwrap(),
        format!(
            "https://auth.nodkey.test/confirm/{}",
            a["pending_id"].as_str().unwrap()
        )
    );
}

/// Read grants: success on the subject's own account; T26 foreign resource; T15 write grant on
/// W; a read grant delivered as a write grant on A; wrong workload; missing grant.
#[tokio::test]
#[ignore]
async fn t15_t26_read_grants() {
    let h = harness().await;
    let now = h.now();
    let rd = |acct: &str, g: &str| obj(json!({"account": acct, "grant": g}));
    let g = read_grant(now, AGENT, "acme", "user:alice", KEY_A);
    let ok =
        h.b.read(&h.wl(AGENT), "ledger.get_balance", &rd("alice", &g))
            .await
            .unwrap();
    assert_eq!(ok, json!({"account":"alice","balance_minor":100000}));
    assert!(
        h.b.read(&h.wl(AGENT), "ledger.get_balance", &rd("dave", &g))
            .await
            .is_ok()
    );
    // T26: foreign or missing resource.
    for acct in ["bob", "carol", "nosuch"] {
        let e =
            h.b.read(&h.wl(AGENT), "ledger.get_balance", &rd(acct, &g))
                .await
                .unwrap_err();
        assert_eq!(e.code, Code::GrantDenied, "{acct}");
    }
    // Presented over another workload's socket.
    let e =
        h.b.read(&h.wl(AGENT2), "ledger.get_balance", &rd("alice", &g))
            .await
            .unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (Code::GrantDenied, "grant_workload_mismatch")
    );
    // Foreign key.
    let gb = read_grant(now, AGENT, "acme", "user:alice", KEY_B);
    let e =
        h.b.read(&h.wl(AGENT), "ledger.get_balance", &rd("alice", &gb))
            .await
            .unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (Code::GrantDenied, "grant_unknown_kid")
    );
    // Missing grant.
    let e =
        h.b.read(
            &h.wl(AGENT),
            "ledger.get_balance",
            &obj(json!({"account":"alice"})),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (Code::GrantDenied, "grant_missing")
    );
    // T15: a write grant (knd = 1) on socket W.
    let pid = h
        .propose_transfer(AGENT, "alice", "bob", 5, ALICE)
        .await
        .unwrap();
    let rec = h.get(&pid).await;
    let wg = sign_from_record(&rec, now, KEY_A, |b| b);
    let e =
        h.b.read(&h.wl(AGENT), "ledger.get_balance", &rd("alice", &wg))
            .await
            .unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (Code::GrantDenied, "grant_channel_invalid")
    );
    // T26: a read grant delivered as the approval of a write.
    assert!(matches!(h.deliver(&pid, &g).await, Delivery::Rejected(_)));
    assert_eq!(h.state(&pid).await, "PENDING");
    // Revocation (R13).
    h.su.execute(
        "INSERT INTO revoked_before (ten, sub, before) VALUES ('acme','user:alice',$1)",
        &[&((now + 1) as i64)],
    )
    .await
    .unwrap();
    let e =
        h.b.read(&h.wl(AGENT), "ledger.get_balance", &rd("alice", &g))
            .await
            .unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (Code::GrantDenied, "grant_revoked")
    );
}

/// T17 / T46 / T24 / T34: delivery preconditions and idempotent re-delivery.
#[tokio::test]
#[ignore]
async fn t17_t24_t34_t46_delivery_states() {
    let h = harness().await;
    // T46: same bytes again → accepted, idempotent; never a second effect.
    let pid = h
        .propose_transfer(AGENT, "alice", "bob", 10, ALICE)
        .await
        .unwrap();
    let r = h.render(&pid, ALICE).await.unwrap();
    let g = h
        .authority_sign(&pid, r["digest"].as_str().unwrap(), ALICE)
        .await
        .unwrap();
    assert_eq!(h.deliver(&pid, &g).await, Delivery::Accepted);
    assert_eq!(h.deliver(&pid, &g).await, Delivery::Accepted);
    // A different grant for an APPROVED record (T17) → expired, unchanged.
    h.set_now(T0 + 1);
    let rec = h.get(&pid).await;
    let g2 = sign_from_record(&rec, h.now(), KEY_A, |b| b);
    assert_ne!(g, g2);
    assert!(matches!(h.deliver(&pid, &g2).await, Delivery::Expired(_)));
    let pidb = decode_id(&pid).unwrap();
    assert_eq!(h.b.execute(pidb, "t").await.unwrap(), Execution::Succeeded);
    // T46: a retry after a lost `accepted` may arrive after execution: still `accepted`, and
    // never a second effect. A different grant stays `expired`.
    assert_eq!(h.deliver(&pid, &g).await, Delivery::Accepted);
    assert!(matches!(h.deliver(&pid, &g2).await, Delivery::Expired(_)));
    assert_eq!(
        h.b.execute(pidb, "t").await.unwrap(),
        Execution::NotApproved
    );
    assert_eq!(h.transfers_for(&pid).await, 1);

    // T17: DENIED record.
    let d = h
        .propose_transfer(AGENT, "alice", "bob", 11, ALICE)
        .await
        .unwrap();
    let r = h.render(&d, ALICE).await.unwrap();
    let digest = r["digest"].as_str().unwrap().to_owned();
    let gd = h.authority_sign(&d, &digest, ALICE).await.unwrap();
    h.b.deny(&obj(
        json!({"pending_id": d, "digest": digest, "subject": {"ten":"acme","sub":"user:alice"}}),
    ))
    .await
    .unwrap();
    assert!(matches!(h.deliver(&d, &gd).await, Delivery::Expired(_)));
    let st = h.status(AGENT, &d).await.unwrap();
    assert_eq!(
        (st["state"].as_str(), st["outcome"]["class"].as_str()),
        (Some("DENIED"), Some("denied"))
    );

    // T24/T34: delivery after expires_at.
    let x = h
        .propose_transfer(AGENT, "alice", "bob", 12, ALICE)
        .await
        .unwrap();
    let r = h.render(&x, ALICE).await.unwrap();
    let gx = h
        .authority_sign(&x, r["digest"].as_str().unwrap(), ALICE)
        .await
        .unwrap();
    let exp = r["record"]["expires_at"].as_u64().unwrap();
    h.set_now(exp);
    assert!(matches!(h.deliver(&x, &gx).await, Delivery::Expired(_)));
    assert_eq!(h.state(&x).await, "EXPIRED");
    assert_eq!(h.consumed(&x).await, None);
}

/// T34: execution after grant.exp + skew → APPROVED → EXPIRED, nothing consumed, no effect.
#[tokio::test]
#[ignore]
async fn t34_execution_window() {
    let h = harness().await;
    let pid = approved_transfer(&h, 10).await;
    h.set_now(T0 + 30 + 5); // exp = T0 + 30, skew 5
    assert_eq!(
        h.b.execute(decode_id(&pid).unwrap(), "t").await.unwrap(),
        Execution::Expired
    );
    assert_eq!(h.state(&pid).await, "EXPIRED");
    assert_eq!(h.consumed(&pid).await, None);
    assert_eq!(h.transfers_for(&pid).await, 0);
    let st = h.status(AGENT, &pid).await.unwrap();
    assert_eq!(st["outcome"]["class"], "expired");
    // Lazy expiry through status for a second record.
    let p2 = approved_transfer(&h, 11).await;
    h.set_now(h.now() + 60);
    assert_eq!(h.status(AGENT, &p2).await.unwrap()["state"], "EXPIRED");
    assert_eq!(h.consumed(&p2).await, None);
}

/// T18: a grant whose bound values differ from the record → rejected; T36: foreign key.
/// Also a grant with cfm = 0, wrong jti, wrong subject, wrong audience.
#[tokio::test]
#[ignore]
async fn t18_t36_mismatched_grants_rejected() {
    use nodkey_grant::ParamValue;
    let h = harness().await;
    let pid = h
        .propose_transfer(AGENT, "alice", "bob", 10, ALICE)
        .await
        .unwrap();
    let rec = h.get(&pid).await;
    let now = h.now();
    let cases: Vec<(&str, String)> = vec![
        (
            "amount",
            sign_from_record(&rec, now, KEY_A, |b| b.exact(1, ParamValue::Uint(11))),
        ),
        (
            "to",
            sign_from_record(&rec, now, KEY_A, |b| {
                b.exact(0, ParamValue::Text("carol".into()))
            }),
        ),
        (
            "from",
            sign_from_record(&rec, now, KEY_A, |b| {
                b.resource(0, ParamValue::Text("dave".into()))
            }),
        ),
        (
            "cfm",
            sign_from_record(&rec, now, KEY_A, |b| b.confirmed(false)),
        ),
        (
            "jti",
            sign_from_record(&rec, now, KEY_A, |b| b.jti([1u8; 16])),
        ),
        (
            "sub",
            sign_from_record(&rec, now, KEY_A, |b| b.subject("user:bob")),
        ),
        (
            "ten",
            sign_from_record(&rec, now, KEY_A, |b| b.tenant("globex")),
        ),
        (
            "wid",
            sign_from_record(&rec, now, KEY_A, |b| b.workload(AGENT2)),
        ),
        (
            "aud",
            sign_from_record(&rec, now, KEY_A, |b| b.audience("other.broker")),
        ),
        ("T36 foreign key", sign_from_record(&rec, now, KEY_B, |b| b)),
    ];
    for (name, g) in cases {
        let d = h.deliver(&pid, &g).await;
        assert!(matches!(d, Delivery::Rejected(_)), "{name}: {d:?}");
    }
    assert!(matches!(h.deliver(&pid, "!!").await, Delivery::Rejected(_)));
    assert_eq!(h.state(&pid).await, "PENDING");
    // Approval check at delivery: the approver no longer owns `from`.
    h.su.execute(
        "UPDATE account_owner SET owner_sub = 'user:bob' WHERE account_id = 'alice'",
        &[],
    )
    .await
    .unwrap();
    let g = sign_from_record(&rec, now, KEY_A, |b| b);
    assert!(matches!(h.deliver(&pid, &g).await, Delivery::Rejected(_)));
    assert_eq!(h.state(&pid).await, "PENDING");
}

/// T19: 64 concurrent deliveries + executions of one grant; approve racing deny.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn t19_concurrency_one_decision() {
    let h = harness().await;
    let pid = h
        .propose_transfer(AGENT, "alice", "bob", 100, ALICE)
        .await
        .unwrap();
    let r = h.render(&pid, ALICE).await.unwrap();
    let g = h
        .authority_sign(&pid, r["digest"].as_str().unwrap(), ALICE)
        .await
        .unwrap();
    let pidb = decode_id(&pid).unwrap();
    let mut tasks = Vec::new();
    for i in 0..64 {
        let b = h.b.clone();
        let (pid, g) = (pid.clone(), g.clone());
        tasks.push(tokio::spawn(async move {
            let d = b
                .deliver(&obj(json!({"pending_id": pid, "grant": g})))
                .await;
            let e = b.execute(pidb, &format!("c{i}")).await;
            (d, e)
        }));
    }
    let mut succeeded = 0;
    for t in tasks {
        let (d, e) = t.await.unwrap();
        assert!(
            matches!(
                d,
                Delivery::Accepted | Delivery::Expired(_) | Delivery::Unavailable(_)
            ),
            "{d:?}"
        );
        if e == Ok(Execution::Succeeded) {
            succeeded += 1;
        }
    }
    // Retries (e.g. the recovery loop) finish anything that saw `unavailable`.
    let _ = h.b.recovery_tick().await;
    assert!(succeeded <= 1);
    assert_eq!(h.state(&pid).await, "SUCCEEDED");
    assert_eq!(h.transfers_for(&pid).await, 1);
    assert_eq!(h.balance("alice").await, 100000 - 100);

    // Approve racing deny, 16 rounds: exactly one transition per record, at most one effect.
    for _ in 0..16 {
        let p = h
            .propose_transfer(AGENT, "alice", "bob", 1, ALICE)
            .await
            .unwrap();
        let r = h.render(&p, ALICE).await.unwrap();
        let digest = r["digest"].as_str().unwrap().to_owned();
        let g = h.authority_sign(&p, &digest, ALICE).await.unwrap();
        let (b1, b2) = (h.b.clone(), h.b.clone());
        let (p1, p2, d2) = (p.clone(), p.clone(), digest.clone());
        let a = tokio::spawn(async move {
            b1.deliver(&obj(json!({"pending_id": p1, "grant": g})))
                .await
        });
        let d = tokio::spawn(async move {
            b2.deny(&obj(json!({"pending_id": p2, "digest": d2, "subject": {"ten":"acme","sub":"user:alice"}}))).await
        });
        let (a, d) = (a.await.unwrap(), d.await.unwrap());
        let approved = a == Delivery::Accepted;
        let denied = d.is_ok();
        assert!(approved ^ denied, "approve {a:?} deny {d:?}");
        let _ = h.b.execute(decode_id(&p).unwrap(), "race").await;
        assert_eq!(h.transfers_for(&p).await, i64::from(approved));
        h.set_now(h.now() + 6); // proposal rate: 10/min
    }
}

/// T23: limits per (wid, approver), per wid, and proposal rate; other workloads unaffected.
#[tokio::test]
#[ignore]
async fn t23_limits() {
    let h = harness().await;
    for i in 0..8 {
        h.propose_transfer(AGENT, "alice", "bob", 1 + i, ALICE)
            .await
            .unwrap();
    }
    let e = h
        .propose_transfer(AGENT, "alice", "bob", 99, ALICE)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::LimitExceeded);
    // Another workload proceeds.
    h.propose_transfer(AGENT2, "bob", "alice", 1, BOB)
        .await
        .unwrap();
    // Rate: the agent used 9 of its burst of 10; one more passes the bucket, then 429-like.
    let e = h
        .propose_transfer(AGENT, "alice", "bob", 99, ALICE)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::LimitExceeded);
    let e = h
        .propose_transfer(AGENT, "alice", "bob", 99, ALICE)
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (Code::LimitExceeded, "proposal rate")
    );
    // Expired records no longer count (lazy expiry / sweeper).
    h.set_now(T0 + 601);
    let res = h.b.recovery_tick().await.unwrap();
    assert!(res.is_empty());
    let n: i64 =
        h.su.query_one(
            "SELECT count(*) FROM pending_effect WHERE state = 'EXPIRED'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 9);
}

/// T25: duplicates and outstanding counts are shown at render.
#[tokio::test]
#[ignore]
async fn t25_render_context() {
    let h = harness().await;
    let a = h
        .propose_transfer(AGENT, "alice", "bob", 5, ALICE)
        .await
        .unwrap();
    let b = h
        .propose_transfer(AGENT, "alice", "bob", 5, ALICE)
        .await
        .unwrap();
    h.propose_transfer(AGENT, "alice", "bob", 6, ALICE)
        .await
        .unwrap();
    let r = h.render(&b, ALICE).await.unwrap();
    let c = &r["context"];
    assert_eq!(c["pending_from_workload_for_subject"], 3);
    let recent = c["recent_identical"].as_array().unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0]["pending_id"], a.as_str());
    assert_eq!(c["other_open_on_resource"].as_array().unwrap().len(), 2);
    assert_eq!(recent[0]["amount_minor"], 5);
    assert_eq!(c["workload_display_name"], "Budget agent");
}

/// T33 / T30 (internal effect): forced failures in the execution transaction (W10 insert, the
/// denial record after the savepoint, commit) leave the record APPROVED with nothing consumed;
/// the recovery loop then completes it.
#[tokio::test]
#[ignore]
async fn t33_forced_failures_roll_back() {
    let h = harness().await;
    h.su.batch_execute(
        "CREATE FUNCTION fail_now() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$;",
    )
    .await
    .unwrap();
    let faults = [
        (
            "W10 insert",
            "CREATE TRIGGER f BEFORE INSERT ON consumed_grant FOR EACH ROW EXECUTE FUNCTION fail_now()",
            100u64,
        ),
        (
            "denial record",
            "CREATE TRIGGER f BEFORE UPDATE ON consumed_grant FOR EACH ROW WHEN (NEW.outcome = 'DENIED') EXECUTE FUNCTION fail_now()",
            999_999,
        ),
        (
            "commit",
            "CREATE CONSTRAINT TRIGGER f AFTER INSERT ON consumed_grant DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_now()",
            100,
        ),
    ];
    for (name, ddl, amount) in faults {
        let before = h.balance("alice").await;
        let pid = approved_transfer(&h, amount).await;
        let pidb = decode_id(&pid).unwrap();
        h.su.batch_execute(ddl).await.unwrap();
        let r = h.b.execute(pidb, "t").await;
        assert!(r.is_err(), "{name}: {r:?}");
        assert_eq!(h.state(&pid).await, "APPROVED", "{name}");
        assert_eq!(h.consumed(&pid).await, None, "{name}");
        assert_eq!(h.transfers_for(&pid).await, 0, "{name}");
        assert_eq!(h.balance("alice").await, before, "{name}");
        // Still failing: the recovery loop retries without effect.
        let _ = h.b.recovery_tick().await;
        assert_eq!(h.state(&pid).await, "APPROVED", "{name}");
        h.su.batch_execute("DROP TRIGGER f ON consumed_grant")
            .await
            .unwrap();
        let out = h.b.recovery_tick().await.unwrap();
        assert_eq!(out.len(), 1, "{name}");
        let want = if amount > 100_000 {
            "FAILED"
        } else {
            "SUCCEEDED"
        };
        assert_eq!(h.state(&pid).await, want, "{name}");
        assert!(h.consumed(&pid).await.is_some(), "{name}");
        h.set_now(h.now() + 1);
    }
    // Fault until the window closes: the record expires, nothing consumed.
    let pid = approved_transfer(&h, 1).await;
    h.su.batch_execute(
        "CREATE TRIGGER f BEFORE INSERT ON consumed_grant FOR EACH ROW EXECUTE FUNCTION fail_now()",
    )
    .await
    .unwrap();
    let _ = h.b.recovery_tick().await;
    h.set_now(h.now() + 40);
    let _ = h.b.recovery_tick().await;
    assert_eq!(h.state(&pid).await, "EXPIRED");
    assert_eq!(h.consumed(&pid).await, None);
}

/// Restart: an APPROVED record left by a crashed broker is executed by a new instance's
/// recovery loop (T30 "APPROVED before commit", internal effect).
#[tokio::test]
#[ignore]
async fn t30_restart_recovery() {
    let h = harness().await;
    let pid = approved_transfer(&h, 42).await;
    let b2 = Arc::new(build_broker(&h.db, h.now.clone(), "active"));
    b2.startup_checks().await.unwrap();
    let out = b2.recovery_tick().await.unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].1, Ok(Execution::Succeeded));
    assert_eq!(h.transfers_for(&pid).await, 1);
}

/// T35 (broker side): a row forced to APPROVED with a grant that is not the authority's (or
/// garbage) never executes; it stays unconsumed and expires.
#[tokio::test]
#[ignore]
async fn t35_forced_approved_row() {
    let h = harness().await;
    let pid = h
        .propose_transfer(AGENT, "alice", "bob", 10, ALICE)
        .await
        .unwrap();
    let rec = h.get(&pid).await;
    let forged =
        nodkey_grant::decode_transport(Some(&sign_from_record(&rec, h.now(), KEY_B, |b| b)))
            .unwrap();
    let id = decode_id(&pid).unwrap();
    h.su.execute(
        "UPDATE pending_effect SET state = 'APPROVED', grant_bytes = $2, grant_exp = $3, state_changed_at = $3 WHERE pending_id = $1",
        &[&id.as_slice(), &forged, &((h.now() + 30) as i64)],
    )
    .await
    .unwrap();
    assert_eq!(
        h.b.execute(id, "t").await.unwrap(),
        Execution::Unverified("grant_unknown_kid")
    );
    assert_eq!(h.consumed(&pid).await, None);
    h.set_now(h.now() + 36);
    assert_eq!(h.b.execute(id, "t").await.unwrap(), Execution::Expired);
    assert_eq!(h.transfers_for(&pid).await, 0);
}

/// T38: approve, deny and expiry racing at expires_at ± 1 s: exactly one transition.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn t38_races_at_expiry() {
    let h = harness().await;
    for offset in [-1i64, 0, 1] {
        let p = h
            .propose_transfer(AGENT, "alice", "bob", 1, ALICE)
            .await
            .unwrap();
        let r = h.render(&p, ALICE).await.unwrap();
        let digest = r["digest"].as_str().unwrap().to_owned();
        let g = h.authority_sign(&p, &digest, ALICE).await.unwrap();
        let exp = r["record"]["expires_at"].as_u64().unwrap();
        let at = (exp as i64 + offset) as u64;
        h.set_now(at);
        let (b1, b2, b3) = (h.b.clone(), h.b.clone(), h.b.clone());
        let (p1, p2, p3) = (p.clone(), p.clone(), p.clone());
        let a = tokio::spawn(async move {
            b1.deliver(&obj(json!({"pending_id": p1, "grant": g})))
                .await
        });
        let d = tokio::spawn(async move {
            b2.deny(&obj(json!({"pending_id": p2, "digest": digest, "subject": {"ten":"acme","sub":"user:alice"}}))).await
        });
        let s = tokio::spawn(async move { b3.pending_get(&obj(json!({"pending_id": p3}))).await });
        let (a, d, _) = (a.await.unwrap(), d.await.unwrap(), s.await.unwrap());
        let state = h.state(&p).await;
        let approved = a == Delivery::Accepted;
        let denied = d.is_ok();
        match state.as_str() {
            "APPROVED" => assert!(approved && !denied && offset < 0),
            "DENIED" => assert!(denied && !approved && offset < 0),
            "EXPIRED" => assert!(!approved && !denied && offset >= 0),
            s => panic!("unexpected {s}"),
        }
        h.set_now(at + 700);
        let _ = h.b.recovery_tick().await;
        h.set_now(at + 701);
    }
}

/// T39: revocation between approval and execution → FAILED/denied (W13), consumed DENIED.
/// Key revocation (registry reloaded at restart) → never executes, expires.
#[tokio::test]
#[ignore]
async fn t39_revocation_between_approval_and_execution() {
    let h = harness().await;
    let pid = approved_transfer(&h, 10).await;
    h.su.execute(
        "INSERT INTO revoked_before (ten, wid, before) VALUES ('acme', $1, $2)",
        &[&AGENT, &((h.now() + 1) as i64)],
    )
    .await
    .unwrap();
    let r = h.b.execute(decode_id(&pid).unwrap(), "t").await.unwrap();
    assert_eq!(r, Execution::Denied("grant_revoked".into()));
    assert_eq!(h.consumed(&pid).await.as_deref(), Some("DENIED"));
    assert_eq!(h.transfers_for(&pid).await, 0);

    let h2 = harness().await;
    let pid = approved_transfer(&h2, 10).await;
    let revoked = build_broker(&h2.db, h2.now.clone(), "revoked");
    let r = revoked
        .execute(decode_id(&pid).unwrap(), "t")
        .await
        .unwrap();
    assert_eq!(r, Execution::Unverified("grant_key_revoked"));
    h2.set_now(h2.now() + 36);
    assert_eq!(
        revoked
            .execute(decode_id(&pid).unwrap(), "t")
            .await
            .unwrap(),
        Execution::Expired
    );
    assert_eq!(h2.consumed(&pid).await, None);
    assert_eq!(h2.transfers_for(&pid).await, 0);
}

/// T40: ownership change or a missing destination between approval and execution →
/// FAILED/denied; the effect never happens.
#[tokio::test]
#[ignore]
async fn t40_state_changes_before_execution() {
    let h = harness().await;
    let pid = approved_transfer(&h, 10).await;
    h.su.execute(
        "UPDATE account_owner SET owner_sub = 'user:mallory' WHERE account_id = 'alice'",
        &[],
    )
    .await
    .unwrap();
    let r = h.b.execute(decode_id(&pid).unwrap(), "t").await.unwrap();
    assert!(
        matches!(r, Execution::Denied(ref d) if d.contains("not owned")),
        "{r:?}"
    );
    h.su.execute(
        "UPDATE account_owner SET owner_sub = 'user:alice' WHERE account_id = 'alice'",
        &[],
    )
    .await
    .unwrap();
    // Destination in another tenant.
    let p2 = h
        .propose_transfer(AGENT, "alice", "carol", 10, ALICE)
        .await
        .unwrap();
    assert_eq!(h.approve(&p2, ALICE).await, Delivery::Accepted);
    let r = h.b.execute(decode_id(&p2).unwrap(), "t").await.unwrap();
    assert!(matches!(r, Execution::Denied(_)), "{r:?}");
    assert_eq!(h.balance("alice").await, 100000);
}

/// T45: status fields for DENIED, EXPIRED, UNKNOWN; receipt ids random and set only when final.
#[tokio::test]
#[ignore]
async fn t45_status_fields() {
    let h = harness().await;
    let p = h
        .propose_transfer(AGENT, "alice", "bob", 1, ALICE)
        .await
        .unwrap();
    let id = decode_id(&p).unwrap();
    // Force a path through EXECUTING → UNKNOWN (no Phase 3 adapter produces it; the trigger allows
    // it once the grant is consumed, BR-08).
    h.su.execute(
        "INSERT INTO consumed_grant (iss, jti, exp, request_hash, outcome) VALUES ($1, $2, 0, $3, 'PENDING')",
        &[&ISS, &id.as_slice(), &[0u8; 32].as_slice()],
    )
    .await
    .unwrap();
    h.su.execute(
        "UPDATE pending_effect SET state='APPROVED', grant_bytes='\\x00', grant_exp=$2, state_changed_at=$2 WHERE pending_id=$1",
        &[&id.as_slice(), &(h.now() as i64)],
    )
    .await
    .unwrap();
    h.su.execute(
        "UPDATE pending_effect SET state='EXECUTING' WHERE pending_id=$1",
        &[&id.as_slice()],
    )
    .await
    .unwrap();
    h.su.execute(
        "UPDATE pending_effect SET state='UNKNOWN', outcome_class='unknown' WHERE pending_id=$1",
        &[&id.as_slice()],
    )
    .await
    .unwrap();
    let st = h.status(AGENT, &p).await.unwrap();
    assert_eq!(st["state"], "UNKNOWN");
    assert_eq!(st["outcome"], json!({"class":"unknown","receipt_id":null}));
    // Undeclared transition rejected by the trigger.
    assert!(h.su.execute("UPDATE pending_effect SET state='EXPIRED', outcome_class='expired', receipt_id='\\x00112233445566778899aabbccddeeff' WHERE pending_id=$1", &[&id.as_slice()]).await.is_err());

    let a = approved_transfer(&h, 1).await;
    let b = approved_transfer(&h, 2).await;
    assert_eq!(
        h.status(AGENT, &a).await.unwrap()["outcome"],
        serde_json::Value::Null
    );
    h.b.execute(decode_id(&a).unwrap(), "t").await.unwrap();
    h.b.execute(decode_id(&b).unwrap(), "t").await.unwrap();
    let ra = h.status(AGENT, &a).await.unwrap()["outcome"]["receipt_id"].clone();
    let rb = h.status(AGENT, &b).await.unwrap()["outcome"]["receipt_id"].clone();
    assert_ne!(ra, rb);
    assert_ne!(ra.as_str().unwrap(), a);
}

/// T32 (database part): a v2 broker refuses a database claimed by a v1 broker, and the v1
/// broker refuses a database claimed by v2.
#[tokio::test]
#[ignore]
async fn t32_database_claims() {
    let h = harness().await; // claimed by v2
    let e = pg_env();
    let dbcfg: nodkey_broker::config::DbConfig = serde_json::from_value(json!({
        "host": e.host, "port": e.port, "dbname": h.db, "user": "nodkey_broker", "password_file": "/x"}))
    .unwrap();
    let v1 = nodkey_broker::ledger::Ledger::new(&dbcfg, e.broker_pw.clone());
    let err = v1.claim_protocol_v1().await.unwrap_err();
    assert!(err.contains("refusing"), "{err}");

    let db2 = fresh_db().await;
    let dbcfg2: nodkey_broker::config::DbConfig = serde_json::from_value(json!({
        "host": e.host, "port": e.port, "dbname": db2, "user": "nodkey_broker", "password_file": "/x"}))
    .unwrap();
    let v1 = nodkey_broker::ledger::Ledger::new(&dbcfg2, e.broker_pw.clone());
    assert_eq!(v1.claim_protocol_v1().await, Ok(()));
    let b = build_broker(
        &db2,
        Arc::new(std::sync::atomic::AtomicU64::new(T0)),
        "active",
    );
    let err = b.startup_checks().await.unwrap_err();
    assert!(err.contains("refusing"), "{err}");
}

/// Clock high-water mark (grant-v1 §7.6): a broker whose clock is behind the persisted mark by
/// more than skew refuses to start.
#[tokio::test]
#[ignore]
async fn clock_high_water_mark() {
    let h = harness().await;
    h.set_now(T0 + 100);
    h.b.recovery_tick().await.unwrap();
    let b = build_broker(
        &h.db,
        Arc::new(std::sync::atomic::AtomicU64::new(T0 + 94)),
        "active",
    );
    assert!(b.startup_checks().await.unwrap_err().contains("high-water"));
    let b = build_broker(
        &h.db,
        Arc::new(std::sync::atomic::AtomicU64::new(T0 + 95)),
        "active",
    );
    b.startup_checks().await.unwrap();
}

/// Sockets: T16 (a grant on G closes the connection; a wrong-uid peer on A is refused and
/// closed), and the real authority client (crates/nodkey-authority) driving socket A with its
/// own message shapes: config.digest, pending.get, grant.deliver (accepted, idempotent
/// re-delivery, rejected, expired).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn sockets_and_authority_wire_format() {
    use nodkey_authority::broker_client::{BrokerClient, CallError, DeliverResult};
    use nodkey_authority::digest::PendingId;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let h = harness().await;
    let my_uid = {
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        a.peer_cred().unwrap().uid()
    };
    let dir = std::env::temp_dir().join(format!(
        "gb-{}",
        &encode_id(&nodkey_broker::v2::ids::random16().unwrap())[..10]
    ));
    for d in ["a", "g", "x"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let srv = Arc::new(Server {
        broker: h.b.clone(),
        ids: nodkey_broker::server::CorrelationIds::new([1; 8]),
    });
    let a_path = dir.join("a/broker.sock");
    let g_path = dir.join("g/broker.sock");
    let x_path = dir.join("x/broker.sock");
    let la = nodkey_broker::v2::server::bind_socket(&a_path).unwrap();
    let lg = nodkey_broker::v2::server::bind_socket(&g_path).unwrap();
    let lx = nodkey_broker::v2::server::bind_socket(&x_path).unwrap();
    tokio::spawn(serve(la, Channel::Authority, my_uid, srv.clone()));
    tokio::spawn(serve(lg, Channel::Gateway, my_uid, srv.clone()));
    // An authority socket that expects a different uid.
    tokio::spawn(serve(lx, Channel::Authority, my_uid + 1, srv.clone()));

    async fn exchange(path: &std::path::Path, line: &str) -> (Option<serde_json::Value>, bool) {
        let s = tokio::net::UnixStream::connect(path).await.unwrap();
        let (r, mut w) = s.into_split();
        // A wrong-uid peer is refused at accept: the broker writes `unauthenticated` and closes
        // before reading, so this write may race the close (EPIPE). The assertions below still
        // require the refusal response and the closed connection.
        let _ = w.write_all(format!("{line}\n").as_bytes()).await;
        let mut r = BufReader::new(r);
        let mut first = String::new();
        r.read_line(&mut first).await.unwrap();
        let resp = (!first.is_empty()).then(|| serde_json::from_str(&first).unwrap());
        // A second request on the same connection: is it still open?
        let _ = w
            .write_all(b"{\"v\":2,\"id\":\"x\",\"op\":\"pending.get\",\"args\":{}}\n")
            .await;
        let mut second = String::new();
        let n = tokio::time::timeout(Duration::from_secs(2), r.read_line(&mut second))
            .await
            .map(|x| x.unwrap_or(0))
            .unwrap_or(0);
        (resp, n == 0)
    }

    // T16: a grant on G → refused, connection closed.
    let (resp, closed) = exchange(&g_path, r#"{"v":2,"id":"g1","op":"grant.deliver","args":{"pending_id":"AAAAAAAAAAAAAAAAAAAAAA","grant":"x"}}"#).await;
    assert_eq!(resp.unwrap()["error"]["code"], "unknown_operation");
    assert!(closed);
    // T16: wrong-uid peer on A → unauthenticated, closed.
    let (resp, closed) = exchange(
        &x_path,
        r#"{"v":2,"id":"a1","op":"config.digest","args":{}}"#,
    )
    .await;
    assert_eq!(resp.unwrap()["error"]["code"], "unauthenticated");
    assert!(closed);

    // The authority's own client with its own config digest definition.
    let digest =
        nodkey_authority::config::config_digest(OPS_JSON.as_bytes(), AUTH_WORKLOADS.as_bytes());
    let client = BrokerClient::new(a_path.clone(), my_uid, digest, Duration::from_secs(5));
    client
        .check()
        .await
        .expect("config.digest matches the authority's");
    let wrong = BrokerClient::new(a_path.clone(), my_uid, [0u8; 32], Duration::from_secs(5));
    assert!(wrong.check().await.is_err());

    let pid = h
        .propose_transfer(AGENT, "alice", "bob", 77, ALICE)
        .await
        .unwrap();
    let apid = PendingId::parse(&pid).unwrap();
    let fetched = client
        .pending_get(&apid)
        .await
        .expect("pending.get parses under the authority's §3.2 rules");
    assert_eq!(fetched.state, "PENDING");
    assert_eq!(
        fetched.record.digest(),
        fetched.broker_digest,
        "authority digest == broker digest"
    );
    assert_eq!(
        client.pending_get(&PendingId([5u8; 16])).await.unwrap_err(),
        CallError::NotFound
    );

    let rec = h.get(&pid).await;
    let g = nodkey_grant::decode_transport(Some(&sign_from_record(&rec, h.now(), KEY_A, |b| b)))
        .unwrap();
    let bad = nodkey_grant::decode_transport(Some(&sign_from_record(&rec, h.now(), KEY_B, |b| b)))
        .unwrap();
    assert_eq!(
        client.deliver(&apid, &bad).await,
        Ok(DeliverResult::Rejected)
    );
    assert_eq!(client.deliver(&apid, &g).await, Ok(DeliverResult::Accepted));
    // Re-delivery of identical bytes (lost response, authority restart): accepted again.
    assert_eq!(client.deliver(&apid, &g).await, Ok(DeliverResult::Accepted));
    // The server started execution after `accepted`.
    for _ in 0..50 {
        if h.state(&pid).await == "SUCCEEDED" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(h.state(&pid).await, "SUCCEEDED");
    // Re-delivery after execution: still accepted (T46), no second effect; other bytes: expired.
    assert_eq!(client.deliver(&apid, &g).await, Ok(DeliverResult::Accepted));
    let g3 =
        nodkey_grant::decode_transport(Some(&sign_from_record(&rec, h.now() + 1, KEY_A, |b| b)))
            .unwrap();
    assert_eq!(client.deliver(&apid, &g3).await, Ok(DeliverResult::Expired));
    assert_eq!(h.transfers_for(&pid).await, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Socket G driven by the gateway's own client (crates/nodkey-gateway `ipc::render`,
/// `ipc::deny`) and its strict result types and checks (GW-1): render parses, the gateway's own
/// digest equals the broker's, display texts pass its bounds; failures are `not_available`;
/// deny moves PENDING → DENIED.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn gateway_wire_format() {
    use nodkey_gateway::ipc::{IpcError, Peer, Subject, deny, render};

    let h = harness().await;
    let my_uid = {
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        a.peer_cred().unwrap().uid()
    };
    let dir = std::env::temp_dir().join(format!(
        "gg-{}",
        &encode_id(&nodkey_broker::v2::ids::random16().unwrap())[..10]
    ));
    std::fs::create_dir_all(dir.join("g")).unwrap();
    let path = dir.join("g/broker.sock");
    let srv = Arc::new(Server {
        broker: h.b.clone(),
        ids: nodkey_broker::server::CorrelationIds::new([2; 8]),
    });
    let l = nodkey_broker::v2::server::bind_socket(&path).unwrap();
    tokio::spawn(serve(l, Channel::Gateway, my_uid, srv));
    let peer = Peer {
        path: path.clone(),
        expected_uid: Some(my_uid),
        timeout: Duration::from_secs(5),
    };
    let alice = Subject {
        ten: "acme",
        sub: "user:alice",
    };
    let bob = Subject {
        ten: "acme",
        sub: "user:bob",
    };

    let p1 = h
        .propose_transfer(AGENT, "alice", "bob", 5, ALICE)
        .await
        .unwrap();
    let p0 = h
        .propose_transfer(AGENT, "alice", "bob", 5, ALICE)
        .await
        .unwrap();
    let rd = render(&peer, &p1, alice)
        .await
        .expect("render parses under the gateway's types");
    let checked = nodkey_gateway::digest::check(rd.record.clone()).expect("gateway §3.2 check");
    assert_eq!(nodkey_broker::v2::ids::hex(&checked.digest), rd.digest);
    assert_eq!(rd.state, "PENDING");
    assert_eq!(rd.context.approver_source, "enrolled");
    assert_eq!(rd.context.recent_identical.len(), 1);
    assert_eq!(rd.context.recent_identical[0].pending_id, p0);
    assert_eq!(rd.context.other_open_on_resource.len(), 1);
    assert!(
        rd.facts
            .iter()
            .all(|f| f.label.len() <= 128 && f.value.len() <= 256)
    );
    assert!(rd.facts.iter().any(|f| f.value == "1000.00 EUR"));

    // Non-approver and unknown id: not_available.
    for r in [
        render(&peer, &p1, bob).await,
        render(&peer, &encode_id(&[3u8; 16]), alice).await,
    ] {
        assert!(
            matches!(r, Err(IpcError::Refused(ref c)) if c == "not_available"),
            "{r:?}"
        );
    }
    // Deny with the wrong digest, then the right one.
    let wrong = "0".repeat(64);
    assert!(
        matches!(deny(&peer, &p1, &wrong, alice).await, Err(IpcError::Refused(ref c)) if c == "not_available")
    );
    assert!(deny(&peer, &p1, &rd.digest, bob).await.is_err());
    deny(&peer, &p1, &rd.digest, alice).await.expect("deny");
    assert_eq!(h.state(&p1).await, "DENIED");
    let rd = render(&peer, &p1, alice).await.unwrap();
    assert_eq!(rd.state, "DENIED");
    assert!(deny(&peer, &p1, &rd.digest, alice).await.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// BR-08: the database refuses APPROVED → SUCCEEDED/FAILED/EXECUTING without a matching consumed
/// grant, even for the broker's own role (checked at commit).
#[tokio::test]
#[ignore]
async fn br08_final_state_requires_consumption() {
    let h = harness().await;
    let pid = approved_transfer(&h, 10).await;
    let id = decode_id(&pid).unwrap();
    let e = pg_env();
    let mut br = connect(pg_config(&h.db, "nodkey_broker", &e.broker_pw)).await;
    for (to, class) in [("SUCCEEDED", "succeeded"), ("FAILED", "denied")] {
        let tx = br.transaction().await.unwrap();
        tx.execute(
            "UPDATE public.pending_effect SET state = $2, outcome_class = $3, state_changed_at = 0, \
             receipt_id = '\\x00112233445566778899aabbccddeeff' WHERE pending_id = $1",
            &[&id.as_slice(), &to, &class],
        )
        .await
        .unwrap();
        let err = tx.commit().await.unwrap_err();
        assert!(
            format!("{err:?}").contains("without a consumed grant"),
            "{to}: {err:?}"
        );
    }
    assert_eq!(h.state(&pid).await, "APPROVED");
    // The real execution path still succeeds.
    assert_eq!(h.b.execute(id, "t").await.unwrap(), Execution::Succeeded);
}

/// BR-01: a workload flood cannot starve sockets G/A or execution. (a) With every workload-lane
/// connection held, render, delivery and execution still complete on the control lane. (b) One
/// workload's concurrent read flood is capped per workload and does not block another
/// workload's approved effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn br01_workload_flood_does_not_starve_effects() {
    let h = harness().await;
    let pid = h
        .propose_transfer(AGENT, "alice", "bob", 25, ALICE)
        .await
        .unwrap();
    // (a) Exhaust the workload lane completely.
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(h.b.db.get().await.unwrap());
    }
    let e =
        h.b.status(&h.wl(AGENT), &obj(json!({"pending_id": pid})))
            .await
            .unwrap_err();
    assert_eq!(e.code, Code::Unavailable, "workload lane is exhausted");
    assert_eq!(h.approve(&pid, ALICE).await, Delivery::Accepted);
    assert_eq!(
        h.b.execute(decode_id(&pid).unwrap(), "t").await.unwrap(),
        Execution::Succeeded
    );
    drop(held);

    // (b) AGENT2 floods reads; AGENT's approved transfer executes meanwhile.
    let p2 = h
        .propose_transfer(AGENT, "alice", "bob", 26, ALICE)
        .await
        .unwrap();
    let g = read_grant(h.now(), AGENT2, "acme", "user:bob", KEY_A);
    let mut flood = Vec::new();
    for _ in 0..200 {
        let (b, wl, g) = (h.b.clone(), h.wl(AGENT2), g.clone());
        flood.push(tokio::spawn(async move {
            b.read(
                &wl,
                "ledger.get_balance",
                &obj(json!({"account": "bob", "grant": g})),
            )
            .await
        }));
    }
    assert_eq!(h.approve(&p2, ALICE).await, Delivery::Accepted);
    assert_eq!(
        h.b.execute(decode_id(&p2).unwrap(), "t").await.unwrap(),
        Execution::Succeeded
    );
    let mut ok = 0;
    for f in flood {
        match f.await.unwrap() {
            Ok(_) => ok += 1,
            Err(e) => assert!(
                matches!(e.code, Code::LimitExceeded | Code::Unavailable),
                "{e:?}"
            ),
        }
    }
    assert!(ok > 0);
    // AGENT itself is unaffected by AGENT2's flood.
    let ga = read_grant(h.now(), AGENT, "acme", "user:alice", KEY_A);
    assert!(
        h.b.read(
            &h.wl(AGENT),
            "ledger.get_balance",
            &obj(json!({"account": "alice", "grant": ga}))
        )
        .await
        .is_ok()
    );
}
