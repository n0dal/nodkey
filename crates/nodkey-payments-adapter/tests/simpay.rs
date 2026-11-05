// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! `refund.create` through socket P against a real simpay process over TLS with the pinned test
//! CA: happy path, deduplicated resends, every create-relevant simpay fault and malicious kind
//! (payments-adapter-v1 §11 PT-04/06..09/16..18/26/29), with simpay's admin ledger as ground truth.

mod common;

use std::time::Duration;

use common::*;
use nodkey_payments_adapter::provider::Call;
use nodkey_payments_adapter::result::{Expected, Lookup, classify_find, classify_get};
use serde_json::{Value, json};

struct Env {
    s: Simpay,
    p: P,
}

async fn env_with(f: impl FnOnce(&mut Opts)) -> Env {
    let s = Simpay::start(Tls::Good);
    let mut o = Opts::new(s.api);
    f(&mut o);
    let p = start_p(o).await;
    Env { s, p }
}

async fn env() -> Env {
    env_with(|_| {}).await
}

fn grant(amount: u64) -> String {
    sign(&refund_grant(amount, "USD", CH_USD, now()), SEED)
}

fn create_rule(kind: Value) -> Value {
    json!([{"match": {"op": "create_refund"}, "fault": kind, "nth": 1, "times": 1}])
}

/// The derived reference for a grant, taken from the adapter's own result.
fn reference(v: &Value) -> String {
    v["result"]["reference"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hello_reports_format_caps_kid_and_r_max() {
    let e = env().await;
    let v = e.p.call("adapter.hello", json!({})).await;
    assert_eq!(v["ok"], json!(true));
    let r = &v["result"];
    assert_eq!(r["format"], json!("nodkey.payments-adapter.v1"));
    assert_eq!(r["profile"], json!("simpay"));
    assert_eq!(r["caps"], json!(["idem_status"]));
    assert_eq!(r["r_max_s"], json!(43_200));
    let kid = r["idem_kid"].as_str().unwrap();
    assert_eq!(kid.len(), 16);
    assert!(kid.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(
        err_code(&e.p.call("adapter.hello", json!({"x": 1})).await),
        "malformed_request"
    );
}

/// Happy path; the result is bounded to the §4 members; a resend of the same grant is the same
/// key and fingerprint (no `idempotency_params_mismatch`), and the ledger shows one refund (PT-26).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_then_resend_is_one_refund() {
    let e = env().await;
    let g = grant(500);
    let v = e.p.create(&g).await;
    assert_eq!(result_class(&v), ("created", ""));
    let r = &v["result"];
    let mut keys: Vec<&str> = r.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["anomalies", "class", "reference", "refund"]);
    let mut rk: Vec<&str> = r["refund"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    rk.sort();
    assert_eq!(
        rk,
        [
            "amount_minor",
            "charge",
            "currency",
            "id",
            "reference",
            "status"
        ]
    );
    assert_eq!(r["refund"]["amount_minor"], json!(500));
    assert_eq!(r["refund"]["currency"], json!("USD"));
    assert_eq!(r["refund"]["charge"], json!(CH_USD));
    assert_eq!(r["refund"]["reference"], r["reference"]);
    assert_eq!(reference(&v).len(), 43);
    assert_eq!(e.s.ledger(CH_USD), (1, 500));
    let again = e.p.create(&g).await;
    assert_eq!(result_class(&again), ("created", ""));
    assert_eq!(again["result"]["refund"]["id"], r["refund"]["id"]);
    assert_eq!(again["result"]["reference"], r["reference"]);
    assert_eq!(e.s.ledger(CH_USD), (1, 500));
    // A different grant (new jti) for the same values is a different key and reference.
    let other = e.p.create(&grant(500)).await;
    assert_eq!(result_class(&other), ("created", ""));
    assert_ne!(other["result"]["reference"], r["reference"]);
    assert_eq!(e.s.ledger(CH_USD), (2, 1000));
}

/// PT-29 / PT-04: the same grant 20× sequentially and 20× concurrently → ledger 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn same_grant_many_times_is_one_refund() {
    let e = env_with(|o| o.max_concurrent = 32).await;
    let g = grant(100);
    for _ in 0..20 {
        let v = e.p.create(&g).await;
        assert_eq!(result_class(&v).0, "created");
    }
    assert_eq!(e.s.ledger(CH_USD), (1, 100));
    let g2 = grant(200);
    let mut hs = Vec::new();
    let p = std::sync::Arc::new(e.p);
    for _ in 0..20 {
        let (p, g2) = (p.clone(), g2.clone());
        hs.push(tokio::spawn(async move { p.create(&g2).await }));
    }
    let mut classes = Vec::new();
    for h in hs {
        let v = h.await.unwrap();
        let c = result_class(&v).0.to_owned();
        assert!(c == "created" || c == "busy", "{v}");
        classes.push(c);
    }
    assert!(classes.iter().any(|c| c == "created"));
    assert_eq!(e.s.ledger(CH_USD), (2, 300));
}

/// PT-06: `commit_then_drop` → ambiguous (abrupt EOF after send); ledger 1; the same-key resend
/// replays the cached 200 → created, ledger still 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commit_then_drop_is_ambiguous_and_resend_replays() {
    let e = env().await;
    e.s.faults(create_rule(json!({"kind": "commit_then_drop"})));
    let g = grant(500);
    let v = e.p.create(&g).await;
    assert_eq!(result_class(&v), ("ambiguous", "reset_after_send"));
    assert_eq!(v["result"]["anomalies"], json!(["reset_after_send"]));
    assert_eq!(e.s.ledger(CH_USD), (1, 500));
    let r = e.p.create(&g).await;
    assert_eq!(result_class(&r).0, "created");
    assert_eq!(e.s.ledger(CH_USD), (1, 500));
}

/// PT-08: `commit_then_500` → ambiguous/http_5xx (body not decoded); the cached 500 replays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commit_then_500_is_ambiguous_and_cached() {
    let e = env().await;
    e.s.faults(create_rule(json!({"kind": "commit_then_500"})));
    let g = grant(500);
    assert_eq!(
        result_class(&e.p.create(&g).await),
        ("ambiguous", "http_5xx")
    );
    assert_eq!(e.s.ledger(CH_USD), (1, 500));
    assert_eq!(
        result_class(&e.p.create(&g).await),
        ("ambiguous", "http_5xx")
    );
    assert_eq!(e.s.ledger(CH_USD), (1, 500));
}

/// PT-09: faults where nothing was executed are still ambiguous (or busy), never `not_sent`; a
/// same-key resend then executes exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_executed_faults_then_resend_once() {
    let e = env().await;
    for (kind, want) in [
        (
            json!({"kind": "fail_before_commit"}),
            ("ambiguous", "http_5xx"),
        ),
        (
            json!({"kind": "drop_before_commit"}),
            ("ambiguous", "reset_after_send"),
        ),
        (json!({"kind": "rate_limit"}), ("busy", "rate_limited")),
    ] {
        let before = e.s.ledger(CH_USD);
        e.s.faults(create_rule(kind.clone()));
        let g = grant(10);
        let v = e.p.create(&g).await;
        assert_eq!(result_class(&v), want, "{kind}");
        assert_eq!(e.s.ledger(CH_USD), before, "{kind}: nothing executed");
        let r = e.p.create(&g).await;
        assert_eq!(result_class(&r).0, "created", "{kind}");
        assert_eq!(e.s.ledger(CH_USD).0, before.0 + 1, "{kind}");
        assert_eq!(result_class(&e.p.create(&g).await).0, "created");
        assert_eq!(
            e.s.ledger(CH_USD).0,
            before.0 + 1,
            "{kind}: resend deduplicated"
        );
    }
}

/// PT-09 `inflight_409`: two concurrent sends of one grant → one created, one busy/in_progress.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inflight_409_is_busy_in_progress() {
    let e = env().await;
    e.s.faults(create_rule(
        json!({"kind": "inflight_409", "hold_ms": 1500}),
    ));
    let g = grant(25);
    let p = std::sync::Arc::new(e.p);
    let (p1, g1) = (p.clone(), g.clone());
    let first = tokio::spawn(async move { p1.create(&g1).await });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let second = p.create(&g).await;
    assert_eq!(result_class(&second), ("busy", "in_progress"));
    assert_eq!(result_class(&first.await.unwrap()).0, "created");
    assert_eq!(e.s.ledger(CH_USD), (1, 25));
}

/// PT-07: `commit_after_delay` longer than `total_ms` → ambiguous/timeout; a resend meanwhile is
/// busy/in_progress; after the commit the resend replays → ledger 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commit_after_delay_times_out_then_in_progress_then_one() {
    let e = env_with(|o| {
        o.total_ms = 1500;
        o.connect_ms = 1000;
    })
    .await;
    e.s.faults(create_rule(
        json!({"kind": "commit_after_delay", "ms": 3000}),
    ));
    let g = grant(30);
    let v = e.p.create(&g).await;
    assert_eq!(result_class(&v), ("ambiguous", "timeout"));
    let busy = e.p.create(&g).await;
    assert_eq!(result_class(&busy), ("busy", "in_progress"));
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(result_class(&e.p.create(&g).await).0, "created");
    assert_eq!(e.s.ledger(CH_USD), (1, 30));
}

/// `slow_response` and `slow_drip` beyond `total_ms` are bounded: ambiguous/timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_responses_are_bounded() {
    let e = env_with(|o| {
        o.total_ms = 1500;
        o.connect_ms = 1000;
    })
    .await;
    e.s.faults(create_rule(json!({"kind": "slow_response", "ms": 4000})));
    let t = std::time::Instant::now();
    assert_eq!(
        result_class(&e.p.create(&grant(5)).await),
        ("ambiguous", "timeout")
    );
    assert!(t.elapsed() < Duration::from_millis(2500));
    e.s.malicious(true);
    e.s.faults(create_rule(
        json!({"kind": "slow_drip", "chunk": 1, "interval_ms": 100}),
    ));
    let t = std::time::Instant::now();
    assert_eq!(
        result_class(&e.p.create(&grant(6)).await),
        ("ambiguous", "timeout")
    );
    assert!(t.elapsed() < Duration::from_millis(2500));
    assert_eq!(e.s.ledger(CH_USD), (2, 11));
}

/// PT-16: lies are never `created`; the ledger shows what really happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lies_are_ambiguous_echo_mismatch() {
    let e = env().await;
    e.s.malicious(true);
    for kind in [
        json!({"kind": "lie_amount", "amount": 1}),
        json!({"kind": "lie_charge", "charge": CH_JPY}),
        json!({"kind": "lie_currency", "currency": "eur"}),
    ] {
        e.s.faults(create_rule(kind.clone()));
        let v = e.p.create(&grant(7)).await;
        assert_eq!(result_class(&v), ("ambiguous", "echo_mismatch"), "{kind}");
        assert_eq!(
            v["result"]["anomalies"],
            json!(["echo_mismatch", "contradicts_request"])
        );
    }
    assert_eq!(e.s.ledger(CH_USD), (3, 21));
    // A lied status is a valid status: it is reported, not trusted (the broker confirms by GET).
    e.s.faults(create_rule(
        json!({"kind": "lie_status", "status": "pending"}),
    ));
    let v = e.p.create(&grant(8)).await;
    assert_eq!(result_class(&v).0, "created");
    assert_eq!(v["result"]["refund"]["status"], json!("pending"));
}

/// PT-16: `phantom_success` is indistinguishable at create (undetectable lie, §6.3) but a lookup
/// of the returned id finds nothing; `deny_but_commit` is `refused` while the ledger shows the
/// refund (refused is evidence, not a decision).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn phantom_success_and_deny_but_commit() {
    let e = env().await;
    e.s.malicious(true);
    e.s.faults(create_rule(json!({"kind": "phantom_success"})));
    let g = grant(9);
    let v = e.p.create(&g).await;
    assert_eq!(result_class(&v).0, "created");
    assert_eq!(e.s.ledger(CH_USD), (0, 0));
    let id = v["result"]["refund"]["id"].as_str().unwrap().to_owned();
    let exp = Expected {
        charge: CH_USD.into(),
        amount_minor: 9,
        currency: "USD".into(),
        reference: reference(&v),
    };
    let x =
        e.p.adapter
            .provider
            .exchange(&Call::Get {
                path_and_query: format!("/v1/refunds/{id}"),
            })
            .await;
    assert_eq!(classify_get(&x, &exp, &id), Lookup::NotFound);
    // Not cached by simpay: the same-key resend executes once.
    let r = e.p.create(&g).await;
    assert_eq!(result_class(&r).0, "created");
    assert_eq!(e.s.ledger(CH_USD), (1, 9));

    e.s.faults(create_rule(json!({"kind": "deny_but_commit"})));
    let g = grant(11);
    let v = e.p.create(&g).await;
    assert_eq!(result_class(&v), ("refused", "charge_already_refunded"));
    assert_eq!(v["result"]["http"], json!(400));
    assert_eq!(e.s.ledger(CH_USD), (2, 20));
    let q = format!(
        "/v1/refunds?charge={CH_USD}&reference={}&limit=3",
        reference(&v)
    );
    let x =
        e.p.adapter
            .provider
            .exchange(&Call::Get { path_and_query: q })
            .await;
    let exp = Expected {
        charge: CH_USD.into(),
        amount_minor: 11,
        currency: "USD".into(),
        reference: reference(&v),
    };
    assert!(matches!(classify_find(&x, &exp), Lookup::Found(_)));
}

/// PT-17: a redirect is ambiguous and never followed (the target sees no connection).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redirect_is_never_followed() {
    let e = env().await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = l.local_addr().unwrap();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h2 = hits.clone();
    tokio::spawn(async move {
        while l.accept().await.is_ok() {
            h2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    e.s.malicious(true);
    for status in [301, 302, 307, 308] {
        e.s.faults(create_rule(json!({"kind": "redirect", "status": status,
            "location": format!("http://{target}/v1/refunds")})));
        assert_eq!(
            result_class(&e.p.create(&grant(3)).await),
            ("ambiguous", "redirect")
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(e.s.ledger(CH_USD), (0, 0));
}

/// PT-18: oversized bodies and heads, header-injection variants and malformed JSON are bounded
/// and ambiguous; no provider text reaches any response or log line (byte search).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_responses_are_bounded_and_ambiguous() {
    let e = env().await;
    e.s.malicious(true);
    let cases: Vec<(Value, &[&str])> = vec![
        (
            json!({"kind": "oversized_body", "bytes": 200_000}),
            &["oversized"],
        ),
        (
            json!({"kind": "oversized_header", "bytes": 40_000}),
            &["bad_headers"],
        ),
        (
            json!({"kind": "header_injection", "variant": "bare_cr"}),
            &["bad_headers"],
        ),
        (
            json!({"kind": "header_injection", "variant": "nul_byte"}),
            &["bad_headers"],
        ),
        (
            json!({"kind": "header_injection", "variant": "obs_fold"}),
            &["bad_headers"],
        ),
        (
            json!({"kind": "header_injection", "variant": "duplicate_content_length"}),
            &["bad_headers"],
        ),
        (
            json!({"kind": "header_injection", "variant": "te_and_cl"}),
            &["bad_headers", "reset_after_send"],
        ),
        (
            json!({"kind": "malformed_json", "variant": "truncated"}),
            &["bad_json", "reset_after_send"],
        ),
        (
            json!({"kind": "malformed_json", "variant": "duplicate_keys"}),
            &["bad_json"],
        ),
        (
            json!({"kind": "malformed_json", "variant": "deep_nesting"}),
            &["bad_json", "oversized"],
        ),
        (
            json!({"kind": "malformed_json", "variant": "huge_number"}),
            &["bad_json"],
        ),
        (
            json!({"kind": "malformed_json", "variant": "trailing_garbage"}),
            &["bad_json"],
        ),
        (
            json!({"kind": "malformed_json", "variant": "not_json"}),
            &["bad_json"],
        ),
        (
            json!({"kind": "malformed_json", "variant": "wrong_content_type"}),
            &["bad_content_type"],
        ),
        (
            json!({"kind": "malformed_json", "variant": "invalid_utf8"}),
            &["bad_json"],
        ),
    ];
    let mut responses = Vec::new();
    for (kind, causes) in &cases {
        e.s.faults(create_rule(kind.clone()));
        let v = e.p.create(&grant(1)).await;
        let (c, cause) = result_class(&v);
        assert_eq!(c, "ambiguous", "{kind}: {v}");
        assert!(causes.contains(&cause), "{kind}: cause {cause}");
        responses.push(v.to_string());
    }
    // crlf_injection smuggles syntactically valid extra header lines into an otherwise exact
    // response; they are ignored (never parsed or forwarded), so the result is the real refund.
    e.s.faults(create_rule(
        json!({"kind": "header_injection", "variant": "crlf_injection"}),
    ));
    let v = e.p.create(&grant(1)).await;
    assert_eq!(result_class(&v).0, "created");
    responses.push(v.to_string());
    // hostile_error_text: a 400 with markup and prompt-injection text → refused/other_4xx.
    e.s.faults(create_rule(json!({"kind": "hostile_error_text"})));
    let v = e.p.create(&grant(1)).await;
    assert_eq!(result_class(&v), ("refused", "other_4xx"));
    responses.push(v.to_string());
    // Every case executed underneath (respond-stage faults): the ledger is the truth.
    assert_eq!(e.s.ledger(CH_USD).0, cases.len() as u64 + 2);
    let logs = logs().join("\n");
    for hay in responses.iter().chain(std::iter::once(&logs)) {
        for needle in [
            "<script",
            "<img",
            "onerror",
            "IGNORE",
            "ignore previous",
            "Set-Cookie",
            "simpay_injected",
            "attacker.invalid",
            "SIMULATED payment",
            "Simpay",
            "simulator",
            RK,
            "rk_sim_",
            "Bearer",
        ] {
            assert!(!hay.contains(needle), "found {needle:?} in {hay}");
        }
    }
}

/// The restricted key from another source address is refused by simpay (PT-13 analogue); the
/// adapter reports `refused/auth_failed` (evidence, not a decision).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_outside_allowed_cidrs_is_refused() {
    let e = env_with(|o| o.key = "rk_sim_OTHERSOURCEONLY0001").await;
    let v = e.p.create(&grant(5)).await;
    assert_eq!(result_class(&v), ("refused", "auth_failed"));
    assert_eq!(v["result"]["http"], json!(401));
    assert_eq!(e.s.ledger(CH_USD), (0, 0));
}

/// Business refusals from the provider: amount above the remaining amount; cap `send_currency`
/// with a currency that does not match the charge (the order view agrees with the grant, simpay
/// disagrees).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_business_refusals() {
    let e = env_with(|o| o.caps = vec!["send_currency"]).await;
    let v = e.p.create(&grant(6000)).await;
    assert_eq!(result_class(&v), ("refused", "amount_too_large"));
    let v = e.p.create(&grant(5)).await;
    assert_eq!(result_class(&v).0, "created");
    let orders = FakeOrders::standard();
    orders.rows.lock().unwrap().get_mut(&4711).unwrap().currency = "EUR".into();
    let e2 = env_with(|o| {
        o.caps = vec!["send_currency"];
        o.orders = orders.clone();
    })
    .await;
    let g = sign(&refund_grant(5, "EUR", CH_USD, now()), SEED);
    assert_eq!(
        result_class(&e2.p.create(&g).await),
        ("refused", "currency_mismatch")
    );
}

async fn find(p: &P, g: &str) -> Value {
    p.call("refund.find", json!({"grant": g})).await
}
async fn get(p: &P, g: &str, id: &str) -> Value {
    p.call("refund.get", json!({"grant": g, "refund_id": id}))
        .await
}
async fn idem(p: &P, g: &str) -> Value {
    p.call("idem.status", json!({"grant": g})).await
}

/// Lookups through socket P (§4, §7.3 step 1): not_found / none before; found / done after;
/// `refund.get` of the created id is found; a grant for another charge never finds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookups_through_p() {
    let e = env().await;
    let g = grant(500);
    assert_eq!(result_class(&find(&e.p, &g).await).0, "not_found");
    assert_eq!(idem(&e.p, &g).await["result"]["state"], json!("none"));
    let c = e.p.create(&g).await;
    let id = c["result"]["refund"]["id"].as_str().unwrap().to_owned();
    let f = find(&e.p, &g).await;
    assert_eq!(result_class(&f).0, "found");
    assert_eq!(f["result"]["refunds"], json!([c["result"]["refund"]]));
    let r = get(&e.p, &g, &id).await;
    assert_eq!(result_class(&r).0, "found");
    assert_eq!(r["result"]["refunds"][0], c["result"]["refund"]);
    assert_eq!(idem(&e.p, &g).await["result"]["state"], json!("done"));
    // A different grant (other charge) asking for this refund id: the echo does not match.
    let other = sign(&refund_grant(500, "JPY", CH_JPY, now()), SEED);
    assert_eq!(
        result_class(&get(&e.p, &other, &id).await),
        ("ambiguous", "echo_mismatch")
    );
    assert_eq!(
        result_class(&get(&e.p, &g, "re_DOESNOTEXIST1").await).0,
        "not_found"
    );
    assert_eq!(e.s.ledger(CH_USD), (1, 500));
}

/// PT-06 / PT-08 reconciler path: after `commit_then_drop` / `commit_then_500`, `refund.find`
/// resolves the effect without any resend; PT-07: during `commit_after_delay` the key state is
/// `in_progress` and the lookup finds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookups_resolve_ambiguous_creates() {
    let e = env().await;
    for kind in ["commit_then_drop", "commit_then_500"] {
        e.s.faults(create_rule(json!({"kind": kind})));
        let g = grant(40);
        assert_eq!(result_class(&e.p.create(&g).await).0, "ambiguous");
        assert_eq!(result_class(&find(&e.p, &g).await).0, "found", "{kind}");
        assert_eq!(idem(&e.p, &g).await["result"]["state"], json!("done"));
    }
    assert_eq!(e.s.ledger(CH_USD), (2, 80));
    e.s.faults(create_rule(
        json!({"kind": "commit_after_delay", "ms": 2500}),
    ));
    let g = grant(41);
    let p = std::sync::Arc::new(e.p);
    let (p1, g1) = (p.clone(), g.clone());
    let h = tokio::spawn(async move { p1.create(&g1).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(idem(&p, &g).await["result"]["state"], json!("in_progress"));
    assert_eq!(result_class(&find(&p, &g).await).0, "not_found");
    assert_eq!(result_class(&h.await.unwrap()).0, "created");
    assert_eq!(result_class(&find(&p, &g).await).0, "found");
}

/// PT-40: after `R_max` a create is refused with nothing sent, but lookups are served, so a late
/// `UNKNOWN` can still resolve. PT-23: `late_refund_failed` is observed as status `failed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_r_max_lookups_still_served_and_settlement_observed() {
    let e = env().await;
    e.s.faults(create_rule(
        json!({"kind": "late_refund_failed", "after_s": 0}),
    ));
    let g = grant(60);
    let c = e.p.create(&g).await;
    assert_eq!(result_class(&c).0, "created");
    let id = c["result"]["refund"]["id"].as_str().unwrap().to_owned();
    e.s.admin("POST", "/admin/clock/advance", Some(json!({"seconds": 1})));
    let r = get(&e.p, &g, &id).await;
    assert_eq!(r["result"]["refunds"][0]["status"], json!("failed"));
    // An old grant: lookups only.
    let old = sign(&refund_grant(70, "USD", CH_USD, now() - 50_000), SEED);
    assert_eq!(err_code(&e.p.create(&old).await), "grant_refused");
    assert_eq!(result_class(&find(&e.p, &old).await).0, "not_found");
    assert_eq!(idem(&e.p, &old).await["result"]["state"], json!("none"));
    assert_eq!(e.s.ledger(CH_USD).0, 1);
}

/// PT-16 on lookups: lies on GET and list are ambiguous, never found.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookup_lies_are_ambiguous() {
    let e = env().await;
    let g = grant(80);
    let c = e.p.create(&g).await;
    let id = c["result"]["refund"]["id"].as_str().unwrap().to_owned();
    e.s.malicious(true);
    for (op, kind) in [
        ("get_refund", json!({"kind": "lie_amount", "amount": 8})),
        ("list_refunds", json!({"kind": "lie_amount", "amount": 8})),
        (
            "get_refund",
            json!({"kind": "lie_charge", "charge": CH_JPY}),
        ),
        (
            "list_refunds",
            json!({"kind": "lie_currency", "currency": "eur"}),
        ),
        (
            "get_refund",
            json!({"kind": "malformed_json", "variant": "duplicate_keys"}),
        ),
        (
            "list_refunds",
            json!({"kind": "oversized_body", "bytes": 100_000}),
        ),
    ] {
        e.s.faults(json!([{"match": {"op": op}, "fault": kind, "nth": 1, "times": 1}]));
        let v = if op == "get_refund" {
            get(&e.p, &g, &id).await
        } else {
            find(&e.p, &g).await
        };
        assert_eq!(result_class(&v).0, "ambiguous", "{op} {kind}: {v}");
    }
}

/// PC-A-01 / PT-36 variant, the reviewer's scenario: a grant younger than `R_max` is executed
/// (SUCCEEDED) under K1; the operator rotates `K_idem` and restarts the adapter only; a
/// compromised broker resends the grant. With `idem_key_not_before` = rotation time the resend
/// is refused under the new kid and refused under the old kid; nothing is sent; ledger 1.
/// Baseline positive control: the same resend to an adapter with K2 but no activation time
/// executes a second refund (the attack the rule prevents).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotated_key_does_not_repeat_a_young_grant() {
    let e = env().await;
    let g = grant(500);
    assert_eq!(result_class(&e.p.create(&g).await).0, "created");
    assert_eq!(e.s.ledger(CH_USD), (1, 500));
    let k1 = e.p.adapter.idem.kid();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    // Rotation: the adapter restarts with K2, activation time = now.
    let mut o = Opts::new(e.s.api);
    o.kidem = [0x77; 32];
    o.idem_key_not_before = now();
    let p2 = start_p(o).await;
    let k2 = p2.adapter.idem.kid();
    assert_ne!(k1, k2);
    let v = p2.create(&g).await;
    assert_eq!(err_code(&v), "grant_refused", "{v}");
    let v = p2
        .call("refund.create", json!({"grant": g, "idem_kid": k1}))
        .await;
    assert_eq!(err_code(&v), "idem_kid_mismatch", "{v}");
    assert_eq!(e.s.ledger(CH_USD), (1, 500), "no second refund");
    // A grant issued after the rotation is served under K2.
    assert_eq!(result_class(&p2.create(&grant(7)).await).0, "created");
    assert_eq!(e.s.ledger(CH_USD), (2, 507));
    // Baseline: K2 without an activation time repeats the young grant.
    let mut o = Opts::new(e.s.api);
    o.kidem = [0x77; 32];
    let p3 = start_p(o).await;
    assert_eq!(result_class(&p3.create(&g).await).0, "created");
    assert_eq!(
        e.s.ledger(CH_USD),
        (3, 1007),
        "baseline: the attack succeeds"
    );
}
