// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! The deterministic fault catalogue (research note 06 §2.1) and webhooks.

mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

fn p(amount: u64, reference: &str) -> String {
    format!("charge={CH_USD}&amount={amount}&reference={reference}")
}

#[tokio::test]
async fn fail_before_commit_is_not_cached() {
    let s = start(json!({})).await;
    faults(
        &s,
        json!([{"match": {"op": "create_refund"}, "fault": {"kind": "fail_before_commit"}}]),
    )
    .await;
    let r = refund(&s, SK, "k", &p(100, "eff_a")).await;
    assert_eq!(r.status, 500);
    assert_eq!(r.json()["error"]["type"], "api_error");
    assert_eq!(r.header("simpay-should-retry").as_deref(), Some("true"));
    assert_eq!(ledger(&s, CH_USD).await, (0, 0, 0));
    assert_eq!(
        get(&s, SK, "/v1/idempotency_keys?key=k").await.json()["state"],
        "none"
    );
    // Same-key retry executes once.
    let r = refund(&s, SK, "k", &p(100, "eff_a")).await;
    assert_eq!(r.status, 200);
    assert!(r.header("idempotent-replayed").is_none());
    assert_eq!(ledger(&s, CH_USD).await, (1, 100, 100));
}

#[tokio::test]
async fn commit_then_500_caches_the_500() {
    let s = start(json!({})).await;
    faults(&s, json!([{"fault": {"kind": "commit_then_500"}}])).await;
    let r = refund(&s, SK, "k", &p(100, "eff_b")).await;
    assert_eq!(r.status, 500);
    assert_eq!(r.header("simpay-should-retry").as_deref(), Some("false"));
    assert_eq!(ledger(&s, CH_USD).await, (1, 100, 100));
    // The cached 500 does not resolve.
    let r2 = refund(&s, SK, "k", &p(100, "eff_b")).await;
    assert_eq!(r2.status, 500);
    assert_eq!(r2.header("idempotent-replayed").as_deref(), Some("true"));
    assert_eq!(r.body, r2.body);
    // Reconciliation by lookup does.
    let l = get(
        &s,
        SK,
        &format!("/v1/refunds?charge={CH_USD}&reference=eff_b"),
    )
    .await
    .json();
    assert_eq!(l["data"][0]["amount"], 100);
    assert_eq!(ledger(&s, CH_USD).await, (1, 100, 100));
}

#[tokio::test]
async fn commit_then_drop_connection() {
    let s = start(json!({})).await;
    faults(&s, json!([{"fault": {"kind": "commit_then_drop"}}])).await;
    let r = refund_t(&s, SK, "k", &p(250, "eff_c"), Duration::from_secs(5)).await;
    assert_eq!(r.unwrap_err(), ClientError::Closed);
    assert_eq!(ledger(&s, CH_USD).await, (1, 250, 250));
    // Same-key retry returns the original success.
    let r = refund(&s, SK, "k", &p(250, "eff_c")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("idempotent-replayed").as_deref(), Some("true"));
    let l = get(&s, SK, "/v1/refunds?reference=eff_c").await.json();
    assert_eq!(l["data"][0]["id"], r.json()["id"]);
    assert_eq!(ledger(&s, CH_USD).await, (1, 250, 250));
}

#[tokio::test]
async fn drop_before_commit() {
    let s = start(json!({})).await;
    faults(&s, json!([{"fault": {"kind": "drop_before_commit"}}])).await;
    let r = refund_t(&s, SK, "k", &p(250, "eff_d"), Duration::from_secs(5)).await;
    assert_eq!(r.unwrap_err(), ClientError::Closed);
    assert_eq!(ledger(&s, CH_USD).await, (0, 0, 0));
    let r = refund(&s, SK, "k", &p(250, "eff_d")).await;
    assert!(r.header("idempotent-replayed").is_none());
    assert_eq!(ledger(&s, CH_USD).await, (1, 250, 250));
}

#[tokio::test]
async fn late_commit_after_client_timeout() {
    let s = start(json!({})).await;
    faults(
        &s,
        json!([{"fault": {"kind": "commit_after_delay", "ms": 600}}]),
    )
    .await;
    let r = refund_t(&s, SK, "k", &p(300, "eff_e"), Duration::from_millis(100)).await;
    assert_eq!(r.unwrap_err(), ClientError::Timeout);
    // While in progress: not found by lookup, key reported in_progress, retry gets 409.
    let l = get(&s, SK, "/v1/refunds?reference=eff_e").await.json();
    assert!(
        l["data"].as_array().unwrap().is_empty(),
        "not found ≠ no effect"
    );
    assert_eq!(
        get(&s, SK, "/v1/idempotency_keys?key=k").await.json()["state"],
        "in_progress"
    );
    let r = refund(&s, SK, "k", &p(300, "eff_e")).await;
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (409, "idempotency_key_in_progress")
    );
    assert_eq!(r.header("simpay-should-retry").as_deref(), Some("true"));
    // The commit lands even though the client went away.
    let shared = s.shared().clone();
    assert!(wait_until(|| shared.lock().refunds.len() == 1, Duration::from_secs(3)).await);
    let r = refund(&s, SK, "k", &p(300, "eff_e")).await;
    assert_eq!(
        (r.status, r.header("idempotent-replayed").as_deref()),
        (200, Some("true"))
    );
    assert_eq!(
        get(&s, SK, "/v1/idempotency_keys?key=k").await.json()["state"],
        "done"
    );
    assert_eq!(ledger(&s, CH_USD).await, (1, 300, 300));
}

#[tokio::test]
async fn slow_response_commits_first() {
    let s = start(json!({})).await;
    faults(&s, json!([{"fault": {"kind": "slow_response", "ms": 500}}])).await;
    let r = refund_t(&s, SK, "k", &p(10, "eff_f"), Duration::from_millis(100)).await;
    assert_eq!(r.unwrap_err(), ClientError::Timeout);
    // Already committed when the client gave up.
    assert_eq!(ledger(&s, CH_USD).await, (1, 10, 10));
    // A patient client receives the late 200.
    faults(&s, json!([{"fault": {"kind": "slow_response", "ms": 300}}])).await;
    let t = Instant::now();
    let r = refund(&s, SK, "k2", &p(10, "eff_g")).await;
    assert!(t.elapsed() >= Duration::from_millis(300));
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn inflight_duplicate_gets_409() {
    let s = start(json!({})).await;
    faults(
        &s,
        json!([{"fault": {"kind": "inflight_409", "hold_ms": 500}}]),
    )
    .await;
    let addr_s = &s;
    let body = p(40, "eff_h");
    let first = refund(addr_s, SK, "k", &body);
    let second = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let dup = refund(addr_s, SK, "k", &p(40, "eff_h")).await;
        let other = refund(addr_s, SK, "k", &p(41, "eff_h")).await;
        (dup, other)
    };
    let (a, (dup, other)) = tokio::join!(first, second);
    assert_eq!(a.status, 200);
    assert_eq!(
        (dup.status, dup.err_code().as_str()),
        (409, "idempotency_key_in_progress")
    );
    assert_eq!(
        (other.status, other.err_code().as_str()),
        (400, "idempotency_params_mismatch")
    );
    // The 409 was not cached; a later retry replays the success.
    let c = refund(&s, SK, "k", &p(40, "eff_h")).await;
    assert_eq!(c.header("idempotent-replayed").as_deref(), Some("true"));
    assert_eq!(c.body, a.body);
    assert_eq!(ledger(&s, CH_USD).await, (1, 40, 40));
}

#[tokio::test]
async fn rate_limit_fault_executes_nothing() {
    let s = start(json!({})).await;
    faults(&s, json!([{"fault": {"kind": "rate_limit"}, "times": 2}])).await;
    for _ in 0..2 {
        let r = refund(&s, SK, "k", &p(5, "eff_i")).await;
        assert_eq!(r.status, 429);
        assert_eq!(
            r.header("simpay-rate-limited-reason").as_deref(),
            Some("fault-injected")
        );
    }
    assert_eq!(ledger(&s, CH_USD).await, (0, 0, 0));
    let r = refund(&s, SK, "k", &p(5, "eff_i")).await;
    assert_eq!(r.status, 200);
    assert!(r.header("idempotent-replayed").is_none());
}

#[tokio::test]
async fn rules_are_deterministic_by_match_count_and_filter() {
    let s = start(json!({})).await;
    faults(
        &s,
        json!([
            {"id": "second-call", "match": {"op": "create_refund"}, "nth": 2,
             "fault": {"kind": "fail_before_commit", "status": 503}},
            {"id": "by-key", "match": {"idempotency_key": "special"},
             "fault": {"kind": "fail_before_commit", "status": 502}},
            {"id": "by-charge", "match": {"charge": CH_JPY}, "times": 0,
             "fault": {"kind": "fail_before_commit"}}
        ]),
    )
    .await;
    assert_eq!(refund(&s, SK, "a", &p(1, "eff_1")).await.status, 200);
    assert_eq!(refund(&s, SK, "b", &p(1, "eff_2")).await.status, 503);
    assert_eq!(refund(&s, SK, "c", &p(1, "eff_3")).await.status, 200);
    assert_eq!(refund(&s, SK, "special", &p(1, "eff_4")).await.status, 502);
    for i in 0..3 {
        let r = refund(
            &s,
            SK,
            &format!("j{i}"),
            &format!("charge={CH_JPY}&amount=1"),
        )
        .await;
        assert_eq!(r.status, 500, "unlimited rule");
    }
    let plan = admin(&s, "GET", "/admin/faults", Value::Null).await.json();
    assert_eq!(plan["rules"][0]["fired"], 1);
    assert_eq!(plan["rules"][2]["fired"], 3);
    // Clearing the plan restores normal behaviour.
    admin(&s, "DELETE", "/admin/faults", Value::Null).await;
    assert_eq!(
        refund(&s, SK, "j9", &format!("charge={CH_JPY}&amount=1"))
            .await
            .status,
        200
    );
    // Bad plans are rejected.
    for bad in [
        json!([{"fault": {"kind": "fail_before_commit", "status": 404}}]),
        json!([{"fault": {"kind": "nope"}}]),
        json!([{"fault": {"kind": "rate_limit"}, "nth": 0}]),
        json!([{"fault": {"kind": "rate_limit"}, "extra": 1}]),
    ] {
        let r = admin(&s, "PUT", "/admin/faults", json!({"rules": bad})).await;
        assert_eq!(r.status, 400, "{bad}");
    }
}

#[tokio::test]
async fn webhooks_are_signed_and_retried() {
    let s = start(json!({})).await;
    let hook = hook_server(2).await; // first two attempts fail with 500
    set_endpoint(&s, &hook.url()).await;
    let r = refund(&s, SK, "k", &p(100, "eff_w")).await;
    let refund_id = r.json()["id"].as_str().unwrap().to_string();
    assert!(wait_until(|| hook.count() == 1, Duration::from_secs(5)).await);
    let got = hook.all().remove(0);
    let ev = got.json();
    assert_eq!(ev["type"], "refund.created");
    assert_eq!(ev["data"]["object"]["id"], refund_id.as_str());
    assert_eq!(ev["simulator"], true);
    assert_eq!(got.event_id_header, ev["id"].as_str().unwrap());
    let now = now(&s).await;
    assert_eq!(verify(WHSEC, &got.signature, &got.body, now, 300), Ok(now));
    // Wrong secret, altered body, and stale timestamps are rejected by a correct receiver.
    assert!(
        verify(
            "whsec_sim_wrongwrongwrong00",
            &got.signature,
            &got.body,
            now,
            300
        )
        .is_err()
    );
    let mut tampered = got.body.clone();
    tampered[10] ^= 1;
    assert!(verify(WHSEC, &got.signature, &tampered, now, 300).is_err());
    assert_eq!(
        verify(WHSEC, &got.signature, &got.body, now + 301, 300),
        Err("stale timestamp")
    );
    // Delivery log shows the retries.
    let d = admin(&s, "GET", "/admin/webhooks/deliveries", Value::Null)
        .await
        .json();
    let results: Vec<&str> = d["deliveries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["result"].as_str().unwrap())
        .collect();
    assert_eq!(results, ["500", "500", "200"]);
}

#[tokio::test]
async fn webhook_duplicate_delivery() {
    let s = start(json!({})).await;
    let hook = hook_server(0).await;
    set_endpoint(&s, &hook.url()).await;
    faults(&s, json!([{"match": {"event_type": "refund.created"}, "fault": {"kind": "webhook_duplicate", "n": 3}}])).await;
    refund(&s, SK, "k", &p(1, "eff_x")).await;
    assert!(wait_until(|| hook.count() == 3, Duration::from_secs(5)).await);
    let all = hook.all();
    let ids: Vec<Value> = all.iter().map(|r| r.json()["id"].clone()).collect();
    assert!(ids.iter().all(|i| *i == ids[0]), "same event id each time");
    let now = now(&s).await;
    for r in &all {
        assert!(verify(WHSEC, &r.signature, &r.body, now, 300).is_ok());
    }
}

#[tokio::test]
async fn webhook_replay_with_old_signature() {
    let s = start(json!({})).await;
    let hook = hook_server(0).await;
    set_endpoint(&s, &hook.url()).await;
    faults(
        &s,
        json!([{"fault": {"kind": "webhook_replay", "after_ms": 400}}]),
    )
    .await;
    refund(&s, SK, "k", &p(1, "eff_y")).await;
    assert!(wait_until(|| hook.count() == 1, Duration::from_secs(5)).await);
    // Time moves on before the replay arrives.
    advance(&s, 3600).await;
    assert!(wait_until(|| hook.count() == 2, Duration::from_secs(5)).await);
    let all = hook.all();
    assert_eq!(all[0].body, all[1].body, "identical bytes");
    assert_eq!(
        all[0].signature, all[1].signature,
        "old timestamp and signature"
    );
    let now = now(&s).await;
    // The signature is still cryptographically valid; only freshness rejects it.
    assert_eq!(
        verify(WHSEC, &all[1].signature, &all[1].body, now, 300),
        Err("stale timestamp")
    );
    // Manual replay of a logged delivery via the admin API.
    let r = admin(&s, "POST", "/admin/webhooks/resend", json!({"index": 0})).await;
    assert_eq!(r.json()["result"], "200");
    assert!(wait_until(|| hook.count() == 3, Duration::from_secs(5)).await);
    assert_eq!(hook.all()[2].signature, all[0].signature);
}

#[tokio::test]
async fn webhook_suppressed() {
    let s = start(json!({})).await;
    let hook = hook_server(0).await;
    set_endpoint(&s, &hook.url()).await;
    faults(&s, json!([{"fault": {"kind": "webhook_suppress"}}])).await;
    refund(&s, SK, "k1", &p(1, "eff_s1")).await;
    refund(&s, SK, "k2", &p(1, "eff_s2")).await;
    assert!(wait_until(|| hook.count() == 1, Duration::from_secs(5)).await);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(hook.count(), 1, "first event suppressed");
    assert_eq!(
        hook.all()[0].json()["data"]["object"]["reference"],
        "eff_s2"
    );
}

#[tokio::test]
async fn late_refund_failed_after_success() {
    let s = start(json!({})).await;
    let hook = hook_server(0).await;
    set_endpoint(&s, &hook.url()).await;
    faults(
        &s,
        json!([{"fault": {"kind": "late_refund_failed", "after_s": 60}}]),
    )
    .await;
    let r = refund(&s, SK, "k", &p(900, "eff_z")).await;
    assert_eq!(r.json()["status"], "succeeded");
    let id = r.json()["id"].as_str().unwrap().to_string();
    advance(&s, 59).await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(
        get(&s, SK, &format!("/v1/refunds/{id}")).await.json()["status"],
        "succeeded"
    );
    advance(&s, 1).await;
    assert_eq!(
        get(&s, SK, &format!("/v1/refunds/{id}")).await.json()["status"],
        "failed"
    );
    // The failed amount returns to the charge (provider view).
    assert_eq!(ledger(&s, CH_USD).await, (1, 900, 0));
    assert!(wait_until(|| hook.count() == 3, Duration::from_secs(5)).await);
    let mut types: Vec<String> = hook
        .all()
        .iter()
        .map(|r| r.json()["type"].as_str().unwrap().to_string())
        .collect();
    types.sort();
    assert_eq!(types, ["refund.created", "refund.failed", "refund.updated"]);
}

#[tokio::test]
async fn system_clock_mode_and_ticker() {
    let s = start(json!({"clock": {"mode": "system"}})).await;
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(now(&s).await.abs_diff(wall) <= 2);
    faults(
        &s,
        json!([{"fault": {"kind": "late_refund_failed", "after_s": 0}}]),
    )
    .await;
    let r = refund(&s, SK, "k", &p(1, "eff_t")).await;
    let id = r.json()["id"].as_str().unwrap().to_string();
    let shared = s.shared().clone();
    assert!(
        wait_until(
            || shared.lock().refunds.get(&id).map(|r| r.status)
                == Some(simpay::state::RefundStatus::Failed),
            Duration::from_secs(3)
        )
        .await
    );
}
