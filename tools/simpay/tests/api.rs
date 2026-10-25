//! API behaviour: authentication, restricted keys, access policy, refunds, lookups,
//! idempotency, rate limits, HTTP strictness, determinism.

mod common;

use common::*;
use serde_json::{Value, json};

#[tokio::test]
async fn every_response_is_labelled_simulator() {
    let s = start(json!({})).await;
    let ok = get(&s, SK, &format!("/v1/charges/{CH_USD}")).await;
    let bad = get(&s, "nope", "/v1/charges/ch_usd00000001").await;
    let adm = admin(&s, "GET", "/admin/health", Value::Null).await;
    for r in [&ok, &bad, &adm] {
        assert!(
            r.header("simpay-simulator").unwrap().contains("SIMULATED"),
            "missing simulator header"
        );
        assert_eq!(r.json()["simulator"], true);
    }
    assert_eq!(ok.json()["livemode"], false);
}

#[tokio::test]
async fn authentication() {
    let s = start(json!({})).await;
    let r = request(s.api_addr, "GET", "/v1/refunds", &[], b"")
        .await
        .unwrap();
    assert_eq!((r.status, r.err_code().as_str()), (401, "missing_api_key"));
    let r = get(&s, "sk_sim_wrongwrongwrong00", "/v1/refunds").await;
    assert_eq!((r.status, r.err_code().as_str()), (401, "invalid_api_key"));
    assert_eq!(r.json()["error"]["type"], "authentication_error");
    // Basic or other schemes are not accepted.
    let r = request(
        s.api_addr,
        "GET",
        "/v1/refunds",
        &[("Authorization", SK)],
        b"",
    )
    .await
    .unwrap();
    assert_eq!(r.status, 401);
    // Duplicate Authorization headers are rejected.
    let auth = format!("Bearer {SK}");
    let r = request(
        s.api_addr,
        "GET",
        "/v1/refunds",
        &[("Authorization", &auth), ("Authorization", &auth)],
        b"",
    )
    .await
    .unwrap();
    assert_eq!(r.status, 400);
}

#[tokio::test]
async fn restricted_key_permissions() {
    let s = start(json!({})).await;
    // Read-only on refunds: may list, may not create, may not read charges.
    assert_eq!(get(&s, RK_READ, "/v1/refunds").await.status, 200);
    let r = refund(&s, RK_READ, "k1", &format!("charge={CH_USD}&amount=1")).await;
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (403, "insufficient_permissions")
    );
    assert_eq!(r.json()["error"]["type"], "permission_error");
    assert_eq!(
        get(&s, RK_READ, &format!("/v1/charges/{CH_USD}"))
            .await
            .status,
        403
    );
    // Charges-only: refunds none.
    assert_eq!(
        get(&s, RK_CHARGES, &format!("/v1/charges/{CH_USD}"))
            .await
            .status,
        200
    );
    assert_eq!(get(&s, RK_CHARGES, "/v1/refunds").await.status, 403);
    // Write implies read.
    let r = refund(&s, RK_WRITE, "k2", &format!("charge={CH_USD}&amount=100")).await;
    assert_eq!(r.status, 200);
    assert_eq!(get(&s, RK_WRITE, "/v1/refunds").await.status, 200);
    // A forbidden request executes nothing and caches nothing.
    assert_eq!(ledger(&s, CH_USD).await, (1, 100, 100));
    let r = refund(&s, SK, "k1", &format!("charge={CH_USD}&amount=1")).await;
    assert_eq!(r.status, 200);
    assert!(r.header("idempotent-replayed").is_none());
}

#[tokio::test]
async fn source_address_access_policy() {
    let s = start(json!({})).await;
    let r = get(&s, RK_CIDR_BAD, "/v1/refunds").await;
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (401, "source_address_not_allowed")
    );
    let r = refund(&s, RK_CIDR_BAD, "k", &format!("charge={CH_USD}")).await;
    assert_eq!(r.status, 401);
    assert_eq!(ledger(&s, CH_USD).await, (0, 0, 0));
    let r = refund(&s, RK_CIDR_OK, "k", &format!("charge={CH_USD}&amount=5")).await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn refund_amounts_and_remaining() {
    let s = start(json!({})).await;
    // Partial refunds.
    let r = refund(
        &s,
        SK,
        "a",
        &format!("charge={CH_USD}&amount=1000&reference=eff_1"),
    )
    .await;
    assert_eq!(r.status, 200);
    let j = r.json();
    assert_eq!(j["object"], "refund");
    assert_eq!(j["amount"], 1000);
    assert_eq!(j["currency"], "usd");
    assert_eq!(j["charge"], CH_USD);
    assert_eq!(j["status"], "succeeded");
    assert_eq!(j["reference"], "eff_1");
    assert!(j["id"].as_str().unwrap().starts_with("re_"));
    let r = refund(&s, SK, "b", &format!("charge={CH_USD}&amount=1500")).await;
    assert_eq!(r.status, 200);
    // Over the remaining 2500.
    let r = refund(&s, SK, "c", &format!("charge={CH_USD}&amount=2501")).await;
    assert_eq!((r.status, r.err_code().as_str()), (400, "amount_too_large"));
    assert_eq!(r.header("simpay-should-retry").as_deref(), Some("false"));
    // Default amount = remaining.
    let r = refund(&s, SK, "d", &format!("charge={CH_USD}")).await;
    assert_eq!(r.json()["amount"], 2500);
    let c = get(&s, SK, &format!("/v1/charges/{CH_USD}")).await.json();
    assert_eq!(
        (c["amount_refunded"].as_u64(), c["refunded"].as_bool()),
        (Some(5000), Some(true))
    );
    // Fully refunded.
    let r = refund(&s, SK, "e", &format!("charge={CH_USD}&amount=1")).await;
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (400, "charge_already_refunded")
    );
    assert_eq!(ledger(&s, CH_USD).await, (3, 5000, 5000));
}

#[tokio::test]
async fn currency_must_match() {
    let s = start(json!({})).await;
    let r = refund(
        &s,
        SK,
        "a",
        &format!("charge={CH_JPY}&amount=100&currency=usd"),
    )
    .await;
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (400, "currency_mismatch")
    );
    let r = refund(
        &s,
        SK,
        "b",
        &format!("charge={CH_JPY}&amount=100&currency=jpy"),
    )
    .await;
    assert_eq!(r.status, 200);
    // Without the parameter the refund inherits the charge currency.
    let r = refund(&s, SK, "c", &format!("charge={CH_JPY}&amount=100")).await;
    assert_eq!(r.json()["currency"], "jpy");
    let r = refund(
        &s,
        SK,
        "d",
        &format!("charge={CH_JPY}&amount=1&currency=JPY"),
    )
    .await;
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (400, "parameter_invalid")
    );
}

#[tokio::test]
async fn refund_parameter_strictness() {
    let s = start(json!({})).await;
    let cases = [
        (format!("charge={CH_USD}&amount=0"), "parameter_invalid"),
        (format!("charge={CH_USD}&amount=-1"), "parameter_invalid"),
        (format!("charge={CH_USD}&amount=1.5"), "parameter_invalid"),
        (format!("charge={CH_USD}&amount=1e3"), "parameter_invalid"),
        (
            format!("charge={CH_USD}&amount=9223372036854775808"),
            "parameter_invalid",
        ),
        (
            format!("charge={CH_USD}&amount=5&amount=6"),
            "parameter_duplicate",
        ),
        (format!("charge={CH_USD}&metadata=x"), "parameter_unknown"),
        (format!("charge={CH_USD}&url=http://x"), "parameter_unknown"),
        (
            format!("charge={CH_USD}&reason=because"),
            "parameter_invalid",
        ),
        (
            format!("charge={CH_USD}&reference=a%20b"),
            "parameter_invalid",
        ),
        ("amount=5".to_string(), "parameter_missing"),
        ("charge=../../x".to_string(), "parameter_invalid"),
    ];
    for (i, (body, code)) in cases.iter().enumerate() {
        let r = refund(&s, SK, &format!("k{i}"), body).await;
        assert_eq!((r.status, r.err_code()), (400, code.to_string()), "{body}");
    }
    let r = refund(&s, SK, "x1", &format!("charge={CH_UNPAID}")).await;
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (400, "charge_not_refundable")
    );
    let r = refund(&s, SK, "x2", &format!("charge={CH_OTHER}")).await;
    assert_eq!((r.status, r.err_code().as_str()), (404, "resource_missing"));
    let r = refund(&s, SK, "x3", "charge=ch_doesnotexist01").await;
    assert_eq!(r.status, 404);
    assert_eq!(ledger(&s, CH_OTHER).await, (0, 0, 0));
    assert_eq!(ledger(&s, CH_USD).await, (0, 0, 0));
    // JSON bodies are refused.
    let auth = format!("Bearer {SK}");
    let r = request(
        s.api_addr,
        "POST",
        "/v1/refunds",
        &[
            ("Authorization", &auth),
            ("Idempotency-Key", "j"),
            ("Content-Type", "application/json"),
        ],
        br#"{"charge":"ch_usd00000001"}"#,
    )
    .await
    .unwrap();
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (400, "unsupported_content_type")
    );
}

#[tokio::test]
async fn pending_refund_and_settlement_transitions() {
    let s = start(json!({})).await;
    let r = refund(&s, SK, "p", &format!("charge={CH_PENDING}&amount=1000")).await;
    let j = r.json();
    assert_eq!(
        (j["status"].as_str(), j["currency"].as_str()),
        (Some("pending"), Some("eur"))
    );
    let id = j["id"].as_str().unwrap().to_string();
    let r = admin(
        &s,
        "POST",
        &format!("/admin/refunds/{id}/status"),
        json!({"status": "succeeded"}),
    )
    .await;
    assert_eq!(r.json()["status"], "succeeded");
    // succeeded -> succeeded is not a transition; failed is terminal.
    let r = admin(
        &s,
        "POST",
        &format!("/admin/refunds/{id}/status"),
        json!({"status": "succeeded"}),
    )
    .await;
    assert_eq!(r.status, 400);
    let r = admin(
        &s,
        "POST",
        &format!("/admin/refunds/{id}/status"),
        json!({"status": "failed"}),
    )
    .await;
    assert_eq!(r.json()["status"], "failed");
    // A failed refund returns its amount to the charge.
    assert_eq!(ledger(&s, CH_PENDING).await, (1, 1000, 0));
    let r = admin(
        &s,
        "POST",
        &format!("/admin/refunds/{id}/status"),
        json!({"status": "succeeded"}),
    )
    .await;
    assert_eq!(r.status, 400);
    assert_eq!(
        get(&s, SK, &format!("/v1/refunds/{id}")).await.json()["status"],
        "failed"
    );
}

#[tokio::test]
async fn lookup_and_list_for_reconciliation() {
    let s = start(json!({})).await;
    let mut ids = vec![];
    for i in 0..5 {
        let r = refund(
            &s,
            SK,
            &format!("k{i}"),
            &format!("charge={CH_USD}&amount=10&reference=eff_{i}"),
        )
        .await;
        ids.push(r.json()["id"].as_str().unwrap().to_string());
    }
    refund(
        &s,
        SK,
        "j",
        &format!("charge={CH_JPY}&amount=10&reference=eff_0"),
    )
    .await;
    refund(
        &s,
        SK_OTHER,
        "o",
        &format!("charge={CH_OTHER}&amount=10&reference=eff_0"),
    )
    .await;

    let one = get(&s, SK, &format!("/v1/refunds/{}", ids[2])).await.json();
    assert_eq!(one["reference"], "eff_2");
    // Another account's refund is invisible.
    let other = get(&s, SK_OTHER, &format!("/v1/refunds/{}", ids[2])).await;
    assert_eq!(other.status, 404);

    let l = get(
        &s,
        SK,
        &format!("/v1/refunds?charge={CH_USD}&reference=eff_3"),
    )
    .await
    .json();
    assert_eq!(l["data"].as_array().unwrap().len(), 1);
    assert_eq!(l["data"][0]["id"], ids[3].as_str());
    let l = get(&s, SK, "/v1/refunds?reference=eff_0").await.json();
    assert_eq!(
        l["data"].as_array().unwrap().len(),
        2,
        "other account excluded"
    );
    let l = get(
        &s,
        SK,
        &format!("/v1/refunds?charge={CH_USD}&reference=eff_404"),
    )
    .await
    .json();
    assert!(l["data"].as_array().unwrap().is_empty());

    // Newest first, paginated.
    let p1 = get(&s, SK, &format!("/v1/refunds?charge={CH_USD}&limit=2"))
        .await
        .json();
    assert_eq!(p1["has_more"], true);
    assert_eq!(p1["data"][0]["id"], ids[4].as_str());
    let last = p1["data"][1]["id"].as_str().unwrap();
    let p2 = get(
        &s,
        SK,
        &format!("/v1/refunds?charge={CH_USD}&limit=10&starting_after={last}"),
    )
    .await
    .json();
    let got: Vec<&str> = p2["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(got, [ids[2].as_str(), ids[1].as_str(), ids[0].as_str()]);
    assert_eq!(p2["has_more"], false);

    for q in [
        "limit=0",
        "limit=101",
        "limit=x",
        "foo=1",
        "charge=a&charge=b",
    ] {
        assert_eq!(
            get(&s, SK, &format!("/v1/refunds?{q}")).await.status,
            400,
            "{q}"
        );
    }
    assert_eq!(
        get(&s, SK, "/v1/refunds/re_doesnotexist00").await.status,
        404
    );
    assert_eq!(
        get(&s, SK, "/v1/charges/ch_doesnotexist00").await.status,
        404
    );
    assert_eq!(
        get(&s, SK, &format!("/v1/charges/{CH_OTHER}")).await.status,
        404
    );
}

#[tokio::test]
async fn idempotency_replay_and_mismatch() {
    let s = start(json!({})).await;
    let p = format!("charge={CH_USD}&amount=700&reference=eff_x");
    let a = refund(&s, SK, "key-1", &p).await;
    assert_eq!(a.status, 200);
    assert!(a.header("idempotent-replayed").is_none());
    // Same key, same parameters (in a different order) → identical cached body.
    let reordered = format!("reference=eff_x&amount=700&charge={CH_USD}");
    let b = refund(&s, SK, "key-1", &reordered).await;
    assert_eq!(b.status, 200);
    assert_eq!(b.header("idempotent-replayed").as_deref(), Some("true"));
    assert_eq!(a.body, b.body);
    // Same key, different parameters → 400 idempotency_error; nothing executes.
    let c = refund(
        &s,
        SK,
        "key-1",
        &format!("charge={CH_USD}&amount=701&reference=eff_x"),
    )
    .await;
    assert_eq!(
        (c.status, c.err_code().as_str()),
        (400, "idempotency_params_mismatch")
    );
    assert_eq!(c.json()["error"]["type"], "idempotency_error");
    assert_eq!(ledger(&s, CH_USD).await, (1, 700, 700));
    // Keys are scoped per account, and shared by all keys of one account.
    let d = refund(&s, RK_WRITE, "key-1", &p).await;
    assert_eq!(d.header("idempotent-replayed").as_deref(), Some("true"));
    assert_eq!(d.body, a.body);
    let e = refund(
        &s,
        SK_OTHER,
        "key-1",
        &format!("charge={CH_OTHER}&amount=700&reference=eff_x"),
    )
    .await;
    assert_eq!(e.status, 200);
    assert!(e.header("idempotent-replayed").is_none());
}

#[tokio::test]
async fn idempotency_what_is_and_is_not_cached() {
    let s = start(json!({})).await;
    // Validation failures are not cached: the same key can then execute.
    let r = refund(&s, SK, "v", &format!("charge={CH_USD}&amount=abc")).await;
    assert_eq!(r.status, 400);
    let r = refund(&s, SK, "v", &format!("charge={CH_USD}&amount=5")).await;
    assert_eq!(r.status, 200);
    assert!(r.header("idempotent-replayed").is_none());
    // Auth and permission failures are not cached.
    let r = refund(&s, RK_READ, "w", &format!("charge={CH_USD}&amount=5")).await;
    assert_eq!(r.status, 403);
    let r = refund(&s, SK, "w", &format!("charge={CH_USD}&amount=5")).await;
    assert!(r.header("idempotent-replayed").is_none());
    // Business errors after execution started are cached (same answer even once possible).
    let r = refund(&s, SK, "big", &format!("charge={CH_JPY}&amount=1001")).await;
    assert_eq!(r.err_code(), "amount_too_large");
    let r = refund(&s, SK, "big", &format!("charge={CH_JPY}&amount=1001")).await;
    assert_eq!(r.err_code(), "amount_too_large");
    assert_eq!(r.header("idempotent-replayed").as_deref(), Some("true"));
}

#[tokio::test]
async fn idempotency_key_rules() {
    let s = start(json!({})).await;
    let auth = format!("Bearer {SK}");
    let body = format!("charge={CH_USD}&amount=1");
    let r = request(
        s.api_addr,
        "POST",
        "/v1/refunds",
        &[
            ("Authorization", &auth),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        body.as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (400, "idempotency_key_missing")
    );
    let long = "k".repeat(65);
    let r = refund(&s, SK, &long, &body).await;
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (400, "idempotency_key_invalid")
    );
    let r = refund(&s, SK, &"k".repeat(64), &body).await;
    assert_eq!(r.status, 200);
    let r = request(
        s.api_addr,
        "POST",
        "/v1/refunds",
        &[
            ("Authorization", &auth),
            ("Idempotency-Key", "a"),
            ("Idempotency-Key", "b"),
        ],
        body.as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 400);
    assert_eq!(ledger(&s, CH_USD).await, (1, 1, 1));
}

#[tokio::test]
async fn idempotency_retention_window() {
    let s = start(json!({"idempotency_retention_s": 3600})).await;
    let p = format!("charge={CH_USD}&amount=100");
    refund(&s, SK, "r", &p).await;
    let st = get(&s, SK, "/v1/idempotency_keys?key=r").await.json();
    assert_eq!(st["state"], "done");
    assert_eq!(
        st["expires_at"].as_u64().unwrap() - st["created"].as_u64().unwrap(),
        3600
    );
    advance(&s, 3599).await;
    let r = refund(&s, SK, "r", &p).await;
    assert_eq!(r.header("idempotent-replayed").as_deref(), Some("true"));
    assert_eq!(ledger(&s, CH_USD).await, (1, 100, 100));
    // After pruning, reuse of the key executes a new request (Stripe-documented behaviour).
    advance(&s, 1).await;
    assert_eq!(
        get(&s, SK, "/v1/idempotency_keys?key=r").await.json()["state"],
        "none"
    );
    let r = refund(&s, SK, "r", &p).await;
    assert!(r.header("idempotent-replayed").is_none());
    assert_eq!(ledger(&s, CH_USD).await, (2, 200, 200));
}

#[tokio::test]
async fn configured_rate_limit() {
    let s = start(json!({"rate_limit": {"max_requests": 2, "window_s": 60}})).await;
    let p = format!("charge={CH_USD}&amount=1");
    assert_eq!(refund(&s, SK, "a", &p).await.status, 200);
    assert_eq!(refund(&s, SK, "b", &p).await.status, 200);
    let r = refund(&s, SK, "c", &p).await;
    assert_eq!((r.status, r.err_code().as_str()), (429, "rate_limit"));
    assert_eq!(r.header("simpay-should-retry").as_deref(), Some("true"));
    assert_eq!(
        r.header("simpay-rate-limited-reason").as_deref(),
        Some("per-key")
    );
    // Per key: another key of the same account is unaffected.
    assert_eq!(refund(&s, RK_WRITE, "d", &p).await.status, 200);
    assert_eq!(ledger(&s, CH_USD).await, (3, 3, 3));
    // Nothing executed or cached for "c": after the window it executes.
    advance(&s, 60).await;
    let r = refund(&s, SK, "c", &p).await;
    assert_eq!(r.status, 200);
    assert!(r.header("idempotent-replayed").is_none());
}

#[tokio::test]
async fn http_strictness() {
    let s = start(json!({})).await;
    let auth = format!("Bearer {SK}");
    let h = [("Authorization", auth.as_str())];
    assert_eq!(
        request(s.api_addr, "GET", "/v2/x", &h, b"")
            .await
            .unwrap()
            .status,
        404
    );
    assert_eq!(
        request(s.api_addr, "DELETE", "/v1/refunds", &h, b"")
            .await
            .unwrap()
            .status,
        405
    );
    assert_eq!(
        request(s.api_addr, "POST", "/v1/charges/ch_usd00000001", &h, b"")
            .await
            .unwrap()
            .status,
        405
    );
    // Admin paths are not served on the API listener and vice versa.
    assert_eq!(
        request(s.api_addr, "GET", "/admin/health", &[], b"")
            .await
            .unwrap()
            .status,
        404
    );
    assert_eq!(
        request(s.admin_addr, "GET", "/v1/refunds", &h, b"")
            .await
            .unwrap()
            .status,
        404
    );
    // Body limit.
    let big = vec![b'a'; 20_000];
    let r = request(s.api_addr, "POST", "/v1/refunds", &h, &big)
        .await
        .unwrap();
    assert_eq!(r.status, 413);
    // Chunked bodies are not supported.
    let r = raw(
        s.api_addr,
        b"POST /v1/refunds HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        std::time::Duration::from_secs(5),
    )
    .await
    .map(parse)
    .unwrap();
    assert_eq!(r.status, 501);
    // Conflicting Content-Length.
    let r = raw(
        s.api_addr,
        b"POST /v1/refunds HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
        std::time::Duration::from_secs(5),
    )
    .await
    .map(parse)
    .unwrap();
    assert_eq!(r.status, 400);
    // Header block too large.
    let mut req = b"GET /v1/refunds HTTP/1.1\r\nX-Pad: ".to_vec();
    req.extend(vec![b'a'; 20_000]);
    req.extend_from_slice(b"\r\n\r\n");
    let r = raw(s.api_addr, &req, std::time::Duration::from_secs(5))
        .await
        .map(parse)
        .unwrap();
    assert_eq!(r.status, 431);
}

#[tokio::test]
async fn deterministic_ids_given_seed() {
    async fn run(seed: &str) -> Vec<String> {
        let s = start(json!({"seed": seed})).await;
        let mut v = vec![];
        for i in 0..3 {
            let r = refund(
                &s,
                SK,
                &format!("k{i}"),
                &format!("charge={CH_USD}&amount=10"),
            )
            .await;
            v.push(r.json()["id"].as_str().unwrap().to_string());
        }
        v
    }
    let a = run("alpha").await;
    let b = run("alpha").await;
    let c = run("beta").await;
    assert_eq!(a, b);
    assert_ne!(a, c);
    for id in &a {
        assert!(simpay::config::valid_object_id(id), "{id}");
    }
}

#[tokio::test]
async fn admin_token_protects_control_plane() {
    let s = start(json!({"admin_token": "admintoken-0123456789"})).await;
    assert_eq!(
        admin(&s, "GET", "/admin/health", Value::Null).await.status,
        401
    );
    let r = request(
        s.admin_addr,
        "GET",
        "/admin/health",
        &[("Authorization", "Bearer admintoken-0123456789")],
        b"",
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
}
