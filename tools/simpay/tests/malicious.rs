//! Malicious-provider mode (attacker G): the simulator lies, redirects, and emits
//! oversized, malformed, or hostile responses. Ledger assertions show what really happened.

mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

fn p(amount: u64) -> String {
    format!("charge={CH_USD}&amount={amount}&reference=eff_m")
}

async fn with_fault(fault: Value) -> simpay::Server {
    let s = start(json!({})).await;
    malicious(&s, true).await;
    faults(&s, json!([{ "fault": fault }])).await;
    s
}

#[tokio::test]
async fn malicious_faults_require_the_mode() {
    let s = start(json!({})).await;
    for f in [
        json!({"kind": "phantom_success"}),
        json!({"kind": "lie_amount", "amount": 1}),
        json!({"kind": "redirect", "location": "http://attacker.invalid/"}),
        json!({"kind": "malformed_json", "variant": "truncated"}),
        json!({"kind": "webhook_contradict"}),
    ] {
        let r = admin(&s, "PUT", "/admin/faults", json!({"rules": [{"fault": f}]})).await;
        assert_eq!(r.status, 400, "{f}");
    }
    malicious(&s, true).await;
    faults(
        &s,
        json!([{"fault": {"kind": "phantom_success"}}, {"fault": {"kind": "rate_limit"}}]),
    )
    .await;
    // Turning the mode off removes malicious rules and keeps the others.
    malicious(&s, false).await;
    let plan = admin(&s, "GET", "/admin/faults", Value::Null).await.json();
    assert_eq!(plan["rules"].as_array().unwrap().len(), 1);
    assert_eq!(plan["rules"][0]["rule"]["fault"]["kind"], "rate_limit");
    // Mode can also be set at start.
    let s2 = start(json!({"malicious_mode": true})).await;
    faults(&s2, json!([{"fault": {"kind": "phantom_success"}}])).await;
}

#[tokio::test]
async fn lies_about_echoed_fields() {
    for (fault, field, lie) in [
        (
            json!({"kind": "lie_amount", "amount": 99999}),
            "amount",
            json!(99999),
        ),
        (
            json!({"kind": "lie_charge", "charge": "ch_somebodyelse01"}),
            "charge",
            json!("ch_somebodyelse01"),
        ),
        (
            json!({"kind": "lie_currency", "currency": "jpy"}),
            "currency",
            json!("jpy"),
        ),
        (
            json!({"kind": "lie_status", "status": "failed"}),
            "status",
            json!("failed"),
        ),
    ] {
        let s = with_fault(fault).await;
        let r = refund(&s, SK, "k", &p(100)).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.json()[field], lie, "{field}");
        // Truth: one refund of 100 USD succeeded; a same-key replay tells the truth.
        assert_eq!(ledger(&s, CH_USD).await, (1, 100, 100));
        let truth = refund(&s, SK, "k", &p(100)).await.json();
        assert_eq!(
            (
                truth["amount"].clone(),
                truth["charge"].clone(),
                truth["currency"].clone(),
                truth["status"].clone()
            ),
            (json!(100), json!(CH_USD), json!("usd"), json!("succeeded"))
        );
    }
}

#[tokio::test]
async fn lies_on_lookup_too() {
    let s = start(json!({})).await;
    let id = refund(&s, SK, "k", &p(100)).await.json()["id"]
        .as_str()
        .unwrap()
        .to_string();
    malicious(&s, true).await;
    faults(&s, json!([{"match": {"op": "get_refund"}, "fault": {"kind": "lie_amount", "amount": 5}},
                      {"match": {"op": "list_refunds"}, "fault": {"kind": "lie_status", "status": "failed"}}])).await;
    assert_eq!(
        get(&s, SK, &format!("/v1/refunds/{id}")).await.json()["amount"],
        5
    );
    assert_eq!(
        get(&s, SK, "/v1/refunds?reference=eff_m").await.json()["data"][0]["status"],
        "failed"
    );
}

#[tokio::test]
async fn phantom_success_and_deny_but_commit() {
    let s = with_fault(json!({"kind": "phantom_success"})).await;
    let r = refund(&s, SK, "k", &p(100)).await;
    assert_eq!(r.status, 200);
    let id = r.json()["id"].as_str().unwrap().to_string();
    assert_eq!(
        get(&s, SK, &format!("/v1/refunds/{id}")).await.status,
        404,
        "never stored"
    );
    assert_eq!(ledger(&s, CH_USD).await, (0, 0, 0));

    let s = with_fault(json!({"kind": "deny_but_commit"})).await;
    let r = refund(&s, SK, "k", &p(100)).await;
    assert_eq!(
        (r.status, r.err_code().as_str()),
        (400, "charge_already_refunded")
    );
    assert_eq!(
        ledger(&s, CH_USD).await,
        (1, 100, 100),
        "the refund happened anyway"
    );
}

#[tokio::test]
async fn redirect_to_other_host() {
    let s =
        with_fault(json!({"kind": "redirect", "location": "http://attacker.invalid/v1/refunds"}))
            .await;
    let r = refund(&s, SK, "k", &p(100)).await;
    assert_eq!(r.status, 307);
    assert_eq!(
        r.header("location").as_deref(),
        Some("http://attacker.invalid/v1/refunds")
    );
    assert_eq!(ledger(&s, CH_USD).await, (0, 0, 0));
}

#[tokio::test]
async fn oversized_body_and_header() {
    let s = with_fault(json!({"kind": "oversized_body", "bytes": 5_000_000})).await;
    let r = refund(&s, SK, "k", &p(1)).await;
    assert!(r.body.len() >= 4_999_000, "{}", r.body.len());
    assert_eq!(
        r.header("content-length").unwrap(),
        r.body.len().to_string()
    );
    assert_eq!(r.json()["amount"], 1);

    let s = with_fault(json!({"kind": "oversized_header", "bytes": 200_000})).await;
    let r = refund(&s, SK, "k", &p(1)).await;
    assert_eq!(r.header("x-simpay-padding").unwrap().len(), 200_000);
}

#[tokio::test]
async fn header_injection_variants() {
    async fn raw_for(variant: &str) -> Vec<u8> {
        let s = with_fault(json!({"kind": "header_injection", "variant": variant})).await;
        refund(&s, SK, "k", &p(1)).await.raw
    }
    fn strict_parse_ok(raw: &[u8]) -> bool {
        let mut h = [httparse::EMPTY_HEADER; 64];
        httparse::Response::new(&mut h).parse(raw).is_ok()
    }
    fn contains(h: &[u8], n: &[u8]) -> bool {
        h.windows(n.len()).any(|w| w == n)
    }
    let r = raw_for("crlf_injection").await;
    assert!(contains(&r, b"X-Simpay-Note: ok\r\nSet-Cookie: simpay_injected=1\r\nLocation: http://attacker.invalid/\r\n"));
    let r = raw_for("bare_cr").await;
    assert!(contains(&r, b"a\rb"));
    assert!(!strict_parse_ok(&r), "strict parser must reject a bare CR");
    let r = raw_for("nul_byte").await;
    assert!(contains(&r, b"a\0b"));
    assert!(!strict_parse_ok(&r), "strict parser must reject NUL");
    let r = raw_for("obs_fold").await;
    assert!(contains(&r, b"first\r\n second-line-folded"));
    let r = raw_for("duplicate_content_length").await;
    let resp = parse(r);
    let cls = resp.headers_named("content-length");
    assert_eq!(cls.len(), 2);
    assert_ne!(cls[0], cls[1]);
    let resp = parse(raw_for("te_and_cl").await);
    assert_eq!(resp.header("transfer-encoding").as_deref(), Some("chunked"));
    assert!(resp.header("content-length").is_some());
}

#[tokio::test]
async fn malformed_json_variants() {
    async fn body_for(variant: &str) -> simpay_resp::R {
        let s = with_fault(json!({"kind": "malformed_json", "variant": variant})).await;
        let r = refund(&s, SK, "k", &p(1)).await;
        let led = ledger(&s, CH_USD).await;
        simpay_resp::R {
            body: r.body.clone(),
            ct: r.header("content-type"),
            ledger: led,
        }
    }
    for v in [
        "truncated",
        "deep_nesting",
        "huge_number",
        "trailing_garbage",
        "not_json",
        "invalid_utf8",
    ] {
        let r = body_for(v).await;
        assert!(
            serde_json::from_slice::<Value>(&r.body).is_err(),
            "{v} must not parse"
        );
        assert_eq!(r.ledger, (1, 1, 1), "{v}: the operation still ran");
    }
    let r = body_for("duplicate_keys").await;
    let text = String::from_utf8(r.body.clone()).unwrap();
    assert_eq!(text.matches("\"amount\":").count(), 2);
    // A lenient parser silently takes one of them; a strict one should refuse.
    assert!(serde_json::from_slice::<Value>(&r.body).is_ok());
    let r = body_for("wrong_content_type").await;
    assert_eq!(r.ct.as_deref(), Some("text/html"));
    assert!(serde_json::from_slice::<Value>(&r.body).is_ok());
}

mod simpay_resp {
    pub struct R {
        pub body: Vec<u8>,
        pub ct: Option<String>,
        pub ledger: (u64, u64, u64),
    }
}

#[tokio::test]
async fn hostile_error_text() {
    let s = with_fault(json!({"kind": "hostile_error_text"})).await;
    let r = refund(&s, SK, "k", &p(1)).await;
    assert_eq!(r.status, 400);
    let j = r.json();
    let msg = j["error"]["message"].as_str().unwrap();
    assert!(msg.contains("<script>"));
    assert!(msg.to_lowercase().contains("ignore previous instructions"));
    assert!(j["error"]["code"].as_str().unwrap().contains("onerror"));
    // The refund actually committed: the error text is a lie.
    assert_eq!(ledger(&s, CH_USD).await, (1, 1, 1));
}

#[tokio::test]
async fn slow_drip() {
    let s = with_fault(json!({"kind": "slow_drip", "chunk": 64, "interval_ms": 20})).await;
    let t = Instant::now();
    let r = refund(&s, SK, "k", &p(1)).await;
    assert_eq!(r.status, 200);
    let chunks = r.raw.len().div_ceil(64) as u32;
    assert!(
        t.elapsed() >= Duration::from_millis(20) * (chunks - 1),
        "{:?}",
        t.elapsed()
    );
    // A client with a total deadline gives up.
    let s = with_fault(json!({"kind": "slow_drip", "chunk": 1, "interval_ms": 50})).await;
    let r = refund_t(&s, SK, "k", &p(1), Duration::from_millis(300)).await;
    assert_eq!(r.unwrap_err(), ClientError::Timeout);
}

#[tokio::test]
async fn webhook_contradicts_lookup() {
    let s = start(json!({})).await;
    let hook = hook_server(0).await;
    set_endpoint(&s, &hook.url()).await;
    malicious(&s, true).await;
    faults(&s, json!([{"fault": {"kind": "webhook_contradict"}}])).await;
    let r = refund(&s, SK, "k", &p(100)).await.json();
    assert!(wait_until(|| hook.count() == 1, Duration::from_secs(5)).await);
    let got = hook.all().remove(0);
    let now = now(&s).await;
    assert!(
        verify(WHSEC, &got.signature, &got.body, now, 300).is_ok(),
        "correctly signed"
    );
    let ev = got.json();
    let fetched = get(
        &s,
        SK,
        &format!("/v1/refunds/{}", r["id"].as_str().unwrap()),
    )
    .await
    .json();
    assert_eq!(fetched["status"], "succeeded");
    assert_eq!(ev["data"]["object"]["status"], "failed");
    assert_ne!(ev["data"]["object"]["amount"], fetched["amount"]);
}
