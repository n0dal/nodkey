//! Mandate pages on the auth origin (effect-protocol-v2 Draft 4 §12.6; agent-interface-v1 Draft 2
//! §4.2, §4.7): the template confirmation page, the labelled message body, `/pending`,
//! `/mandates` and the broker-first revoke with acknowledgement. Needs `--features test-login`.
#![cfg(feature = "test-login")]

mod common;
use common::*;
use nodkey_gateway::config::{TestLoginConfig, TestUser};
use nodkey_gateway::util::now_secs;
use serde_json::{Value, json};

async fn start_tl() -> Harness {
    start_with(|c| {
        c.dev_local_only = true;
        c.test_login = Some(TestLoginConfig {
            enabled: true,
            users: vec![
                TestUser {
                    ten: "shop1".into(),
                    sub: "op_ana".into(),
                    label: "Ana".into(),
                },
                TestUser {
                    ten: "shop1".into(),
                    sub: "op_bob".into(),
                    label: "Bob".into(),
                },
            ],
        })
    })
    .await
}

fn sess(sid: &str) -> String {
    format!("Cookie: __Host-nodkey_session={sid}")
}

fn agent_record(pid: &str, op: &str, params: Value, types: Value, display: Value) -> Value {
    let now = now_secs();
    json!({
        "pending_id": pid, "broker_id": "nodkey.broker.test", "wid": "spiffe://nodkey.test/workload/agent",
        "ten": "shop1", "approver_sub": "op_ana", "op": op, "opv": 1, "params": params,
        "param_types": types, "created_at": now, "expires_at": now + 600, "display": display
    })
}

fn template_record(pid: &str) -> Value {
    agent_record(
        pid,
        "mandate.support_ticket",
        json!({"customer_sub": "c42", "currency": "EUR", "refund_max_count": 3,
               "refund_max_per_call_minor": 2500, "refund_max_total_minor": 5000,
               "message_max_count": 3, "valid_for_s": 3600, "customer_email": "alice@customer.test"}),
        json!({"customer_sub": "text64", "currency": "currency", "refund_max_count": "uint",
               "refund_max_per_call_minor": "uint", "refund_max_total_minor": "uint",
               "message_max_count": "uint", "valid_for_s": "uint", "customer_email": "text256"}),
        json!({"amount_exponent": 2, "currency": "EUR"}),
    )
}

fn mandate_item(mid: &str, state: &str) -> Value {
    json!({"mid": mid, "workload_display_name": "support-bot",
           "terms": {"customer_sub": "c42", "customer_email": "alice@customer.test", "currency": "EUR",
                     "refund_max_count": 3, "refund_max_per_call_minor": 2500,
                     "refund_max_total_minor": 5000, "message_max_count": 3},
           "counters": {"refund_count": 1, "refund_total_minor": 2000, "message_count": 0},
           "nbf": now_secs(), "exp": now_secs() + 3600, "state": state})
}

/// AT-23, AI §4.2 step 2: the template page states the bounds in the static template, with the
/// trusted email, amounts via key 11, the "without asking you again" warning, and typed
/// confirmation for both `_minor` amounts.
#[tokio::test]
async fn template_page_renders_bounds() {
    let h = start_tl().await;
    let sid = login(h.addr, 0).await;
    let pid = new_pid();
    add_record(&h.world, template_record(&pid), "PENDING");
    let r = get(h.addr, AUTH, &format!("/confirm/{pid}"), &[&sess(&sid)]).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let t = r.text();
    for want in [
        "Approve a mandate",
        "Allow <strong>Demo Shop</strong>, for <strong>3600 seconds</strong>",
        "refund at most <strong>3</strong> times, at most <strong>25.00 EUR</strong> each and <strong>50.00 EUR</strong> in total",
        "only orders of customer <code>c42</code> (<code>alice@customer.test</code>)",
        "send at most <strong>3</strong> messages to <code>alice@customer.test</code>",
        "These will happen without asking you again.",
        "name=\"confirm_refund_max_per_call_minor\"",
        "name=\"confirm_refund_max_total_minor\"",
    ] {
        assert!(t.contains(want), "missing {want:?} in {t}");
    }
}

/// AT-23, §12.6: the message body is shown in full, escaped, monospace and labelled.
#[tokio::test]
async fn message_body_escaped_and_labelled() {
    let h = start_tl().await;
    let sid = login(h.addr, 0).await;
    let pid = new_pid();
    let rec = agent_record(
        &pid,
        "messages.send",
        json!({"customer_sub": "c42", "to": "alice@customer.test", "body": "<script>x</script> & card"}),
        json!({"customer_sub": "text64", "to": "text256", "body": "text256"}),
        json!({}),
    );
    add_record(&h.world, rec, "PENDING");
    let t = get(h.addr, AUTH, &format!("/confirm/{pid}"), &[&sess(&sid)])
        .await
        .text();
    assert!(
        t.contains("Written by the agent \u{2014} unverified"),
        "{t}"
    );
    assert!(
        t.contains(
            "<pre class=\"value unverified\">&lt;script&gt;x&lt;/script&gt; &amp; card</pre>"
        ),
        "{t}"
    );
    assert!(!t.contains("<script>"));
}

/// AI §2.6, §12.6: `/pending` lists the subject's PENDING records with links; others see none.
#[tokio::test]
async fn pending_page_lists_subjects_records() {
    let h = start_tl().await;
    let pid = new_pid();
    add_record(&h.world, template_record(&pid), "PENDING");
    let ana = login(h.addr, 0).await;
    let t = get(h.addr, AUTH, "/pending", &[&sess(&ana)]).await.text();
    assert!(t.contains(&format!("href=\"/confirm/{pid}\"")), "{t}");
    let bob = login(h.addr, 1).await;
    let t = get(h.addr, AUTH, "/pending", &[&sess(&bob)]).await.text();
    assert!(!t.contains(&pid));
    // No session: no data.
    let t = get(h.addr, AUTH, "/pending", &[]).await.text();
    assert!(t.contains("Sign in first") && !t.contains(&pid));
}

/// AT-15 / AT-23 / T57 (gateway): revoke is a POST with a single-use token bound to session,
/// mid and action, under the §7.3 provenance rule; the broker is called first, the authority
/// after its acknowledgement; "revoked" only then.
#[tokio::test]
async fn revoke_broker_first_with_token_rules() {
    let h = start_tl().await;
    let mid = new_pid();
    let other = new_pid();
    h.world.lock().unwrap().mandates.insert(
        "shop1/op_ana".into(),
        vec![
            mandate_item(&mid, "active"),
            mandate_item(&other, "expired"),
        ],
    );
    let sid = login(h.addr, 0).await;
    let page = get(h.addr, AUTH, "/mandates", &[&sess(&sid)]).await.text();
    assert!(
        page.contains(&format!("action=\"/mandates/{mid}/revoke\"")),
        "{page}"
    );
    assert!(!page.contains(&format!("action=\"/mandates/{other}/revoke\"")));
    let token = form_value(&page, "token").unwrap();
    let post = |path: String, prov: Vec<&'static str>, body: String, sid: String| {
        let addr = h.addr;
        async move {
            let c = sess(&sid);
            let mut extra: Vec<&str> = prov;
            extra.push(&c);
            post_form(addr, AUTH, &path, &extra, &body).await
        }
    };
    let path = format!("/mandates/{mid}/revoke");
    // Cross-site provenance (§7.3 step 2): uniform error, nothing sent.
    let r = post(
        path.clone(),
        vec!["Sec-Fetch-Site: same-site", "Sec-Fetch-Mode: navigate"],
        format!("token={token}"),
        sid.clone(),
    )
    .await;
    assert_eq!(r.status, 404);
    assert!(h.world.lock().unwrap().order.is_empty());
    // Token bound to the mid: presenting it for another mid fails and consumes it (step 4).
    let r = post(
        format!("/mandates/{other}/revoke"),
        NAV_SAME_ORIGIN.to_vec(),
        format!("token={token}"),
        sid.clone(),
    )
    .await;
    assert_eq!(r.status, 404);
    let r = post(
        path.clone(),
        NAV_SAME_ORIGIN.to_vec(),
        format!("token={token}"),
        sid.clone(),
    )
    .await;
    assert_eq!(r.status, 404, "a consumed token is refused");
    // Bound to the session: another user's session fails.
    let page = get(h.addr, AUTH, "/mandates", &[&sess(&sid)]).await.text();
    let token = form_value(&page, "token").unwrap();
    let bob = login(h.addr, 1).await;
    let r = post(
        path.clone(),
        NAV_SAME_ORIGIN.to_vec(),
        format!("token={token}"),
        bob,
    )
    .await;
    assert_eq!(r.status, 404);
    // Extra field: refused.
    let page = get(h.addr, AUTH, "/mandates", &[&sess(&sid)]).await.text();
    let token = form_value(&page, "token").unwrap();
    let r = post(
        path.clone(),
        NAV_SAME_ORIGIN.to_vec(),
        format!("token={token}&x=1"),
        sid.clone(),
    )
    .await;
    assert_eq!(r.status, 404);
    assert!(h.world.lock().unwrap().order.is_empty());
    // Valid.
    let page = get(h.addr, AUTH, "/mandates", &[&sess(&sid)]).await.text();
    let token = form_value(&page, "token").unwrap();
    let r = post(
        path.clone(),
        NAV_SAME_ORIGIN.to_vec(),
        format!("token={token}"),
        sid.clone(),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.text().contains("Mandate revoked"));
    assert_eq!(
        h.world.lock().unwrap().order,
        vec![
            "G:mandate.revoke".to_string(),
            "I:mandate.revoke".to_string()
        ]
    );
    let page = get(h.addr, AUTH, "/mandates", &[&sess(&sid)]).await.text();
    assert!(
        !page.contains("name=\"token\""),
        "no form for a revoked mandate"
    );
}

/// T59: broker down → "not confirmed", no "revoked" text; background retries reach the broker
/// first and then the authority once the broker answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t59_revoke_with_broker_down_retries() {
    let h = start_tl().await;
    let mid = new_pid();
    {
        let mut w = h.world.lock().unwrap();
        w.mandates
            .insert("shop1/op_ana".into(), vec![mandate_item(&mid, "active")]);
        w.broker_revoke_down = true;
    }
    let sid = login(h.addr, 0).await;
    let page = get(h.addr, AUTH, "/mandates", &[&sess(&sid)]).await.text();
    let token = form_value(&page, "token").unwrap();
    let c = sess(&sid);
    let mut extra = NAV_SAME_ORIGIN.to_vec();
    extra.push(&c);
    let r = post_form(
        h.addr,
        AUTH,
        &format!("/mandates/{mid}/revoke"),
        &extra,
        &format!("token={token}"),
    )
    .await;
    assert_eq!(r.status, 200);
    let t = r.text();
    assert!(
        t.contains("Revocation not confirmed") && !t.contains("Mandate revoked"),
        "{t}"
    );
    assert!(
        h.world.lock().unwrap().order.is_empty(),
        "authority not called before the broker"
    );
    h.world.lock().unwrap().broker_revoke_down = false;
    // One retry period (5 s) plus margin.
    for _ in 0..80 {
        if h.world.lock().unwrap().order.len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        h.world.lock().unwrap().order,
        vec![
            "G:mandate.revoke".to_string(),
            "I:mandate.revoke".to_string()
        ]
    );
}
