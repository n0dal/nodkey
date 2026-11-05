// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Socket I `approve` against a fake broker (socket A) and a fake gateway (effect-protocol-v2
//! §4.2–§4.3). Test ids refer to the spec's §8 test plan.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use nodkey_authority::digest::PendingId;
use nodkey_authority::store::Status;
use serde_json::json;

async fn setup(name: &str) -> (std::path::PathBuf, FakeBroker, Running) {
    setup_with(name, |_| {}).await
}

async fn setup_with(
    name: &str,
    f: impl FnOnce(&mut Opts),
) -> (std::path::PathBuf, FakeBroker, Running) {
    let dir = tmpdir(name);
    let keys = make_key(&dir);
    let broker = FakeBroker::start(&dir, &keys.registry_json).await;
    let mut o = Opts::new();
    f(&mut o);
    let run = start_authority(&dir, &keys, &broker.path, o).await;
    (dir, broker, run)
}

#[tokio::test]
async fn approve_happy_path_signs_once_and_broker_verifies() {
    let (_d, broker, run) = setup("happy").await;
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");

    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert!(is_ok(&r), "{r}");
    let d = broker.deliveries();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].0, pid);
    // The fake broker verified the grant with nodkey-grant (signature, aud, jti = pending_id,
    // sub = approver, params, cfm) before accepting.
    assert_eq!(broker.state.lock().unwrap().results, vec!["accepted"]);
    assert_eq!(broker.record_state(&pid), "APPROVED");
    let row = run
        .authority
        .issuance(&PendingId::parse(&pid).unwrap())
        .await
        .unwrap();
    assert_eq!(row.status, Status::Accepted);
    assert_eq!(row.grant, d[0].1);
    assert!(row.exp - row.signed_at == 30);
}

#[tokio::test]
async fn enrolled_transfer_and_free_param_ops_are_signed() {
    let (_d, broker, run) = setup("enrolled").await;
    let pid = random_pid();
    let rec = transfer_record(&pid, "user:u-17", now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert!(is_ok(&r), "{r}");

    // Free parameter: in the digest, omitted from the grant, still verifies.
    let pid2 = random_pid();
    let mut rec2 = refund_record(&pid2, "user:u-17", 1, now() + 600);
    rec2.insert("op".into(), json!("test.note"));
    rec2.insert("display".into(), json!({}));
    rec2.insert(
        "params".into(),
        json!({"order_id": 9821, "note": "hello \"world\""}),
    );
    rec2.insert(
        "param_types".into(),
        json!({"order_id": "uint", "note": "text64"}),
    );
    let digest2 = digest_of(&rec2);
    broker.add(rec2, "PENDING");
    let r = approve(&run.gateway_path, &pid2, &digest2, "acme", "user:u-17").await;
    assert!(is_ok(&r), "{r}");
    assert_eq!(
        broker.state.lock().unwrap().results,
        vec!["accepted", "accepted"]
    );
}

#[tokio::test]
async fn enrolled_workload_rejects_other_approver() {
    let (_d, broker, run) = setup("enrolled-other").await;
    let pid = random_pid();
    // The broker record names another approver (e.g. a buggy or compromised broker).
    let rec = transfer_record(&pid, "user:u-99", now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-99").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert!(broker.deliveries().is_empty());
}

#[tokio::test]
async fn t08_mismatched_digest_gives_no_grant() {
    let (_d, broker, run) = setup("digest").await;
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    // What the gateway displayed: a different amount.
    let shown = digest_of(&refund_record(&pid, "user:u-17", 1, now() + 600));
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &shown, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert!(broker.deliveries().is_empty());
    assert!(
        run.authority
            .issuance(&PendingId::parse(&pid).unwrap())
            .await
            .is_none()
    );
}

#[tokio::test]
async fn t35_lying_broker_digest_and_forced_state() {
    let (_d, broker, run) = setup("liar").await;
    // Broker returns a digest that does not match its own record.
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let shown = digest_of(&refund_record(&pid, "user:u-17", 1, now() + 600));
    broker.add(rec, "PENDING");
    broker
        .state
        .lock()
        .unwrap()
        .records
        .get_mut(&pid)
        .unwrap()
        .digest_override = Some(shown.clone());
    let r = approve(&run.gateway_path, &pid, &shown, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));

    // A row forced to APPROVED (no gateway approval reached the authority): no grant.
    let pid2 = random_pid();
    let rec2 = refund_record(&pid2, "user:u-17", 1250, now() + 600);
    let d2 = digest_of(&rec2);
    broker.add(rec2, "APPROVED");
    let r = approve(&run.gateway_path, &pid2, &d2, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert!(broker.deliveries().is_empty());
}

#[tokio::test]
async fn t01_wrong_subject_same_and_other_tenant() {
    let (_d, broker, run) = setup("subject").await;
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    for (ten, sub) in [
        ("acme", "user:u-18"),
        ("globex", "user:u-17"),
        ("acme", "user:u-17x"),
    ] {
        let r = approve(&run.gateway_path, &pid, &digest, ten, sub).await;
        assert_eq!(err_code(&r), Some("not_available"), "{ten}/{sub}");
    }
    assert!(broker.deliveries().is_empty());
    assert_eq!(broker.record_state(&pid), "PENDING");
}

#[tokio::test]
async fn t17_t24_expired_and_decided_records() {
    let (_d, broker, run) = setup("expired").await;
    // T24: approve at/after expires_at.
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now());
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    // T17: DENIED, EXPIRED, APPROVED, and every other non-PENDING state.
    for st in [
        "DENIED",
        "EXPIRED",
        "APPROVED",
        "EXECUTING",
        "SUCCEEDED",
        "FAILED",
        "UNKNOWN",
    ] {
        let pid = random_pid();
        let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
        let digest = digest_of(&rec);
        broker.add(rec, st);
        let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
        assert_eq!(err_code(&r), Some("not_available"), "{st}");
    }
    // Unknown id.
    let r = approve(
        &run.gateway_path,
        &random_pid(),
        &"0".repeat(64),
        "acme",
        "user:u-17",
    )
    .await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert!(broker.deliveries().is_empty());
}

#[tokio::test]
async fn t37_input_validation() {
    let (_d, broker, run) = setup("input").await;
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    // Uppercase hex digest is rejected, not normalized.
    let r = approve(
        &run.gateway_path,
        &pid,
        &digest.to_uppercase(),
        "acme",
        "user:u-17",
    )
    .await;
    assert_eq!(err_code(&r), Some("not_available"));
    // Alias (non-canonical) pending id.
    let r = approve(
        &run.gateway_path,
        "-xEiM0RVZneImaq7zN3u_x",
        &digest,
        "acme",
        "user:u-17",
    )
    .await;
    assert_eq!(err_code(&r), Some("not_available"));
    // Non-ID subject.
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user u17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert_eq!(broker.state.lock().unwrap().pending_gets, 0);

    // Envelope errors.
    let gp = run.gateway_path.clone();
    let raw = |s: &'static str| gateway_raw_owned(gp.clone(), s.to_owned());
    let r = raw(r#"{"v":2,"id":"x","op":"approve","args":{},"extra":1}"#)
        .await
        .unwrap();
    assert_eq!(err_code(&r), Some("malformed_request"));
    let r = raw(r#"{"v":2,"id":"x","id":"y","op":"approve","args":{}}"#)
        .await
        .unwrap();
    assert_eq!(err_code(&r), Some("malformed_request"));
    let r = raw(r#"{"v":1,"id":"x","op":"approve","args":{}}"#)
        .await
        .unwrap();
    assert_eq!(err_code(&r), Some("unsupported_version"));
    let r = raw(r#"{"v":2,"id":"x","op":"sign","args":{}}"#)
        .await
        .unwrap();
    assert_eq!(err_code(&r), Some("unknown_operation"));
    let big = format!(
        r#"{{"v":2,"id":"x","op":"approve","args":{{"p":"{}"}}}}"#,
        "a".repeat(9000)
    );
    let r = gateway_raw(&run.gateway_path, &big).await.unwrap();
    assert_eq!(err_code(&r), Some("request_too_large"));
    // Extra member in approve args.
    let req = json!({"v":2,"id":"g","op":"approve","args":{"pending_id":pid,"digest_shown":digest,
        "subject":{"ten":"acme","sub":"user:u-17"},"grant":"x"}});
    let r = gateway_raw(&run.gateway_path, &req.to_string())
        .await
        .unwrap();
    assert_eq!(err_code(&r), Some("not_available"));
    assert!(broker.deliveries().is_empty());
}

#[tokio::test]
async fn t43_wrong_uid_gateway_is_closed_without_response() {
    let (_d, broker, run) =
        setup_with("uid", |o| o.gateway_uid = o.gateway_uid.wrapping_add(1)).await;
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let req = json!({"v":2,"id":"g-1","op":"approve","args":{
        "pending_id": pid, "digest_shown": digest, "subject": {"ten": "acme", "sub": "user:u-17"}}});
    assert!(
        gateway_raw(&run.gateway_path, &req.to_string())
            .await
            .is_none()
    );
    assert_eq!(broker.state.lock().unwrap().pending_gets, 0);
    assert!(broker.deliveries().is_empty());
}

#[tokio::test]
async fn t16_wrong_uid_broker_and_config_digest_mismatch() {
    // The broker socket's peer uid differs from the configured broker uid.
    let (_d, broker, run) =
        setup_with("buid", |o| o.broker_uid = o.broker_uid.wrapping_add(1)).await;
    assert!(run.authority.broker().check().await.is_err());
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));

    // Configuration copies differ (config.digest).
    let (_d, broker, run) = setup("cfgdigest").await;
    broker.state.lock().unwrap().config_digest = [9u8; 32];
    assert!(run.authority.broker().check().await.is_err());
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert_eq!(broker.state.lock().unwrap().pending_gets, 0);
}

#[tokio::test]
async fn t46_retry_after_unavailable_and_lost_response_redelivers_same_bytes() {
    let (_d, broker, run) = setup("retry").await;
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    {
        let mut st = broker.state.lock().unwrap();
        st.fail_first = 2;
        st.mode = DeliverMode::ApplyAndDrop;
    }
    let gw = run.gateway_path.clone();
    let p = pid.clone();
    let d = digest.clone();
    let h = tokio::spawn(async move { approve(&gw, &p, &d, "acme", "user:u-17").await });
    // After 2 unavailable + 1 applied-but-lost, switch to normal answers.
    for _ in 0..200 {
        if broker.deliveries().len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    broker.set_mode(DeliverMode::Accept);
    let r = h.await.unwrap();
    assert!(is_ok(&r), "{r}");
    let d = broker.deliveries();
    assert!(d.len() >= 4, "{}", d.len());
    assert!(
        d.iter().all(|(p, g)| *p == pid && *g == d[0].1),
        "same bytes on every retry"
    );
    let results = broker.state.lock().unwrap().results.clone();
    assert_eq!(results.last().map(String::as_str), Some("accepted"));

    // A second gateway approve for the now-APPROVED record signs nothing new.
    let n = broker.deliveries().len();
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert_eq!(broker.deliveries().len(), n);
}

#[tokio::test]
async fn t34_delivery_deadline_marks_expired() {
    let (_d, broker, run) = setup_with("deadline", |o| {
        o.ttl = 1;
        o.skew = 0;
    })
    .await;
    broker.set_mode(DeliverMode::Unavailable);
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    let row = run
        .authority
        .issuance(&PendingId::parse(&pid).unwrap())
        .await
        .unwrap();
    assert_eq!(row.status, Status::Expired);
    let d = broker.deliveries();
    assert!(!d.is_empty() && d.iter().all(|(_, g)| *g == row.grant));
    // Re-approve after expiry: no new signature, no delivery.
    broker.set_mode(DeliverMode::Accept);
    let n = d.len();
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert_eq!(broker.deliveries().len(), n);
}

#[tokio::test]
async fn reply_timeout_then_gateway_retry_redelivers_stored_bytes() {
    let (_d, broker, run) = setup_with("replyto", |o| {
        o.reply_timeout = Duration::from_millis(300);
    })
    .await;
    broker.set_mode(DeliverMode::Unavailable);
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    broker.set_mode(DeliverMode::Accept);
    // Gateway retry while the record is still PENDING: same row, same bytes.
    let _ = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    for _ in 0..200 {
        if broker.record_state(&pid) == "APPROVED" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(broker.record_state(&pid), "APPROVED");
    let d = broker.deliveries();
    assert!(d.iter().all(|(_, g)| *g == d[0].1));
}

#[tokio::test]
async fn issuance_conflict_never_signs_a_second_grant_for_one_jti() {
    let (_d, broker, run) = setup_with("conflict", |o| {
        o.reply_timeout = Duration::from_millis(300);
    })
    .await;
    broker.set_mode(DeliverMode::Unavailable);
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let _ = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    let first = run
        .authority
        .issuance(&PendingId::parse(&pid).unwrap())
        .await
        .unwrap();
    // The broker now presents a different record under the same pending id.
    let rec2 = refund_record(&pid, "user:u-17", 999_999, now() + 600);
    let digest2 = digest_of(&rec2);
    broker.add(rec2, "PENDING");
    broker.set_mode(DeliverMode::Accept);
    let r = approve(&run.gateway_path, &pid, &digest2, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    let after = run
        .authority
        .issuance(&PendingId::parse(&pid).unwrap())
        .await
        .unwrap();
    assert_eq!(after.grant, first.grant);
    assert_eq!(after.digest, first.digest);
    assert!(broker.deliveries().iter().all(|(_, g)| *g == first.grant));
}

#[tokio::test]
async fn t19_concurrent_approves_sign_once() {
    let (_d, broker, run) = setup("concurrent").await;
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let gw = Arc::new(run.gateway_path.clone());
    let mut hs = vec![];
    for _ in 0..12 {
        let (gw, p, d) = (gw.clone(), pid.clone(), digest.clone());
        hs.push(tokio::spawn(async move {
            approve(&gw, &p, &d, "acme", "user:u-17").await
        }));
    }
    let mut oks = 0;
    for h in hs {
        if is_ok(&h.await.unwrap()) {
            oks += 1;
        }
    }
    assert!(oks >= 1);
    let d = broker.deliveries();
    assert!(d.iter().all(|(_, g)| *g == d[0].1), "one grant per jti");
    assert_eq!(broker.record_state(&pid), "APPROVED");
}

#[tokio::test]
async fn demo2_f02_reconnects_after_broker_closes_idle_connection() {
    let (_d, broker, run) = setup("idle").await;
    broker.state.lock().unwrap().idle_close = Some(Duration::from_millis(200));
    // Establish the pooled connection, then let the broker close it as idle.
    run.authority.broker().check().await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert!(is_ok(&r), "first approval after idleness must succeed: {r}");
    // Idle again before a second approval (stale connection on pending.get *and* deliver path).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let pid2 = random_pid();
    let rec2 = refund_record(&pid2, "user:u-17", 99, now() + 600);
    let d2 = digest_of(&rec2);
    broker.add(rec2, "PENDING");
    let r = approve(&run.gateway_path, &pid2, &d2, "acme", "user:u-17").await;
    assert!(is_ok(&r), "{r}");
    // One signature and one delivery per pending id; reconnects happened.
    let d = broker.deliveries();
    assert_eq!(d.iter().filter(|(p, _)| *p == pid).count(), 1);
    assert_eq!(d.iter().filter(|(p, _)| *p == pid2).count(), 1);
    assert!(broker.state.lock().unwrap().connections >= 3);
}

#[tokio::test]
async fn demo2_f02_reconnect_retry_is_bounded_to_once() {
    // The broker drops every pending.get without answering: one retry on a fresh connection,
    // then fail closed (no grant, no endless loop).
    let (_d, broker, run) = setup("idle-drop").await;
    run.authority.broker().check().await.unwrap();
    broker.state.lock().unwrap().drop_pending_get = true;
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert_eq!(broker.state.lock().unwrap().pending_gets, 2);
    // A fresh connection that fails is not retried.
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert_eq!(broker.state.lock().unwrap().pending_gets, 3);
    assert!(broker.deliveries().is_empty());
}

#[tokio::test]
async fn au_r_01_lying_display_facts_give_no_grant() {
    let (_d, broker, run) = setup("display").await;
    let lies = [
        json!({"amount_exponent": 6, "currency": "EUR"}),
        json!({"amount_exponent": 2, "currency": "USD"}),
        json!({}),
        json!({"amount_exponent": 2, "currency": "EUR", "note": "x"}),
    ];
    for lie in lies {
        let pid = random_pid();
        let mut rec = refund_record(&pid, "user:u-17", 1_000_000, now() + 600);
        rec.insert("display".into(), lie.clone());
        // The digest covers the lie, and the gateway showed exactly that digest.
        let digest = digest_of(&rec);
        broker.add(rec, "PENDING");
        let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
        assert_eq!(err_code(&r), Some("not_available"), "{lie}");
    }
    // Ledger transfer: display must be the configured ledger currency.
    let pid = random_pid();
    let mut rec = transfer_record(&pid, "user:u-17", now() + 600);
    rec.insert(
        "display".into(),
        json!({"amount_exponent": 0, "currency": "JPY"}),
    );
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert!(broker.deliveries().is_empty());
}

#[tokio::test]
async fn au_r_11_implausible_pending_lifetime_gives_no_grant() {
    let (_d, broker, run) = setup("lifetime").await;
    let t = now();
    for (created, expires) in [(t - 10, t + 5000), (t + 120, t + 600), (t + 600, t + 600)] {
        let pid = random_pid();
        let mut rec = refund_record(&pid, "user:u-17", 1250, expires);
        rec.insert("created_at".into(), json!(created));
        let digest = digest_of(&rec);
        broker.add(rec, "PENDING");
        let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
        assert_eq!(err_code(&r), Some("not_available"), "{created} {expires}");
    }
    assert!(broker.deliveries().is_empty());
}

#[tokio::test]
async fn au_r_04_clock_error_and_rollback_refuse_to_sign() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let t = Arc::new(AtomicU64::new(now()));
    let t2 = t.clone();
    let (_d, broker, run) = setup_with("clock", |o| {
        o.clock = Arc::new(move || t2.load(Ordering::SeqCst));
    })
    .await;
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    assert!(is_ok(
        &approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await
    ));
    // Rollback by more than skew below the high-water mark: refuse.
    let base = t.load(Ordering::SeqCst);
    t.store(base - 100, Ordering::SeqCst);
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    // Clock error (the system clock maps errors to 0): refuse.
    t.store(0, Ordering::SeqCst);
    let req = json!({"v":2,"id":"g-r","op":"read_grant","args":{
        "subject": {"ten": "acme", "sub": "user:u-1"}, "wid": SHOP, "rop": ["payments.get_order"]}});
    let r = gateway_raw(&run.gateway_path, &req.to_string())
        .await
        .unwrap();
    assert_eq!(err_code(&r), Some("not_available"));
    assert_eq!(broker.deliveries().len(), 1);
}

#[tokio::test]
async fn rx6_refund_with_unresolved_or_malformed_charge_id_is_never_signed() {
    let (_d, broker, run) = setup("charge").await;
    for bad in [
        "unresolved",
        "ch_x",
        "ch_1234567",
        "ch_abc/../12345",
        "ch_abcdefgh?x=1",
        "CH_abcdefgh",
        "",
        "ch_abcd efgh",
        "ch_abcdefgh\\",
    ] {
        let pid = random_pid();
        let mut rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
        rec["params"]["charge_id"] = json!(bad);
        let digest = digest_of(&rec);
        broker.add(rec, "PENDING");
        let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
        assert_eq!(err_code(&r), Some("not_available"), "{bad:?}");
        assert!(
            run.authority
                .issuance(&PendingId::parse(&pid).unwrap())
                .await
                .is_none()
        );
    }
    assert!(broker.deliveries().is_empty());
}

#[tokio::test]
async fn rx6_refund_with_resolved_charge_id_signs_con2_end_to_end() {
    let (_d, broker, run) = setup("charge-ok").await;
    let pid = random_pid();
    let mut rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    rec["params"]["charge_id"] = json!("ch_A1b2C3d4");
    // Display facts derived by the authority itself: EUR, exponent 2.
    rec.insert(
        "display".into(),
        json!({"amount_exponent": 2, "currency": "EUR"}),
    );
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert!(is_ok(&r), "{r}");
    // The fake broker verified the grant against the record's params, including charge_id
    // as con2 exact (a different charge_id would fail W12).
    assert_eq!(broker.state.lock().unwrap().results, vec!["accepted"]);
    assert_eq!(broker.record_state(&pid), "APPROVED");
    let row = run
        .authority
        .issuance(&PendingId::parse(&pid).unwrap())
        .await
        .unwrap();
    assert_eq!(row.status, nodkey_authority::store::Status::Accepted);
}
