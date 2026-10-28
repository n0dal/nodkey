//! Mandates at the authority (agent-interface-v1 Draft 2 §4.2 step 3, §4.4, §4.7; ADR-0006
//! Amendment 3): the template approval records the mandate in the issuance row; mandated issuance
//! checks the authority's **own** mandate and counters; no replacement; revocation; restart.
//! AT-xx ids refer to agent-interface-v1 §7.

mod common;

use common::*;
use nodkey_authority::digest::PendingId;
use nodkey_authority::server::MandateOutcome;
use nodkey_authority::store::{Extra, Status};
use serde_json::{Map, Value, json};

const ANA: (&str, &str) = ("shop1", "op_ana");

fn record(pid: &str, op: &str, params: Value, types: Value, display: Value) -> Map<String, Value> {
    let exp = now() + 600;
    json!({
        "pending_id": pid, "broker_id": BROKER_ID, "wid": SUPPORT, "ten": ANA.0,
        "approver_sub": ANA.1, "op": op, "opv": 1, "params": params, "param_types": types,
        "created_at": exp - 600, "expires_at": exp, "display": display
    })
    .as_object()
    .unwrap()
    .clone()
}

fn template(
    pid: &str,
    cs: &str,
    n: u64,
    per: u64,
    total: u64,
    msgs: u64,
    valid: u64,
) -> Map<String, Value> {
    record(
        pid,
        "mandate.support_ticket",
        json!({"customer_sub": cs, "currency": "EUR", "refund_max_count": n,
               "refund_max_per_call_minor": per, "refund_max_total_minor": total,
               "message_max_count": msgs, "valid_for_s": valid,
               "customer_email": format!("{cs}@customer.test")}),
        json!({"customer_sub": "text64", "currency": "currency", "refund_max_count": "uint",
               "refund_max_per_call_minor": "uint", "refund_max_total_minor": "uint",
               "message_max_count": "uint", "valid_for_s": "uint", "customer_email": "text256"}),
        json!({"amount_exponent": 2, "currency": "EUR"}),
    )
}

fn refund(pid: &str, cs: &str, order: u64, amount: u64, cur: &str) -> Map<String, Value> {
    record(
        pid,
        "payments.support_refund",
        json!({"order_id": order, "amount_minor": amount, "currency": cur,
               "charge_id": format!("ch_order{order:06}"), "customer_sub": cs}),
        json!({"order_id": "uint", "amount_minor": "uint", "currency": "currency",
               "charge_id": "text64", "customer_sub": "text64"}),
        json!({"amount_exponent": 2, "currency": cur}),
    )
}

fn message(pid: &str, cs: &str, to: &str, body: &str) -> Map<String, Value> {
    record(
        pid,
        "messages.send",
        json!({"customer_sub": cs, "to": to, "body": body}),
        json!({"customer_sub": "text64", "to": "text256", "body": "text256"}),
        json!({}),
    )
}

async fn setup(name: &str) -> (std::path::PathBuf, FakeBroker, Running) {
    let dir = tmpdir(name);
    let keys = make_key(&dir);
    let broker = FakeBroker::start(&dir, &keys.registry_json).await;
    let run = start_authority(&dir, &keys, &broker.path, Opts::new()).await;
    (dir, broker, run)
}

/// Approves a template record (human path); on success the fake broker reports the activation
/// as executed (`SUCCEEDED`) and the authority confirms it (MD-7). Returns the gateway reply.
async fn approve_template(broker: &FakeBroker, run: &Running, rec: Map<String, Value>) -> Value {
    approve_template_as(broker, run, rec, Some("SUCCEEDED")).await
}

/// As [`approve_template`], with the broker's record state after an accepted delivery set to
/// `activation` (`None`: left as the fake broker set it, i.e. not yet executed).
async fn approve_template_as(
    broker: &FakeBroker,
    run: &Running,
    rec: Map<String, Value>,
    activation: Option<&str>,
) -> Value {
    let pid = rec["pending_id"].as_str().unwrap().to_owned();
    let d = digest_of(&rec);
    broker.add(rec, "PENDING");
    let r = approve(&run.gateway_path, &pid, &d, ANA.0, ANA.1).await;
    if is_ok(&r) {
        if let Some(st) = activation {
            set_state(broker, &pid, st);
        }
        run.authority.confirm_activations().await;
    }
    r
}

fn set_state(broker: &FakeBroker, pid: &str, st: &str) {
    broker
        .state
        .lock()
        .unwrap()
        .records
        .get_mut(pid)
        .unwrap()
        .state = st.to_owned();
}

async fn issue(broker: &FakeBroker, run: &Running, rec: Map<String, Value>) -> MandateOutcome {
    let pid = rec["pending_id"].as_str().unwrap().to_owned();
    broker.add(rec, "PENDING");
    run.authority
        .mandate_issue(PendingId::parse(&pid).unwrap())
        .await
}

fn pid() -> String {
    random_pid()
}

/// AT-09, AT-11, AT-19 (counters), AT-21 (cfm = 2 + mid verified by the broker's crate): the
/// mandate's terms are recorded with the template's row; in-scope effects get `cfm = 2` grants
/// with that `mid`; per-call, count, total and currency are exact boundaries on the authority's
/// own counters; out-of-scope effects are declined (`final: false`).
#[tokio::test]
async fn mandated_issuance_within_own_counters() {
    let (_d, broker, run) = setup("mnd-issue").await;
    let mid = pid();
    let r = approve_template(&broker, &run, template(&mid, "c42", 3, 2500, 5000, 1, 3600)).await;
    assert!(is_ok(&r), "{r}");
    let mrow = PendingId::parse(&mid).unwrap();
    match run.authority.store_extra(&mrow).await {
        Some(Extra::Mandate(t)) => {
            assert_eq!(t.customer_sub, "c42");
            assert_eq!(t.exp - t.nbf, 3600);
        }
        x => panic!("no mandate terms recorded: {x:?}"),
    }
    let ok = |p: &str| (p.to_owned(), MandateOutcome::Issued);
    // In scope, exactly per-call.
    let a = pid();
    assert_eq!(
        (
            a.clone(),
            issue(&broker, &run, refund(&a, "c42", 101, 2500, "EUR")).await
        ),
        ok(&a)
    );
    let mids = broker.state.lock().unwrap().mandated.clone();
    assert_eq!(
        mids,
        vec![(a.clone(), mrow.0)],
        "cfm = 2 grant with mid verified by the broker"
    );
    // Declined: per-call + 1, other customer, other currency.
    for rec in [
        refund(&pid(), "c42", 102, 2501, "EUR"),
        refund(&pid(), "c9", 777, 100, "EUR"),
        refund(&pid(), "c42", 103, 100, "USD"),
    ] {
        let p = rec["pending_id"].as_str().unwrap().to_owned();
        assert_eq!(issue(&broker, &run, rec).await, MandateOutcome::Declined);
        assert!(broker.state.lock().unwrap().declined.contains(&(p, false)));
    }
    // Total: 2500 + 2500 = 5000 exactly; then the count would allow a third but total not.
    let b = pid();
    assert_eq!(
        issue(&broker, &run, refund(&b, "c42", 104, 2500, "EUR")).await,
        MandateOutcome::Issued
    );
    assert_eq!(
        issue(&broker, &run, refund(&pid(), "c42", 105, 1, "EUR")).await,
        MandateOutcome::Declined
    );
    // Messages: recipient must be the mandate's email; count is not an authority bound (R-A9),
    // but C6 refuses an identical repeat.
    let m1 = pid();
    assert_eq!(
        issue(
            &broker,
            &run,
            message(&m1, "c42", "c42@customer.test", "hi")
        )
        .await,
        MandateOutcome::Issued
    );
    assert_eq!(
        issue(
            &broker,
            &run,
            message(&pid(), "c42", "x@evil.example", "hi")
        )
        .await,
        MandateOutcome::Declined
    );
    assert_eq!(
        issue(
            &broker,
            &run,
            message(&pid(), "c42", "c42@customer.test", "hi")
        )
        .await,
        MandateOutcome::Declined,
        "C6"
    );
    // An existing issuance row stops (AI-07): no second grant, no counter change.
    let before = broker.deliveries().len();
    broker.add(refund(&a, "c42", 101, 2500, "EUR"), "PENDING");
    assert_eq!(
        run.authority
            .mandate_issue(PendingId::parse(&a).unwrap())
            .await,
        MandateOutcome::Exists
    );
    assert_eq!(broker.deliveries().len(), before);
}

/// AT-12 (authority side): 32 concurrent issuance attempts against one mandate never sign
/// beyond its count and total.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_issuance_bounded() {
    let (_d, broker, run) = setup("mnd-race").await;
    let mid = pid();
    assert!(is_ok(
        &approve_template(&broker, &run, template(&mid, "c42", 5, 2000, 5000, 0, 3600)).await
    ));
    let mut ids = vec![];
    for i in 0..32u64 {
        let p = pid();
        broker.add(refund(&p, "c42", 200 + i, 2000, "EUR"), "PENDING");
        ids.push(p);
    }
    let mut tasks = vec![];
    for p in ids {
        let a = run.authority.clone();
        tasks.push(tokio::spawn(async move {
            a.mandate_issue(PendingId::parse(&p).unwrap()).await
        }));
    }
    let mut issued = 0;
    for t in tasks {
        if t.await.unwrap() == MandateOutcome::Issued {
            issued += 1;
        }
    }
    assert_eq!(issued, 2);
    assert_eq!(broker.state.lock().unwrap().mandated.len(), 2);
}

/// AT-17 (authority): a second template while a mandate is active is refused; AT-20: terms above
/// the ceilings, a non-principal approver, and an unresolved (" ") customer are refused.
#[tokio::test]
async fn no_replacement_and_template_refusals() {
    let (_d, broker, run) = setup("mnd-repl").await;
    let first = pid();
    assert!(is_ok(
        &approve_template(&broker, &run, template(&first, "c42", 1, 100, 100, 1, 600)).await
    ));
    let r = approve_template(&broker, &run, template(&pid(), "c42", 1, 100, 100, 1, 600)).await;
    assert_eq!(err_code(&r), Some("not_available"));
    for rec in [
        template(&pid(), "c9", 6, 100, 100, 1, 600),
        template(&pid(), "c9", 1, 100, 10001, 1, 600),
        template(&pid(), "c9", 1, 100, 100, 11, 600),
        template(&pid(), "c9", 1, 200, 100, 1, 600),
        template(&pid(), "c9", 1, 100, 100, 1, 3601),
        template(&pid(), "c9", 1, 100, 100, 1, 59),
        template(&pid(), " ", 1, 100, 100, 1, 600),
    ] {
        assert_eq!(
            err_code(&approve_template(&broker, &run, rec).await),
            Some("not_available")
        );
    }
    // After revocation (AI-04: the principal revokes first) a new mandate is accepted.
    let rv = gateway_raw(
        &run.gateway_path,
        &json!({"v":2,"id":"r1","op":"mandate.revoke","args":{"mid": first, "subject": {"ten": ANA.0, "sub": ANA.1}}}).to_string(),
    )
    .await
    .unwrap();
    assert!(is_ok(&rv), "{rv}");
    assert!(is_ok(
        &approve_template(&broker, &run, template(&pid(), "c42", 1, 100, 100, 1, 600)).await
    ));
}

/// AT-15 (authority): revocation on socket I stops new signing; it is idempotent; another
/// subject or an unknown mid gets `not_available`. A broker that rejects a mandated delivery
/// gets `mandate.declined{final: true}` (AI-08).
#[tokio::test]
async fn revocation_and_rejected_delivery() {
    let (_d, broker, run) = setup("mnd-revoke").await;
    let mid = pid();
    assert!(is_ok(
        &approve_template(
            &broker,
            &run,
            template(&mid, "c42", 5, 2500, 10000, 5, 3600)
        )
        .await
    ));
    // Rejected delivery → declined final.
    broker.state.lock().unwrap().reject_mandated = true;
    let p = pid();
    assert_eq!(
        issue(&broker, &run, refund(&p, "c42", 101, 100, "EUR")).await,
        MandateOutcome::Rejected
    );
    assert!(
        broker
            .state
            .lock()
            .unwrap()
            .declined
            .contains(&(p.clone(), true))
    );
    let row = run
        .authority
        .issuance(&PendingId::parse(&p).unwrap())
        .await
        .unwrap();
    assert_eq!(row.status, Status::Rejected);
    broker.state.lock().unwrap().reject_mandated = false;
    let revoke = |mid: String, sub: &'static str| {
        let path = run.gateway_path.clone();
        async move {
            gateway_raw(
                &path,
                &json!({"v":2,"id":"r1","op":"mandate.revoke","args":{"mid": mid, "subject": {"ten": "shop1", "sub": sub}}}).to_string(),
            )
            .await
            .unwrap()
        }
    };
    assert_eq!(
        err_code(&revoke(mid.clone(), "op_bob").await),
        Some("not_available")
    );
    assert_eq!(
        err_code(&revoke(pid(), "op_ana").await),
        Some("not_available")
    );
    assert!(is_ok(&revoke(mid.clone(), "op_ana").await));
    assert!(is_ok(&revoke(mid.clone(), "op_ana").await));
    assert_eq!(
        issue(&broker, &run, refund(&pid(), "c42", 102, 100, "EUR")).await,
        MandateOutcome::Declined
    );
}

/// AT-19: counters and revocation are durable across a restart (same store file).
#[tokio::test]
async fn counters_durable_across_restart() {
    let dir = tmpdir("mnd-restart");
    let keys = make_key(&dir);
    let broker = FakeBroker::start(&dir, &keys.registry_json).await;
    let mid = pid();
    {
        let run = start_authority(&dir, &keys, &broker.path, Opts::new()).await;
        assert!(is_ok(
            &approve_template(&broker, &run, template(&mid, "c42", 2, 2500, 5000, 0, 3600)).await
        ));
        assert_eq!(
            issue(&broker, &run, refund(&pid(), "c42", 101, 2500, "EUR")).await,
            MandateOutcome::Issued
        );
        run.task.abort();
        drop(run);
    }
    // The store's flock is released when the authority is dropped; reopen.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let run = start_authority(&dir, &keys, &broker.path, Opts::new()).await;
    assert_eq!(
        issue(&broker, &run, refund(&pid(), "c42", 102, 2501, "EUR")).await,
        MandateOutcome::Declined
    );
    assert_eq!(
        issue(&broker, &run, refund(&pid(), "c42", 103, 2500, "EUR")).await,
        MandateOutcome::Issued
    );
    assert_eq!(
        issue(&broker, &run, refund(&pid(), "c42", 104, 1, "EUR")).await,
        MandateOutcome::Declined,
        "count 2 reached"
    );
}

/// MD-7 (fail closed): the authority treats a mandate as active only after the broker confirmed
/// its activation. Unconfirmed (record still `APPROVED`): no `cfm = 2` grant, and no replacement
/// template. Failed (`FAILED`/denied, e.g. the broker's no-replacement refusal): the mandate is
/// inactive for good — no grants even if the broker later reports otherwise — and the key is
/// released for a new template. A record that does not match the mandate row is a failure.
/// Positive control: the same flow with `SUCCEEDED` issues.
#[tokio::test]
async fn activation_must_be_confirmed_by_the_broker() {
    let (_d, broker, run) = setup("mnd-activation").await;
    // Unconfirmed.
    let mid = pid();
    let r = approve_template_as(
        &broker,
        &run,
        template(&mid, "c42", 3, 2500, 5000, 1, 3600),
        None,
    )
    .await;
    assert!(is_ok(&r), "{r}");
    assert_eq!(broker.record_state(&mid), "APPROVED");
    let m = PendingId::parse(&mid).unwrap();
    assert_eq!(run.authority.activation(&m).await, None);
    assert_eq!(
        issue(&broker, &run, refund(&pid(), "c42", 101, 100, "EUR")).await,
        MandateOutcome::Declined,
        "no grant under an unconfirmed mandate"
    );
    assert_eq!(
        err_code(
            &approve_template_as(
                &broker,
                &run,
                template(&pid(), "c42", 1, 100, 100, 1, 600),
                None
            )
            .await
        ),
        Some("not_available"),
        "an unconfirmed mandate still blocks replacement"
    );
    // Activation fails at the broker.
    set_state(&broker, &mid, "FAILED");
    assert_eq!(run.authority.confirm_activations().await, 1);
    assert_eq!(run.authority.activation(&m).await, Some(false));
    assert_eq!(
        issue(&broker, &run, refund(&pid(), "c42", 101, 100, "EUR")).await,
        MandateOutcome::Declined
    );
    // Settled: a later contrary broker report changes nothing.
    set_state(&broker, &mid, "SUCCEEDED");
    assert_eq!(run.authority.confirm_activations().await, 0);
    assert_eq!(run.authority.activation(&m).await, Some(false));
    assert_eq!(
        issue(&broker, &run, refund(&pid(), "c42", 101, 100, "EUR")).await,
        MandateOutcome::Declined
    );
    assert!(broker.state.lock().unwrap().mandated.is_empty());

    // The failed mandate no longer blocks a new template (MD-7); positive control.
    let second = pid();
    let r = approve_template(
        &broker,
        &run,
        template(&second, "c42", 3, 2500, 5000, 1, 3600),
    )
    .await;
    assert!(is_ok(&r), "{r}");
    let second_id = PendingId::parse(&second).unwrap();
    assert_eq!(run.authority.activation(&second_id).await, Some(true));
    assert_eq!(
        issue(&broker, &run, refund(&pid(), "c42", 101, 100, "EUR")).await,
        MandateOutcome::Issued,
        "positive control: confirmed activation issues"
    );
}

/// MD-7: a broker record whose digest does not match the mandate row is recorded as a failed
/// activation, and the outcome survives a restart.
#[tokio::test]
async fn activation_mismatch_fails_closed_and_is_durable() {
    let dir = tmpdir("mnd-act-durable");
    let keys = make_key(&dir);
    let broker = FakeBroker::start(&dir, &keys.registry_json).await;
    let mid = pid();
    let m = PendingId::parse(&mid).unwrap();
    {
        let run = start_authority(&dir, &keys, &broker.path, Opts::new()).await;
        let r = approve_template_as(
            &broker,
            &run,
            template(&mid, "c42", 3, 2500, 5000, 1, 3600),
            None,
        )
        .await;
        assert!(is_ok(&r), "{r}");
        {
            let mut st = broker.state.lock().unwrap();
            let rec = st.records.get_mut(&mid).unwrap();
            rec.state = "SUCCEEDED".into();
            rec.digest_override = Some("00".repeat(32));
        }
        assert_eq!(run.authority.confirm_activations().await, 1);
        assert_eq!(run.authority.activation(&m).await, Some(false));
        run.task.abort();
        drop(run);
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    broker
        .state
        .lock()
        .unwrap()
        .records
        .get_mut(&mid)
        .unwrap()
        .digest_override = None;
    let run = start_authority(&dir, &keys, &broker.path, Opts::new()).await;
    assert_eq!(run.authority.activation(&m).await, Some(false));
    assert_eq!(run.authority.confirm_activations().await, 0);
    assert_eq!(
        issue(&broker, &run, refund(&pid(), "c42", 101, 100, "EUR")).await,
        MandateOutcome::Declined
    );
}
