// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Socket P: the broker-compromise suite (PT-29), grant rules RX-1..RX-3 (PT-42), charge-id
//! pattern (PT-41), age rule (PT-40, create side), order view (§3.2), strict framing (PT-12),
//! peer uid (PT-24), connection limits, and the lookup gate. Every refusal is checked against a
//! counting TLS server: nothing may reach the provider.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use nodkey_grant::{GrantBuilder, ParamValue};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Env {
    f: FakeServer,
    p: P,
    orders: std::sync::Arc<FakeOrders>,
}

async fn env_with(f: impl FnOnce(&mut Opts)) -> Env {
    let fs = FakeServer::start(
        Script::Respond(vec![(ok_response("", ECHO_BODY), 0)]),
        false,
    )
    .await;
    let orders = FakeOrders::standard();
    let mut o = Opts::new(fs.addr);
    o.orders = orders.clone();
    f(&mut o);
    let p = start_p(o).await;
    Env { f: fs, p, orders }
}

async fn env() -> Env {
    env_with(|_| {}).await
}

impl Env {
    fn sent(&self) -> usize {
        self.f.tcp_accepts.load(Ordering::SeqCst)
    }
    async fn refused(&self, grant: &str, what: &str) {
        let before = self.sent();
        let v = self.p.create(grant).await;
        assert_eq!(err_code(&v), "grant_refused", "{what}: {v}");
        assert_eq!(
            v["error"]["message"],
            json!("grant refused; nothing was sent")
        );
        assert_eq!(
            self.sent(),
            before,
            "{what}: something reached the provider"
        );
    }
    async fn created(&self, grant: &str, what: &str) {
        let v = self.p.create(grant).await;
        assert_eq!(result_class(&v).0, "created", "{what}: {v}");
    }
}

fn base() -> GrantBuilder {
    refund_grant(500, "USD", CH_USD, now())
}

fn with_charge(c: &str) -> GrantBuilder {
    refund_grant(500, "USD", c, now())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_compromise_suite() {
    let e = env().await;
    e.created(&sign(&base(), SEED), "control").await;
    let t = now();
    let other_op = GrantBuilder::write("ledger.transfer", 1)
        .issuer(ISS)
        .audience(BROKER)
        .jti(jti())
        .times(t, t, t + 30)
        .workload(SHOP)
        .tenant("acme")
        .subject("user:u-17")
        .resource(0, ParamValue::Uint(4711))
        .exact(0, ParamValue::Uint(500))
        .exact(1, ParamValue::Text("USD".into()))
        .exact(2, ParamValue::Text(CH_USD.into()))
        .confirmed(true);
    let read = GrantBuilder::read()
        .issuer(ISS)
        .audience(BROKER)
        .jti(jti())
        .times(t, t, t + 30)
        .workload(SHOP)
        .tenant("acme")
        .subject("user:u-17")
        .read_op("payments.get_order", 1);
    let opv2 = GrantBuilder::write("payments.refund", 2)
        .issuer(ISS)
        .audience(BROKER)
        .jti(jti())
        .times(t, t, t + 30)
        .workload(SHOP)
        .tenant("acme")
        .subject("user:u-17")
        .resource(0, ParamValue::Uint(4711))
        .exact(0, ParamValue::Uint(500))
        .exact(1, ParamValue::Text("USD".into()))
        .exact(2, ParamValue::Text(CH_USD.into()))
        .confirmed(true);
    let cases: Vec<(&str, String)> = vec![
        ("other op", sign(&other_op, SEED)),
        ("opv 2", sign(&opv2, SEED)),
        ("read grant", sign(&read, SEED)),
        (
            "other wid",
            sign(
                &base().workload("spiffe://nodkey.test/workload/other"),
                SEED,
            ),
        ),
        ("other aud", sign(&base().audience("broker.other"), SEED)),
        (
            "other iss",
            sign(&base().issuer("nodkey.authority.other"), SEED),
        ),
        ("cfm 0", sign(&base().confirmed(false), SEED)),
        ("foreign key", sign(&base(), SEED_FOREIGN)),
        ("revoked key (RX-2 4c)", sign(&base(), SEED_REVOKED)),
        (
            "tenant not configured (RX-1)",
            sign(&base().tenant("globex"), SEED),
        ),
        (
            "amount 0 (RX-3)",
            sign(&refund_grant(0, "USD", CH_USD, t), SEED),
        ),
        (
            "currency not in ISO table",
            sign(&refund_grant(5, "XYZ", CH_USD, t), SEED),
        ),
        (
            "extra con key",
            sign(&base().exact(3, ParamValue::Uint(1)), SEED),
        ),
        ("missing charge (Draft 3.0 shape)", {
            let g = GrantBuilder::write("payments.refund", 1)
                .issuer(ISS)
                .audience(BROKER)
                .jti(jti())
                .times(t, t, t + 30)
                .workload(SHOP)
                .tenant("acme")
                .subject("user:u-17")
                .resource(0, ParamValue::Uint(4711))
                .exact(0, ParamValue::Uint(500))
                .exact(1, ParamValue::Text("USD".into()))
                .confirmed(true);
            sign(&g, SEED)
        }),
        (
            "amount as text",
            sign(&base().exact(0, ParamValue::Text("500".into())), SEED),
        ),
        ("bounded amount", sign(&base().bounded(0, 500), SEED)),
        (
            "iat in the future",
            sign(&refund_grant(500, "USD", CH_USD, t + 60), SEED),
        ),
        (
            "older than R_max (PT-40)",
            sign(&refund_grant(500, "USD", CH_USD, t - 43_260), SEED),
        ),
        ("garbage transport", "!!!not-base64!!!".into()),
        ("empty transport", String::new()),
        ("oversized transport", "A".repeat(2800)),
        ("padded transport", format!("{}=", sign(&base(), SEED))),
    ];
    for (what, g) in &cases {
        e.refused(g, what).await;
    }
    // PT-41: con2 malformed on create.
    for c in [
        "unresolved",
        "ch_x",
        "ch_ABCDEFGH/../x",
        "ch_ABCDEFGH?a=1",
        "ch_ABCDEFGH&amount=9",
        "ch_ABC DEFGH",
    ] {
        e.refused(&sign(&with_charge(c), SEED), c).await;
    }
    // A valid grant whose order now has another owner (§3.2), another charge, another tenant
    // row, another currency, or no row at all.
    let g = sign(&base(), SEED);
    for m in 0..5 {
        {
            let mut rows = e.orders.rows.lock().unwrap();
            let r = rows.get_mut(&4711).unwrap();
            *r = FakeOrders::standard().rows.lock().unwrap()[&4711].clone();
            match m {
                0 => r.owner_sub = "user:u-99".into(),
                1 => r.charge_id = CH_JPY.into(),
                2 => r.ten = "globex".into(),
                3 => r.currency = "EUR".into(),
                _ => {
                    rows.remove(&4711);
                }
            }
        }
        e.refused(&g, &format!("order view mutation {m}")).await;
    }
    // DB unavailable → `unavailable`, nothing sent.
    *e.orders.rows.lock().unwrap() = FakeOrders::standard().rows.lock().unwrap().clone();
    e.orders.down.store(true, Ordering::SeqCst);
    let before = e.sent();
    let v = e.p.create(&g).await;
    assert_eq!(err_code(&v), "unavailable");
    assert_eq!(e.sent(), before);
    e.orders.down.store(false, Ordering::SeqCst);
    e.created(&g, "order restored").await;
}

/// Accepted edge cases: an expired-but-young grant (published residual), the age boundary, and
/// a key whose validity window ended between `iat` and now (window evaluated at `iat`, RX-2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepted_edges() {
    let e = env().await;
    let t = now();
    e.created(
        &sign(&refund_grant(500, "USD", CH_USD, t - 600), SEED),
        "expired but young",
    )
    .await;
    e.created(
        &sign(&refund_grant(500, "USD", CH_USD, t - 43_140), SEED),
        "age just below R_max",
    )
    .await;
    e.created(
        &sign(&refund_grant(500, "USD", CH_USD, t - 2000), SEED_SHORT),
        "key window at iat",
    )
    .await;
    e.refused(
        &sign(&refund_grant(500, "USD", CH_USD, t - 500), SEED_SHORT),
        "iat after window",
    )
    .await;
}

/// The request built from the grant: exact values, fixed headers, derived reference.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uniform_errors_do_not_depend_on_cause() {
    let e = env().await;
    let a = e.p.create(&sign(&base().audience("x.y"), SEED)).await;
    let b = e.p.create(&sign(&with_charge("unresolved"), SEED)).await;
    assert_eq!(a["error"], b["error"]);
    let mut ka: Vec<_> = a.as_object().unwrap().keys().cloned().collect();
    ka.sort();
    assert_eq!(ka, ["correlation_id", "error", "id", "ok", "v"]);
}

/// Lookups verify with `verify_binding`: every binding failure is refused with nothing sent
/// (PT-29, PT-41 on every op); a grant older than `R_max` is still served (PT-40).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookup_grant_checks() {
    let e = env().await;
    let t = now();
    let bad: Vec<(&str, String)> = vec![
        ("other aud", sign(&base().audience("broker.other"), SEED)),
        (
            "other wid",
            sign(&base().workload("spiffe://x/other"), SEED),
        ),
        ("foreign key", sign(&base(), SEED_FOREIGN)),
        ("revoked key", sign(&base(), SEED_REVOKED)),
        ("tenant", sign(&base().tenant("globex"), SEED)),
        ("cfm 0", sign(&base().confirmed(false), SEED)),
        ("amount 0", sign(&refund_grant(0, "USD", CH_USD, t), SEED)),
        ("unresolved", sign(&with_charge("unresolved"), SEED)),
        ("ch_x", sign(&with_charge("ch_x"), SEED)),
        ("path chars", sign(&with_charge("ch_ABCDEFGH/../x"), SEED)),
        (
            "query chars",
            sign(&with_charge("ch_ABCDEFGH?limit=100"), SEED),
        ),
        ("garbage", "%%%".into()),
    ];
    for (what, g) in &bad {
        for (op, args) in [
            ("refund.find", json!({"grant": g})),
            (
                "refund.get",
                json!({"grant": g, "refund_id": "re_ABCDEFGH1234"}),
            ),
            ("idem.status", json!({"grant": g})),
        ] {
            let v = e.p.call(op, args).await;
            assert_eq!(err_code(&v), "grant_refused", "{op} {what}");
        }
    }
    assert_eq!(e.sent(), 0);
    let g = sign(&base(), SEED);
    let v =
        e.p.call("refund.get", json!({"grant": g, "refund_id": "re_../../x"}))
            .await;
    assert_eq!(err_code(&v), "invalid_argument");
    let v =
        e.p.call(
            "refund.get",
            json!({"grant": g, "refund_id": "re_ABCDEFGH1234", "x": 1}),
        )
        .await;
    assert_eq!(err_code(&v), "malformed_request");
    assert_eq!(e.sent(), 0);
    // Older than R_max: create refused, lookup sent (the fake server's body does not match, so
    // the lookup itself is ambiguous; served is what matters here).
    let old = sign(&refund_grant(500, "USD", CH_USD, t - 50_000), SEED);
    e.refused(&old, "old create").await;
    let v = e.p.call("refund.find", json!({"grant": old})).await;
    assert_eq!(result_class(&v).0, "ambiguous");
    assert_eq!(e.sent(), 1);
    // Without the capability, idem.status is not served.
    let e2 = env_with(|o| o.caps = vec![]).await;
    assert_eq!(
        err_code(&e2.p.call("idem.status", json!({"grant": g})).await),
        "unknown_operation"
    );
    assert_eq!(e2.sent(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_framing_and_envelope() {
    let e = env().await;
    let g = sign(&base(), SEED);
    let cases: Vec<(String, &str)> = vec![
        (
            json!({"v":2,"id":"a","op":"refund.create","args":{"grant": g, "amount_minor": 1}})
                .to_string(),
            "malformed_request",
        ),
        (
            json!({"v":2,"id":"a","op":"refund.create","args":{"grant": g, "charge_id": CH_JPY}})
                .to_string(),
            "malformed_request",
        ),
        (
            json!({"v":2,"id":"a","op":"refund.create","args":{}}).to_string(),
            "malformed_request",
        ),
        (
            json!({"v":2,"id":"a","op":"refund.create","args":{"grant": 1}}).to_string(),
            "malformed_request",
        ),
        (
            json!({"v":2,"id":"a","op":"refund.create","args":{"grant": g},"x":1}).to_string(),
            "malformed_request",
        ),
        (
            format!(
                r#"{{"v":2,"id":"a","op":"refund.create","args":{{"grant":"{g}","grant":"x"}}}}"#
            ),
            "malformed_request",
        ),
        (
            json!({"v":1,"id":"a","op":"refund.create","args":{"grant": g}}).to_string(),
            "unsupported_version",
        ),
        (
            json!({"v":2,"id":"a","op":"refund.delete","args":{}}).to_string(),
            "unknown_operation",
        ),
        (
            json!({"v":2,"id":"a","op":"pending.get","args":{}}).to_string(),
            "unknown_operation",
        ),
        ("not json".to_string(), "malformed_request"),
    ];
    for (line, code) in cases {
        let v =
            e.p.raw(format!("{line}\n").as_bytes())
                .await
                .expect("response");
        assert_eq!(err_code(&v), code, "{line}");
    }
    // Oversized line → request_too_large; no newline before EOF → malformed_request.
    let big = format!("{}\n", "x".repeat(9000));
    assert_eq!(
        err_code(&e.p.raw(big.as_bytes()).await.unwrap()),
        "request_too_large"
    );
    let mut s = tokio::net::UnixStream::connect(&e.p.path).await.unwrap();
    s.write_all(br#"{"v":2"#).await.unwrap();
    s.shutdown().await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let v: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(err_code(&v), "malformed_request");
    assert_eq!(e.sent(), 0);
}

/// One request per connection: a second line is never answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_request_per_connection_and_idle_timeout() {
    let e = env().await;
    let hello = json!({"v":2,"id":"a","op":"adapter.hello","args":{}}).to_string();
    let mut s = tokio::net::UnixStream::connect(&e.p.path).await.unwrap();
    s.write_all(format!("{hello}\n{hello}\n").as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert_eq!(out.lines().count(), 1);
    // Idle: nothing sent → closed after ~2 s without a response.
    let mut s = tokio::net::UnixStream::connect(&e.p.path).await.unwrap();
    let t = std::time::Instant::now();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    assert!(buf.is_empty());
    assert!(t.elapsed() >= Duration::from_millis(1900) && t.elapsed() < Duration::from_secs(4));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_limit() {
    let e = env_with(|o| o.max_concurrent = 3).await;
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(tokio::net::UnixStream::connect(&e.p.path).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut extra = tokio::net::UnixStream::connect(&e.p.path).await.unwrap();
    let t = std::time::Instant::now();
    let mut buf = Vec::new();
    let _ = extra.read_to_end(&mut buf).await;
    assert!(buf.is_empty());
    assert!(
        t.elapsed() < Duration::from_millis(1000),
        "over-limit connection must close at once"
    );
    drop(held);
}

/// PT-24: a peer with another uid is closed without any response and raises an alarm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_peer_uid_is_closed_without_response() {
    let e = env_with(|o| o.broker_uid = Some(my_uid().wrapping_add(1))).await;
    let line = json!({"v":2,"id":"a","op":"refund.create","args":{"grant": sign(&base(), SEED)}})
        .to_string()
        + "\n";
    assert!(e.p.raw(line.as_bytes()).await.is_none());
    assert_eq!(e.sent(), 0);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(logs().iter().any(|l| l.contains("peer_uid_mismatch")));
}

/// The provider request contains exactly the grant-derived values and fixed headers (§5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_bytes_are_fixed_and_grant_derived() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_server_config(false)));
    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut buf = vec![0u8; 8192];
        let mut got = Vec::new();
        while !got.windows(4).any(|w| w == b"\r\n\r\n") || !got.ends_with(b"=") && got.len() < 400 {
            let n = tls.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if let Some(p) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..p]).to_lowercase();
                let cl: usize = head
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("content-length: ")
                            .map(|v| v.parse().unwrap())
                    })
                    .unwrap_or(0);
                if got.len() >= p + 4 + cl {
                    break;
                }
            }
        }
        let _ = tx.send(got);
    });
    let mut o = Opts::new(addr);
    o.caps = vec!["send_currency"];
    let p = start_p(o).await;
    let v = p
        .create(&sign(&refund_grant(1234, "USD", CH_USD, now()), SEED))
        .await;
    assert_eq!(result_class(&v), ("ambiguous", "reset_after_send"));
    let req = String::from_utf8(rx.await.unwrap()).unwrap();
    let (head, body) = req.split_once("\r\n\r\n").unwrap();
    let mut lines = head.lines();
    assert_eq!(lines.next(), Some("POST /v1/refunds HTTP/1.1"));
    let mut names: Vec<String> = lines
        .map(|l| l.split(':').next().unwrap().to_ascii_lowercase())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "authorization",
            "content-length",
            "content-type",
            "host",
            "idempotency-key",
            "user-agent"
        ]
    );
    assert!(head.contains("\r\nhost: simpay.test") || head.contains("\r\nHost: simpay.test"));
    assert!(
        head.to_ascii_lowercase()
            .contains("user-agent: nodkey-payments-adapter/1")
    );
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/x-www-form-urlencoded")
    );
    assert!(head.contains(&format!("Bearer {RK}")) || head.contains(&format!("bearer {RK}")));
    let reference = v["result"]["reference"].as_str().unwrap();
    assert_eq!(
        body,
        format!("charge={CH_USD}&amount=1234&reference={reference}&currency=usd")
    );
    let idem = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .starts_with("idempotency-key:")
                .then(|| l[16..].trim().to_string())
        })
        .unwrap();
    assert_eq!(idem.len(), 43);
    assert_ne!(idem, reference);
    // The idempotency key never appears in a socket-P response or a log line.
    assert!(!v.to_string().contains(&idem));
    assert!(!logs().join("\n").contains(&idem));
}

/// PC-A-01 / BP-01: every grant-carrying call must name the loaded key's `idem_kid`; any other
/// value (or none) is refused with nothing sent, on every op.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idem_kid_must_match_the_loaded_key() {
    let e = env().await;
    let g = sign(&base(), SEED);
    let other = "0000000000000000";
    assert_ne!(e.p.adapter.idem.kid(), other);
    for (op, args) in [
        ("refund.create", json!({"grant": g, "idem_kid": other})),
        ("refund.find", json!({"grant": g, "idem_kid": other})),
        (
            "refund.get",
            json!({"grant": g, "refund_id": "re_ABCDEFGH1234", "idem_kid": other}),
        ),
        ("idem.status", json!({"grant": g, "idem_kid": other})),
    ] {
        let v = e.p.call(op, args).await;
        assert_eq!(err_code(&v), "idem_kid_mismatch", "{op}: {v}");
        assert_eq!(
            v["error"]["message"],
            json!("idem_kid is not the loaded key; nothing was sent")
        );
    }
    // Without the member the request is malformed.
    let line = json!({"v":2,"id":"k1","op":"refund.create","args":{"grant": g}}).to_string() + "\n";
    assert_eq!(
        err_code(&e.p.raw(line.as_bytes()).await.unwrap()),
        "malformed_request"
    );
    assert_eq!(e.sent(), 0);
    // Control: the loaded kid is served.
    e.created(&g, "matching kid").await;
}

/// PC-A-01: a grant issued before `idem_key_not_before` is refused for `refund.create`, nothing
/// sent; lookups are unaffected. A not-before time in the future refuses start-up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grants_older_than_the_key_are_not_created() {
    let t = now();
    let e = env_with(|o| o.idem_key_not_before = t - 60).await;
    e.refused(
        &sign(&refund_grant(500, "USD", CH_USD, t - 61), SEED),
        "iat before not_before",
    )
    .await;
    let v =
        e.p.call(
            "refund.find",
            json!({"grant": sign(&refund_grant(500, "USD", CH_USD, t - 61), SEED)}),
        )
        .await;
    assert_eq!(v["ok"], json!(true), "{v}");
    e.created(
        &sign(&refund_grant(500, "USD", CH_USD, t - 60), SEED),
        "iat = not_before",
    )
    .await;
    let mut o = Opts::new(e.f.addr);
    o.idem_key_not_before = now() + 3600;
    let err = try_build_adapter(&o, &sockdir().join("x.sock")).unwrap_err();
    assert!(err.contains("future"), "{err}");
}

/// An order view that never answers in time.
struct SlowOrders;
impl nodkey_payments_adapter::orders::OrderView for SlowOrders {
    fn fetch(
        &self,
        _id: u64,
    ) -> nodkey_payments_adapter::orders::BoxFut<
        '_,
        Result<Option<nodkey_payments_adapter::orders::OrderRow>, &'static str>,
    > {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Err("db_query")
        })
    }
}

/// PC-A-02: one deadline per request from receipt. A slow order view is cut at its share of the
/// deadline; the answer is `unavailable` (nothing sent) well within `total_ms`, so within the
/// broker's wait (`total_ms + 2 s`); `adapter.hello` publishes the deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_order_view_is_bounded_by_the_request_deadline() {
    let e = env_with(|o| {
        o.orders = std::sync::Arc::new(SlowOrders);
        o.total_ms = 1500;
        o.connect_ms = 1000;
    })
    .await;
    let hello = e.p.call("adapter.hello", json!({})).await;
    assert_eq!(hello["result"]["deadline_ms"], json!(1500));
    let t = std::time::Instant::now();
    let v = e.p.create(&sign(&base(), SEED)).await;
    let took = t.elapsed();
    assert_eq!(err_code(&v), "unavailable", "{v}");
    assert!(took < Duration::from_millis(1500 + 300), "{took:?}");
    assert_eq!(e.sent(), 0);
}
