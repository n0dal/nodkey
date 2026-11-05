// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! PT-25: TLS policy. Wrong CA, wrong SAN, expired certificate, plain HTTP, a TLS 1.2-only
//! server, refused connect and a stalled handshake are all `not_sent` (no request byte written),
//! and the ledger stays at 0.

mod common;

use common::*;
use serde_json::json;

async fn create_once(o: Opts) -> serde_json::Value {
    let p = start_p(o).await;
    p.create(&sign(&refund_grant(5, "USD", CH_USD, now()), SEED))
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn foreign_ca_is_not_sent() {
    let s = Simpay::start(Tls::Good);
    let mut o = Opts::new(s.api);
    o.ca = foreign_certs().ca();
    let v = create_once(o).await;
    assert_eq!(result_class(&v), ("not_sent", "tls"));
    assert_eq!(
        v["result"],
        json!({"class": "not_sent", "cause": "tls", "anomalies": []})
    );
    assert_eq!(s.total_refunds(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_hostname_certificate_is_not_sent() {
    let (c, k) = certs().wrong_host();
    let s = Simpay::start(Tls::Files(c, k));
    let v = create_once(Opts::new(s.api)).await;
    assert_eq!(result_class(&v), ("not_sent", "tls"));
    assert_eq!(s.total_refunds(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_certificate_is_not_sent() {
    let (c, k) = certs().expired();
    let s = Simpay::start(Tls::Files(c, k));
    let v = create_once(Opts::new(s.api)).await;
    assert_eq!(result_class(&v), ("not_sent", "tls"));
    assert_eq!(s.total_refunds(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_http_endpoint_is_not_sent() {
    let s = Simpay::start(Tls::Plain);
    let v = create_once(Opts::new(s.api)).await;
    assert_eq!(result_class(&v), ("not_sent", "tls"));
    assert_eq!(s.total_refunds(), 0);
}

/// The test build has rustls' `tls12` feature compiled in (dev-dependency), so this also shows
/// that the adapter's client configuration, not the library build, restricts it to TLS 1.3.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls12_only_server_is_not_sent() {
    let f = FakeServer::start(Script::Respond(vec![(ok_response("", ECHO_BODY), 0)]), true).await;
    let v = create_once(Opts::new(f.addr)).await;
    assert_eq!(result_class(&v), ("not_sent", "tls"));
    assert_eq!(f.tcp_accepts.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(f.requests.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// Control for the fake server: the same script over TLS 1.3 is `created`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls13_fake_server_control() {
    let f = FakeServer::start(
        Script::Respond(vec![(ok_response("", ECHO_BODY), 0)]),
        false,
    )
    .await;
    let v = create_once(Opts::new(f.addr)).await;
    assert_eq!(result_class(&v).0, "created", "{v}");
    assert_eq!(f.requests.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_connect_is_not_sent_connect() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let v = create_once(Opts::new(addr)).await;
    assert_eq!(result_class(&v), ("not_sent", "connect"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_handshake_is_bounded_and_not_sent() {
    let f = FakeServer::start(Script::StallHandshake, false).await;
    let mut o = Opts::new(f.addr);
    o.connect_ms = 800;
    let t = std::time::Instant::now();
    let v = create_once(o).await;
    assert_eq!(result_class(&v), ("not_sent", "tls"));
    assert!(t.elapsed() < std::time::Duration::from_millis(2000));
}
