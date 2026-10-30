// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! mailsink admin endpoint and in-memory view (no database needed).

use std::net::SocketAddr;

use mailsink::{LABEL, MAX_MESSAGES, Message, Sink, check_bind, route, serve_admin};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn msg(id: &str, at: i64, to: &str) -> Message {
    Message {
        message_id: id.into(),
        ten: "shop1".into(),
        to: to.into(),
        body: "Card details: none".into(),
        created_at: at,
    }
}

async fn get(addr: SocketAddr, req: &str) -> (String, Value) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap();
    (head.to_owned(), serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn listing_over_http_is_labelled() {
    let sink = Sink::new();
    sink.ingest(vec![msg("aa", 10, "alice@customer.test")]);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve_admin(l, sink.clone()));
    let (head, body) = get(addr, "GET /messages HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 200"));
    assert!(head.contains(&format!("Mailsink-Simulator: {LABEL}")));
    assert_eq!(body["simulator"], true);
    assert_eq!(
        body["messages"],
        json!([{"message_id":"aa","ten":"shop1","to":"alice@customer.test",
                "body":"Card details: none","created_at":10}])
    );
    let (head, body) = get(addr, "GET /healthz HTTP/1.1\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 200"));
    assert_eq!(body["polls_ok"], 1);
    let (head, _) = get(addr, "GET /other HTTP/1.1\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 404"));
    let (head, _) = get(addr, "POST /messages HTTP/1.1\r\nContent-Length: 0\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 405"));
    let (head, _) = get(addr, "garbage\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 400"));
}

#[test]
fn ingest_dedupes_orders_cursor_and_caps() {
    let sink = Sink::new();
    sink.ingest(vec![msg("bb", 5, "a@x"), msg("aa", 5, "a@x")]);
    assert_eq!(sink.cursor(), Some((5, "bb".into())));
    sink.ingest(vec![msg("aa", 5, "a@x"), msg("cc", 7, "b@x")]);
    assert_eq!(sink.messages().len(), 3, "duplicate not stored twice");
    assert_eq!(sink.cursor(), Some((7, "cc".into())));
    let many: Vec<Message> = (0..MAX_MESSAGES + 5)
        .map(|i| msg(&format!("{i:08x}"), 100 + i as i64, "a@x"))
        .collect();
    sink.ingest(many);
    assert_eq!(sink.messages().len(), MAX_MESSAGES);
    let l = sink.listing();
    assert_eq!(l["not_stored"], 8);
    sink.poll_failed("db down");
    assert_eq!(sink.health()["last_error"], "db down");
}

#[test]
fn bind_policy() {
    for ok in [
        "127.0.0.1:1",
        "10.0.0.5:1",
        "192.168.1.2:1",
        "[::1]:1",
        "[fd00::1]:1",
    ] {
        assert!(check_bind(ok.parse().unwrap(), false).is_ok(), "{ok}");
    }
    for bad in ["8.8.8.8:1", "[2001:db8::1]:1", "[::ffff:8.8.8.8]:1"] {
        assert!(check_bind(bad.parse().unwrap(), true).is_err(), "{bad}");
    }
    assert!(check_bind("0.0.0.0:1".parse().unwrap(), false).is_err());
    assert!(check_bind("0.0.0.0:1".parse().unwrap(), true).is_ok());
}

#[test]
fn route_needs_a_complete_head() {
    let sink = Sink::new();
    let out = String::from_utf8(route(&sink, b"GET /messages HTTP/1.1\r\n")).unwrap();
    assert!(out.starts_with("HTTP/1.1 400"));
}
