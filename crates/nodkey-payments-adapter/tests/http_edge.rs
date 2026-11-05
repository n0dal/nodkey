// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! PT-35: byte-level HTTP edge cases from a scripted TLS 1.3 server that presents the pinned
//! test CA's `simpay.test` certificate. Malformed input is never `created`.

mod common;

use common::*;
use serde_json::Value;

async fn run(chunks: Vec<(String, u64)>, total_ms: u64) -> Value {
    let f = FakeServer::start(Script::Respond(chunks), false).await;
    let mut o = Opts::new(f.addr);
    o.total_ms = total_ms;
    o.connect_ms = total_ms.min(2000);
    let p = start_p(o).await;
    p.create(&sign(&refund_grant(5, "USD", CH_USD, now()), SEED))
        .await
}

async fn one(resp: String) -> Value {
    run(vec![(resp, 0)], 5000).await
}

fn headers(n: usize) -> String {
    (0..n).map(|i| format!("X-H{i}: v\r\n")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn informational_then_200_is_created() {
    let r = format!(
        "HTTP/1.1 100 Continue\r\n\r\n{}",
        ok_response("", ECHO_BODY)
    );
    assert_eq!(result_class(&one(r).await).0, "created");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn header_count_limit() {
    // ok_response adds Content-Type, Content-Length and Connection: 61 + 3 = 64 headers.
    assert_eq!(
        result_class(&one(ok_response(&headers(61), ECHO_BODY)).await).0,
        "created"
    );
    let v = one(ok_response(&headers(62), ECHO_BODY)).await;
    assert_eq!(result_class(&v), ("ambiguous", "bad_headers"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_ascii_header_value_is_bad_headers() {
    let v = one(ok_response("X-Note: caf\u{e9}\r\n", ECHO_BODY)).await;
    assert_eq!(result_class(&v), ("ambiguous", "bad_headers"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_content_length_is_ambiguous() {
    let r = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 900\r\n\r\n{ECHO_BODY}"
    );
    let v = one(r).await;
    assert_eq!(result_class(&v), ("ambiguous", "reset_after_send"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_with_trailers_is_parsed() {
    // A valid chunked body with a trailer field. The body is complete and exact → created.
    let body = ECHO_BODY;
    let r = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\nCHUNKLEN\r\n{body}\r\n0\r\nX-Trailer: t\r\n\r\n"
    );
    let v = run_chunked(r).await;
    assert_eq!(result_class(&v).0, "created", "{v}");
}

/// The server substitutes only `{BODYLEN}`, so the chunk size is computed here from the known
/// lengths of the echoed values (amount "5", a 16-byte charge, a 43-byte reference).
async fn run_chunked(template: String) -> Value {
    // The echoed reference is 43 bytes, the amount "5", the charge 16 bytes: fixed length.
    let filled = ECHO_BODY
        .replace("{amount}", "5")
        .replace("{charge}", CH_USD)
        .replace("{reference}", &"x".repeat(43));
    let len = filled.len();
    run(
        vec![(template.replace("CHUNKLEN", &format!("{len:x}")), 0)],
        5000,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn content_type_must_be_exact_and_single() {
    for extra_ct in [
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {BODYLEN}\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: Application/JSON\r\nContent-Length: {BODYLEN}\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: {BODYLEN}\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: {BODYLEN}\r\n\r\n",
    ] {
        let v = one(format!("{extra_ct}{ECHO_BODY}")).await;
        assert_eq!(
            result_class(&v),
            ("ambiguous", "bad_content_type"),
            "{extra_ct}"
        );
    }
}

const STALL_HEAD: &str =
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 300\r\n\r\n{";

/// PC-A-08: the timer covers only the request (setup excluded) and asserts the `total_ms` bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stall_after_head_times_out() {
    let f = FakeServer::start(Script::Respond(vec![(STALL_HEAD.into(), 10_000)]), false).await;
    let mut o = Opts::new(f.addr);
    o.total_ms = 1200;
    o.connect_ms = 1000;
    let p = start_p(o).await;
    let g = sign(&refund_grant(5, "USD", CH_USD, now()), SEED);
    let t = std::time::Instant::now();
    let v = p.create(&g).await;
    let took = t.elapsed();
    assert_eq!(result_class(&v), ("ambiguous", "timeout"));
    assert!(
        took < std::time::Duration::from_millis(1200 + 500),
        "{took:?}"
    );
}

/// PC-A-05: a timed-out exchange releases its TLS connection (the hyper connection task is
/// aborted), so a stalling provider cannot accumulate open sockets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_exchanges_release_their_connections() {
    let f = FakeServer::start(Script::StallUntilClosed(STALL_HEAD.into()), false).await;
    let mut o = Opts::new(f.addr);
    o.total_ms = 600;
    o.connect_ms = 500;
    let p = start_p(o).await;
    const N: usize = 6;
    for _ in 0..N {
        let v = p
            .create(&sign(&refund_grant(5, "USD", CH_USD, now()), SEED))
            .await;
        assert_eq!(result_class(&v), ("ambiguous", "timeout"));
    }
    let closed = || f.closed.load(std::sync::atomic::Ordering::SeqCst);
    for _ in 0..50 {
        if closed() == N {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(closed(), N, "connections left open after the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn garbage_status_line_and_http09_are_bad_headers() {
    for r in [
        "HTTP/1.1 2OO OK\r\n\r\n",
        "{\"id\":\"re_x\"}\r\n",
        "HTTP/1.1 200 OK\r\nBad Header\r\n\r\n",
    ] {
        let v = one(r.to_string()).await;
        assert_eq!(result_class(&v), ("ambiguous", "bad_headers"), "{r:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_closed_without_response_is_ambiguous() {
    let v = run(vec![(String::new(), 0)], 3000).await;
    assert_eq!(result_class(&v), ("ambiguous", "reset_after_send"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn json_number_forms_and_depth() {
    for body in [
        ECHO_BODY.replace("{amount}", "5.0"),
        ECHO_BODY.replace("{amount}", "5e0"),
        ECHO_BODY.replace("{amount}", "-5"),
        format!(
            "{}{}",
            ECHO_BODY.trim_end_matches('}'),
            r#","x":[[[[[[[[1]]]]]]]]}"#
        ),
    ] {
        let v = one(ok_response("", &body)).await;
        assert_eq!(result_class(&v), ("ambiguous", "bad_json"), "{body}");
    }
    // Depth 8 is allowed: object(1) > x array(2..8).
    let ok = format!(
        "{}{}",
        ECHO_BODY.trim_end_matches('}'),
        r#","x":[[[[[[[1]]]]]]]}"#
    );
    assert_eq!(result_class(&one(ok_response("", &ok)).await).0, "created");
}
