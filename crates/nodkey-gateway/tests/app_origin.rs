// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! App-origin proxy: request/response filtering, cookies, Service-Worker, Host routing (SI-18,
//! ADR-0003 profile item 2). Runs with and without the `test-login` feature.

mod common;
use common::*;

#[tokio::test]
async fn request_headers_are_allowlisted_and_gateway_context_cannot_be_forged() {
    let h = start().await;
    let r = get(
        h.addr,
        APP,
        "/page?x=1",
        &[
            "Accept: text/html",
            "User-Agent: test",
            "Authorization: Bearer secret",
            "Nodkey-Grant: forged-by-client",
            "nodkey-subject: admin",
            "X-Forwarded-For: 1.2.3.4",
            "X-Forwarded-Host: auth.localhost",
            "Proxy-Authorization: x",
            "Cookie: PHPSESSID=s1; __Host-nodkey_session=sid; tracking=1; nodkey_x=1",
        ],
    )
    .await;
    assert_eq!(r.status, 200);
    let w = h.world.lock().unwrap();
    let seen = w.upstream.last().unwrap();
    assert_eq!(seen.target, "/page?x=1");
    assert_eq!(seen.header("host"), vec![APP]);
    assert_eq!(seen.header("accept"), vec!["text/html"]);
    assert_eq!(seen.header("user-agent"), vec!["test"]);
    assert_eq!(
        seen.header("cookie"),
        vec!["PHPSESSID=s1"],
        "only allowlisted app cookies"
    );
    for dropped in [
        "authorization",
        "nodkey-grant",
        "nodkey-subject",
        "x-forwarded-for",
        "x-forwarded-host",
        "proxy-authorization",
    ] {
        assert!(
            seen.header(dropped).is_empty(),
            "{dropped} must not be forwarded"
        );
    }
    // No read route and no session: the authority is never asked.
    assert!(w.authority_calls.is_empty());
}

#[tokio::test]
async fn response_headers_and_set_cookie_are_filtered() {
    let h = start().await;
    let r = get(h.addr, APP, "/headers", &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.header("set-cookie"),
        vec!["PHPSESSID=abc; Path=/; HttpOnly"]
    );
    for dropped in [
        "service-worker-allowed",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "expires",
        "x-custom",
        "nodkey-grant",
        "clear-site-data",
    ] {
        assert!(r.header(dropped).is_empty(), "{dropped} must be dropped");
    }
    assert_eq!(r.header("cache-control"), vec!["no-store"]);
    assert_eq!(r.header("x-content-type-options"), vec!["nosniff"]);
    assert_eq!(r.header("x-frame-options"), vec!["SAMEORIGIN"]);
    assert_eq!(r.header("location"), vec!["/next"]);
    let csp = r.header("content-security-policy");
    assert!(csp.contains(&"default-src 'self'"), "app CSP kept");
    assert!(
        csp.contains(&"frame-ancestors 'self'"),
        "gateway frame-ancestors added"
    );
    assert_eq!(r.text(), "hello from app");
}

#[tokio::test]
async fn service_worker_header_rejected_on_both_origins() {
    let h = start().await;
    for v in [
        "Service-Worker: script",
        "service-worker: anything",
        "SERVICE-WORKER:",
    ] {
        let r = get(h.addr, APP, "/sw.js", &[v]).await;
        assert_eq!(r.status, 400, "{v}");
        let r = get(h.addr, AUTH, "/", &[v]).await;
        assert_eq!(r.status, 404, "{v}");
        assert_eq!(r.text(), "This request is not available.");
    }
    assert!(
        h.world.lock().unwrap().upstream.is_empty(),
        "never forwarded"
    );
}

#[tokio::test]
async fn duplicate_gateway_cookies_rejected() {
    let h = start().await;
    for c in [
        "Cookie: __Host-nodkey_session=a; __Host-nodkey_session=b",
        "Cookie: __Host-nodkey_session=a; __host-NODKEY_session=b",
        "Cookie: __Host-nodkey_login=a\nCookie: __Host-nodkey_login=b",
        "Cookie: __Host-nodkey_preauth=a; __HOST-nodkey_preauth=b",
    ] {
        assert_eq!(get(h.addr, APP, "/", &[c]).await.status, 400, "{c}");
        assert_eq!(get(h.addr, AUTH, "/", &[c]).await.status, 404, "{c}");
    }
    assert!(h.world.lock().unwrap().upstream.is_empty());
}

#[tokio::test]
async fn host_routing_and_reserved_paths() {
    let h = start().await;
    assert_eq!(get(h.addr, "evil.localhost", "/", &[]).await.status, 421);
    assert_eq!(
        get(h.addr, "app.localhost:9999", "/", &[]).await.status,
        421
    );
    let r = raw(
        h.addr,
        "GET / HTTP/1.1\nHost: app.localhost\nHost: auth.localhost",
        b"",
    )
    .await;
    assert_eq!(r.status, 400, "duplicate Host");
    for p in ["/.nodkey/anything", "/.nodkey", "/.nodkey/callback"] {
        assert_eq!(get(h.addr, APP, p, &[]).await.status, 404, "{p}");
    }
    let r = get(
        h.addr,
        APP,
        "/",
        &["Upgrade: websocket", "Connection: Upgrade"],
    )
    .await;
    assert_eq!(r.status, 400);
    let r = raw(h.addr, "TRACE / HTTP/1.1\nHost: app.localhost", b"").await;
    assert_eq!(r.status, 400);
    assert!(
        h.world.lock().unwrap().upstream.is_empty(),
        "none of these forwarded"
    );
}

#[tokio::test]
async fn post_body_forwarded_and_size_capped() {
    let h = start_with(|c| c.limits.max_request_body = 16).await;
    let r = raw(
        h.addr,
        "POST /form HTTP/1.1\nHost: app.localhost\nContent-Type: text/plain",
        b"hello",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        h.world.lock().unwrap().upstream.last().unwrap().body,
        b"hello"
    );
    let r = raw(
        h.addr,
        "POST /form HTTP/1.1\nHost: app.localhost",
        &[b'a'; 17],
    )
    .await;
    assert_eq!(r.status, 413);
}

#[tokio::test]
async fn read_route_without_session_gets_no_grant() {
    let h = start().await;
    let r = get(h.addr, APP, "/orders/9821", &NAV_SAME_ORIGIN).await;
    assert_eq!(r.status, 200);
    let w = h.world.lock().unwrap();
    assert!(w.authority_calls.is_empty());
    assert!(w.upstream.last().unwrap().header("nodkey-grant").is_empty());
}

#[tokio::test]
async fn app_logout_requires_same_origin_provenance() {
    let h = start().await;
    let r = raw(h.addr, "POST /.nodkey/logout HTTP/1.1\nHost: app.localhost\nSec-Fetch-Site: cross-site\nSec-Fetch-Mode: navigate", b"").await;
    assert_eq!(r.status, 403);
    let r = raw(h.addr, "POST /.nodkey/logout HTTP/1.1\nHost: app.localhost\nSec-Fetch-Site: same-origin\nSec-Fetch-Mode: cors", b"").await;
    assert_eq!(r.status, 303);
}

#[tokio::test]
async fn duplicate_single_valued_response_header_is_bad_gateway() {
    let h = start().await;
    let r = get(h.addr, APP, "/dupct", &[]).await;
    assert_eq!(r.status, 502);
    assert!(r.header("content-type").len() <= 1);
}

#[tokio::test]
async fn transfer_encoding_with_content_length_is_not_smuggled() {
    // hyper decodes `Transfer-Encoding: chunked` and drops `Content-Length` (RFC 9112 §6.3); the
    // gateway rebuilds the upstream request with one recomputed length (GW-R-07).
    let h = start().await;
    let r = raw(
        h.addr,
        "POST /x HTTP/1.1\nHost: app.localhost\nTransfer-Encoding: chunked",
        b"5\r\nhello\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: app.localhost\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 200);
    let w = h.world.lock().unwrap();
    assert_eq!(w.upstream.len(), 1, "one request reaches the app");
    let seen = &w.upstream[0];
    assert_eq!(seen.body, b"hello");
    assert!(seen.header("transfer-encoding").is_empty());
    assert_eq!(seen.header("content-length"), vec!["5"]);
}

/// Opens a TLS connection and sends a request head announcing a body that never fully arrives.
async fn stalled_upload(
    addr: std::net::SocketAddr,
    host: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use tokio::io::AsyncWriteExt;
    let mut s = tls_connect(addr, host).await;
    s.write_all(
        format!("POST /upload HTTP/1.1\r\nHost: {host}\r\nContent-Length: 1000\r\n\r\nab")
            .as_bytes(),
    )
    .await
    .unwrap();
    s.flush().await.unwrap();
    s
}

async fn read_all(s: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    out
}

#[tokio::test]
async fn request_body_deadline() {
    let h = start_with(|c| c.limits.request_body_timeout_ms = 300).await;
    let mut s = stalled_upload(h.addr, APP).await;
    let t0 = std::time::Instant::now();
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), read_all(&mut s))
        .await
        .expect("answered before 5 s");
    assert!(t0.elapsed() < std::time::Duration::from_secs(3));
    assert_eq!(parse(&out).status, 408);
    assert!(h.world.lock().unwrap().upstream.is_empty());
}

#[tokio::test]
async fn app_origin_cannot_starve_auth_origin() {
    let h = start_with(|c| {
        c.limits.app_connections = 4;
        c.limits.auth_connections = 4;
    })
    .await;
    let mut held = Vec::new();
    for _ in 0..12 {
        held.push(stalled_upload(h.addr, APP).await);
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let r = get(h.addr, APP, "/", &[]).await;
    assert_eq!(r.status, 503, "app origin budget exhausted");
    let r = get(h.addr, AUTH, "/", &[]).await;
    assert_eq!(r.status, 200, "auth origin still served");
    drop(held);
}

#[tokio::test]
async fn response_write_deadline_drops_non_reading_client() {
    use tokio::io::AsyncWriteExt;
    let h = start_with(|c| c.limits.response_write_timeout_ms = 300).await;
    let mut s = tls_connect(h.addr, APP).await;
    s.write_all(b"GET /big HTTP/1.1\r\nHost: app.localhost\r\n\r\n")
        .await
        .unwrap();
    // Do not read until well past the deadline.
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), read_all(&mut s))
        .await
        .expect("connection closed");
    assert!(
        out.len() < BIG,
        "response cut off after the write deadline ({} bytes)",
        out.len()
    );
}
