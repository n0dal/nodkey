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
    assert!(
        w.upstream
            .last()
            .unwrap()
            .header("nodkey-grant")
            .is_empty()
    );
}

#[tokio::test]
async fn app_logout_requires_same_origin_provenance() {
    let h = start().await;
    let r = raw(h.addr, "POST /.nodkey/logout HTTP/1.1\nHost: app.localhost\nSec-Fetch-Site: cross-site\nSec-Fetch-Mode: navigate", b"").await;
    assert_eq!(r.status, 403);
    let r = raw(h.addr, "POST /.nodkey/logout HTTP/1.1\nHost: app.localhost\nSec-Fetch-Site: same-origin\nSec-Fetch-Mode: cors", b"").await;
    assert_eq!(r.status, 303);
}
