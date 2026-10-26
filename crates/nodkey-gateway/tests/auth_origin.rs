//! Auth-origin behaviour that needs no login (runs with and without `test-login`).

mod common;
use common::*;

fn assert_hardened(r: &Resp) {
    assert_eq!(
        r.header("content-security-policy"),
        vec![
            "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        ]
    );
    assert_eq!(r.header("cross-origin-opener-policy"), vec!["same-origin"]);
    assert_eq!(
        r.header("cross-origin-resource-policy"),
        vec!["same-origin"]
    );
    assert_eq!(r.header("x-frame-options"), vec!["DENY"]);
    assert_eq!(r.header("cache-control"), vec!["no-store"]);
    assert_eq!(r.header("referrer-policy"), vec!["no-referrer"]);
    assert_eq!(r.header("x-content-type-options"), vec!["nosniff"]);
}

#[tokio::test]
async fn uniform_error_is_identical_and_hardened() {
    let h = start().await;
    let pid = new_pid();
    let cases = [
        get(h.addr, AUTH, "/nope", &[]).await,
        get(h.addr, AUTH, "/confirm/short", &[]).await,
        get(h.addr, AUTH, "/confirm/-xEiM0RVZneImaq7zN3u_x", &[]).await, // non-canonical alias
        get(h.addr, AUTH, &format!("/confirm/{pid}?x=1"), &[]).await,    // T14 query
        get(h.addr, AUTH, &format!("/confirm/{pid}?"), &[]).await,
        get(h.addr, AUTH, &format!("/confirm/{pid}/extra"), &[]).await, // T14 path suffix
        post_form(
            h.addr,
            AUTH,
            &format!("/confirm/{pid}/decision"),
            &[],
            "token=a&digest=b&decision=approve",
        )
        .await,
    ];
    let first = cases[0].without_date();
    assert_eq!(cases[0].status, 404);
    assert_eq!(cases[0].text(), "This request is not available.");
    for c in &cases {
        assert_eq!(c.without_date(), first, "byte-identical uniform error");
        assert_hardened(c);
    }
    assert!(h.world.lock().unwrap().broker_calls.is_empty());
}

#[tokio::test]
async fn confirm_without_session_redirects_to_login_with_server_side_return() {
    let h = start().await;
    let pid = new_pid();
    let r = get(h.addr, AUTH, &format!("/confirm/{pid}"), &[]).await;
    assert_eq!(r.status, 303);
    assert_eq!(
        r.header("location"),
        vec!["/login"],
        "no return parameter in the URL"
    );
    let c = r.header("set-cookie");
    assert_eq!(c.len(), 1);
    assert!(
        c[0].starts_with(&format!("__Host-nodkey_return=c.{pid}")),
        "return target in a cookie, no server state"
    );
    for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
        assert!(c[0].contains(attr), "{attr}");
    }
    assert!(!c[0].contains("Domain"));
    assert_hardened(&r);
    assert!(
        h.world.lock().unwrap().broker_calls.is_empty(),
        "nothing rendered without a session"
    );
}

#[tokio::test]
async fn static_css_served_with_hardening() {
    let h = start().await;
    let r = get(h.addr, AUTH, "/static/nodkey.css", &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), vec!["text/css; charset=utf-8"]);
    assert_hardened(&r);
}
