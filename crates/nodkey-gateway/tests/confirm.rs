// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Sessions, test login, confirmation page, approval token, provenance and read grants
//! (effect-protocol-v2 §7, SI-18/20/21). Needs `--features test-login`.
#![cfg(feature = "test-login")]

mod common;
use common::*;
use nodkey_gateway::config::{TestLoginConfig, TestUser};

const ALICE: usize = 0; // acme / user:u-17
const BOB: usize = 1; // acme / user:u-18
const OTHER_TENANT: usize = 2; // globex / user:u-17

async fn start_tl() -> Harness {
    start_tl_with(|_| {}).await
}

async fn start_tl_with(f: impl FnOnce(&mut nodkey_gateway::config::Config)) -> Harness {
    start_with(|c| {
        f(c);
        c.dev_local_only = true;
        c.test_login = Some(TestLoginConfig {
            enabled: true,
            users: vec![
                TestUser {
                    ten: "acme".into(),
                    sub: "user:u-17".into(),
                    label: "Alice".into(),
                },
                TestUser {
                    ten: "acme".into(),
                    sub: "user:u-18".into(),
                    label: "Bob".into(),
                },
                TestUser {
                    ten: "globex".into(),
                    sub: "user:u-17".into(),
                    label: "Other".into(),
                },
            ],
        })
    })
    .await
}

fn sess(sid: &str) -> String {
    format!("Cookie: __Host-nodkey_session={sid}")
}

async fn render(h: &Harness, sid: &str, pid: &str) -> Resp {
    get(h.addr, AUTH, &format!("/confirm/{pid}"), &[&sess(sid)]).await
}

async fn decide(h: &Harness, sid: &str, pid: &str, prov: &[&str], body: &str) -> Resp {
    let c = sess(sid);
    let mut extra: Vec<&str> = prov.to_vec();
    extra.push(&c);
    post_form(
        h.addr,
        AUTH,
        &format!("/confirm/{pid}/decision"),
        &extra,
        body,
    )
    .await
}

/// Decision body; `confirm_amount_minor` is the amount typed by the user (records here are 12.50 EUR).
fn body(tok: &str, digest: &str, d: &str) -> String {
    body_typed(tok, digest, d, "12.50")
}

fn body_typed(tok: &str, digest: &str, d: &str, typed: &str) -> String {
    format!("token={tok}&digest={digest}&decision={d}&confirm_amount_minor={typed}")
}

/// Waits out the server-side approval delay (GW-R-01).
async fn wait_delay() {
    tokio::time::sleep(std::time::Duration::from_millis(1600)).await;
}

fn approvals(h: &Harness) -> usize {
    h.world
        .lock()
        .unwrap()
        .authority_calls
        .iter()
        .filter(|c| c.op == "approve")
        .count()
}

fn uniform(r: &Resp) {
    assert_eq!(r.status, 404, "{}", r.text());
    assert_eq!(r.text(), "This request is not available.");
}

#[tokio::test]
async fn test_login_banner_and_session_cookie() {
    let h = start_tl().await;
    let page = get(h.addr, AUTH, "/login", &[]).await;
    assert!(
        page.text().contains("TEST LOGIN"),
        "banner on the login page"
    );
    let sid = login(h.addr, ALICE).await;
    assert_eq!(sid.len(), 43);
    let home = get(h.addr, AUTH, "/", &[&sess(&sid)]).await;
    assert!(home.text().contains("TEST LOGIN") && home.text().contains("user:u-17"));
    // The login state is single-use: the first POST succeeds, a replay of it fails.
    let pre = page.cookie("__Host-nodkey_preauth").unwrap();
    let csrf = form_value(&page.text(), "csrf").unwrap();
    let ck = format!("Cookie: __Host-nodkey_preauth={pre}");
    let extra = [NAV_SAME_ORIGIN[0], NAV_SAME_ORIGIN[1], ck.as_str()];
    let form = format!("user=0&csrf={csrf}");
    assert_eq!(
        post_form(h.addr, AUTH, "/login", &extra, &form)
            .await
            .status,
        303
    );
    let r = post_form(h.addr, AUTH, "/login", &extra, &form).await;
    uniform(&r);
}

#[tokio::test]
async fn login_requires_csrf_and_provenance_and_mints_fresh_ids() {
    let h = start_tl().await;
    let page = get(h.addr, AUTH, "/login", &[]).await;
    let pre = page.cookie("__Host-nodkey_preauth").unwrap();
    let csrf = form_value(&page.text(), "csrf").unwrap();
    let ck = format!("Cookie: __Host-nodkey_preauth={pre}");
    // Cross-site login POST (login CSRF) is rejected and does not burn the state.
    let r = post_form(
        h.addr,
        AUTH,
        "/login",
        &["Sec-Fetch-Site: same-site", "Sec-Fetch-Mode: navigate", &ck],
        &format!("user=0&csrf={csrf}"),
    )
    .await;
    uniform(&r);
    let r = post_form(
        h.addr,
        AUTH,
        "/login",
        &[NAV_SAME_ORIGIN[0], NAV_SAME_ORIGIN[1], &ck],
        "user=0&csrf=wrong",
    )
    .await;
    uniform(&r);
    // Fresh id per login; the old id presented at login is revoked.
    let a = login(h.addr, ALICE).await;
    let page = get(h.addr, AUTH, "/login", &[]).await;
    let pre = page.cookie("__Host-nodkey_preauth").unwrap();
    let csrf = form_value(&page.text(), "csrf").unwrap();
    let r = post_form(
        h.addr,
        AUTH,
        "/login",
        &[
            NAV_SAME_ORIGIN[0],
            NAV_SAME_ORIGIN[1],
            &format!("Cookie: __Host-nodkey_preauth={pre}; __Host-nodkey_session={a}"),
        ],
        &format!("user=0&csrf={csrf}"),
    )
    .await;
    let b = r.cookie("__Host-nodkey_session").unwrap();
    assert_ne!(a, b);
    let c = r
        .header("set-cookie")
        .into_iter()
        .find(|c| c.starts_with("__Host-nodkey_session="))
        .unwrap()
        .to_owned();
    for attr in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=43200",
    ] {
        assert!(c.contains(attr), "{attr} in {c}");
    }
    assert!(
        get(h.addr, AUTH, "/", &[&sess(&a)])
            .await
            .text()
            .contains("Not signed in")
    );
    assert!(
        get(h.addr, AUTH, "/", &[&sess(&b)])
            .await
            .text()
            .contains("Signed in")
    );
}

#[tokio::test]
async fn approver_sees_page_others_get_identical_404() {
    let h = start_tl().await;
    let pid = new_pid();
    add_record(&h.world, refund_record(&pid, "user:u-17", 1250), "PENDING");
    let alice = login(h.addr, ALICE).await;
    let bob = login(h.addr, BOB).await;
    let other = login(h.addr, OTHER_TENANT).await;

    let ok = render(&h, &alice, &pid).await;
    assert_eq!(ok.status, 200);
    let t = ok.text();
    assert!(t.contains("12.50 EUR (1250 minor units)"));
    assert!(t.contains(&pid));
    assert!(t.contains("Approve only if you just asked Demo Shop to do this."));
    assert!(t.contains("Captured amount"));
    assert!(t.contains("TEST LOGIN"));
    assert!(!t.contains("<script"));
    assert_eq!(form_value(&t, "token").unwrap().len(), 43);

    // T01/T10: non-approver (same and other tenant), unknown pid -> byte-identical.
    let a = render(&h, &bob, &pid).await;
    let b = render(&h, &other, &pid).await;
    let c = render(&h, &alice, &new_pid()).await;
    uniform(&a);
    assert_eq!(a.without_date(), b.without_date());
    assert_eq!(a.without_date(), c.without_date());
}

#[tokio::test]
async fn approve_once_token_single_use_and_bound() {
    let h = start_tl().await;
    let pid = new_pid();
    let digest = add_record(&h.world, refund_record(&pid, "user:u-17", 1250), "PENDING");
    let pid2 = new_pid();
    add_record(&h.world, refund_record(&pid2, "user:u-17", 99), "PENDING");
    let alice = login(h.addr, ALICE).await;
    let alice2 = login(h.addr, ALICE).await; // a second session of the same user

    // Token from another session (T07) — and the token is consumed by that presentation.
    let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    uniform(
        &decide(
            &h,
            &alice2,
            &pid,
            &NAV_SAME_ORIGIN,
            &body(&tok, &digest, "approve"),
        )
        .await,
    );
    uniform(
        &decide(
            &h,
            &alice,
            &pid,
            &NAV_SAME_ORIGIN,
            &body(&tok, &digest, "approve"),
        )
        .await,
    );

    // Token for another pid (T07).
    let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    let d2 = digest_of(&h.world.lock().unwrap().records[&pid2].record);
    uniform(
        &decide(
            &h,
            &alice,
            &pid2,
            &NAV_SAME_ORIGIN,
            &body(&tok, &d2, "approve"),
        )
        .await,
    );

    // Digest mismatch (T08).
    let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    uniform(
        &decide(
            &h,
            &alice,
            &pid,
            &NAV_SAME_ORIGIN,
            &body(&tok, &d2, "approve"),
        )
        .await,
    );
    // Uppercase hex digest is rejected (T37).
    let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    uniform(
        &decide(
            &h,
            &alice,
            &pid,
            &NAV_SAME_ORIGIN,
            &body(&tok, &digest.to_uppercase(), "approve"),
        )
        .await,
    );
    // Re-render invalidates the previous token.
    let old = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    uniform(
        &decide(
            &h,
            &alice,
            &pid,
            &NAV_SAME_ORIGIN,
            &body(&old, &digest, "approve"),
        )
        .await,
    );
    assert_eq!(approvals(&h), 0, "no approval reached the authority");

    // Valid approval (after the activation delay).
    wait_delay().await;
    let r = decide(
        &h,
        &alice,
        &pid,
        &NAV_SAME_ORIGIN,
        &body(&tok, &digest, "approve"),
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(r.text().contains("Your decision has been submitted."));
    assert!(r.text().contains("approved"));
    {
        let w = h.world.lock().unwrap();
        let call = w
            .authority_calls
            .iter()
            .find(|c| c.op == "approve")
            .unwrap();
        assert_eq!(call.args["pending_id"], pid.as_str());
        assert_eq!(call.args["digest_shown"], digest.as_str());
        assert_eq!(call.args["subject"]["ten"], "acme");
        assert_eq!(call.args["subject"]["sub"], "user:u-17");
    }
    // Replay of the same token: never succeeds twice.
    uniform(
        &decide(
            &h,
            &alice,
            &pid,
            &NAV_SAME_ORIGIN,
            &body(&tok, &digest, "approve"),
        )
        .await,
    );
    assert_eq!(approvals(&h), 1);
    // Decided record: shown without a form.
    let t = render(&h, &alice, &pid).await.text();
    assert!(t.contains("no longer waiting") && form_value(&t, "token").is_none());
}

#[tokio::test]
async fn provenance_rules_t04_t06_t44() {
    let h = start_tl().await;
    let pid = new_pid();
    let digest = add_record(&h.world, refund_record(&pid, "user:u-17", 1250), "PENDING");
    let alice = login(h.addr, ALICE).await;
    let bad: &[&[&str]] = &[
        // T04 app-origin fetch with credentials (same-site).
        &[
            "Sec-Fetch-Site: same-site",
            "Sec-Fetch-Mode: cors",
            "Origin: https://app.localhost",
        ],
        // T05 app-origin form POST.
        &[
            "Sec-Fetch-Site: same-site",
            "Sec-Fetch-Mode: navigate",
            "Origin: https://app.localhost",
        ],
        &["Sec-Fetch-Site: cross-site", "Sec-Fetch-Mode: navigate"],
        &["Sec-Fetch-Site: none", "Sec-Fetch-Mode: navigate"],
        // T44 same-origin but not a navigation.
        &["Sec-Fetch-Site: same-origin", "Sec-Fetch-Mode: cors"],
        &["Sec-Fetch-Site: same-origin"],
        // Fetch metadata present but wrong, even with the right Origin.
        &[
            "Sec-Fetch-Site: same-site",
            "Sec-Fetch-Mode: navigate",
            "Origin: https://auth.localhost",
        ],
        // T06 no metadata: no Origin, Origin null, Origin = app origin.
        &[],
        &["Origin: null"],
        &["Origin: https://app.localhost"],
        &["Origin: https://auth.localhost.evil"],
    ];
    for prov in bad {
        let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
        uniform(&decide(&h, &alice, &pid, prov, &body(&tok, &digest, "approve")).await);
    }
    assert_eq!(approvals(&h), 0);
    // Fallback: no Fetch Metadata, exact auth Origin.
    let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    wait_delay().await;
    let r = decide(
        &h,
        &alice,
        &pid,
        &["Origin: https://auth.localhost"],
        &body(&tok, &digest, "approve"),
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(approvals(&h), 1);
}

#[tokio::test]
async fn form_must_be_exact() {
    let h = start_tl().await;
    let pid = new_pid();
    let digest = add_record(&h.world, refund_record(&pid, "user:u-17", 1250), "PENDING");
    let alice = login(h.addr, ALICE).await;
    let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    for b in [
        format!("token={tok}&digest={digest}"),
        format!("token={tok}&digest={digest}&decision=approve&extra=1"),
        format!("token={tok}&token={tok}&digest={digest}&decision=approve"),
        format!("token={tok}&digest={digest}&decision=maybe"),
    ] {
        uniform(&decide(&h, &alice, &pid, &NAV_SAME_ORIGIN, &b).await);
    }
    // Wrong content type.
    let r = raw(
        h.addr,
        &format!("POST /confirm/{pid}/decision HTTP/1.1\nHost: auth.localhost\nContent-Type: text/plain\nSec-Fetch-Site: same-origin\nSec-Fetch-Mode: navigate\n{}", sess(&alice)),
        body(&tok, &digest, "approve").as_bytes(),
    )
    .await;
    uniform(&r);
    assert_eq!(approvals(&h), 0);
}

#[tokio::test]
async fn deny_goes_to_broker() {
    let h = start_tl().await;
    let pid = new_pid();
    let digest = add_record(&h.world, refund_record(&pid, "user:u-17", 1250), "PENDING");
    let alice = login(h.addr, ALICE).await;
    let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    let r = decide(
        &h,
        &alice,
        &pid,
        &NAV_SAME_ORIGIN,
        &body(&tok, &digest, "deny"),
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(r.text().contains("denied"));
    let w = h.world.lock().unwrap();
    assert!(
        w.broker_calls
            .iter()
            .any(|c| c.op == "pending.deny" && c.args["digest"] == digest.as_str())
    );
    assert!(w.authority_calls.is_empty());
}

#[tokio::test]
async fn broker_digest_mismatch_or_foreign_record_gives_uniform_error() {
    let h = start_tl().await;
    let alice = login(h.addr, ALICE).await;
    // Broker reports a digest that is not the digest of the values it returns.
    let pid = new_pid();
    add_record(&h.world, refund_record(&pid, "user:u-17", 1250), "PENDING");
    h.world
        .lock()
        .unwrap()
        .records
        .get_mut(&pid)
        .unwrap()
        .lie_digest = Some("00".repeat(32));
    uniform(&render(&h, &alice, &pid).await);
    // Escaping: hostile display name and free text are escaped.
    let pid = new_pid();
    add_record(&h.world, refund_record(&pid, "user:u-17", 1), "PENDING");
    h.world
        .lock()
        .unwrap()
        .records
        .get_mut(&pid)
        .unwrap()
        .display_name = "<script>alert(1)</script>".into();
    let t = render(&h, &alice, &pid).await.text();
    assert!(!t.contains("<script>") && t.contains("&lt;script&gt;"));
}

#[tokio::test]
async fn login_returns_only_to_stored_confirm_path_and_logout_revokes() {
    let h = start_tl().await;
    let pid = new_pid();
    add_record(&h.world, refund_record(&pid, "user:u-17", 1250), "PENDING");
    let r = get(h.addr, AUTH, &format!("/confirm/{pid}"), &[]).await;
    let (ck, csrf) = login_form_with_return(h.addr, &r).await;
    let r = post_form(
        h.addr,
        AUTH,
        "/login",
        &[NAV_SAME_ORIGIN[0], NAV_SAME_ORIGIN[1], &ck],
        &format!("user=0&csrf={csrf}&return=https://evil"),
    )
    .await;
    uniform(&r); // extra field: crafted return target is not accepted (T44)
    let r = get(h.addr, AUTH, &format!("/confirm/{pid}"), &[]).await;
    let (ck, csrf) = login_form_with_return(h.addr, &r).await;
    let r = post_form(
        h.addr,
        AUTH,
        "/login",
        &[NAV_SAME_ORIGIN[0], NAV_SAME_ORIGIN[1], &ck],
        &format!("user=0&csrf={csrf}"),
    )
    .await;
    assert_eq!(r.header("location"), vec![format!("/confirm/{pid}")]);
    let sid = r.cookie("__Host-nodkey_session").unwrap();
    assert_eq!(render(&h, &sid, &pid).await.status, 200);

    // Logout needs auth-origin provenance; then the session is gone.
    let r = post_form(
        h.addr,
        AUTH,
        "/logout",
        &[
            "Sec-Fetch-Site: same-site",
            "Sec-Fetch-Mode: navigate",
            &sess(&sid),
        ],
        "",
    )
    .await;
    uniform(&r);
    let r = post_form(
        h.addr,
        AUTH,
        "/logout",
        &[NAV_SAME_ORIGIN[0], NAV_SAME_ORIGIN[1], &sess(&sid)],
        "",
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(r.header("set-cookie")[0].contains("Max-Age=0"));
    assert_eq!(render(&h, &sid, &pid).await.status, 303, "back to login");
}

/// Follows a redirect-to-login response: renders the login form with its return cookie and returns
/// the preauth `Cookie:` header line and the CSRF token.
async fn login_form_with_return(addr: std::net::SocketAddr, r: &Resp) -> (String, String) {
    assert_eq!(r.header("location"), vec!["/login"]);
    let rc = r.cookie("__Host-nodkey_return").expect("return cookie");
    let page = get(
        addr,
        AUTH,
        "/login",
        &[&format!("Cookie: __Host-nodkey_return={rc}")],
    )
    .await;
    let pre = page.cookie("__Host-nodkey_preauth").unwrap();
    let csrf = form_value(&page.text(), "csrf").unwrap();
    (format!("Cookie: __Host-nodkey_preauth={pre}"), csrf)
}

/// App-session hand-off and read-grant delivery.
async fn app_login(h: &Harness, idx: usize) -> String {
    let r = get(h.addr, APP, "/.nodkey/login", &[]).await;
    assert_eq!(r.status, 303);
    let state = r.cookie("__Host-nodkey_login").unwrap();
    let loc = r.header("location")[0].to_owned();
    let path = loc.strip_prefix(AUTH_ORIGIN).unwrap();
    assert!(path.starts_with("/login/app?h="));
    let r = get(h.addr, AUTH, path, &[]).await;
    let (ck, csrf) = login_form_with_return(h.addr, &r).await;
    let r = post_form(
        h.addr,
        AUTH,
        "/login",
        &[NAV_SAME_ORIGIN[0], NAV_SAME_ORIGIN[1], &ck],
        &format!("user={idx}&csrf={csrf}"),
    )
    .await;
    let loc = r.header("location")[0].to_owned();
    let cb = loc.strip_prefix(APP_ORIGIN).unwrap().to_owned();
    assert!(cb.starts_with("/.nodkey/callback?code="));
    // Without the login-state cookie the code is refused (and consumed).
    let bad = get(h.addr, APP, &cb, &[]).await;
    assert_eq!(bad.status, 404);
    // Fresh hand-off with the cookie.
    let r = get(h.addr, APP, "/.nodkey/login", &[]).await;
    let state2 = r.cookie("__Host-nodkey_login").unwrap();
    assert_ne!(state, state2);
    let path = r.header("location")[0]
        .strip_prefix(AUTH_ORIGIN)
        .unwrap()
        .to_owned();
    let r = get(h.addr, AUTH, &path, &[]).await;
    let (ck, csrf) = login_form_with_return(h.addr, &r).await;
    let r = post_form(
        h.addr,
        AUTH,
        "/login",
        &[NAV_SAME_ORIGIN[0], NAV_SAME_ORIGIN[1], &ck],
        &format!("user={idx}&csrf={csrf}"),
    )
    .await;
    let cb = r.header("location")[0]
        .strip_prefix(APP_ORIGIN)
        .unwrap()
        .to_owned();
    let r = get(
        h.addr,
        APP,
        &cb,
        &[&format!("Cookie: __Host-nodkey_login={state2}")],
    )
    .await;
    assert_eq!(r.status, 303);
    let sid = r.cookie("__Host-nodkey_session").unwrap();
    // Code replay fails.
    let again = get(
        h.addr,
        APP,
        &cb,
        &[&format!("Cookie: __Host-nodkey_login={state2}")],
    )
    .await;
    assert_eq!(again.status, 404);
    sid
}

#[tokio::test]
async fn read_grant_delivery_and_provenance() {
    let h = start_tl().await;
    let sid = app_login(&h, ALICE).await;
    let ck = sess(&sid);
    // Top-level navigation (cross-site) and same-origin: grant attached as Nodkey-Grant.
    for prov in [
        vec![
            "Sec-Fetch-Site: cross-site",
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-Dest: document",
        ],
        vec![
            "Sec-Fetch-Site: same-origin",
            "Sec-Fetch-Mode: cors",
            "Sec-Fetch-Dest: empty",
        ],
    ] {
        let mut extra = prov.clone();
        extra.push(&ck);
        extra.push("Nodkey-Grant: forged");
        assert_eq!(get(h.addr, APP, "/orders/9821", &extra).await.status, 200);
        let w = h.world.lock().unwrap();
        let seen = w.upstream.last().unwrap();
        assert_eq!(seen.header("nodkey-grant"), vec![FAKE_GRANT], "{prov:?}");
        assert!(
            seen.header("cookie").is_empty(),
            "session cookie never forwarded"
        );
        let call = w.authority_calls.last().unwrap();
        assert_eq!(call.op, "read_grant");
        assert_eq!(call.args["wid"], WID);
        assert_eq!(call.args["rop"][0], "payments.get_order");
        assert_eq!(call.args["subject"]["sub"], "user:u-17");
    }
    let before = h.world.lock().unwrap().authority_calls.len();
    // Not qualifying: cross-site subresource / iframe / no metadata / non-read route.
    for (path, prov) in [
        (
            "/orders/9821",
            vec![
                "Sec-Fetch-Site: cross-site",
                "Sec-Fetch-Mode: no-cors",
                "Sec-Fetch-Dest: image",
            ],
        ),
        (
            "/orders/9821",
            vec![
                "Sec-Fetch-Site: cross-site",
                "Sec-Fetch-Mode: navigate",
                "Sec-Fetch-Dest: iframe",
            ],
        ),
        (
            "/orders/9821",
            vec![
                "Sec-Fetch-Site: same-site",
                "Sec-Fetch-Mode: cors",
                "Sec-Fetch-Dest: empty",
            ],
        ),
        ("/orders/9821", vec![]),
        ("/orders/../admin", NAV_SAME_ORIGIN.to_vec()),
        ("/orders/%2e%2e/admin", NAV_SAME_ORIGIN.to_vec()),
        ("/orders//x", NAV_SAME_ORIGIN.to_vec()),
        ("/other", NAV_SAME_ORIGIN.to_vec()),
    ] {
        let mut extra = prov.clone();
        extra.push(&ck);
        assert_eq!(get(h.addr, APP, path, &extra).await.status, 200);
        let w = h.world.lock().unwrap();
        assert!(
            w.upstream.last().unwrap().header("nodkey-grant").is_empty(),
            "{path} {prov:?}"
        );
    }
    assert_eq!(h.world.lock().unwrap().authority_calls.len(), before);
    // An app session is not an auth session (and vice versa).
    assert!(
        get(h.addr, AUTH, "/", &[&ck])
            .await
            .text()
            .contains("Not signed in")
    );
    let auth_sid = login(h.addr, ALICE).await;
    let mut extra = NAV_SAME_ORIGIN.to_vec();
    let c2 = sess(&auth_sid);
    extra.push(&c2);
    get(h.addr, APP, "/orders/1", &extra).await;
    assert!(
        h.world
            .lock()
            .unwrap()
            .upstream
            .last()
            .unwrap()
            .header("nodkey-grant")
            .is_empty()
    );
}

#[tokio::test]
async fn approval_controls_delayed_and_early_post_rejected() {
    let h = start_tl().await;
    let pid = new_pid();
    let digest = add_record(&h.world, refund_record(&pid, "user:u-17", 1250), "PENDING");
    let alice = login(h.addr, ALICE).await;
    let page = render(&h, &alice, &pid).await.text();
    assert!(
        page.contains("class=\"buttons delayed\""),
        "CSS activation delay on the buttons"
    );
    let css = get(h.addr, AUTH, "/static/nodkey.css", &[]).await.text();
    assert!(css.contains("animation: nodkey-reveal 0s 1.5s both"));
    assert!(css.contains("visibility: hidden; pointer-events: none"));
    assert!(
        page.find("value=\"deny\"").unwrap() < page.find("value=\"approve\"").unwrap(),
        "Deny first"
    );
    // An approve POST right after the render (a hijacked double-click) is rejected, and the token is
    // gone.
    let tok = form_value(&page, "token").unwrap();
    uniform(
        &decide(
            &h,
            &alice,
            &pid,
            &NAV_SAME_ORIGIN,
            &body(&tok, &digest, "approve"),
        )
        .await,
    );
    wait_delay().await;
    uniform(
        &decide(
            &h,
            &alice,
            &pid,
            &NAV_SAME_ORIGIN,
            &body(&tok, &digest, "approve"),
        )
        .await,
    );
    assert_eq!(approvals(&h), 0);
    // Deny is not delayed.
    let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    let r = decide(
        &h,
        &alice,
        &pid,
        &NAV_SAME_ORIGIN,
        &body_typed(&tok, &digest, "deny", ""),
    )
    .await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn typed_amount_must_match() {
    let h = start_tl().await;
    let pid = new_pid();
    let digest = add_record(&h.world, refund_record(&pid, "user:u-17", 1250), "PENDING");
    let alice = login(h.addr, ALICE).await;
    let page = render(&h, &alice, &pid).await.text();
    assert!(page.contains("name=\"confirm_amount_minor\""));
    let tok = form_value(&page, "token").unwrap();
    wait_delay().await;
    for wrong in ["", "1250", "12.5", "12,50", "12.50 EUR", "13.50"] {
        let r = decide(
            &h,
            &alice,
            &pid,
            &NAV_SAME_ORIGIN,
            &body_typed(&tok, &digest, "approve", wrong),
        )
        .await;
        assert_eq!(r.status, 200, "{wrong:?}");
        let t = r.text();
        assert!(t.contains("does not match the amount shown"), "{wrong:?}");
        assert_eq!(
            form_value(&t, "token").as_deref(),
            Some(tok.as_str()),
            "token kept"
        );
    }
    // Missing field entirely: uniform error (the form shape is wrong) and the token is consumed.
    let tok2 = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    wait_delay().await;
    let r = decide(
        &h,
        &alice,
        &pid,
        &NAV_SAME_ORIGIN,
        &format!("token={tok2}&digest={digest}&decision=approve"),
    )
    .await;
    uniform(&r);
    assert_eq!(approvals(&h), 0);
    // Correct amount (surrounding spaces ignored).
    let tok3 = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    wait_delay().await;
    let r = decide(
        &h,
        &alice,
        &pid,
        &NAV_SAME_ORIGIN,
        &body_typed(&tok3, &digest, "approve", "+12.50+"),
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(r.text().contains("Your decision has been submitted."));
    assert_eq!(approvals(&h), 1);
}

#[tokio::test]
async fn login_state_flood_cannot_block_login() {
    let h = start_tl_with(|c| c.limits.max_store_entries = 16).await;
    // Cookie-less GET /confirm creates no server-side state.
    for _ in 0..2000 {
        let r = get(h.addr, AUTH, &format!("/confirm/{}", new_pid()), &[]).await;
        assert_eq!(r.status, 303);
    }
    // Rendering the login form many times only evicts this client's oldest states.
    for _ in 0..200 {
        assert_eq!(get(h.addr, AUTH, "/login", &[]).await.status, 200);
    }
    let _ = login(h.addr, ALICE).await;
}

#[tokio::test]
async fn app_origin_subresource_cannot_reset_token() {
    let h = start_tl().await;
    let pid = new_pid();
    let digest = add_record(&h.world, refund_record(&pid, "user:u-17", 1250), "PENDING");
    let alice = login(h.addr, ALICE).await;
    let tok = form_value(&render(&h, &alice, &pid).await.text(), "token").unwrap();
    // A no-cors fetch from the app origin to the confirm page is not rendered.
    let c = sess(&alice);
    let r = get(
        h.addr,
        AUTH,
        &format!("/confirm/{pid}"),
        &[
            "Sec-Fetch-Site: same-site",
            "Sec-Fetch-Mode: no-cors",
            "Sec-Fetch-Dest: image",
            &c,
        ],
    )
    .await;
    uniform(&r);
    wait_delay().await;
    let r = decide(
        &h,
        &alice,
        &pid,
        &NAV_SAME_ORIGIN,
        &body(&tok, &digest, "approve"),
    )
    .await;
    assert_eq!(r.status, 200, "the open form's token is still valid");
    assert_eq!(approvals(&h), 1);
}
