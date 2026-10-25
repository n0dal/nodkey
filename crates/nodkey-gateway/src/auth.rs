//! Auth origin: login (test login only, behind the `test-login` feature and a config flag), logout,
//! and the confirmation page contract of effect-protocol-v2 §7.

use hyper::{Method, StatusCode};

use crate::config::{PREAUTH_COOKIE, SESSION_COOKIE};
use crate::digest::{self, CheckedRecord};
use crate::html;
use crate::http::{self, Resp};
use crate::ipc::{self, Render, Subject};
use crate::server::{Gateway, Req};
use crate::store::{Return, Session, SessionOrigin};
use crate::util::{ct_eq, decode_pending_id, hex_lower, now_secs, parse_digest_hex};

/// The §7.4 headers, set on every auth-origin response.
fn harden(mut r: Resp) -> Resp {
    http::set(
        &mut r,
        "content-security-policy",
        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    http::set(&mut r, "cross-origin-opener-policy", "same-origin");
    http::set(&mut r, "cross-origin-resource-policy", "same-origin");
    http::set(&mut r, "x-frame-options", "DENY");
    http::set(&mut r, "cache-control", "no-store");
    http::set(&mut r, "referrer-policy", "no-referrer");
    http::set(&mut r, "x-content-type-options", "nosniff");
    r
}

/// The uniform error (§7.5): one status, body and header set for every cause.
pub fn uniform_error() -> Resp {
    harden(http::resp(
        StatusCode::NOT_FOUND,
        "text/plain; charset=utf-8",
        html::UNIFORM_ERROR,
    ))
}

fn html_page(gw: &Gateway, status: StatusCode, title: &str, body: &str) -> Resp {
    harden(http::resp(
        status,
        "text/html; charset=utf-8",
        html::page(title, body, gw.cfg.test_login_active),
    ))
}

fn session(gw: &Gateway, req: &Req) -> Option<(String, Session)> {
    let sid = http::gateway_cookie(&req.cookies, SESSION_COOKIE)
        .ok()
        .flatten()?;
    let s = gw.store()?.session(sid, SessionOrigin::Auth, now_secs())?;
    Some((sid.to_owned(), s))
}

pub async fn handle(gw: &Gateway, req: Req) -> Resp {
    let path = req.path.clone();
    match (&req.method, path.as_str()) {
        (&Method::GET, "/") if req.query.is_none() => home(gw, &req),
        (&Method::GET, "/static/nodkey.css") if req.query.is_none() => harden(http::resp(
            StatusCode::OK,
            "text/css; charset=utf-8",
            html::CSS,
        )),
        (&Method::GET, "/login") if req.query.is_none() => login_page(gw, &req),
        (&Method::GET, "/login/app") => login_app(gw, &req),
        (&Method::POST, "/login") if req.query.is_none() => login_submit(gw, &req),
        (&Method::POST, "/logout") if req.query.is_none() => logout(gw, &req),
        _ => {
            if let Some(rest) = path.strip_prefix("/confirm/") {
                if let Some(pid) = rest.strip_suffix("/decision") {
                    if req.method == Method::POST {
                        return decision(gw, &req, pid).await;
                    }
                } else if req.method == Method::GET {
                    return confirm(gw, &req, rest).await;
                }
            }
            uniform_error()
        }
    }
}

fn home(gw: &Gateway, req: &Req) -> Resp {
    let body = match session(gw, req) {
        Some((_, s)) => format!(
            "<h1>Signed in</h1><p>You are signed in as <code>{}</code> in <code>{}</code>.</p>\
             <form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>",
            crate::util::esc(&s.sub),
            crate::util::esc(&s.ten)
        ),
        None => "<h1>Not signed in</h1><p><a href=\"/login\">Sign in</a></p>".to_owned(),
    };
    html_page(gw, StatusCode::OK, "Account", &body)
}

/// `GET /login/app?h=<64 hex>`: the app origin asks for an app session. A user ceremony on this
/// origin is always required (no silent re-issue, ADR-0003 §2).
fn login_app(gw: &Gateway, req: &Req) -> Resp {
    let Some(h) = req
        .query
        .as_deref()
        .and_then(|q| q.strip_prefix("h="))
        .and_then(parse_digest_hex)
    else {
        return uniform_error();
    };
    let Some(Ok((pid, _))) = gw
        .store()
        .map(|mut s| s.create_preauth(Return::AppHandoff(h), now_secs()))
    else {
        return uniform_error();
    };
    let mut r = http::redirect("/login");
    http::gateway_set_cookie(&mut r, PREAUTH_COOKIE, &pid, crate::store::PREAUTH_TTL);
    harden(r)
}

#[cfg(not(feature = "test-login"))]
fn login_page(gw: &Gateway, _req: &Req) -> Resp {
    html_page(
        gw,
        StatusCode::SERVICE_UNAVAILABLE,
        "No login",
        "<h1>No login method</h1><p>This gateway build has no login method: it was compiled without \
         the <code>test-login</code> feature, and passkey or OIDC login is not implemented yet.</p>",
    )
}

#[cfg(not(feature = "test-login"))]
fn login_submit(_gw: &Gateway, _req: &Req) -> Resp {
    uniform_error()
}

#[cfg(feature = "test-login")]
fn login_page(gw: &Gateway, req: &Req) -> Resp {
    use crate::util::esc;
    if !gw.cfg.test_login_active {
        return html_page(
            gw,
            StatusCode::SERVICE_UNAVAILABLE,
            "No login",
            "<h1>No login method</h1><p>The test login is compiled in but disabled by configuration, \
             and no other login method exists.</p>",
        );
    }
    let now = now_secs();
    let Some(mut store) = gw.store() else {
        return uniform_error();
    };
    let existing = http::gateway_cookie(&req.cookies, PREAUTH_COOKIE)
        .ok()
        .flatten()
        .and_then(|id| store.preauth(id, now).map(|p| (id.to_owned(), p.csrf)));
    let (pid, csrf, fresh) = match existing {
        Some((id, csrf)) => (id, csrf, false),
        None => match store.create_preauth(Return::Home, now) {
            Ok((id, csrf)) => (id, csrf, true),
            Err(_) => return uniform_error(),
        },
    };
    drop(store);
    let users = gw
        .cfg
        .cfg
        .test_login
        .as_ref()
        .map(|t| t.users.as_slice())
        .unwrap_or(&[]);
    let mut b = String::from(
        "<h1>Test login</h1><p>Choose a test user. No credential is checked: this login exists only \
         for local development.</p><form method=\"post\" action=\"/login\"><fieldset><legend>Test user</legend>",
    );
    for (i, u) in users.iter().enumerate() {
        b.push_str(&format!(
            "<label><input type=\"radio\" name=\"user\" value=\"{i}\"{chk}> {} (<code>{}</code> in <code>{}</code>)</label>",
            esc(&u.label),
            esc(&u.sub),
            esc(&u.ten),
            chk = if i == 0 { " checked" } else { "" }
        ));
    }
    b.push_str(&format!(
        "</fieldset><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <div class=\"buttons\"><button type=\"submit\" class=\"approve\">Sign in</button></div></form>",
        esc(&csrf)
    ));
    let mut r = html_page(gw, StatusCode::OK, "Test login", &b);
    if fresh {
        http::gateway_set_cookie(&mut r, PREAUTH_COOKIE, &pid, crate::store::PREAUTH_TTL);
    }
    r
}

/// Strict `application/x-www-form-urlencoded` body with exactly the given field names, each once.
fn form_fields(req: &Req, names: &[&str]) -> Option<Vec<String>> {
    let ct = http::single(&req.headers, "content-type").ok()??;
    if !ct.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return None;
    }
    std::str::from_utf8(&req.body).ok()?;
    let mut out: Vec<Option<String>> = vec![None; names.len()];
    let mut count = 0usize;
    for (k, v) in form_urlencoded::parse(&req.body) {
        count += 1;
        let i = names.iter().position(|n| *n == k)?;
        if out[i].is_some() {
            return None;
        }
        out[i] = Some(v.into_owned());
    }
    if count != names.len() {
        return None;
    }
    out.into_iter().collect()
}

#[cfg(feature = "test-login")]
fn login_submit(gw: &Gateway, req: &Req) -> Resp {
    use crate::store::{Code, Store};
    if !gw.cfg.test_login_active
        || !http::provenance_ok(&req.headers, &gw.cfg.auth.serialized, true)
    {
        return uniform_error();
    }
    let Some(f) = form_fields(req, &["user", "csrf"]) else {
        return uniform_error();
    };
    let now = now_secs();
    let Some(mut store) = gw.store() else {
        return uniform_error();
    };
    let Some(pre_id) = http::gateway_cookie(&req.cookies, PREAUTH_COOKIE)
        .ok()
        .flatten()
    else {
        return uniform_error();
    };
    // The login state is single-use.
    let Some(pre) = store.take_preauth(pre_id, now) else {
        return uniform_error();
    };
    if !ct_eq(pre.csrf.as_bytes(), f[1].as_bytes()) {
        return uniform_error();
    }
    let users = gw
        .cfg
        .cfg
        .test_login
        .as_ref()
        .map(|t| t.users.as_slice())
        .unwrap_or(&[]);
    let Some(u) = f[0]
        .parse::<usize>()
        .ok()
        .filter(|_| f[0].bytes().all(|c| c.is_ascii_digit()) && f[0].len() <= 2)
        .and_then(|i| users.get(i))
    else {
        return uniform_error();
    };
    // Fresh session id at login; any presented session is revoked.
    if let Some(old) = http::gateway_cookie(&req.cookies, SESSION_COOKIE)
        .ok()
        .flatten()
    {
        store.revoke_session(old);
    }
    let Ok(login_id) = Store::new_login_id() else {
        return uniform_error();
    };
    let Ok(sid) = store.create_session(SessionOrigin::Auth, &u.ten, &u.sub, login_id, now) else {
        return uniform_error();
    };
    let target = match pre.ret {
        Return::Home => "/".to_owned(),
        Return::Confirm(pid) => format!("/confirm/{pid}"),
        Return::AppHandoff(h) => {
            let code = Code {
                state_hash: h,
                ten: u.ten.clone(),
                sub: u.sub.clone(),
                login_id,
                expires: now + crate::store::CODE_TTL,
            };
            match store.create_code(code, now) {
                Ok(c) => format!("{}/.nodkey/callback?code={c}", gw.cfg.app.serialized),
                Err(_) => return uniform_error(),
            }
        }
    };
    let mut r = http::redirect(&target);
    http::gateway_clear_cookie(&mut r, PREAUTH_COOKIE);
    http::gateway_set_cookie(
        &mut r,
        SESSION_COOKIE,
        &sid,
        gw.cfg.cfg.session.absolute_lifetime_s,
    );
    harden(r)
}

fn logout(gw: &Gateway, req: &Req) -> Resp {
    if !http::provenance_ok(&req.headers, &gw.cfg.auth.serialized, true) {
        return uniform_error();
    }
    if let Some(sid) = http::gateway_cookie(&req.cookies, SESSION_COOKIE)
        .ok()
        .flatten()
    {
        if let Some(mut s) = gw.store() {
            s.revoke_login_of(sid);
        }
    }
    let mut r = html_page(
        gw,
        StatusCode::OK,
        "Signed out",
        "<h1>Signed out</h1><p>You are signed out.</p>",
    );
    http::gateway_clear_cookie(&mut r, SESSION_COOKIE);
    r
}

/// Renders and verifies a record for `subject`: the broker's answer must parse strictly, pass the
/// §3.2 rules, carry a digest equal to the gateway's own, name this pending id and this subject.
async fn render_checked(
    gw: &Gateway,
    pid_text: &str,
    pid: [u8; 16],
    s: &Session,
) -> Option<(Render, CheckedRecord)> {
    let subj = Subject {
        ten: &s.ten,
        sub: &s.sub,
    };
    let rd = ipc::render(&gw.broker, pid_text, subj).await.ok()?;
    let checked = digest::check(rd.record.clone()).ok()?;
    let theirs = parse_digest_hex(&rd.digest)?;
    let ok = ct_eq(&theirs, &checked.digest)
        && checked.pending_id == pid
        && checked.rec.ten == s.ten
        && checked.rec.approver_sub == s.sub
        && html::is_state(&rd.state)
        && matches!(rd.context.approver_source.as_str(), "named" | "enrolled")
        && texts_ok(&rd);
    ok.then_some((rd, checked))
}

/// Bounds on broker-supplied display text (escaped anyway).
fn texts_ok(rd: &Render) -> bool {
    let t = |s: &str, max: usize| s.len() <= max && s.bytes().all(|c| (0x20..=0x7e).contains(&c));
    t(&rd.context.workload_display_name, 128)
        && rd.facts.len() <= 32
        && rd
            .facts
            .iter()
            .all(|f| t(&f.label, 128) && t(&f.value, 256))
        && rd.context.recent_identical.len() <= 64
        && rd.context.other_open_on_resource.len() <= 64
        && rd
            .context
            .recent_identical
            .iter()
            .chain(&rd.context.other_open_on_resource)
            .all(|r| decode_pending_id(&r.pending_id).is_some() && html::is_state(&r.state))
}

/// `GET /confirm/<pending_id>` (§7.1).
async fn confirm(gw: &Gateway, req: &Req, pid_text: &str) -> Resp {
    let Some(pid) = decode_pending_id(pid_text) else {
        return uniform_error();
    };
    if req.query.is_some() {
        return uniform_error();
    }
    let now = now_secs();
    let Some((sid, s)) = session(gw, req) else {
        // Return path kept server-side, keyed by the login state (EP-13).
        let Some(Ok((pre, _))) = gw
            .store()
            .map(|mut st| st.create_preauth(Return::Confirm(pid_text.to_owned()), now))
        else {
            return uniform_error();
        };
        let mut r = http::redirect("/login");
        http::gateway_set_cookie(&mut r, PREAUTH_COOKIE, &pre, crate::store::PREAUTH_TTL);
        return harden(r);
    };
    let Some((rd, checked)) = render_checked(gw, pid_text, pid, &s).await else {
        return uniform_error();
    };
    let token = if rd.state == "PENDING" && now < checked.rec.expires_at {
        let Some(Ok(t)) = gw
            .store()
            .map(|mut st| st.mint_token(&sid, pid, checked.digest, checked.rec.expires_at, now))
        else {
            return uniform_error();
        };
        Some(t)
    } else {
        None
    };
    let body = html::confirm_page(&rd, &checked, token.as_deref(), gw.cfg.test_login_active);
    harden(http::resp(StatusCode::OK, "text/html; charset=utf-8", body))
}

/// `POST /confirm/<pending_id>/decision` (§7.3). Checks run in order; any failure gives the uniform
/// error and causes no state change (except consuming a presented token, §7.2).
async fn decision(gw: &Gateway, req: &Req, pid_text: &str) -> Resp {
    // 1. Path, method, content type and exact fields.
    let Some(pid) = decode_pending_id(pid_text) else {
        return uniform_error();
    };
    if req.query.is_some() {
        return uniform_error();
    }
    let Some(f) = form_fields(req, &["token", "digest", "decision"]) else {
        return uniform_error();
    };
    let (token, digest_hex, decision) = (&f[0], &f[1], f[2].as_str());
    let Some(digest) = parse_digest_hex(digest_hex) else {
        return uniform_error();
    };
    if decision != "approve" && decision != "deny" {
        return uniform_error();
    }
    // 2. Provenance relative to the auth origin.
    if !http::provenance_ok(&req.headers, &gw.cfg.auth.serialized, true) {
        return uniform_error();
    }
    // 3. Session.
    let Some((sid, s)) = session(gw, req) else {
        return uniform_error();
    };
    // 4. Token: consumed at its first presentation, then checked against session, pid and digest.
    let now = now_secs();
    let Some(t) = gw.store().and_then(|mut st| st.take_token(token)) else {
        return uniform_error();
    };
    if !(ct_eq(t.session_id.as_bytes(), sid.as_bytes())
        && t.pending_id == pid
        && ct_eq(&t.digest, &digest)
        && now < t.expires)
    {
        return uniform_error();
    }
    // 5. Approve via the authority (socket I) or deny via the broker (socket G).
    let subj = Subject {
        ten: &s.ten,
        sub: &s.sub,
    };
    let digest_hex = hex_lower(&digest);
    let result = if decision == "approve" {
        ipc::approve(&gw.authority_approve, pid_text, &digest_hex, subj).await
    } else {
        ipc::deny(&gw.broker, pid_text, &digest_hex, subj).await
    };
    if let Err(e) = result {
        eprintln!("nodkey-gateway: {decision} not accepted: {e:?}");
    }
    // Neutral page in both cases, with the state from a fresh render.
    let state = render_checked(gw, pid_text, pid, &s)
        .await
        .map(|(rd, _)| rd.state);
    harden(http::resp(
        StatusCode::OK,
        "text/html; charset=utf-8",
        html::submitted_page(state.as_deref(), gw.cfg.test_login_active),
    ))
}
