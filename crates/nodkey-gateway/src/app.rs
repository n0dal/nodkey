//! App origin: reverse proxy to the untrusted app web server, plus the reserved `/.nodkey/` paths
//! (app-session hand-off and logout).
//!
//! Request side (ADR-0003 profile item 2, §4): headers are rebuilt from an allowlist; gateway cookies
//! and every `Nodkey-*`/`Authorization` header are dropped; only allowlisted app cookies are
//! forwarded. The only gateway-supplied header is `Nodkey-Grant` (a read grant), which the client
//! cannot inject because no inbound `Nodkey-*` header is ever forwarded.
//!
//! Response side: headers are rebuilt from an allowlist; `Set-Cookie` only for allowlisted app cookie
//! names without a `Domain` attribute; `Cache-Control: no-store`, `nosniff`, `frame-ancestors 'self'`.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};

use crate::config::{LOGIN_COOKIE, SESSION_COOKIE, Upstream, is_gateway_cookie_name};
use crate::http::{self, Resp};
use crate::ipc::{self, Subject};
use crate::server::{Gateway, Req};
use crate::store::{SessionOrigin, Store};
use crate::util::{b64url, hex_lower, now_secs, random_bytes};

/// Request headers forwarded to the app (lowercase). Everything else is dropped.
const FORWARD_REQUEST: &[&str] = &[
    "accept",
    "accept-language",
    "content-type",
    "origin",
    "referer",
    "user-agent",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-user",
    "x-requested-with",
];

/// App response headers passed to the browser (lowercase). `set-cookie` is filtered separately.
const FORWARD_RESPONSE: &[&str] = &[
    "content-type",
    "content-language",
    "content-disposition",
    "content-encoding",
    "location",
    "vary",
    "content-security-policy",
    "content-security-policy-report-only",
    "referrer-policy",
    "permissions-policy",
    "retry-after",
];

/// Allowlisted response headers that must appear at most once.
const SINGLE_VALUED_RESPONSE: &[&str] = &[
    "content-type",
    "content-language",
    "content-disposition",
    "content-encoding",
    "location",
    "referrer-policy",
    "retry-after",
];

/// The header that carries a read grant to the app (grant-v1 §2 transport text).
pub const GRANT_HEADER: &str = "nodkey-grant";

fn text(status: StatusCode, msg: &'static str) -> Resp {
    harden(http::resp(status, "text/plain; charset=utf-8", msg))
}

/// Headers set on every app-origin response, including gateway-generated ones.
fn harden(mut r: Resp) -> Resp {
    http::set(&mut r, "cache-control", "no-store");
    http::set(&mut r, "x-content-type-options", "nosniff");
    http::set(&mut r, "x-frame-options", "SAMEORIGIN");
    http::set(&mut r, "cross-origin-resource-policy", "same-origin");
    // Appended as a separate policy, so it applies in addition to any app CSP.
    http::append(&mut r, "content-security-policy", "frame-ancestors 'self'");
    r
}

pub async fn handle(gw: &Gateway, req: Req) -> Resp {
    if req.path == "/.nodkey" || req.path.starts_with("/.nodkey/") {
        return reserved(gw, &req);
    }
    proxy(gw, req).await
}

fn session_cookie(req: &Req) -> Option<&str> {
    http::gateway_cookie(&req.cookies, SESSION_COOKIE)
        .ok()
        .flatten()
}

fn reserved(gw: &Gateway, req: &Req) -> Resp {
    let now = now_secs();
    match (&req.method, req.path.as_str()) {
        // Start of the app-session hand-off: the state lives in a host-only cookie; the auth origin
        // only ever sees its hash (ADR-0003 §2 steps 1, 4).
        (&Method::GET, "/.nodkey/login") if req.query.is_none() => {
            let Some(state) = random_bytes::<32>() else {
                return text(StatusCode::SERVICE_UNAVAILABLE, "Unavailable.");
            };
            let state = b64url(&state);
            let h = Sha256::digest(state.as_bytes());
            let mut r = http::redirect(&format!(
                "{}/login/app?h={}",
                gw.cfg.auth.serialized,
                hex_lower(&h)
            ));
            http::gateway_set_cookie(&mut r, LOGIN_COOKIE, &state, 300);
            harden(r)
        }
        (&Method::GET, "/.nodkey/callback") => {
            let Some(code) = req.query.as_deref().and_then(|q| q.strip_prefix("code=")) else {
                return text(StatusCode::NOT_FOUND, "Not found.");
            };
            let state = http::gateway_cookie(&req.cookies, LOGIN_COOKIE)
                .ok()
                .flatten();
            let Some(mut store) = gw.store() else {
                return text(StatusCode::SERVICE_UNAVAILABLE, "Unavailable.");
            };
            // The code is consumed at its first presentation.
            let Some(c) = store.take_code(code, now) else {
                return text(StatusCode::NOT_FOUND, "Login failed. Please start again.");
            };
            let Some(state) = state else {
                return text(StatusCode::NOT_FOUND, "Login failed. Please start again.");
            };
            let h: [u8; 32] = Sha256::digest(state.as_bytes()).into();
            if !crate::util::ct_eq(&h, &c.state_hash) {
                return text(StatusCode::NOT_FOUND, "Login failed. Please start again.");
            }
            // Fresh session id; any session id the browser presented is revoked.
            if let Some(old) = session_cookie(req) {
                store.revoke_session(old);
            }
            let Ok(sid) = store.create_session(SessionOrigin::App, &c.ten, &c.sub, c.login_id, now)
            else {
                return text(StatusCode::SERVICE_UNAVAILABLE, "Unavailable.");
            };
            let mut r = http::redirect("/");
            http::gateway_clear_cookie(&mut r, LOGIN_COOKIE);
            http::gateway_set_cookie(
                &mut r,
                SESSION_COOKIE,
                &sid,
                gw.cfg.cfg.session.absolute_lifetime_s,
            );
            harden(r)
        }
        (&Method::POST, "/.nodkey/logout") if req.query.is_none() => {
            if !http::provenance_ok(&req.headers, &gw.cfg.app.serialized, false) {
                return text(StatusCode::FORBIDDEN, "Forbidden.");
            }
            if let (Some(sid), Some(mut store)) = (session_cookie(req), gw.store()) {
                store.revoke_login_of(sid);
            }
            let mut r = http::redirect("/");
            http::gateway_clear_cookie(&mut r, SESSION_COOKIE);
            harden(r)
        }
        _ => text(StatusCode::NOT_FOUND, "Not found."),
    }
}

/// Read routes match only plain paths: no percent-encoding and no `.`/`..`/empty segments, so a
/// route prefix cannot be satisfied by a path the app would resolve elsewhere.
fn read_route<'a>(gw: &'a Gateway, path: &str) -> Option<&'a [String]> {
    let segs: Vec<&str> = path[1..].split('/').collect();
    let last = segs.len() - 1;
    let plain = !path.contains('%')
        && segs
            .iter()
            .enumerate()
            .all(|(i, seg)| *seg != "." && *seg != ".." && (!seg.is_empty() || i == last));
    if !plain {
        return None;
    }
    gw.cfg
        .cfg
        .read_routes
        .iter()
        .find(|r| r.path == path || (r.path.ends_with('/') && path.starts_with(&r.path)))
        .map(|r| r.rop.as_slice())
}

/// Read grants only for same-origin requests or top-level document navigations (SI-21).
fn read_provenance_ok(h: &hyper::HeaderMap) -> bool {
    let site = http::single(h, "sec-fetch-site");
    let mode = http::single(h, "sec-fetch-mode");
    let dest = http::single(h, "sec-fetch-dest");
    matches!(
        (site, mode, dest),
        (Ok(Some("same-origin")), Ok(_), Ok(_))
            | (Ok(Some(_)), Ok(Some("navigate")), Ok(Some("document")))
    )
}

async fn proxy(gw: &Gateway, req: Req) -> Resp {
    let target = match &req.query {
        Some(q) => format!("{}?{}", req.path, q),
        None => req.path.clone(),
    };
    let mut b = Request::builder().method(req.method.clone()).uri(&target);
    // Allowlisted headers; a repeated allowlisted header is rejected (no ambiguity for the app).
    for name in FORWARD_REQUEST {
        match http::values(&req.headers, name) {
            Ok(v) if v.len() <= 1 => {
                if let Some(v) = v.first() {
                    b = b.header(*name, *v);
                }
            }
            _ => return text(StatusCode::BAD_REQUEST, "Bad request."),
        }
    }
    b = b.header("host", gw.cfg.app.authority.as_str());
    let app_cookies: Vec<String> = req
        .cookies
        .iter()
        .filter(|(n, _)| {
            !is_gateway_cookie_name(n) && gw.cfg.cfg.app_cookies.iter().any(|a| a == n)
        })
        .map(|(n, v)| format!("{n}={v}"))
        .collect();
    if !app_cookies.is_empty() {
        b = b.header("cookie", app_cookies.join("; "));
    }

    // Read grant for a qualifying request on a read route with a live app session.
    let is_read_route = read_route(gw, &req.path);
    if let Some(rop) = is_read_route {
        let session = session_cookie(&req).and_then(|sid| {
            gw.store()
                .and_then(|mut s: std::sync::MutexGuard<'_, Store>| {
                    s.session(sid, SessionOrigin::App, now_secs(), true)
                })
        });
        if let Some(s) = session {
            if read_provenance_ok(&req.headers) {
                let subj = Subject {
                    ten: &s.ten,
                    sub: &s.sub,
                };
                match ipc::read_grant(&gw.authority, subj, &gw.cfg.cfg.app_wid, rop).await {
                    Ok(g) => b = b.header(GRANT_HEADER, g),
                    Err(e) => eprintln!("nodkey-gateway: read_grant failed: {e:?}"),
                }
            }
        }
    }
    if !req.body.is_empty() || matches!(req.method, Method::POST | Method::PUT | Method::PATCH) {
        b = b.header("content-length", req.body.len());
    }
    let Ok(upreq) = b.body(Full::new(req.body.clone())) else {
        return text(StatusCode::BAD_REQUEST, "Bad request.");
    };

    let timeout = Duration::from_millis(gw.cfg.cfg.limits.upstream_timeout_ms);
    let max = gw.cfg.cfg.limits.max_response_body;
    let fut = async {
        let resp = match &gw.cfg.cfg.upstream {
            Upstream::Tcp(a) => {
                let s = tokio::net::TcpStream::connect(a).await.map_err(|_| ())?;
                send(TokioIo::new(s), upreq).await?
            }
            Upstream::Unix(p) => {
                let s = tokio::net::UnixStream::connect(p).await.map_err(|_| ())?;
                send(TokioIo::new(s), upreq).await?
            }
        };
        let (parts, body) = resp.into_parts();
        let body = http_body_util::Limited::new(body, max)
            .collect()
            .await
            .map_err(|_| ())?
            .to_bytes();
        Ok::<_, ()>((parts, body))
    };
    let Ok(Ok((parts, body))) = tokio::time::timeout(timeout, fut).await else {
        return text(StatusCode::BAD_GATEWAY, "Bad gateway.");
    };
    if parts.status.is_informational() {
        return text(StatusCode::BAD_GATEWAY, "Bad gateway.");
    }
    let mut r = http::resp(parts.status, "application/octet-stream", Bytes::new());
    r.headers_mut().remove("content-type");
    // Single-valued headers: a duplicate from the app is a bad response (GW-R-06).
    if SINGLE_VALUED_RESPONSE
        .iter()
        .any(|n| parts.headers.get_all(*n).iter().count() > 1)
    {
        return text(StatusCode::BAD_GATEWAY, "Bad gateway.");
    }
    for name in FORWARD_RESPONSE {
        for v in parts.headers.get_all(*name) {
            r.headers_mut()
                .append(HeaderName::from_static(name), v.clone());
        }
    }
    for v in parts.headers.get_all("set-cookie") {
        if let Ok(s) = v.to_str() {
            if app_set_cookie_allowed(s, &gw.cfg.cfg.app_cookies) {
                if let Ok(hv) = HeaderValue::from_str(s) {
                    r.headers_mut().append("set-cookie", hv);
                }
            }
        }
    }
    *r.body_mut() = Full::new(body);
    harden(r)
}

async fn send<I>(
    io: I,
    req: Request<Full<Bytes>>,
) -> Result<hyper::Response<hyper::body::Incoming>, ()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| ())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender.send_request(req).await.map_err(|_| ())
}

/// App `Set-Cookie` is forwarded only for an allowlisted name that is not gateway-like, and only
/// without a `Domain` attribute (host-only, so it cannot be tossed to the auth origin).
pub fn app_set_cookie_allowed(sc: &str, allow: &[String]) -> bool {
    let mut parts = sc.split(';');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some((name, _)) = first.split_once('=') else {
        return false;
    };
    let name = name.trim();
    if is_gateway_cookie_name(name) || !allow.iter().any(|a| a == name) {
        return false;
    }
    !parts.any(|a| {
        a.trim()
            .split('=')
            .next()
            .is_some_and(|k| k.trim().eq_ignore_ascii_case("domain"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_filter() {
        let allow = vec!["PHPSESSID".to_owned()];
        assert!(app_set_cookie_allowed(
            "PHPSESSID=abc; Path=/; HttpOnly",
            &allow
        ));
        assert!(!app_set_cookie_allowed(
            "PHPSESSID=abc; Domain=localhost",
            &allow
        ));
        assert!(!app_set_cookie_allowed("phpsessid=abc", &allow));
        assert!(!app_set_cookie_allowed(
            "__Host-nodkey_session=x; Path=/; Secure",
            &allow
        ));
        assert!(!app_set_cookie_allowed("other=1", &allow));
        assert!(!app_set_cookie_allowed("garbage", &allow));
    }
}
