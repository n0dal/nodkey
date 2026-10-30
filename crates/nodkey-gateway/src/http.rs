// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! HTTP helpers shared by both origins.

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Response, StatusCode};

pub type Resp = Response<Full<Bytes>>;

/// A header or cookie set that the gateway refuses to interpret (non-ASCII, repeated, duplicated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

/// Every value of `name`, or `Err` if any value is not visible ASCII.
pub fn values<'a>(h: &'a HeaderMap, name: &str) -> Result<Vec<&'a str>, Malformed> {
    h.get_all(name)
        .iter()
        .map(|v| v.to_str().map_err(|_| Malformed))
        .collect()
}

/// At most one value of `name`; a repeated header is an error.
pub fn single<'a>(h: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, Malformed> {
    let v = values(h, name)?;
    match v.len() {
        0 => Ok(None),
        1 => Ok(Some(v[0])),
        _ => Err(Malformed),
    }
}

/// All request cookies as `(name, value)`, in order, from every `Cookie` header.
pub fn cookies(h: &HeaderMap) -> Result<Vec<(String, String)>, Malformed> {
    let mut out = Vec::new();
    for v in values(h, "cookie")? {
        for part in v.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (n, val) = part.split_once('=').unwrap_or((part, ""));
            out.push((n.trim().to_owned(), val.trim().to_owned()));
        }
    }
    Ok(out)
}

/// The value of a gateway cookie. Any name equal to `name` ignoring ASCII case counts as an
/// instance: more than one instance is an error (SI-18); a single instance whose case differs from
/// `name` is ignored (it was not set by the gateway).
pub fn gateway_cookie<'a>(
    all: &'a [(String, String)],
    name: &str,
) -> Result<Option<&'a str>, Malformed> {
    let mut found = all.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name));
    let first = found.next();
    if found.next().is_some() {
        return Err(Malformed);
    }
    Ok(first.filter(|(n, _)| n == name).map(|(_, v)| v.as_str()))
}

pub fn resp(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> Resp {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    if let Ok(v) = HeaderValue::from_str(content_type) {
        r.headers_mut().insert("content-type", v);
    }
    r
}

pub fn redirect(location: &str) -> Resp {
    let mut r = resp(StatusCode::SEE_OTHER, "text/plain; charset=utf-8", "");
    if let Ok(v) = HeaderValue::from_str(location) {
        r.headers_mut().insert("location", v);
    }
    r
}

pub fn set(r: &mut Resp, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        r.headers_mut().insert(HeaderName::from_static(name), v);
    }
}

pub fn append(r: &mut Resp, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        r.headers_mut().append(HeaderName::from_static(name), v);
    }
}

/// `Set-Cookie` for a gateway cookie: `__Host-` (Path=/, Secure, no Domain), HttpOnly, Lax.
pub fn gateway_set_cookie(r: &mut Resp, name: &str, value: &str, max_age: u64) {
    append(
        r,
        "set-cookie",
        &format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"),
    );
}

pub fn gateway_clear_cookie(r: &mut Resp, name: &str) {
    append(
        r,
        "set-cookie",
        &format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"),
    );
}

/// Provenance check for a state-changing request to `origin` (SI-21, spec §7.3 step 2):
/// `Sec-Fetch-Site` present ⇒ `same-origin` and `Sec-Fetch-Mode: navigate`; otherwise `Origin` must
/// equal `origin` exactly (`null` and absence are rejected). Repeated headers are rejected.
pub fn provenance_ok(h: &HeaderMap, origin: &str, require_navigate: bool) -> bool {
    let (Ok(site), Ok(mode), Ok(org)) = (
        single(h, "sec-fetch-site"),
        single(h, "sec-fetch-mode"),
        single(h, "origin"),
    ) else {
        return false;
    };
    match site {
        Some(site) => site == "same-origin" && (!require_navigate || mode == Some("navigate")),
        None => org == Some(origin),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn gateway_cookie_rules() {
        let c = cookies(&hm(&[("cookie", "a=1; __Host-nodkey_session=x")])).unwrap();
        assert_eq!(gateway_cookie(&c, "__Host-nodkey_session"), Ok(Some("x")));
        let c = cookies(&hm(&[
            ("cookie", "__Host-nodkey_session=x"),
            ("cookie", "__host-NODKEY_session=y"),
        ]))
        .unwrap();
        assert_eq!(gateway_cookie(&c, "__Host-nodkey_session"), Err(Malformed));
        let c = cookies(&hm(&[("cookie", "__host-nodkey_session=y")])).unwrap();
        assert_eq!(gateway_cookie(&c, "__Host-nodkey_session"), Ok(None));
    }

    #[test]
    fn provenance() {
        let o = "https://auth.localhost";
        assert!(provenance_ok(
            &hm(&[
                ("sec-fetch-site", "same-origin"),
                ("sec-fetch-mode", "navigate")
            ]),
            o,
            true
        ));
        assert!(!provenance_ok(
            &hm(&[
                ("sec-fetch-site", "same-origin"),
                ("sec-fetch-mode", "cors")
            ]),
            o,
            true
        ));
        assert!(!provenance_ok(
            &hm(&[
                ("sec-fetch-site", "same-site"),
                ("sec-fetch-mode", "navigate")
            ]),
            o,
            true
        ));
        assert!(!provenance_ok(
            &hm(&[
                ("sec-fetch-site", "same-site"),
                ("origin", "https://auth.localhost")
            ]),
            o,
            true
        ));
        assert!(provenance_ok(
            &hm(&[("origin", "https://auth.localhost")]),
            o,
            true
        ));
        assert!(!provenance_ok(&hm(&[("origin", "null")]), o, true));
        assert!(!provenance_ok(
            &hm(&[("origin", "https://app.localhost")]),
            o,
            true
        ));
        assert!(!provenance_ok(&hm(&[]), o, true));
        assert!(!provenance_ok(
            &hm(&[
                ("origin", "https://auth.localhost"),
                ("origin", "https://auth.localhost")
            ]),
            o,
            true
        ));
    }
}
