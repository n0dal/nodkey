//! Gateway configuration (strict JSON, administrator-only file). Every rule that can be checked at
//! start-up is checked here; the gateway refuses to start otherwise.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::util::{is_id, is_op_name};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Listening address. Dev TLS, plain HTTP and the test login require a loopback address.
    pub listen: SocketAddr,
    pub tls: TlsConfig,
    /// e.g. `https://app.localhost:8443`.
    pub app_origin: String,
    /// e.g. `https://auth.localhost:8443`.
    pub auth_origin: String,
    pub upstream: Upstream,
    /// The workload identity of the proxied app (read grants are requested for it).
    pub app_wid: String,
    /// Routes for which a read grant is requested (exact path or path prefix ending in `/`).
    #[serde(default)]
    pub read_routes: Vec<ReadRoute>,
    /// App cookie names forwarded to the app and accepted in app `Set-Cookie` (exact, case-sensitive).
    #[serde(default)]
    pub app_cookies: Vec<String>,
    /// Socket G (gateway → broker).
    pub broker_socket: PathBuf,
    /// Socket I (gateway → authority).
    pub authority_socket: PathBuf,
    /// If set, the peer uid of each socket is checked with `SO_PEERCRED`/`getpeereid`.
    #[serde(default)]
    pub expected_broker_uid: Option<u32>,
    #[serde(default)]
    pub expected_authority_uid: Option<u32>,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub limits: Limits,
    /// Test login (R3B-11). Accepted only when the binary was built with the `test-login` feature.
    #[serde(default)]
    pub test_login: Option<TestLoginConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "mode", rename_all = "snake_case")]
pub enum TlsConfig {
    /// Certificate and key from PEM files.
    Files { cert_pem: PathBuf, key_pem: PathBuf },
    /// DEV ONLY: a self-signed certificate for the two host names, generated at start-up. Its PEM is
    /// written to `cert_out` so that a local browser or client can be told to trust it.
    DevSelfSigned { cert_out: PathBuf },
    /// DEV/TEST ONLY: plain HTTP, loopback only. Browsers may refuse `Secure`/`__Host-` cookies.
    PlainHttpLoopbackInsecure,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Upstream {
    /// `host:port` of the app's web server.
    Tcp(SocketAddr),
    /// Unix socket of the app's web server.
    Unix(PathBuf),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRoute {
    pub path: String,
    pub rop: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    pub absolute_lifetime_s: u64,
    pub idle_timeout_s: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            absolute_lifetime_s: 12 * 3600,
            idle_timeout_s: 30 * 60,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_request_body: usize,
    pub max_response_body: usize,
    pub upstream_timeout_ms: u64,
    pub ipc_timeout_ms: u64,
    /// Timeout for `approve` on socket I. The authority waits up to its own
    /// `approve_reply_timeout_ms` (≤ 30 000) for the broker's `accepted` before answering (its spec
    /// gap AU-6), so this must exceed that value.
    pub approve_timeout_ms: u64,
    /// Cap on each in-memory store (sessions, tokens, login states, codes).
    pub max_store_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_request_body: 1 << 20,
            max_response_body: 8 << 20,
            upstream_timeout_ms: 15_000,
            ipc_timeout_ms: 5_000,
            approve_timeout_ms: 31_000,
            max_store_entries: 10_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestLoginConfig {
    pub enabled: bool,
    pub users: Vec<TestUser>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestUser {
    pub ten: String,
    pub sub: String,
    pub label: String,
}

/// A parsed origin: scheme and authority (`host[:port]`, lowercase host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub serialized: String,
    pub authority: String,
}

fn parse_origin(s: &str, https: bool) -> Result<Origin, String> {
    let scheme = if https { "https://" } else { "http://" };
    let rest = s
        .strip_prefix(scheme)
        .ok_or_else(|| format!("origin {s:?} must start with {scheme}"))?;
    let ok = !rest.is_empty()
        && rest.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-' || c == b':'
        });
    if !ok || rest.matches(':').count() > 1 || rest.starts_with(':') {
        return Err(format!(
            "origin {s:?}: expected scheme://lowercase-host[:port] and nothing else"
        ));
    }
    Ok(Origin {
        serialized: s.to_owned(),
        authority: rest.to_owned(),
    })
}

impl Origin {
    pub fn host(&self) -> &str {
        self.authority.split(':').next().unwrap_or("")
    }
}

/// Validated configuration.
#[derive(Debug, Clone)]
pub struct Checked {
    pub cfg: Config,
    pub app: Origin,
    pub auth: Origin,
    pub test_login_active: bool,
}

pub fn load(path: &std::path::Path) -> Result<Checked, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading config: {e}"))?;
    let cfg: Config = serde_json::from_str(&text).map_err(|e| format!("config: {e}"))?;
    check(cfg)
}

pub fn check(cfg: Config) -> Result<Checked, String> {
    let https = !matches!(cfg.tls, TlsConfig::PlainHttpLoopbackInsecure);
    let app = parse_origin(&cfg.app_origin, https)?;
    let auth = parse_origin(&cfg.auth_origin, https)?;
    if app.host() == auth.host() {
        return Err("app and auth origins must have different host names".into());
    }
    let loopback = cfg.listen.ip().is_loopback();
    match cfg.tls {
        TlsConfig::DevSelfSigned { .. } | TlsConfig::PlainHttpLoopbackInsecure if !loopback => {
            return Err("dev TLS modes require a loopback listen address".into());
        }
        _ => {}
    }
    if !is_id(&cfg.app_wid, 256) {
        return Err("app_wid is not an ID".into());
    }
    for r in &cfg.read_routes {
        if !r.path.starts_with('/')
            || r.path.contains(['?', '#'])
            || r.path.starts_with("/.nodkey")
        {
            return Err(format!("read route {:?}: bad path", r.path));
        }
        if r.rop.is_empty() || r.rop.len() > 16 || !r.rop.iter().all(|o| is_op_name(o)) {
            return Err(format!(
                "read route {:?}: rop must be 1-16 operation names",
                r.path
            ));
        }
    }
    for c in &cfg.app_cookies {
        let ok = !c.is_empty()
            && c.len() <= 64
            && c.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !ok || is_gateway_cookie_name(c) || c.to_ascii_lowercase().starts_with("__") {
            return Err(format!("app cookie {c:?} is not allowed"));
        }
    }
    let l = &cfg.limits;
    if l.ipc_timeout_ms == 0 || !(1_000..=60_000).contains(&l.approve_timeout_ms) {
        return Err(
            "limits: ipc_timeout_ms > 0 and approve_timeout_ms 1000..=60000 required".into(),
        );
    }
    let s = &cfg.session;
    if s.absolute_lifetime_s == 0 || s.absolute_lifetime_s > 24 * 3600 || s.idle_timeout_s == 0 {
        return Err("session lifetimes out of range (absolute 1..=86400 s)".into());
    }
    let test_login_active = match &cfg.test_login {
        None => false,
        Some(t) if !t.enabled => false,
        Some(t) => {
            if !cfg!(feature = "test-login") {
                return Err(
                    "test_login.enabled is set, but this binary was built without the \
                            `test-login` feature: it has no login method at all"
                        .into(),
                );
            }
            if !loopback {
                return Err("the test login requires a loopback listen address".into());
            }
            if t.users.is_empty() || t.users.len() > 64 {
                return Err("test_login.users must have 1-64 entries".into());
            }
            for u in &t.users {
                if !is_id(&u.ten, 128) || !is_id(&u.sub, 256) || u.label.len() > 64 {
                    return Err("test_login user: ten/sub must be IDs, label <= 64 bytes".into());
                }
            }
            true
        }
    };
    Ok(Checked {
        cfg,
        app,
        auth,
        test_login_active,
    })
}

/// Gateway-owned cookie names, compared case-insensitively.
pub const SESSION_COOKIE: &str = "__Host-nodkey_session";
pub const LOGIN_COOKIE: &str = "__Host-nodkey_login";
pub const PREAUTH_COOKIE: &str = "__Host-nodkey_preauth";

/// Any name that is, or could be confused with, a gateway cookie.
pub fn is_gateway_cookie_name(name: &str) -> bool {
    name.to_ascii_lowercase().contains("nodkey")
}
