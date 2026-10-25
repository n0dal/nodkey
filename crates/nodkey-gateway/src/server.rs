//! Listener, TLS, Host routing and the checks common to both origins.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::config::{Checked, TlsConfig};
use crate::http::{self, Resp};
use crate::ipc::Peer;
use crate::store::Store;
use crate::{app, auth};

pub const MAX_CONNECTIONS: usize = 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct Gateway {
    pub cfg: Checked,
    pub store: Mutex<Store>,
    pub broker: Peer,
    pub authority: Peer,
    /// Socket I with the longer timeout used for `approve` (authority AU-6).
    pub authority_approve: Peer,
}

impl Gateway {
    pub fn new(cfg: Checked) -> Gateway {
        let ipc_timeout = Duration::from_millis(cfg.cfg.limits.ipc_timeout_ms);
        Gateway {
            store: Mutex::new(Store::new(
                cfg.cfg.limits.max_store_entries,
                cfg.cfg.session.absolute_lifetime_s,
                cfg.cfg.session.idle_timeout_s,
            )),
            broker: Peer {
                path: cfg.cfg.broker_socket.clone(),
                expected_uid: cfg.cfg.expected_broker_uid,
                timeout: ipc_timeout,
            },
            authority_approve: Peer {
                path: cfg.cfg.authority_socket.clone(),
                expected_uid: cfg.cfg.expected_authority_uid,
                timeout: Duration::from_millis(cfg.cfg.limits.approve_timeout_ms),
            },
            authority: Peer {
                path: cfg.cfg.authority_socket.clone(),
                expected_uid: cfg.cfg.expected_authority_uid,
                timeout: ipc_timeout,
            },
            cfg,
        }
    }

    /// Locks the store. A poisoned lock (a panic while holding it) is treated as unavailable.
    pub fn store(&self) -> Option<std::sync::MutexGuard<'_, Store>> {
        self.store.lock().ok()
    }
}

#[derive(Debug)]
pub struct Running {
    pub addr: SocketAddr,
    pub task: tokio::task::JoinHandle<()>,
}

fn tls_acceptor(cfg: &Checked) -> Result<Option<TlsAcceptor>, String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let (certs, key): (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) = match &cfg.cfg.tls {
        TlsConfig::PlainHttpLoopbackInsecure => return Ok(None),
        TlsConfig::Files { cert_pem, key_pem } => {
            let certs = CertificateDer::pem_file_iter(cert_pem)
                .map_err(|e| format!("cert_pem: {e}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("cert_pem: {e}"))?;
            let key = PrivateKeyDer::from_pem_file(key_pem).map_err(|e| format!("key_pem: {e}"))?;
            (certs, key)
        }
        TlsConfig::DevSelfSigned { cert_out } => {
            let names = vec![cfg.app.host().to_owned(), cfg.auth.host().to_owned()];
            let ck =
                rcgen::generate_simple_self_signed(names).map_err(|e| format!("rcgen: {e}"))?;
            std::fs::write(cert_out, ck.cert.pem()).map_err(|e| format!("cert_out: {e}"))?;
            eprintln!(
                "nodkey-gateway: DEV SELF-SIGNED certificate generated for {} and {}; PEM written to {}. \
                 Local development only.",
                cfg.app.host(),
                cfg.auth.host(),
                cert_out.display()
            );
            let key = PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
            (vec![ck.cert.der().clone()], PrivateKeyDer::Pkcs8(key))
        }
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut sc = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls: {e}"))?;
    sc.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Some(TlsAcceptor::from(Arc::new(sc))))
}

/// Binds the listener and serves until the task is aborted.
pub async fn start(cfg: Checked) -> Result<Running, String> {
    let tls = tls_acceptor(&cfg)?;
    if tls.is_none() {
        eprintln!(
            "nodkey-gateway: WARNING plain HTTP on loopback (tls.mode = plain_http_loopback_insecure). \
             For tests and curl only; browsers need HTTPS for Secure/__Host- cookies."
        );
    }
    if cfg.test_login_active {
        eprintln!("nodkey-gateway: WARNING TEST LOGIN is enabled. Local development only.");
    } else {
        eprintln!(
            "nodkey-gateway: no login method is available in this {} (no passkey/OIDC login yet).",
            if cfg!(feature = "test-login") {
                "configuration"
            } else {
                "build (compiled without the `test-login` feature)"
            }
        );
    }
    let listener = TcpListener::bind(cfg.cfg.listen)
        .await
        .map_err(|e| format!("bind: {e}"))?;
    let addr = listener.local_addr().map_err(|e| format!("bind: {e}"))?;
    let gw = Arc::new(Gateway::new(cfg));
    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let task = tokio::spawn(async move {
        loop {
            let Ok(permit) = sem.clone().acquire_owned().await else {
                return;
            };
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let gw = gw.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                let _permit = permit;
                match tls {
                    Some(acc) => {
                        let Ok(Ok(s)) = tokio::time::timeout(TLS_TIMEOUT, acc.accept(stream)).await
                        else {
                            return;
                        };
                        let sni = s.get_ref().1.server_name().map(str::to_owned);
                        serve(gw, TokioIo::new(s), sni).await;
                    }
                    None => serve(gw, TokioIo::new(stream), None).await,
                }
            });
        }
    });
    Ok(Running { addr, task })
}

async fn serve<I>(gw: Arc<Gateway>, io: I, sni: Option<String>)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| {
        let gw = gw.clone();
        let sni = sni.clone();
        async move { Ok::<_, Infallible>(handle(&gw, req, sni.as_deref()).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_buf_size(64 * 1024)
        .serve_connection(io, svc)
        .await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    App,
    Auth,
}

/// Request as seen by an origin handler, with its body read (bounded).
#[derive(Debug)]
pub struct Req {
    pub method: Method,
    pub path: String,
    /// `None` if the request target had no `?`; `Some("")` for a bare `?`.
    pub query: Option<String>,
    pub headers: hyper::HeaderMap,
    pub cookies: Vec<(String, String)>,
    pub body: Bytes,
}

fn bad_request() -> Resp {
    http::resp(
        StatusCode::BAD_REQUEST,
        "text/plain; charset=utf-8",
        "Bad request.",
    )
}

/// Common entry point: Host routing, then the checks of ADR-0003 profile item 2.
pub async fn handle(gw: &Gateway, req: Request<Incoming>, sni: Option<&str>) -> Resp {
    // Route on Host only; SNI (if any) must agree with it (ADR-0003 §1).
    let host = match http::single(req.headers(), "host") {
        Ok(Some(h)) => h.to_ascii_lowercase(),
        _ => return bad_request(),
    };
    if let Some(a) = req.uri().authority() {
        if !a.as_str().eq_ignore_ascii_case(&host) {
            return bad_request();
        }
    }
    let which = if host == gw.cfg.app.authority {
        Which::App
    } else if host == gw.cfg.auth.authority {
        Which::Auth
    } else {
        return http::resp(
            StatusCode::MISDIRECTED_REQUEST,
            "text/plain; charset=utf-8",
            "Misdirected request.",
        );
    };
    if let Some(sni) = sni {
        let expect = match which {
            Which::App => gw.cfg.app.host(),
            Which::Auth => gw.cfg.auth.host(),
        };
        if !sni.eq_ignore_ascii_case(expect) {
            return http::resp(
                StatusCode::MISDIRECTED_REQUEST,
                "text/plain; charset=utf-8",
                "Misdirected request.",
            );
        }
    }
    let reject = |w: Which| match w {
        Which::App => bad_request(),
        Which::Auth => auth::uniform_error(),
    };
    // A request carrying `Service-Worker` (any case, any value) is rejected (SI-18).
    if req.headers().contains_key("service-worker") {
        return reject(which);
    }
    // No protocol upgrades (WebSocket, h2c) and no CONNECT/TRACE.
    if req.headers().contains_key("upgrade")
        || !matches!(
            *req.method(),
            Method::GET
                | Method::HEAD
                | Method::POST
                | Method::PUT
                | Method::PATCH
                | Method::DELETE
                | Method::OPTIONS
        )
    {
        return reject(which);
    }
    // Duplicate gateway cookies are rejected (SI-18).
    let Ok(cookies) = http::cookies(req.headers()) else {
        return reject(which);
    };
    for name in [
        crate::config::SESSION_COOKIE,
        crate::config::LOGIN_COOKIE,
        crate::config::PREAUTH_COOKIE,
    ] {
        if http::gateway_cookie(&cookies, name).is_err() {
            return reject(which);
        }
    }
    let path = req.uri().path().to_owned();
    if !path.starts_with('/') {
        return reject(which);
    }
    let query = req
        .uri()
        .path_and_query()
        .and_then(|pq| pq.as_str().split_once('?').map(|(_, q)| q.to_owned()));
    let (parts, body) = req.into_parts();
    let max = gw.cfg.cfg.limits.max_request_body;
    let Ok(cl) = http::single(&parts.headers, "content-length") else {
        return reject(which);
    };
    if cl
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > max)
    {
        return http::resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            "text/plain; charset=utf-8",
            "Request too large.",
        );
    }
    use http_body_util::BodyExt;
    let body = match http_body_util::Limited::new(body, max).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return http::resp(
                StatusCode::PAYLOAD_TOO_LARGE,
                "text/plain; charset=utf-8",
                "Request too large.",
            );
        }
    };
    let r = Req {
        method: parts.method,
        path,
        query,
        headers: parts.headers,
        cookies,
        body,
    };
    match which {
        Which::App => app::handle(gw, r).await,
        Which::Auth => auth::handle(gw, r).await,
    }
}
