//! Listener, TLS, Host routing and the checks common to both origins.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::config::{Checked, TlsConfig};
use crate::http::{self, Resp};
use crate::ipc::Peer;
use crate::store::Store;
use crate::{app, auth};

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
    pub app_conns: Arc<Semaphore>,
    pub auth_conns: Arc<Semaphore>,
    /// Background retry interval of an unacknowledged mandate revocation (§12.6: 5 s).
    pub revoke_retry: Duration,
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
                expected_uid: Some(cfg.cfg.expected_broker_uid),
                timeout: ipc_timeout,
            },
            revoke_retry: crate::auth::REVOKE_RETRY,
            app_conns: Arc::new(Semaphore::new(cfg.cfg.limits.app_connections)),
            auth_conns: Arc::new(Semaphore::new(cfg.cfg.limits.auth_connections)),
            authority_approve: Peer {
                path: cfg.cfg.authority_socket.clone(),
                expected_uid: Some(cfg.cfg.expected_authority_uid),
                timeout: Duration::from_millis(cfg.cfg.limits.approve_timeout_ms),
            },
            authority: Peer {
                path: cfg.cfg.authority_socket.clone(),
                expected_uid: Some(cfg.cfg.expected_authority_uid),
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
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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
        #[cfg(not(feature = "dev-tls"))]
        TlsConfig::DevSelfSigned { .. } => {
            return Err("dev_self_signed needs the `dev-tls` feature".into());
        }
        #[cfg(feature = "dev-tls")]
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
            let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
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
    let unrouted = Arc::new(Semaphore::new(gw.cfg.cfg.limits.unrouted_connections));
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            // Over the unrouted budget: close at once rather than queue (GW-R-03).
            let Ok(permit) = unrouted.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let gw = gw.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                let conn = Arc::new(ConnState {
                    permit: Mutex::new(Some(permit)),
                    response_ready: Notify::new(),
                    client: peer.ip(),
                });
                match tls {
                    Some(acc) => {
                        let Ok(Ok(s)) = tokio::time::timeout(TLS_TIMEOUT, acc.accept(stream)).await
                        else {
                            return;
                        };
                        let sni = s.get_ref().1.server_name().map(str::to_owned);
                        serve(gw, TokioIo::new(s), sni, conn).await;
                    }
                    None => serve(gw, TokioIo::new(stream), None, conn).await,
                }
            });
        }
    });
    Ok(Running { addr, task })
}

/// Per-connection state. The connection holds an unrouted permit until its request is routed, then
/// the permit of its origin, until the connection ends.
#[derive(Debug)]
pub struct ConnState {
    pub permit: Mutex<Option<OwnedSemaphorePermit>>,
    pub response_ready: Notify,
    pub client: IpAddr,
}

async fn serve<I>(gw: Arc<Gateway>, io: I, sni: Option<String>, conn: Arc<ConnState>)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let write_timeout = Duration::from_millis(gw.cfg.cfg.limits.response_write_timeout_ms);
    let c2 = conn.clone();
    let svc = service_fn(move |req| {
        let gw = gw.clone();
        let sni = sni.clone();
        let conn = c2.clone();
        async move {
            let r = handle(&gw, req, sni.as_deref(), &conn).await;
            conn.response_ready.notify_one();
            Ok::<_, Infallible>(r)
        }
    });
    // One request per connection; headers within 10 s; the response must be written within the
    // write deadline once it is ready, or the connection is dropped (GW-R-03).
    let serving = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .keep_alive(false)
        .max_buf_size(64 * 1024)
        .serve_connection(io, svc);
    tokio::select! {
        _ = serving => {}
        _ = async {
            conn.response_ready.notified().await;
            tokio::time::sleep(write_timeout).await;
        } => {}
    }
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
    /// Client address (per-client limits).
    pub client: IpAddr,
}

fn bad_request() -> Resp {
    http::resp(
        StatusCode::BAD_REQUEST,
        "text/plain; charset=utf-8",
        "Bad request.",
    )
}

/// Common entry point: Host routing, then the checks of ADR-0003 profile item 2.
pub async fn handle(
    gw: &Gateway,
    req: Request<Incoming>,
    sni: Option<&str>,
    conn: &ConnState,
) -> Resp {
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
    // Route to the origin's own connection budget; full → 503 (the other origin is unaffected).
    let sem = match which {
        Which::App => &gw.app_conns,
        Which::Auth => &gw.auth_conns,
    };
    let Ok(p) = sem.clone().try_acquire_owned() else {
        return http::resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain; charset=utf-8",
            "Busy.",
        );
    };
    if let Ok(mut slot) = conn.permit.lock() {
        *slot = Some(p);
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
    let body_deadline = Duration::from_millis(gw.cfg.cfg.limits.request_body_timeout_ms);
    let body = match tokio::time::timeout(
        body_deadline,
        http_body_util::Limited::new(body, max).collect(),
    )
    .await
    {
        Err(_) => {
            return http::resp(
                StatusCode::REQUEST_TIMEOUT,
                "text/plain; charset=utf-8",
                "Request timeout.",
            );
        }
        Ok(Ok(c)) => c.to_bytes(),
        Ok(Err(_)) => {
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
        client: conn.client,
    };
    match which {
        Which::App => app::handle(gw, r).await,
        Which::Auth => auth::handle(gw, r).await,
    }
}
