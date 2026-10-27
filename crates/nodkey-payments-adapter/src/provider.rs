//! Egress to the provider (payments-adapter-v1 §5): TLS 1.3 to one pinned CA, then one HTTP/1.1
//! request per connection with fixed headers, bounded head and body, and hard time limits.
//!
//! "Sent / not sent" is decided at the socket layer: nothing is handed to the stream until the TCP
//! connect and the TLS handshake (including certificate verification) have completed. A failure up
//! to that point is [`Exchange::NotSent`]; anything after is [`Exchange::Failed`] or a response.
//! Error strings are never inspected; only error types.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::client::Resumption;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::result::{AmbCause, Exchange, NotSentCause, decodes_body};

/// The adapter's User-Agent (generic; carries no personal or deployment identifier).
pub const USER_AGENT: &str = "nodkey-payments-adapter/1";

/// §9 `limits` (milliseconds and bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLimits {
    pub connect_ms: u64,
    pub total_ms: u64,
    pub max_head: usize,
    pub max_body: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        HttpLimits {
            connect_ms: 2_000,
            total_ms: 10_000,
            max_head: 16_384,
            max_body: 65_536,
        }
    }
}

/// Maximum response headers (§5).
pub const MAX_RESPONSE_HEADERS: usize = 64;

/// The simpay secret key. Zeroized on drop and redacted in `Debug`.
pub struct ApiKey(Zeroizing<String>);

impl ApiKey {
    pub fn new(s: Zeroizing<String>) -> ApiKey {
        ApiKey(s)
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

/// TLS client policy (§5): root store = the pinned CA only; TLS 1.3 only; no resumption (so no
/// tickets and no early data); no client certificate; ALPN `http/1.1`.
pub fn tls_config(ca: CertificateDer<'static>) -> Result<ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    roots
        .add(ca)
        .map_err(|_| "pinned CA is not a usable trust anchor".to_string())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "TLS 1.3 unsupported by the crypto provider".to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.resumption = Resumption::disabled();
    cfg.enable_early_data = false;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// One provider endpoint. Destination is an IP literal from the configuration: no DNS, no proxy
/// environment variables, no redirects.
pub struct Provider {
    addr: SocketAddr,
    host: String,
    server_name: ServerName<'static>,
    tls: TlsConnector,
    key: ApiKey,
    limits: HttpLimits,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("addr", &self.addr)
            .field("host", &self.host)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// A request the adapter builds; every value is grant-derived or fixed. `Debug` redacts the
/// `Idempotency-Key` (PC-A-04).
#[derive(Clone)]
pub enum Call {
    /// `POST /v1/refunds` with `Idempotency-Key` and a form body.
    Create { idem_key: String, form: String },
    /// `GET <path_and_query>`.
    Get { path_and_query: String },
}

impl std::fmt::Debug for Call {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Call::Create { form, .. } => f
                .debug_struct("Create")
                .field("idem_key", &"<redacted>")
                .field("form", form)
                .finish(),
            Call::Get { path_and_query } => f
                .debug_struct("Get")
                .field("path_and_query", path_and_query)
                .finish(),
        }
    }
}

/// Aborts the hyper connection task when the exchange ends for any reason, including the
/// deadline dropping the exchange future (PC-A-05).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Provider {
    pub fn new(
        addr: SocketAddr,
        server_name: &str,
        tls: ClientConfig,
        key: ApiKey,
        limits: HttpLimits,
    ) -> Result<Provider, String> {
        let sn = ServerName::try_from(server_name.to_owned())
            .map_err(|_| "server_name is not a DNS name".to_string())?;
        if !matches!(sn, ServerName::DnsName(_)) {
            return Err("server_name must be a DNS name".into());
        }
        Ok(Provider {
            addr,
            host: server_name.to_owned(),
            server_name: sn,
            tls: TlsConnector::from(Arc::new(tls)),
            key,
            limits,
        })
    }

    fn build(&self, call: &Call) -> Option<Request<Full<Bytes>>> {
        let auth = {
            let mut v = Zeroizing::new(String::with_capacity(7 + self.key.0.len()));
            v.push_str("Bearer ");
            v.push_str(&self.key.0);
            let mut h = HeaderValue::from_str(&v).ok()?;
            h.set_sensitive(true);
            h
        };
        let (method, pq, body, idem) = match call {
            Call::Create { idem_key, form } => (
                Method::POST,
                "/v1/refunds".to_string(),
                Bytes::from(form.clone().into_bytes()),
                Some(idem_key.as_str()),
            ),
            Call::Get { path_and_query } => {
                (Method::GET, path_and_query.clone(), Bytes::new(), None)
            }
        };
        let mut b = Request::builder()
            .method(method.clone())
            .uri(pq)
            .header(hyper::header::HOST, HeaderValue::from_str(&self.host).ok()?)
            .header(hyper::header::AUTHORIZATION, auth)
            .header(hyper::header::USER_AGENT, USER_AGENT);
        if let Some(k) = idem {
            b = b.header(
                HeaderName::from_static("idempotency-key"),
                HeaderValue::from_str(k).ok()?,
            );
        }
        if method == Method::POST {
            b = b
                .header(
                    hyper::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .header(hyper::header::CONTENT_LENGTH, body.len());
        }
        b.body(Full::new(body)).ok()
    }

    /// Performs one exchange under the §5 limits, with its own `total_ms` deadline.
    pub async fn exchange(&self, call: &Call) -> Exchange {
        let deadline = Instant::now() + Duration::from_millis(self.limits.total_ms);
        self.exchange_by(call, deadline).await
    }

    /// Performs one exchange that must finish by `deadline` (the request's deadline, PC-A-02).
    /// Connect + handshake are bounded by `connect_ms` and by the deadline.
    pub async fn exchange_by(&self, call: &Call, deadline: Instant) -> Exchange {
        let Some(req) = self.build(call) else {
            // Nothing was written; the values are pattern-checked, so this does not happen.
            return Exchange::NotSent(NotSentCause::Connect);
        };
        let start = Instant::now();
        let connect_budget = Duration::from_millis(self.limits.connect_ms)
            .min(deadline.saturating_duration_since(start));

        // Phase 1: TCP connect and TLS handshake. No request byte exists on the wire yet.
        let tcp = match timeout(connect_budget, TcpStream::connect(self.addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(_)) | Err(_) => return Exchange::NotSent(NotSentCause::Connect),
        };
        let _ = tcp.set_nodelay(true);
        let left = connect_budget.saturating_sub(start.elapsed());
        let tls = match timeout(left, self.tls.connect(self.server_name.clone(), tcp)).await {
            Ok(Ok(s)) => s,
            Ok(Err(_)) | Err(_) => return Exchange::NotSent(NotSentCause::Tls),
        };

        // Phase 2: from here on, any failure is ambiguous.
        let mut builder = hyper::client::conn::http1::Builder::new();
        builder
            .max_headers(MAX_RESPONSE_HEADERS)
            .max_buf_size(self.limits.max_head.max(8192))
            .max_header_size(self.limits.max_head)
            .allow_obsolete_multiline_headers_in_responses(false)
            .allow_spaces_after_header_name_in_responses(false)
            .ignore_invalid_headers_in_responses(false)
            .http09_responses(false);
        let work = async {
            let (mut sender, conn) = match builder.handshake(TokioIo::new(tls)).await {
                Ok(v) => v,
                Err(_) => return Exchange::Failed(AmbCause::ResetAfterSend),
            };
            let _driver = AbortOnDrop(tokio::spawn(async move {
                let _ = conn.await;
            }));
            run(&mut sender, req, self.limits.max_body).await
        };
        match timeout_at(deadline, work).await {
            Ok(x) => x,
            Err(_) => Exchange::Failed(AmbCause::Timeout),
        }
    }
}

/// hyper's "head too large" predicate exists only with its `server` feature, which the adapter
/// does not enable; an oversized head or more than 64 headers is therefore `bad_headers`.
fn hyper_cause(e: &hyper::Error) -> AmbCause {
    if e.is_parse() || e.is_parse_status() {
        AmbCause::BadHeaders
    } else if e.is_timeout() {
        AmbCause::Timeout
    } else {
        AmbCause::ResetAfterSend
    }
}

/// Header values must be visible ASCII, space or tab (§5).
fn headers_clean(h: &hyper::HeaderMap) -> bool {
    h.values().all(|v| {
        v.as_bytes()
            .iter()
            .all(|&b| b == b'\t' || (0x20..=0x7e).contains(&b))
    })
}

async fn run(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    req: Request<Full<Bytes>>,
    max_body: usize,
) -> Exchange {
    let resp = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => return Exchange::Failed(hyper_cause(&e)),
    };
    if !headers_clean(resp.headers()) {
        return Exchange::Failed(AmbCause::BadHeaders);
    }
    let status = resp.status().as_u16();
    let mut cts = resp.headers().get_all(hyper::header::CONTENT_TYPE).iter();
    let json_content_type = matches!((cts.next(), cts.next()),
        (Some(v), None) if v.as_bytes() == b"application/json");
    if !decodes_body(status) {
        // 5xx, 3xx and unexpected statuses: the body is not decoded (and not read).
        return Exchange::Response {
            status,
            json_content_type,
            body: None,
        };
    }
    let body = match Limited::new(resp.into_body(), max_body).collect().await {
        Ok(c) => Ok(c.to_bytes().to_vec()),
        Err(e) => Err(
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                AmbCause::Oversized
            } else if let Some(h) = e.downcast_ref::<hyper::Error>() {
                match hyper_cause(h) {
                    AmbCause::BadHeaders => AmbCause::BadHeaders,
                    _ => AmbCause::ResetAfterSend,
                }
            } else {
                AmbCause::ResetAfterSend
            },
        ),
    };
    Exchange::Response {
        status,
        json_content_type,
        body: Some(body),
    }
}

/// `application/x-www-form-urlencoded` serialization (§5): every byte outside
/// `[A-Za-z0-9*-._]` is percent-encoded (the values passed here are pattern-checked, so they
/// contain no space).
pub fn form(pairs: &[(&str, &str)]) -> String {
    let mut s = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encoding() {
        assert_eq!(
            form(&[
                ("charge", "ch_ABCDEFGH"),
                ("amount", "500"),
                ("reference", "a-b_c")
            ]),
            "charge=ch_ABCDEFGH&amount=500&reference=a-b_c"
        );
        assert_eq!(form(&[("k", "a&b=c/d?e")]), "k=a%26b%3Dc%2Fd%3Fe");
    }

    #[test]
    fn header_value_check() {
        let mut h = hyper::HeaderMap::new();
        h.insert("x", HeaderValue::from_static("visible text\tok"));
        assert!(headers_clean(&h));
        h.insert("y", HeaderValue::from_bytes(b"caf\xc3\xa9").unwrap());
        assert!(!headers_clean(&h));
    }

    #[test]
    fn call_debug_redacts_idempotency_key() {
        let c = Call::Create {
            idem_key: "SECRETKEY".into(),
            form: "charge=ch_x".into(),
        };
        let d = format!("{c:?}");
        assert!(!d.contains("SECRETKEY") && d.contains("redacted"), "{d}");
    }

    #[test]
    fn api_key_debug_redacts() {
        let k = ApiKey::new(Zeroizing::new("rk_sim_SECRET".into()));
        assert!(!format!("{k:?}").contains("SECRET"));
    }
}
