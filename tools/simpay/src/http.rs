//! A deliberately small HTTP/1.1 implementation over raw TCP.
//!
//! simpay writes responses byte-by-byte itself so that faults can produce what a
//! general-purpose server library would refuse to emit: dropped connections after a
//! commit, slow-drip bodies, raw CR/LF or NUL bytes in headers, duplicate
//! `Content-Length`, and so on. Inbound parsing is strict and bounded: one request per
//! connection, no chunked bodies, a 16 KiB head limit and a 16 KiB body limit.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const MAX_HEAD: usize = 16 * 1024;
pub const MAX_BODY: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 64;
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Header attached to every response from both listeners.
pub const SIMULATOR_HEADER: (&str, &str) = (
    "Simpay-Simulator",
    "SIMULATED payment provider - not a real payment API",
);

/// A header that must be unique occurred more than once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateHeader;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    /// Header names lowercased; values are visible ASCII (validated).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: SocketAddr,
}

impl Request {
    /// Returns the single value of a header; `Err` if it occurs more than once.
    pub fn header(&self, name: &str) -> Result<Option<&str>, DuplicateHeader> {
        let mut it = self.headers.iter().filter(|(n, _)| n == name);
        let first = it.next().map(|(_, v)| v.as_str());
        if it.next().is_some() {
            return Err(DuplicateHeader);
        }
        Ok(first)
    }
}

/// How the response bytes reach the client.
#[derive(Debug, Clone)]
pub enum Wire {
    Normal,
    /// Close the connection without sending anything.
    Drop,
    /// Sleep before writing.
    Delay(Duration),
    /// Write `chunk` bytes, then sleep `interval`, until done.
    Drip {
        chunk: usize,
        interval: Duration,
    },
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// Raw header lines (name, value bytes). Values are written verbatim.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
    pub wire: Wire,
}

impl Response {
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Self::raw_json(status, body)
    }

    pub fn raw_json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), b"application/json".to_vec())],
            body,
            wire: Wire::Normal,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.as_bytes().to_vec()));
        self
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(name))
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name.into(), value.as_bytes().to_vec()));
    }

    /// Serializes the status line, headers and body.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 512);
        out.extend_from_slice(
            format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status)).as_bytes(),
        );
        out.extend_from_slice(
            format!("{}: {}\r\n", SIMULATOR_HEADER.0, SIMULATOR_HEADER.1).as_bytes(),
        );
        for (n, v) in &self.headers {
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v);
            out.extend_from_slice(b"\r\n");
        }
        if !self.has_header("content-length") {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(b"Connection: close\r\n\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        302 => "Found",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Error while reading a request; carries the status to answer with.
#[derive(Debug)]
pub struct ReadError {
    pub status: u16,
    pub message: &'static str,
    /// When true, the peer is gone; nothing should be written.
    pub silent: bool,
}

fn rerr(status: u16, message: &'static str) -> ReadError {
    ReadError {
        status,
        message,
        silent: false,
    }
}

/// Reads exactly one request from `stream` with the limits above.
pub async fn read_request(stream: &mut TcpStream, peer: SocketAddr) -> Result<Request, ReadError> {
    match timeout(READ_TIMEOUT, read_request_inner(stream, peer)).await {
        Ok(r) => r,
        Err(_) => Err(rerr(408, "request_timeout")),
    }
}

async fn read_request_inner(
    stream: &mut TcpStream,
    peer: SocketAddr,
) -> Result<Request, ReadError> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let head_len = loop {
        let n = stream.read(&mut chunk).await.map_err(|_| ReadError {
            status: 400,
            message: "io",
            silent: true,
        })?;
        if n == 0 {
            return Err(ReadError {
                status: 400,
                message: "eof",
                silent: true,
            });
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err(rerr(431, "request_head_too_large"));
        }
    };
    if head_len > MAX_HEAD {
        return Err(rerr(431, "request_head_too_large"));
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let status = req.parse(&buf[..head_len]).map_err(|e| match e {
        httparse::Error::TooManyHeaders => rerr(431, "too_many_headers"),
        _ => rerr(400, "malformed_request"),
    })?;
    if status.is_partial() {
        return Err(rerr(400, "malformed_request"));
    }
    if req.version != Some(1) {
        return Err(rerr(400, "http_1_1_required"));
    }
    let method = req.method.unwrap_or("").to_string();
    let target = req.path.unwrap_or("");
    if !target.starts_with('/') {
        return Err(rerr(400, "origin_form_required"));
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target.to_string(), None),
    };
    let mut hs = Vec::with_capacity(req.headers.len());
    for h in req.headers.iter() {
        if !h
            .value
            .iter()
            .all(|b| (0x20..0x7f).contains(b) || *b == b'\t')
        {
            return Err(rerr(400, "invalid_header_value"));
        }
        let v = String::from_utf8_lossy(h.value).trim().to_string();
        hs.push((h.name.to_ascii_lowercase(), v));
    }
    if hs.iter().any(|(n, _)| n == "transfer-encoding") {
        return Err(rerr(501, "transfer_encoding_unsupported"));
    }
    let cls: Vec<&str> = hs
        .iter()
        .filter(|(n, _)| n == "content-length")
        .map(|(_, v)| v.as_str())
        .collect();
    let body_len = match cls.as_slice() {
        [] => 0,
        [v] => {
            if v.is_empty() || v.len() > 9 || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(rerr(400, "invalid_content_length"));
            }
            v.parse::<usize>()
                .map_err(|_| rerr(400, "invalid_content_length"))?
        }
        _ => return Err(rerr(400, "duplicate_content_length")),
    };
    if body_len > MAX_BODY {
        return Err(rerr(413, "body_too_large"));
    }
    let mut body = buf[head_len..].to_vec();
    if body.len() > body_len {
        return Err(rerr(400, "body_exceeds_content_length"));
    }
    while body.len() < body_len {
        let n = stream.read(&mut chunk).await.map_err(|_| ReadError {
            status: 400,
            message: "io",
            silent: true,
        })?;
        if n == 0 {
            return Err(ReadError {
                status: 400,
                message: "eof",
                silent: true,
            });
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > body_len {
            return Err(rerr(400, "body_exceeds_content_length"));
        }
    }
    Ok(Request {
        method,
        path,
        query,
        headers: hs,
        body,
        peer,
    })
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Writes `resp` according to its wire mode, then closes the connection.
pub async fn write_response(stream: &mut TcpStream, resp: &Response) {
    match &resp.wire {
        Wire::Drop => {
            let _ = stream.shutdown().await;
            return;
        }
        Wire::Delay(d) => tokio::time::sleep(*d).await,
        _ => {}
    }
    let bytes = resp.to_bytes();
    match &resp.wire {
        Wire::Drip { chunk, interval } => {
            let chunk = (*chunk).max(1);
            for part in bytes.chunks(chunk) {
                if stream.write_all(part).await.is_err() {
                    return;
                }
                let _ = stream.flush().await;
                tokio::time::sleep(*interval).await;
            }
        }
        _ => {
            let _ = stream.write_all(&bytes).await;
        }
    }
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

/// `http://host:port/path` (no TLS, no userinfo, no fragment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_http_url(url: &str) -> Result<HttpUrl, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("webhook URL must start with http://")?;
    if rest.contains('@') || rest.contains('#') || rest.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
        return Err("webhook URL contains forbidden characters".into());
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = if let Some(h) = authority.strip_prefix('[') {
        let (h, p) = h.split_once(']').ok_or("bad IPv6 literal")?;
        let p = p
            .strip_prefix(':')
            .ok_or("webhook URL needs an explicit port")?;
        (h.to_string(), p)
    } else {
        let (h, p) = authority
            .rsplit_once(':')
            .ok_or("webhook URL needs an explicit port")?;
        (h.to_string(), p)
    };
    if host.is_empty() {
        return Err("webhook URL host is empty".into());
    }
    let port: u16 = port.parse().map_err(|_| "bad port")?;
    if port == 0 {
        return Err("bad port".into());
    }
    Ok(HttpUrl {
        host,
        port,
        path: path.to_string(),
    })
}

/// Minimal outbound POST used for webhook delivery. Returns the response status.
pub async fn post(
    url: &HttpUrl,
    headers: &[(String, String)],
    body: &[u8],
    limit: Duration,
) -> Result<u16, String> {
    let fut = async {
        let mut s = TcpStream::connect((url.host.as_str(), url.port))
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let host = if url.host.contains(':') {
            format!("[{}]:{}", url.host, url.port)
        } else {
            format!("{}:{}", url.host, url.port)
        };
        let mut req = format!(
            "POST {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: simpay-simulator/0.1\r\n\
             Content-Length: {}\r\nConnection: close\r\n",
            url.path,
            body.len()
        );
        for (n, v) in headers {
            req.push_str(n);
            req.push_str(": ");
            req.push_str(v);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        s.write_all(body).await.map_err(|e| format!("write: {e}"))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = s.read(&mut chunk).await.map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if find(&buf, b"\r\n\r\n").is_some() || buf.len() > MAX_HEAD {
                break;
            }
        }
        let mut hdrs = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut resp = httparse::Response::new(&mut hdrs);
        match resp.parse(&buf) {
            Ok(_) => resp.code.ok_or_else(|| "no status".to_string()),
            Err(e) => Err(format!("parse: {e}")),
        }
    };
    match timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err("timeout".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_http_url("http://127.0.0.1:9000/hook").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("127.0.0.1", 9000, "/hook")
        );
        let u = parse_http_url("http://[::1]:80").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("::1", 80, "/"));
        assert!(parse_http_url("https://a:1/").is_err());
        assert!(parse_http_url("http://a/").is_err());
        assert!(parse_http_url("http://u@a:1/").is_err());
        assert!(parse_http_url("http://a:1/\r\nX: y").is_err());
        assert!(parse_http_url("http://a:0/").is_err());
    }

    #[test]
    fn serializes_with_simulator_header() {
        let r = Response::json(200, &serde_json::json!({"a":1}));
        let b = String::from_utf8(r.to_bytes()).unwrap();
        assert!(b.starts_with("HTTP/1.1 200 OK\r\nSimpay-Simulator: SIMULATED"));
        assert!(b.contains("Content-Length: 7\r\n"));
        assert!(b.ends_with("\r\n\r\n{\"a\":1}"));
    }
}
