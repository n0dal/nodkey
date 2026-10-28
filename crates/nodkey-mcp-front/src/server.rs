//! The `mcp.sock` listener (agent-interface-v1 §2.2): MCP stdio framing over a Unix socket.
//!
//! - **Peer uid check (AI-11, required control).** A connection whose `SO_PEERCRED` uid is not the
//!   agent's uid is closed without a response.
//! - Bounded resources: at most [`MAX_CONNECTIONS`] connections, at most [`MAX_IN_FLIGHT`] requests
//!   in progress per connection (further lines wait), 64 KiB per line. A line over the cap gets one
//!   `-32600` error and the connection is closed (the stream cannot be resynchronised safely).
//! - Requests on one connection are handled concurrently; responses are written as they finish,
//!   one line each, correlated by `id`.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc};

use crate::mcp::{Front, INVALID_REQUEST, MAX_LINE};

pub const MAX_CONNECTIONS: usize = 8;
pub const MAX_IN_FLIGHT: usize = 8;

fn log(event: &str, fields: Value) {
    let mut v = json!({"event": event, "component": "nodkey-mcp"});
    if let (Some(o), Value::Object(f)) = (v.as_object_mut(), fields) {
        o.extend(f);
    }
    println!("{v}");
}

/// Binds `path` with mode 0660. The parent directory must be a real directory with no "other"
/// permission bits (the deployment makes it `2750`, group = the agent's group). A stale socket at
/// `path` is replaced; anything else there is an error.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("socket path has no parent"))?;
    let meta = std::fs::symlink_metadata(parent)?;
    if !meta.file_type().is_dir() || meta.mode() & 0o007 != 0 {
        return Err(std::io::Error::other(
            "socket directory must be a real directory without other-permission bits",
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()) => {
            std::fs::remove_file(path)?
        }
        Ok(_) => return Err(std::io::Error::other("non-socket file at the socket path")),
        Err(_) => {}
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(l)
}

pub enum Frame {
    Line(Vec<u8>),
    TooLarge,
    Eof,
}

/// Reads one `\n`-terminated line of at most `max` bytes (without the newline). A final line
/// without a newline is treated as end of stream (it is incomplete).
pub async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<Frame> {
    let mut buf = Vec::new();
    loop {
        let avail = r.fill_buf().await?;
        if avail.is_empty() {
            return Ok(Frame::Eof);
        }
        if let Some(pos) = avail.iter().position(|&b| b == b'\n') {
            if buf.len() + pos > max {
                return Ok(Frame::TooLarge);
            }
            buf.extend_from_slice(&avail[..pos]);
            r.consume(pos + 1);
            return Ok(Frame::Line(buf));
        }
        let n = avail.len();
        if buf.len() + n > max {
            return Ok(Frame::TooLarge);
        }
        buf.extend_from_slice(avail);
        r.consume(n);
    }
}

async fn connection(front: Arc<Front>, stream: UnixStream, agent_uid: u32) {
    let uid = match stream.peer_cred() {
        Ok(c) => c.uid(),
        Err(_) => return,
    };
    if uid != agent_uid {
        log("peer_refused", json!({"alarm": true, "peer_uid": uid}));
        return;
    }
    let (r, mut w) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<String>(MAX_IN_FLIGHT);
    let writer = tokio::spawn(async move {
        while let Some(mut line) = rx.recv().await {
            line.push('\n');
            if w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let slots = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut reader = BufReader::with_capacity(16 * 1024, r);
    loop {
        match read_line(&mut reader, MAX_LINE).await {
            Ok(Frame::Line(line)) => {
                let Ok(permit) = slots.clone().acquire_owned().await else {
                    break;
                };
                let (front, tx) = (front.clone(), tx.clone());
                tokio::spawn(async move {
                    if let Some(resp) = front.handle_line(&line).await {
                        let _ = tx.send(resp).await;
                    }
                    drop(permit);
                });
            }
            Ok(Frame::TooLarge) => {
                let e = json!({"jsonrpc": "2.0", "id": null,
                    "error": {"code": INVALID_REQUEST, "message": "Request too large"}});
                let _ = tx.send(e.to_string()).await;
                break;
            }
            Ok(Frame::Eof) | Err(_) => break,
        }
    }
    // Let in-flight requests finish, then close.
    let _ = slots.acquire_many(MAX_IN_FLIGHT as u32).await;
    drop(tx);
    let _ = writer.await;
}

/// Accept loop.
pub async fn serve(front: Arc<Front>, listener: UnixListener, agent_uid: u32) {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                log("accept_error", json!({"detail": e.to_string()}));
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            log("connection_limit", json!({}));
            continue;
        };
        let front = front.clone();
        tokio::spawn(async move {
            connection(front, stream, agent_uid).await;
            drop(permit);
        });
    }
}
