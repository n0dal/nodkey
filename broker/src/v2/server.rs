//! v2 Unix-socket listeners (spec §1.2): one socket per workload (W), one for the gateway (G),
//! one for the authority (A). Every connection's `SO_PEERCRED` uid must equal the uid configured
//! for that socket; otherwise the connection is answered `unauthenticated` and closed. The socket
//! a request arrives on is the only source of the workload identity.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use super::config::{MAX_LINE_BYTES, WorkloadReg};
use super::ids::decode_id;
use super::service::{Broker, Delivery, RECOVERY_PERIOD};
use super::wire::{Code, Fail, err_response, ok_response, parse_envelope};
use crate::server::{
    CorrelationIds, Frame, MAX_CONNECTIONS_PER_WORKLOAD, MAX_REQUESTS_PER_CONNECTION, READ_TIMEOUT,
    WRITE_TIMEOUT, log_event, read_frame,
};

/// Which socket a connection arrived on.
#[derive(Debug, Clone)]
pub enum Channel {
    Workload(Arc<WorkloadReg>),
    Gateway,
    Authority,
}

impl Channel {
    fn name(&self) -> String {
        match self {
            Channel::Workload(w) => format!("W:{}", w.wid),
            Channel::Gateway => "G".into(),
            Channel::Authority => "A".into(),
        }
    }
}

pub struct Server {
    pub broker: Arc<Broker>,
    pub ids: CorrelationIds,
}

/// Outcome of one line: the response and whether to close the connection afterwards.
pub struct Reply {
    pub response: Value,
    pub close: bool,
    /// A pending id whose grant was just accepted (execution is started by the caller).
    pub execute: Option<[u8; 16]>,
}

impl Server {
    pub async fn handle_line(&self, ch: &Channel, line: &[u8]) -> Reply {
        let cid = self.ids.next();
        let env = match parse_envelope(line) {
            Ok(e) => e,
            Err(e) => {
                log_event(
                    "v2_decision",
                    json!({"correlation_id": cid, "channel": ch.name(), "decision": "deny",
                           "code": e.fail.code.as_str(), "detail": e.fail.detail}),
                );
                // Framing violations on the control channels close the connection.
                let close = !matches!(ch, Channel::Workload(_));
                return Reply {
                    response: err_response(e.id.as_ref(), &cid, e.fail.code),
                    close,
                    execute: None,
                };
            }
        };
        let b = &self.broker;
        let mut close = false;
        let mut execute = None;
        let mut deliver_detail = String::new();
        let result: Result<Value, Fail> = match (ch, env.op.as_str()) {
            (Channel::Workload(w), "effect.propose") => b.propose(w, &env.args).await,
            (Channel::Workload(w), "effect.status") => b.status(w, &env.args).await,
            (Channel::Workload(w), op) => b.read(w, op, &env.args).await,
            (Channel::Gateway, "pending.render") => b.render(&env.args).await,
            (Channel::Gateway, "pending.deny") => b.deny(&env.args).await,
            (Channel::Authority, "pending.get") => b.pending_get(&env.args).await,
            (Channel::Authority, "config.digest") => Ok(b.config_digest()),
            (Channel::Authority, "grant.deliver") => match b.deliver(&env.args).await {
                Delivery::Accepted => {
                    execute = env
                        .args
                        .get("pending_id")
                        .and_then(Value::as_str)
                        .and_then(decode_id);
                    Ok(json!({"status": "accepted"}))
                }
                // Authority wire format (crates/nodkey-authority README, AU-1): rejected and
                // expired are results; only `unavailable` is an error.
                Delivery::Rejected(d) => {
                    deliver_detail = d;
                    Ok(json!({"status": "rejected"}))
                }
                Delivery::Expired(d) => {
                    deliver_detail = d;
                    Ok(json!({"status": "expired"}))
                }
                Delivery::Unavailable(d) => Err(Fail::new(Code::Unavailable, d)),
            },
            // Anything else on a control socket (including a grant on G, T16) is refused and
            // the connection is closed.
            (Channel::Gateway | Channel::Authority, _) => {
                close = true;
                Err(Fail::new(
                    Code::UnknownOperation,
                    "method not served on this socket",
                ))
            }
        };
        let (decision, code, detail) = match &result {
            Ok(_) => ("allow", None, deliver_detail),
            Err(f) => ("deny", Some(f.code.as_str()), f.detail.clone()),
        };
        log_event(
            "v2_decision",
            json!({"correlation_id": cid, "channel": ch.name(), "op": env.op.chars().take(64).collect::<String>(),
                   "decision": decision, "code": code, "detail": detail}),
        );
        let response = match result {
            Ok(v) => ok_response(&env.id, &cid, v),
            Err(f) => err_response(Some(&env.id), &cid, f.code),
        };
        Reply {
            response,
            close,
            execute,
        }
    }
}

async fn write_line(w: &mut (impl AsyncWriteExt + Unpin), v: &Value) -> bool {
    let mut bytes = v.to_string().into_bytes();
    bytes.push(b'\n');
    matches!(
        tokio::time::timeout(WRITE_TIMEOUT, w.write_all(&bytes)).await,
        Ok(Ok(()))
    )
}

pub fn spawn_execution(server: &Arc<Server>, pid: [u8; 16]) {
    let s = server.clone();
    tokio::spawn(async move {
        let cid = s.ids.next();
        let _ = s.broker.execute(pid, &cid).await;
    });
}

async fn handle_connection(
    stream: UnixStream,
    ch: Channel,
    expected_uid: u32,
    server: Arc<Server>,
) {
    let uid = match stream.peer_cred() {
        Ok(c) => c.uid(),
        Err(e) => {
            log_event(
                "peer_cred_error",
                json!({"channel": ch.name(), "detail": e.to_string()}),
            );
            return;
        }
    };
    let (r, mut w) = stream.into_split();
    if uid != expected_uid {
        let cid = server.ids.next();
        log_event(
            "v2_decision",
            json!({"correlation_id": cid, "channel": ch.name(), "decision": "deny",
                   "code": Code::Unauthenticated.as_str(), "peer_uid": uid}),
        );
        let _ = write_line(&mut w, &err_response(None, &cid, Code::Unauthenticated)).await;
        return;
    }
    let mut reader = BufReader::with_capacity(8192, r);
    let mut buf = Vec::with_capacity(1024);
    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let frame = match tokio::time::timeout(
            READ_TIMEOUT,
            read_frame(&mut reader, MAX_LINE_BYTES, &mut buf),
        )
        .await
        {
            Ok(Ok(f)) => f,
            Ok(Err(_)) | Err(_) => return,
        };
        let reply = match frame {
            Frame::Eof => return,
            Frame::Line => server.handle_line(&ch, &buf).await,
            Frame::Incomplete | Frame::TooLarge => {
                let code = if frame == Frame::TooLarge {
                    Code::RequestTooLarge
                } else {
                    Code::MalformedRequest
                };
                let cid = server.ids.next();
                let _ = write_line(&mut w, &err_response(None, &cid, code)).await;
                return;
            }
        };
        if let Some(pid) = reply.execute {
            spawn_execution(&server, pid);
        }
        if !write_line(&mut w, &reply.response).await || reply.close {
            return;
        }
    }
}

pub async fn serve(listener: UnixListener, ch: Channel, expected_uid: u32, server: Arc<Server>) {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_WORKLOAD));
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                log_event(
                    "accept_error",
                    json!({"channel": ch.name(), "detail": e.to_string()}),
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            // Over the connection limit: refuse rather than queue unboundedly.
            drop(stream);
            continue;
        };
        let (ch, server) = (ch.clone(), server.clone());
        tokio::spawn(async move {
            handle_connection(stream, ch, expected_uid, server).await;
            drop(permit);
        });
    }
}

/// The recovery loop (§4.4): at start-up, then every 5 s.
pub async fn recovery_loop(server: Arc<Server>) {
    loop {
        if let Err(f) = server.broker.recovery_tick().await {
            log_event("v2_recovery_error", json!({"detail": f.detail}));
        }
        tokio::time::sleep(RECOVERY_PERIOD).await;
    }
}

/// Binds a socket, removing only a stale *socket* at the path. The socket's own directory is the
/// access boundary (deployment, spec §1.2); the `SO_PEERCRED` uid check is enforced here.
pub fn bind_socket(path: &Path) -> Result<UnixListener, String> {
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if m.file_type().is_socket() {
            std::fs::remove_file(path)
                .map_err(|e| format!("remove stale socket {}: {e}", path.display()))?;
        } else {
            return Err(format!("{} exists and is not a socket", path.display()));
        }
    }
    let l = UnixListener::bind(path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(l)
}
