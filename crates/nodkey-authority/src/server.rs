//! Socket I (gateway → authority): `approve` and `read_grant` (effect-protocol-v2 §4.2), the
//! delivery loop and start-up recovery.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nodkey_grant::{Binding, GrantBuilder, OpKind, Operations, SigningKey, encode_transport};
use serde_json::{Map, Value, json};
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore};

use crate::broker_client::{BrokerClient, CallError, DeliverResult};
use crate::config::{ApproverSource, Workloads};
use crate::digest::{PendingId, hex, is_id, parse_hex_digest};
use crate::log;
use crate::store::{Issuance, Status, Store, StoreError};
use crate::wire::{
    Frame, MAX_LINE, PROTOCOL_VERSION, READ_TIMEOUT, exact_members, is_request_id,
    parse_strict_object, read_frame, write_line,
};

pub const MAX_GATEWAY_CONNECTIONS: usize = 16;
pub const MAX_REQUESTS_PER_CONNECTION: usize = 256;
/// Maximum `rop` entries in a read grant (grant-v1 §5.1).
pub const MAX_ROP: usize = 16;

/// Source of `now` (Unix seconds, floored). Injectable for tests.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// Settings that do not come from files.
#[derive(Debug, Clone)]
pub struct Settings {
    pub issuer: String,
    pub broker_id: String,
    pub gateway_uid: u32,
    pub grant_ttl_secs: u64,
    pub skew_secs: u64,
    pub approve_reply_timeout: Duration,
    /// Pause between delivery retries.
    pub retry_interval: Duration,
}

pub struct Authority {
    settings: Settings,
    ops: Operations,
    workloads: Workloads,
    key: SigningKey,
    store: Mutex<Store>,
    broker: BrokerClient,
    clock: Clock,
    counter: AtomicU64,
    cid_prefix: String,
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key.
        f.debug_struct("Authority")
            .field("issuer", &self.settings.issuer)
            .field("broker_id", &self.settings.broker_id)
            .finish_non_exhaustive()
    }
}

/// Why a request failed. Static reason for the audit log; the gateway always sees
/// `not_available` (§4.2 "Any failure → not_available").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal(pub &'static str);

/// The final answer of one approve (for the gateway).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveOutcome {
    Ok,
    NotAvailable,
}

impl Authority {
    pub fn new(
        settings: Settings,
        ops: Operations,
        workloads: Workloads,
        key: SigningKey,
        store: Store,
        broker: BrokerClient,
        clock: Clock,
    ) -> Arc<Authority> {
        let mut seed = [0u8; 6];
        let _ = getrandom::fill(&mut seed);
        Arc::new(Authority {
            settings,
            ops,
            workloads,
            key,
            store: Mutex::new(store),
            broker,
            clock,
            counter: AtomicU64::new(0),
            cid_prefix: hex(&seed),
        })
    }

    fn cid(&self) -> String {
        format!(
            "au-{}-{:08x}",
            self.cid_prefix,
            self.counter.fetch_add(1, Ordering::Relaxed)
        )
    }

    pub fn broker(&self) -> &BrokerClient {
        &self.broker
    }

    // ---------------------------------------------------------------- approve (§4.2)

    /// Steps 1–7 of §4.2. Returns the outcome for the gateway; every refusal is logged.
    pub async fn approve(self: &Arc<Self>, args: &Map<String, Value>, cid: &str) -> ApproveOutcome {
        match self.approve_inner(args, cid).await {
            Ok(outcome) => outcome,
            Err(Refusal(reason)) => {
                log::event(
                    "approve_refused",
                    json!({"correlation_id": cid, "reason": reason}),
                );
                ApproveOutcome::NotAvailable
            }
        }
    }

    async fn approve_inner(
        self: &Arc<Self>,
        args: &Map<String, Value>,
        cid: &str,
    ) -> Result<ApproveOutcome, Refusal> {
        // Step 1: input validation.
        exact_members(args, &["pending_id", "digest_shown", "subject"], &[]).map_err(Refusal)?;
        let pid = args["pending_id"]
            .as_str()
            .ok_or(Refusal("pending_id type"))
            .and_then(|s| PendingId::parse(s).map_err(|e| Refusal(e.0)))?;
        let shown = args["digest_shown"]
            .as_str()
            .ok_or(Refusal("digest_shown type"))
            .and_then(|s| parse_hex_digest(s).map_err(|e| Refusal(e.0)))?;
        let (ten, sub) = parse_subject(&args["subject"])?;

        // Step 2: read-only fetch.
        let fetched = match self.broker.pending_get(&pid).await {
            Ok(f) => f,
            Err(CallError::NotFound) => return Err(Refusal("pending.get: not_found")),
            Err(CallError::Unavailable(r)) => {
                log::event(
                    "broker_unavailable",
                    json!({"correlation_id": cid, "call": "pending.get", "detail": r}),
                );
                return Err(Refusal("pending.get: unavailable"));
            }
        };
        let rec = &fetched.record;

        // Step 3: checks.
        if rec.pending_id != pid {
            log::alarm(
                "broker_record_mismatch",
                json!({"correlation_id": cid, "jti": pid.to_text(), "detail": "pending_id"}),
            );
            return Err(Refusal("record pending_id differs from request"));
        }
        if rec.broker_id != self.settings.broker_id {
            return Err(Refusal("record broker_id is not this authority's broker"));
        }
        if fetched.state != "PENDING" {
            return Err(Refusal("state is not PENDING"));
        }
        let now = (self.clock)();
        if now >= rec.expires_at {
            return Err(Refusal("record expired"));
        }
        let digest = rec.digest();
        if digest != fetched.broker_digest {
            log::alarm(
                "broker_digest_mismatch",
                json!({"correlation_id": cid, "jti": pid.to_text()}),
            );
            return Err(Refusal("recomputed digest differs from broker digest"));
        }
        if digest != shown {
            return Err(Refusal("digest_shown differs from record digest"));
        }
        if ten != rec.ten || sub != rec.approver_sub {
            return Err(Refusal("subject is not the intended approver"));
        }
        let wl = self
            .workloads
            .get(&rec.wid)
            .ok_or(Refusal("workload not registered"))?;
        if !wl.tenants.contains(&rec.ten) {
            return Err(Refusal("tenant not registered for workload"));
        }
        if !wl.write_ops.contains(&rec.op) {
            return Err(Refusal("operation not allowed for workload"));
        }
        let decl = self
            .ops
            .get(&rec.op)
            .ok_or(Refusal("operation not declared"))?;
        if decl.kind != OpKind::Write || !decl.requires_confirmation {
            return Err(Refusal("operation is not a confirmed write"));
        }
        if decl.opv != rec.opv {
            return Err(Refusal("opv differs from declaration"));
        }
        if decl.params.len() != rec.param_types.len()
            || decl
                .params
                .iter()
                .any(|p| rec.param_types.get(&p.name) != Some(&p.ty))
        {
            return Err(Refusal("param_types differ from declaration"));
        }
        match &wl.approver_source {
            ApproverSource::Enrolled { ten: et, sub: es } => {
                if *et != rec.ten || *es != rec.approver_sub {
                    return Err(Refusal("approver is not the enrolled principal"));
                }
            }
            ApproverSource::Named => {
                if decl.params.iter().any(|p| p.destination) {
                    return Err(Refusal("named workload: destination operation"));
                }
            }
        }

        // Steps 4–5: exactly once, then sign and store before any delivery.
        let row = {
            let mut store = self.store.lock().await;
            match store.get(&pid) {
                Some(row) if row.digest == digest && row.ten == ten && row.sub == sub => {
                    log::event(
                        "issuance_exists",
                        json!({"correlation_id": cid, "jti": pid.to_text(), "status": row.status.as_str()}),
                    );
                    row.clone()
                }
                Some(_) => {
                    log::alarm(
                        "issuance_conflict",
                        json!({"correlation_id": cid, "jti": pid.to_text(), "digest": hex(&digest)}),
                    );
                    return Err(Refusal(
                        "existing issuance with different digest or subject",
                    ));
                }
                None => {
                    let iat = (self.clock)();
                    let exp = iat + self.settings.grant_ttl_secs;
                    let mut b = GrantBuilder::write(&rec.op, rec.opv)
                        .issuer(&self.settings.issuer)
                        .audience(&self.settings.broker_id)
                        .jti(pid.0)
                        .times(iat, iat, exp)
                        .workload(&rec.wid)
                        .tenant(&rec.ten)
                        .subject(&rec.approver_sub)
                        .confirmed(true);
                    for p in &decl.params {
                        let v = rec.params[&p.name].clone();
                        b = match p.binding {
                            Binding::Resource(k) => b.resource(k, v),
                            Binding::Exact(k) => b.exact(k, v),
                            Binding::Free => b,
                            Binding::Bounded(_) | Binding::OwnerScoped => {
                                return Err(Refusal("declaration not exact-bindable"));
                            }
                        };
                    }
                    let grant = b.sign(&self.key).map_err(|e| Refusal(e.0))?;
                    let row = Issuance {
                        jti: pid,
                        digest,
                        ten: rec.ten.clone(),
                        sub: rec.approver_sub.clone(),
                        wid: rec.wid.clone(),
                        op: rec.op.clone(),
                        signed_at: iat,
                        exp,
                        grant,
                        status: Status::Signed,
                    };
                    match store.insert(row.clone()) {
                        Ok(()) => {}
                        Err(e) => {
                            log::alarm(
                                "issuance_store_failed",
                                json!({"correlation_id": cid, "jti": pid.to_text(), "detail": format!("{e:?}")}),
                            );
                            return Err(Refusal("issuance store write failed"));
                        }
                    }
                    log::event(
                        "grant_signed",
                        json!({
                            "correlation_id": cid, "jti": pid.to_text(), "kind": "write",
                            "digest": hex(&digest), "wid": row.wid, "ten": row.ten, "sub": row.sub,
                            "op": row.op, "iat": iat, "exp": exp,
                        }),
                    );
                    row
                }
            }
        };

        // Steps 6–7.
        match row.status {
            Status::Accepted => return Ok(ApproveOutcome::Ok),
            Status::Rejected | Status::Expired => return Err(Refusal("issuance already final")),
            Status::Signed => {}
        }
        let this = self.clone();
        let task = tokio::spawn(async move { this.deliver_until_deadline(row).await });
        match tokio::time::timeout(self.settings.approve_reply_timeout, task).await {
            Ok(Ok(Some(DeliverResult::Accepted))) => Ok(ApproveOutcome::Ok),
            Ok(_) => Err(Refusal("delivery not accepted")),
            // Delivery continues in the background; the gateway shows a neutral page.
            Err(_) => Err(Refusal("delivery still in progress at reply deadline")),
        }
    }

    /// §4.2 step 6: deliver the stored bytes; retry while `now < exp`; mark `expired` if not
    /// accepted by `exp + skew`. Returns the final broker result, or `None` on expiry or a store
    /// failure.
    pub async fn deliver_until_deadline(self: Arc<Self>, row: Issuance) -> Option<DeliverResult> {
        let jti = row.jti;
        let mut attempts = 0u32;
        while (self.clock)() < row.exp {
            attempts += 1;
            match self.broker.deliver(&jti, &row.grant).await {
                Ok(result) => {
                    let status = match result {
                        DeliverResult::Accepted => Status::Accepted,
                        DeliverResult::Rejected => Status::Rejected,
                        DeliverResult::Expired => Status::Expired,
                    };
                    let fields = json!({"jti": jti.to_text(), "result": status.as_str(), "attempts": attempts});
                    if result == DeliverResult::Rejected {
                        log::alarm("grant_delivery_rejected", fields);
                    } else {
                        log::event("grant_delivered", fields);
                    }
                    self.finish(&jti, status).await;
                    return Some(result);
                }
                Err(e) => {
                    log::event(
                        "grant_delivery_retry",
                        json!({"jti": jti.to_text(), "attempt": attempts, "detail": format!("{e:?}")}),
                    );
                    tokio::time::sleep(self.settings.retry_interval).await;
                }
            }
        }
        // No accepted by exp: wait until exp + skew (the broker can no longer verify it), then
        // record `expired`.
        let deadline = row.exp + self.settings.skew_secs;
        loop {
            let now = (self.clock)();
            if now >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200).min(Duration::from_secs(deadline - now)))
                .await;
        }
        log::event(
            "grant_delivery_expired",
            json!({"jti": jti.to_text(), "attempts": attempts}),
        );
        self.finish(&jti, Status::Expired).await;
        None
    }

    async fn finish(&self, jti: &PendingId, status: Status) {
        let mut store = self.store.lock().await;
        match store.set_status(jti, status) {
            Ok(()) | Err(StoreError::AlreadyFinal) => {}
            Err(e) => log::alarm(
                "issuance_status_write_failed",
                json!({"jti": jti.to_text(), "status": status.as_str(), "detail": format!("{e:?}")}),
            ),
        }
    }

    /// Start-up recovery (T29/T46): re-deliver the stored bytes of every `signed` row before its
    /// `exp`, or mark it expired. Returns the spawned tasks.
    pub async fn recover(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<Option<DeliverResult>>> {
        let rows = self.store.lock().await.unfinished();
        log::event("recovery_start", json!({"unfinished": rows.len()}));
        rows.into_iter()
            .map(|row| {
                let this = self.clone();
                tokio::spawn(async move { this.deliver_until_deadline(row).await })
            })
            .collect()
    }

    /// Test and operator helper: the stored row for `jti`.
    pub async fn issuance(&self, jti: &PendingId) -> Option<Issuance> {
        self.store.lock().await.get(jti).cloned()
    }

    // ---------------------------------------------------------------- read_grant (§4.2)

    pub fn read_grant(&self, args: &Map<String, Value>, cid: &str) -> Result<String, Refusal> {
        exact_members(args, &["subject", "wid", "rop"], &[]).map_err(Refusal)?;
        let (ten, sub) = parse_subject(&args["subject"])?;
        let wid = args["wid"]
            .as_str()
            .filter(|w| is_id(w, 256))
            .ok_or(Refusal("wid"))?;
        let rop = args["rop"].as_array().ok_or(Refusal("rop type"))?;
        if rop.is_empty() || rop.len() > MAX_ROP {
            return Err(Refusal("rop must have 1..=16 entries"));
        }
        let wl = self
            .workloads
            .get(wid)
            .ok_or(Refusal("workload not registered"))?;
        if !wl.tenants.contains(&ten) {
            return Err(Refusal("subject tenant not registered for workload"));
        }
        let mut b = GrantBuilder::read();
        let mut seen = std::collections::BTreeSet::new();
        for op in rop {
            let op = op.as_str().ok_or(Refusal("rop entry type"))?;
            if !seen.insert(op) {
                return Err(Refusal("duplicate rop entry"));
            }
            if !wl.read_ops.contains(op) {
                return Err(Refusal("rop entry not allowed for workload"));
            }
            let d = self.ops.get(op).ok_or(Refusal("rop entry not declared"))?;
            if d.kind != OpKind::Read {
                return Err(Refusal("rop entry is not a read operation"));
            }
            b = b.read_op(op, d.opv);
        }
        let mut jti = [0u8; 16];
        getrandom::fill(&mut jti).map_err(|_| Refusal("CSPRNG"))?;
        let iat = (self.clock)();
        let exp = iat + self.settings.grant_ttl_secs;
        let grant = b
            .issuer(&self.settings.issuer)
            .audience(&self.settings.broker_id)
            .jti(jti)
            .times(iat, iat, exp)
            .workload(wid)
            .tenant(&ten)
            .subject(&sub)
            .sign(&self.key)
            .map_err(|e| Refusal(e.0))?;
        log::event(
            "grant_signed",
            json!({
                "correlation_id": cid, "jti": encode_transport(&jti), "kind": "read", "wid": wid,
                "ten": ten, "sub": sub, "rop": seen.into_iter().collect::<Vec<_>>(), "iat": iat, "exp": exp,
            }),
        );
        Ok(encode_transport(&grant))
    }

    // ---------------------------------------------------------------- socket I

    async fn handle_line(self: &Arc<Self>, line: &[u8]) -> Value {
        let cid = self.cid();
        let err = |id: Option<&str>, code: &str| {
            json!({"v": PROTOCOL_VERSION, "id": id, "correlation_id": cid, "ok": false,
                   "error": {"code": code, "message": static_message(code)}})
        };
        let Ok(o) = parse_strict_object(line) else {
            log::event("request_malformed", json!({"correlation_id": cid}));
            return err(None, "malformed_request");
        };
        let id = o
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| is_request_id(s));
        if exact_members(&o, &["v", "id", "op", "args"], &[]).is_err() || id.is_none() {
            log::event("request_malformed", json!({"correlation_id": cid}));
            return err(id, "malformed_request");
        }
        if o["v"].as_u64() != Some(PROTOCOL_VERSION) || o["v"].is_f64() {
            return err(id, "unsupported_version");
        }
        let Some(args) = o["args"].as_object() else {
            return err(id, "malformed_request");
        };
        match o["op"].as_str() {
            Some("approve") => match self.approve(args, &cid).await {
                ApproveOutcome::Ok => {
                    json!({"v": PROTOCOL_VERSION, "id": id, "correlation_id": cid, "ok": true, "result": {}})
                }
                ApproveOutcome::NotAvailable => err(id, "not_available"),
            },
            Some("read_grant") => match self.read_grant(args, &cid) {
                Ok(g) => {
                    json!({"v": PROTOCOL_VERSION, "id": id, "correlation_id": cid, "ok": true, "result": {"grant": g}})
                }
                Err(Refusal(reason)) => {
                    log::event(
                        "read_grant_refused",
                        json!({"correlation_id": cid, "reason": reason}),
                    );
                    err(id, "not_available")
                }
            },
            _ => err(id, "unknown_operation"),
        }
    }

    async fn handle_connection(self: Arc<Self>, stream: UnixStream) {
        let peer = match stream.peer_cred() {
            Ok(c) => c,
            Err(_) => {
                log::event("gateway_peer_cred_error", json!({}));
                return;
            }
        };
        if peer.uid() != self.settings.gateway_uid {
            // §1.2: close every connection whose uid differs; nothing is sent.
            log::alarm(
                "gateway_peer_uid_rejected",
                json!({"peer_uid": peer.uid(), "peer_pid": peer.pid(), "expected_uid": self.settings.gateway_uid}),
            );
            return;
        }
        let (r, mut w) = stream.into_split();
        let mut reader = BufReader::with_capacity(MAX_LINE + 1, r);
        let mut buf = Vec::with_capacity(1024);
        for _ in 0..MAX_REQUESTS_PER_CONNECTION {
            let frame = match tokio::time::timeout(
                READ_TIMEOUT,
                read_frame(&mut reader, MAX_LINE, &mut buf),
            )
            .await
            {
                Ok(Ok(f)) => f,
                _ => return,
            };
            let resp = match frame {
                Frame::Eof => return,
                Frame::Line => self.handle_line(&buf).await,
                Frame::Incomplete | Frame::TooLarge => {
                    let code = if frame == Frame::TooLarge {
                        "request_too_large"
                    } else {
                        "malformed_request"
                    };
                    let v = json!({"v": PROTOCOL_VERSION, "id": null, "correlation_id": self.cid(), "ok": false,
                                   "error": {"code": code, "message": static_message(code)}});
                    let _ = write_line(&mut w, &v).await;
                    return;
                }
            };
            if !write_line(&mut w, &resp).await {
                log::event(
                    "response_not_delivered",
                    json!({"correlation_id": resp["correlation_id"]}),
                );
                return;
            }
        }
    }

    /// Accept loop for socket I.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        let limit = Arc::new(Semaphore::new(MAX_GATEWAY_CONNECTIONS));
        loop {
            let stream = match listener.accept().await {
                Ok((s, _)) => s,
                Err(e) => {
                    log::event("accept_error", json!({"detail": e.to_string()}));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                log::event("connection_refused", json!({"detail": "connection limit"}));
                drop(stream);
                continue;
            };
            let this = self.clone();
            tokio::spawn(async move {
                this.handle_connection(stream).await;
                drop(permit);
            });
        }
    }
}

fn parse_subject(v: &Value) -> Result<(String, String), Refusal> {
    let o = v.as_object().ok_or(Refusal("subject type"))?;
    exact_members(o, &["ten", "sub"], &[]).map_err(Refusal)?;
    let ten = o["ten"]
        .as_str()
        .filter(|s| is_id(s, 128))
        .ok_or(Refusal("subject.ten"))?;
    let sub = o["sub"]
        .as_str()
        .filter(|s| is_id(s, 256))
        .ok_or(Refusal("subject.sub"))?;
    Ok((ten.to_owned(), sub.to_owned()))
}

fn static_message(code: &str) -> &'static str {
    match code {
        "not_available" => "This request is not available.",
        "malformed_request" => "request is not a valid v2 request",
        "unsupported_version" => "protocol version not supported",
        "request_too_large" => "request exceeds maximum size",
        "unknown_operation" => "operation is not declared",
        _ => "error",
    }
}
