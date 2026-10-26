//! Socket I (gateway → authority): `approve` and `read_grant` (effect-protocol-v2 §4.2), the
//! delivery loop and start-up recovery.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use nodkey_grant::{
    Binding, GrantBuilder, OpKind, Operations, ParamType, ParamValue, SigningKey, encode_transport,
};
use serde_json::{Map, Value, json};
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore, watch};

use crate::broker_client::{BrokerClient, CallError, DeliverResult};
use crate::config::{ApproverSource, Workloads};
use crate::digest::{DisplayValue, PendingId, hex, is_id, parse_hex_digest};
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
    /// The ledger's currency (ISO 4217), for the display facts of operations without a
    /// `currency` parameter (AU-R-01). The authority never takes key 11 from the broker's word.
    pub ledger_currency: String,
}

/// Earliest plausible clock value (2024-01-01). A clock below it is treated as a clock error.
pub const MIN_SANE_TIME: u64 = 1_704_067_200;
/// Longest pending lifetime the authority accepts (§2.5: 60–900 s).
pub const MAX_PENDING_LIFETIME: u64 = 900;

/// Decimal exponents from ISO 4217 for the currencies this prototype may display (§3.2 key 11).
/// Same table as the broker's (`broker/src/v2/decls.rs`); the authority holds its own copy.
pub fn iso4217_exponent(code: &str) -> Option<u64> {
    Some(match code {
        "EUR" | "USD" | "GBP" | "CHF" | "SEK" | "NOK" | "DKK" | "CAD" | "AUD" => 2,
        "JPY" | "KRW" | "ISK" => 0,
        "BHD" | "KWD" | "JOD" | "OMR" | "TND" => 3,
        _ => return None,
    })
}

type DeliveryRx = watch::Receiver<Option<Option<DeliverResult>>>;

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
    /// Clock high-water mark: the latest `iat` this authority has used (AU-R-04).
    clock_mark: AtomicU64,
    /// At most one delivery loop per `jti` (AU-R-09).
    inflight: StdMutex<HashMap<PendingId, DeliveryRx>>,
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
        let mark = store.max_signed_at();
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
            clock_mark: AtomicU64::new(mark),
            inflight: StdMutex::new(HashMap::new()),
        })
    }

    /// `now` for signing (AU-R-04): refuses a clock error (implausibly small value) and a clock
    /// more than `skew` behind the persisted high-water mark (the latest write-grant `iat` in the
    /// store, and any `iat` used since start), then advances the mark.
    fn signing_now(&self) -> Result<u64, Refusal> {
        let now = (self.clock)();
        if now < MIN_SANE_TIME {
            log::alarm("clock_error", json!({"now": now}));
            return Err(Refusal("clock error"));
        }
        let mark = self.clock_mark.load(Ordering::SeqCst);
        if now + self.settings.skew_secs < mark {
            log::alarm(
                "clock_behind_high_water_mark",
                json!({"now": now, "mark": mark}),
            );
            return Err(Refusal("clock behind high-water mark"));
        }
        self.clock_mark.fetch_max(now, Ordering::SeqCst);
        Ok(now)
    }

    /// Key 11 as the authority itself derives it (AU-R-01): for an operation with a `currency`
    /// parameter, `{amount_exponent: ISO 4217 exponent of that value, currency: that value}`;
    /// for one with an `amount_minor` parameter and no currency parameter, the same for the
    /// configured ledger currency; otherwise `{}`.
    fn expected_display(
        &self,
        decl: &nodkey_grant::OperationDecl,
        rec: &crate::digest::PendingRecord,
    ) -> Result<BTreeMap<String, DisplayValue>, Refusal> {
        let currency_params: Vec<&str> = decl
            .params
            .iter()
            .filter(|p| p.ty == ParamType::Currency)
            .map(|p| p.name.as_str())
            .collect();
        let currency = match currency_params.as_slice() {
            [] if decl.params.iter().any(|p| p.name == "amount_minor") => {
                self.settings.ledger_currency.clone()
            }
            [] => return Ok(BTreeMap::new()),
            [name] => match rec.params.get(*name) {
                Some(ParamValue::Text(c)) => c.clone(),
                _ => return Err(Refusal("currency parameter missing")),
            },
            _ => return Err(Refusal("more than one currency parameter")),
        };
        let exp = iso4217_exponent(&currency).ok_or(Refusal("currency not in ISO 4217 table"))?;
        Ok(BTreeMap::from([
            ("amount_exponent".to_owned(), DisplayValue::Uint(exp)),
            ("currency".to_owned(), DisplayValue::Text(currency)),
        ]))
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
        // AU-R-11: bound the broker's word on the pending lifetime (§2.5).
        if rec.created_at > now + self.settings.skew_secs
            || rec.expires_at <= rec.created_at
            || rec.expires_at - rec.created_at > MAX_PENDING_LIFETIME
        {
            log::alarm(
                "broker_record_lifetime_invalid",
                json!({"correlation_id": cid, "jti": pid.to_text()}),
            );
            return Err(Refusal(
                "pending lifetime outside 0..=900 s or created in the future",
            ));
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
        // RX-6 (effect-protocol-v2 Draft 3.1 §2.3): a refund is signed only for a resolved charge;
        // the reserved value `unresolved` (or anything not a charge id) is never signed.
        let has_charge = decl.params.iter().any(|p| p.name == "charge_id");
        if rec.op == "payments.refund" || has_charge {
            match rec.params.get("charge_id") {
                Some(ParamValue::Text(c)) if is_charge_id(c) => {}
                _ => {
                    log::event(
                        "charge_id_unresolved",
                        json!({"correlation_id": cid, "jti": pid.to_text()}),
                    );
                    return Err(Refusal("charge_id is not a resolved charge id"));
                }
            }
        }
        // AU-R-01: what the gateway displayed is interpreted with key 11, so the authority
        // requires key 11 to equal its own derivation instead of trusting the broker.
        if rec.display != self.expected_display(decl, rec)? {
            log::alarm(
                "broker_display_mismatch",
                json!({"correlation_id": cid, "jti": pid.to_text(), "op": rec.op}),
            );
            return Err(Refusal("display facts differ from the authority's own"));
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
                    let iat = self.signing_now()?;
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
            Status::Accepted => {
                // The broker shows PENDING although it accepted this grant: a restore or broker
                // inconsistency (ADR-0006 §9). Safe (nothing is re-signed), but alarm (AU-R-12).
                log::alarm(
                    "accepted_issuance_but_broker_pending",
                    json!({"correlation_id": cid, "jti": pid.to_text()}),
                );
                return Ok(ApproveOutcome::Ok);
            }
            Status::Rejected | Status::Expired => return Err(Refusal("issuance already final")),
            Status::Signed => {}
        }
        let mut rx = self.deliver_shared(row);
        let wait = async move {
            rx.wait_for(Option::is_some)
                .await
                .ok()
                .and_then(|v| (*v).flatten())
        };
        match tokio::time::timeout(self.settings.approve_reply_timeout, wait).await {
            Ok(Some(DeliverResult::Accepted)) => Ok(ApproveOutcome::Ok),
            Ok(_) => Err(Refusal("delivery not accepted")),
            // Delivery continues in the background; the gateway shows a neutral page.
            Err(_) => Err(Refusal("delivery still in progress at reply deadline")),
        }
    }

    /// Starts the delivery loop for `row` unless one is already running for its `jti`, and
    /// returns a receiver for its final result (AU-R-09).
    fn deliver_shared(self: &Arc<Self>, row: Issuance) -> DeliveryRx {
        let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(rx) = map.get(&row.jti) {
            return rx.clone();
        }
        let (tx, rx) = watch::channel(None);
        map.insert(row.jti, rx.clone());
        let this = self.clone();
        tokio::spawn(async move {
            let jti = row.jti;
            let result = this.clone().deliver_until_deadline(row).await;
            this.inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&jti);
            let _ = tx.send(Some(result));
        });
        rx
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
                let mut rx = self.deliver_shared(row);
                tokio::spawn(async move {
                    rx.wait_for(Option::is_some)
                        .await
                        .ok()
                        .and_then(|v| (*v).flatten())
                })
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
        // AU-R-03: a single-principal (enrolled) workload reads only its principal's data.
        if let ApproverSource::Enrolled { ten: et, sub: es } = &wl.approver_source
            && (*et != ten || *es != sub)
        {
            return Err(Refusal(
                "enrolled workload: subject is not the enrolled principal",
            ));
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
        let iat = self.signing_now()?;
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

/// `^ch_[A-Za-z0-9]{8,64}$` (payments-adapter-v1 PA-19, RX-6).
pub fn is_charge_id(s: &str) -> bool {
    s.strip_prefix("ch_").is_some_and(|rest| {
        (8..=64).contains(&rest.len()) && rest.bytes().all(|c| c.is_ascii_alphanumeric())
    })
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
