// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

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
use crate::config::{ApproverSource, MANDATE_TEMPLATE, Workloads, is_support_op};
use crate::digest::{DisplayValue, PendingId, hex, is_id, parse_hex_digest};
use crate::log;
use crate::store::{Extra, Issuance, MandateTerms, MandatedUse, Status, Store, StoreError};
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
/// Mandate lifetime bounds (AI §4.1: `valid_for_s` 60 … 3600).
pub const MANDATE_MIN_S: u64 = 60;
pub const MANDATE_MAX_S: u64 = 3600;
/// Mandate loop period (AI §4.4: every 500 ms).
pub const MANDATE_POLL: Duration = Duration::from_millis(500);

/// Result of one mandated issuance attempt (AI §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MandateOutcome {
    /// Signed and accepted by the broker.
    Issued,
    /// Signed; the broker rejected delivery; `mandate.declined{final: true}` sent.
    Rejected,
    /// Signed; delivery still in progress at the reply deadline.
    Pending,
    /// Not within the authority's mandate: `mandate.declined{final: false}` sent.
    Declined,
    /// An issuance row already existed for this jti: nothing changed.
    Exists,
    /// `pending.get` failed.
    Unavailable,
}

/// C6 key: SHA-256 over the op name, `0x00`, and the params as canonical JSON (sorted keys).
pub fn params_key(op: &str, params: &BTreeMap<String, ParamValue>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut m = Map::new();
    for (k, v) in params {
        let j = match v {
            ParamValue::Uint(n) => json!(n),
            ParamValue::Text(t) => json!(t),
        };
        m.insert(k.clone(), j);
    }
    let mut h = Sha256::new();
    h.update(op.as_bytes());
    h.update([0u8]);
    h.update(Value::Object(m).to_string().as_bytes());
    h.finalize().into()
}

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
        let (digest, decl) = self.validate_record(&pid, &fetched, cid)?;
        let rec = &fetched.record;
        if digest != shown {
            return Err(Refusal("digest_shown differs from record digest"));
        }
        if ten != rec.ten || sub != rec.approver_sub {
            return Err(Refusal("subject is not the intended approver"));
        }
        // AI §3, §4.2: agent operations and the template (support principal, ceilings).
        let extra_terms = self.agent_approval_checks(rec)?;

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
                    // AI §4.2 step 3 / AI-04: no replacement — refuse while this authority holds
                    // an active mandate for (wid, ten, sub).
                    if extra_terms.is_some()
                        && self
                            .live_mandate(&store, &rec.wid, &rec.ten, &rec.approver_sub, false)
                            .is_some()
                    {
                        return Err(Refusal("a mandate is active for (wid, ten, sub)"));
                    }
                    let iat = self.signing_now()?;
                    let exp = iat + self.settings.grant_ttl_secs;
                    let grant = self.sign_record(rec, decl, pid, iat, None)?;
                    // The mandate is recorded in the same durable row as its grant.
                    let extra = extra_terms.map(|(t, valid)| {
                        Extra::Mandate(MandateTerms {
                            nbf: iat,
                            exp: iat + valid,
                            cfg: self.broker.config_digest(),
                            ..t
                        })
                    });
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
                    match store.insert_with(row.clone(), extra) {
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

    /// §4.2 step 3 record checks, except `digest_shown` and the subject (shared by `approve` and
    /// the mandate loop, AI §4.4). Returns the recomputed digest and the declaration.
    fn validate_record<'s>(
        &'s self,
        pid: &PendingId,
        fetched: &crate::broker_client::Fetched,
        cid: &str,
    ) -> Result<([u8; 32], &'s nodkey_grant::OperationDecl), Refusal> {
        let pid = *pid;
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

        // AI §3: the reserved unresolved value " " is never signed.
        for k in ["customer_sub", "to", "customer_email"] {
            if let Some(ParamValue::Text(v)) = rec.params.get(k)
                && (v.contains(' ') || v.is_empty())
            {
                log::event(
                    "agent_param_unresolved",
                    json!({"correlation_id": cid, "jti": pid.to_text(), "param": k}),
                );
                return Err(Refusal("unresolved agent-operation parameter"));
            }
        }
        Ok((digest, decl))
    }

    /// Signs a write grant from the fetched record only (§4.2 step 5): `cfm = 1`, or `cfm = 2`
    /// with `mid` for a mandated issuance (grant-v1 Draft 4).
    fn sign_record(
        &self,
        rec: &crate::digest::PendingRecord,
        decl: &nodkey_grant::OperationDecl,
        pid: PendingId,
        iat: u64,
        mid: Option<PendingId>,
    ) -> Result<Vec<u8>, Refusal> {
        let exp = iat + self.settings.grant_ttl_secs;
        let mut b = GrantBuilder::write(&rec.op, rec.opv)
            .issuer(&self.settings.issuer)
            .audience(&self.settings.broker_id)
            .jti(pid.0)
            .times(iat, iat, exp)
            .workload(&rec.wid)
            .tenant(&rec.ten)
            .subject(&rec.approver_sub);
        b = match mid {
            Some(m) => b.mandated(m.0),
            None => b.confirmed(true),
        };
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
        b.sign(&self.key).map_err(|e| Refusal(e.0))
    }

    /// Approval checks of the agent operations (AI §3) on the authority's own configuration:
    /// the approver is a support principal; for the template, the terms are within the
    /// ceilings. Returns the template terms (without window and `cfg`) and `valid_for_s`.
    fn agent_approval_checks(
        &self,
        rec: &crate::digest::PendingRecord,
    ) -> Result<Option<(MandateTerms, u64)>, Refusal> {
        if !is_support_op(&rec.op) {
            return Ok(None);
        }
        let m = self
            .workloads
            .mandates
            .as_ref()
            .ok_or(Refusal("agent operation without mandate configuration"))?;
        if !m.is_support_principal(&rec.ten, &rec.approver_sub) {
            return Err(Refusal("approver is not a support principal"));
        }
        if rec.op != MANDATE_TEMPLATE {
            return Ok(None);
        }
        let t = m.template.as_ref().ok_or(Refusal("no mandate template"))?;
        let u = |k: &str| match rec.params.get(k) {
            Some(ParamValue::Uint(n)) => Ok(*n),
            _ => Err(Refusal("template parameter")),
        };
        let x = |k: &str| match rec.params.get(k) {
            Some(ParamValue::Text(v)) => Ok(v.clone()),
            _ => Err(Refusal("template parameter")),
        };
        let terms = MandateTerms {
            customer_sub: x("customer_sub")?,
            customer_email: x("customer_email")?,
            currency: x("currency")?,
            refund_max_count: u("refund_max_count")?,
            refund_max_per_call_minor: u("refund_max_per_call_minor")?,
            refund_max_total_minor: u("refund_max_total_minor")?,
            message_max_count: u("message_max_count")?,
            nbf: 0,
            exp: 0,
            cfg: [0; 32],
        };
        let valid = u("valid_for_s")?;
        let ok = is_id(&terms.customer_sub, 64)
            && is_id(&terms.customer_email, 256)
            && terms.refund_max_count <= t.max_refund_count
            && terms.message_max_count <= t.max_message_count
            && terms.refund_max_per_call_minor <= terms.refund_max_total_minor
            && t.max_refund_total_minor
                .get(&terms.currency)
                .is_some_and(|c| terms.refund_max_total_minor <= *c)
            && (MANDATE_MIN_S..=MANDATE_MAX_S).contains(&valid);
        if !ok {
            return Err(Refusal("mandate terms outside the template ceilings"));
        }
        Ok(Some((terms, valid)))
    }

    /// The authority's own mandate for `(wid, ten, sub)` (AI §4.4 step 2): not revoked, its
    /// grant not finally rejected or expired at the broker, `nbf ≤ now < exp`, `cfg` current.
    ///
    /// MD-7 (fail closed): with `confirmed`, the broker's activation must also be confirmed (the
    /// only form used for mandated issuance). Without it — the no-replacement check (AI-04) — a
    /// mandate whose activation is still unconfirmed counts as live, and only a confirmed failed
    /// activation releases the key.
    fn live_mandate(
        &self,
        store: &Store,
        wid: &str,
        ten: &str,
        sub: &str,
        confirmed: bool,
    ) -> Option<(PendingId, MandateTerms)> {
        let now = (self.clock)();
        let cfg = self.broker.config_digest();
        store
            .mandates()
            .find(|(r, m)| {
                r.wid == wid
                    && r.ten == ten
                    && r.sub == sub
                    && !store.is_revoked(&r.jti)
                    && !matches!(r.status, Status::Rejected | Status::Expired)
                    && match store.activation(&r.jti) {
                        Some(active) => active,
                        None => !confirmed,
                    }
                    && m.nbf <= now
                    && now < m.exp
                    && m.cfg == cfg
            })
            .map(|(r, m)| (r.jti, m.clone()))
    }

    /// Mandated issuance for one candidate (AI §4.4). Checks the record like `approve` (except
    /// approval), then under the store lock: an existing row stops (AI-07); C1–C4 and C6 against
    /// the authority's own mandate; C5 against its own counters for refunds; then sign
    /// `cfm = 2` + `mid` and append the row (which carries the counter increment) before
    /// delivery. A refusal sends `mandate.declined{final: false}`; a delivery `rejected` sends
    /// `mandate.declined{final: true}`.
    pub async fn mandate_issue(self: &Arc<Self>, pid: PendingId) -> MandateOutcome {
        let cid = self.cid();
        let fetched = match self.broker.pending_get(&pid).await {
            Ok(f) => f,
            Err(_) => return MandateOutcome::Unavailable,
        };
        let row = match self.mandate_sign(&pid, &fetched, &cid).await {
            Ok(Some(row)) => row,
            Ok(None) => return MandateOutcome::Exists,
            Err(Refusal(reason)) => {
                log::event(
                    "mandate_declined",
                    json!({"correlation_id": cid, "jti": pid.to_text(), "reason": reason}),
                );
                let _ = self.broker.mandate_declined(&pid, false).await;
                return MandateOutcome::Declined;
            }
        };
        let mut rx = self.deliver_shared(row);
        let wait = async move {
            rx.wait_for(Option::is_some)
                .await
                .ok()
                .and_then(|v| (*v).flatten())
        };
        match tokio::time::timeout(self.settings.approve_reply_timeout, wait).await {
            Ok(Some(DeliverResult::Accepted)) => MandateOutcome::Issued,
            Ok(Some(DeliverResult::Rejected)) => {
                // effect-protocol-v2 §12.3 / AI §4.5: the jti is final; the record ends DENIED.
                let _ = self.broker.mandate_declined(&pid, true).await;
                MandateOutcome::Rejected
            }
            _ => MandateOutcome::Pending,
        }
    }

    async fn mandate_sign(
        &self,
        pid: &PendingId,
        fetched: &crate::broker_client::Fetched,
        cid: &str,
    ) -> Result<Option<Issuance>, Refusal> {
        let (digest, decl) = self.validate_record(pid, fetched, cid)?;
        let rec = &fetched.record;
        let m = self
            .workloads
            .mandates
            .as_ref()
            .ok_or(Refusal("mandates not configured"))?;
        let t = m.template.as_ref().ok_or(Refusal("no mandate template"))?;
        let mut store = self.store.lock().await;
        // 1. AI-07: an issuance row for this jti (e.g. a human approval) ends here.
        if store.get(pid).is_some() {
            return Ok(None);
        }
        // 2. C1: enrolled (checked by validate_record) and a support principal.
        if !m.is_support_principal(&rec.ten, &rec.approver_sub) {
            return Err(Refusal("C1: not a support principal"));
        }
        let text = |k: &str| match rec.params.get(k) {
            Some(ParamValue::Text(v)) => Ok(v.as_str()),
            _ => Err(Refusal("parameter")),
        };
        // C2: the authority's own active mandate.
        let (mid, terms) = self
            .live_mandate(&store, &rec.wid, &rec.ten, &rec.approver_sub, true)
            .ok_or(Refusal("C2: no active mandate"))?;
        // C3, C4.
        let refund = if rec.op == t.refund_op {
            if text("customer_sub")? != terms.customer_sub {
                return Err(Refusal("C4: customer"));
            }
            match rec.params.get("amount_minor") {
                Some(ParamValue::Uint(a)) => Some(*a),
                _ => return Err(Refusal("amount_minor")),
            }
        } else if rec.op == t.message_op {
            if text("customer_sub")? != terms.customer_sub || text("to")? != terms.customer_email {
                return Err(Refusal("C4: customer or recipient"));
            }
            None
        } else {
            return Err(Refusal("C3: operation not covered"));
        };
        // C6.
        let pkey = params_key(&rec.op, &rec.params);
        if store.used(&mid, &pkey) {
            return Err(Refusal(
                "C6: identical effect already signed under this mandate",
            ));
        }
        // 3. C5 for refunds against the authority's own counters (never released).
        if let Some(a) = refund {
            let (n, total) = store.refund_counters(&mid);
            let ok = text("currency")? == terms.currency
                && a <= terms.refund_max_per_call_minor
                && n < terms.refund_max_count
                && total
                    .checked_add(a)
                    .is_some_and(|x| x <= terms.refund_max_total_minor);
            if !ok {
                return Err(Refusal(
                    "C5: refund outside the mandate's terms or counters",
                ));
            }
        }
        // 4. Sign cfm = 2 + mid; one durable row with the counter increment, before delivery.
        let iat = self.signing_now()?;
        let grant = self.sign_record(rec, decl, *pid, iat, Some(mid))?;
        let row = Issuance {
            jti: *pid,
            digest,
            ten: rec.ten.clone(),
            sub: rec.approver_sub.clone(),
            wid: rec.wid.clone(),
            op: rec.op.clone(),
            signed_at: iat,
            exp: iat + self.settings.grant_ttl_secs,
            grant,
            status: Status::Signed,
        };
        let extra = Extra::Mandated(MandatedUse {
            mid,
            refund_minor: refund,
            pkey,
        });
        if let Err(e) = store.insert_with(row.clone(), Some(extra)) {
            log::alarm(
                "issuance_store_failed",
                json!({"correlation_id": cid, "jti": pid.to_text(), "detail": format!("{e:?}")}),
            );
            return Err(Refusal("issuance store write failed"));
        }
        log::event(
            "grant_signed",
            json!({"correlation_id": cid, "jti": pid.to_text(), "kind": "write", "cfm": 2,
                   "mid": mid.to_text(), "wid": row.wid, "ten": row.ten, "sub": row.sub,
                   "op": row.op, "iat": iat, "exp": row.exp}),
        );
        Ok(Some(row))
    }

    /// `mandate.revoke{mid, subject}` on socket I (effect-protocol-v2 §12.3): `{}` once the
    /// authority's mandate is revoked (idempotent); it then signs no further `cfm = 2` grant.
    pub async fn mandate_revoke(&self, args: &Map<String, Value>) -> Result<(), Refusal> {
        exact_members(args, &["mid", "subject"], &[]).map_err(Refusal)?;
        let mid = args["mid"]
            .as_str()
            .ok_or(Refusal("mid type"))
            .and_then(|s| PendingId::parse(s).map_err(|e| Refusal(e.0)))?;
        let (ten, sub) = parse_subject(&args["subject"])?;
        let mut store = self.store.lock().await;
        let owner_ok = store
            .mandates()
            .any(|(r, _)| r.jti == mid && r.ten == ten && r.sub == sub);
        if !owner_ok {
            return Err(Refusal("unknown mid or other subject"));
        }
        store.revoke_mandate(&mid).map_err(|e| {
            log::alarm(
                "mandate_revoke_store_failed",
                json!({"mid": mid.to_text(), "detail": format!("{e:?}")}),
            );
            Refusal("store write failed")
        })?;
        log::event("mandate_revoked", json!({"mid": mid.to_text()}));
        Ok(())
    }

    /// MD-7: settles the broker's activation outcome of every unsettled, unexpired mandate from the
    /// template record's state (`pending.get`): `SUCCEEDED` = active; `FAILED`, `DENIED`, `EXPIRED`
    /// = failed; any other state stays unconfirmed (inactive for issuance). A record that does not
    /// match the mandate row (digest, workload, tenant, principal, operation) is recorded as failed,
    /// with an alarm. Returns the number of outcomes recorded.
    pub async fn confirm_activations(&self) -> usize {
        let now = (self.clock)();
        let todo: Vec<Issuance> = {
            let store = self.store.lock().await;
            store
                .mandates()
                .filter(|(r, m)| {
                    store.activation(&r.jti).is_none()
                        && !store.is_revoked(&r.jti)
                        && !matches!(r.status, Status::Rejected | Status::Expired)
                        && now < m.exp
                })
                .map(|(r, _)| r.clone())
                .collect()
        };
        let mut n = 0;
        for row in todo {
            let fetched = match self.broker.pending_get(&row.jti).await {
                Ok(f) => f,
                Err(e) => {
                    log::event(
                        "mandate_activation_unconfirmed",
                        json!({"mid": row.jti.to_text(), "detail": format!("{e:?}")}),
                    );
                    continue;
                }
            };
            let rec = &fetched.record;
            let matches = fetched.broker_digest == row.digest
                && rec.pending_id == row.jti
                && rec.wid == row.wid
                && rec.ten == row.ten
                && rec.approver_sub == row.sub
                && rec.op == row.op;
            let outcome = if !matches {
                log::alarm(
                    "mandate_activation_mismatch",
                    json!({"mid": row.jti.to_text()}),
                );
                Some(false)
            } else {
                match fetched.state.as_str() {
                    "SUCCEEDED" => Some(true),
                    "FAILED" | "DENIED" | "EXPIRED" => Some(false),
                    _ => None,
                }
            };
            let Some(active) = outcome else { continue };
            let mut store = self.store.lock().await;
            match store.set_activation(&row.jti, active) {
                Ok(()) => {
                    n += 1;
                    log::event(
                        "mandate_activation",
                        json!({"mid": row.jti.to_text(), "active": active, "state": fetched.state}),
                    );
                }
                Err(e) => log::alarm(
                    "mandate_activation_store_failed",
                    json!({"mid": row.jti.to_text(), "detail": format!("{e:?}")}),
                ),
            }
        }
        n
    }

    /// The mandate loop (AI §4.4): `mandate.candidates` every `MANDATE_POLL`, then one issuance
    /// attempt per candidate. Runs only when a mandate template is configured.
    pub async fn mandate_loop(self: Arc<Self>) {
        if self
            .workloads
            .mandates
            .as_ref()
            .and_then(|m| m.template.as_ref())
            .is_none()
        {
            return;
        }
        loop {
            self.confirm_activations().await;
            match self.broker.mandate_candidates().await {
                Ok(ids) => {
                    for pid in ids {
                        let _ = self.mandate_issue(pid).await;
                    }
                }
                Err(e) => log::event(
                    "mandate_candidates_failed",
                    json!({"detail": format!("{e:?}")}),
                ),
            }
            tokio::time::sleep(MANDATE_POLL).await;
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

    /// Test and operator helper: the mandate extra of `jti`'s row.
    /// The stored activation outcome of mandate `mid` (MD-7); `None` while unconfirmed.
    pub async fn activation(&self, mid: &PendingId) -> Option<bool> {
        self.store.lock().await.activation(mid)
    }

    pub async fn store_extra(&self, jti: &PendingId) -> Option<Extra> {
        self.store.lock().await.extra(jti).cloned()
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
            Some("mandate.revoke") => match self.mandate_revoke(args).await {
                Ok(()) => {
                    json!({"v": PROTOCOL_VERSION, "id": id, "correlation_id": cid, "ok": true, "result": {}})
                }
                Err(Refusal(reason)) => {
                    log::event(
                        "mandate_revoke_refused",
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

/// `^ch_[A-Za-z0-9]{8,61}$` (payments-adapter-v1 PA-19, RX-6).
/// 61 so that the whole id (`ch_` + 61) fits the grant type `text64`.
pub fn is_charge_id(s: &str) -> bool {
    s.strip_prefix("ch_").is_some_and(|rest| {
        (8..=61).contains(&rest.len()) && rest.bytes().all(|c| c.is_ascii_alphanumeric())
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
