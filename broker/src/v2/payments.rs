//! Broker side of payments-adapter-v1 Draft 3 (§7, §8) and ADR-0012 rev. 2.
//!
//! - **T1** ([`refund_t1`]): inside the execution transaction, after W10 + savepoint + W11–W13,
//!   the W14 checks in the normative order (pattern, budget lock, per-charge lock, trusted order
//!   read after the lock, currency/status, one-in-flight, remaining, budget update), then the
//!   encumbrance and the `RESERVED` row. The caller moves the record `APPROVED → EXECUTING`.
//! - **T2/T3** ([`Broker::dispatch`]): `RESERVED → DISPATCHED` under a row lease, `refund.create`
//!   (≤ 3 calls while `busy`), then a confirming `refund.get`, and the result applied by CAS
//!   under the same lease.
//! - **Recovery and reconciliation** ([`Broker::payments_tick`]): stale `RESERVED` →
//!   `FAILED/not_dispatched`; `DISPATCHED` with an expired lease → `UNKNOWN/lost_response`;
//!   lookup-first reconciliation of `UNKNOWN`; settlement polling.
//!
//! Every adapter call on a row is made by the holder of that row's lease, taken by a committed CAS
//! before the call (PA-06). Lock order: `pending_effect` → `refund_budget` →
//! `charge_refund_state` → `payment_effect` (§7.2).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use nodkey_grant::{Params, encode_transport};
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio_postgres::{Client, GenericClient, Transaction};

use super::adapter::{
    AdapterClient, Attempt, BUSINESS_REFUSALS, Call, Hello, IdemState, Lookup, Refund,
    RefundStatus, is_charge_id, parse_attempt, parse_idem, parse_lookup,
};
use super::config::PaymentsConfig;
use super::decls;
use super::ids::{encode_id, random16};
use super::service::{
    Broker, Record, State, dbf, finalize, format_amount, text_param, to_i64, to_u64, uint_param,
    unavailable,
};
use super::wire::Fail;
use crate::server::log_event;

/// `RESERVED` rows older than this are failed as never dispatched (§7.2 recovery).
pub const RESERVED_TIMEOUT_S: u64 = 30;
pub const ADAPTER_MAX_CONCURRENT: usize = 8;
/// Rows worked on at once in one payments tick (below the call slots, so a new dispatch still
/// finds a slot; BP-04).
pub const ROW_CONCURRENCY: usize = 4;
/// Next check of a row whose work failed with an error (BP-05).
pub const ROW_ERROR_BACKOFF_S: u64 = 60;
const BATCH: i64 = 64;
/// Reconciler backoff after each round (§7.3): 10 s, 1 min, 5 min, 30 min, then hourly.
pub fn backoff_s(round: u32) -> u64 {
    match round {
        0 => 10,
        1 => 60,
        2 => 300,
        3 => 1800,
        _ => 3600,
    }
}
/// After the resend gate: lookups daily for 7 days (§7.3 step 4); settlement up to 30 days.
pub const LOOKUP_ONLY_PERIOD_S: u64 = 86_400;
pub const LOOKUP_ONLY_WINDOW_S: u64 = 7 * 86_400;
pub const SETTLEMENT_WINDOW_S: u64 = 30 * 86_400;

pub fn utc_day(now: u64) -> i32 {
    i32::try_from(now / 86_400).unwrap_or(i32::MAX)
}

/// Workload-facing reason (§8).
pub fn workload_reason(internal: &str) -> Option<&'static str> {
    Some(match internal {
        "not_owner_or_unknown" => "not_permitted",
        "currency" | "order_status" | "order_busy" | "insufficient_refundable" => "not_refundable",
        "budget" => "limit",
        // BP-11: a stored grant that fails W11–W13 (e.g. revoked) is not permitted.
        "grant" => "not_permitted",
        "not_dispatched" | "not_sent" | "provider_declined" => "not_executed",
        _ => return None,
    })
}

/// Runtime of the payments side of the broker.
#[derive(Debug)]
pub struct PaymentsRuntime {
    pub cfg: PaymentsConfig,
    pub client: AdapterClient,
    /// Lease owner: random per process start.
    pub me: [u8; 16],
    pub hello: RwLock<Option<Hello>>,
    pub ready: AtomicBool,
    pub calls: Semaphore,
}

impl PaymentsRuntime {
    pub fn new(cfg: PaymentsConfig) -> std::io::Result<Self> {
        let timeout = Duration::from_millis(cfg.call_timeout_ms());
        Ok(PaymentsRuntime {
            client: AdapterClient::new(cfg.adapter_socket.clone(), cfg.adapter_uid, timeout),
            cfg,
            me: random16()?,
            hello: RwLock::new(None),
            ready: AtomicBool::new(false),
            calls: Semaphore::new(ADAPTER_MAX_CONCURRENT),
        })
    }
    pub fn hello(&self) -> Option<Hello> {
        self.hello.read().ok().and_then(|h| h.clone())
    }
    fn is_ready(&self) -> Option<Hello> {
        if self.ready.load(Ordering::SeqCst) {
            self.hello()
        } else {
            None
        }
    }
}

/// Trusted order row (`nodkey.orders`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub order_id: u64,
    pub ten: String,
    pub owner_sub: String,
    pub charge_id: String,
    pub currency: String,
    pub captured: i64,
    pub external_refunded: i64,
    pub status: String,
}

pub async fn read_order(c: &impl GenericClient, order_id: u64) -> Result<Option<Order>, Fail> {
    let row = c
        .query_opt(
            "SELECT order_id, ten, owner_sub, charge_id, currency, captured_minor, \
             external_refunded_minor, status FROM nodkey.orders WHERE order_id = $1",
            &[&to_i64(order_id)],
        )
        .await
        .map_err(dbf("orders"))?;
    let Some(r) = row else { return Ok(None) };
    Ok(Some(Order {
        order_id: to_u64(r.try_get(0).map_err(unavailable)?)?,
        ten: r.try_get(1).map_err(unavailable)?,
        owner_sub: r.try_get(2).map_err(unavailable)?,
        charge_id: r.try_get(3).map_err(unavailable)?,
        currency: r.try_get(4).map_err(unavailable)?,
        captured: r.try_get(5).map_err(unavailable)?,
        external_refunded: r.try_get(6).map_err(unavailable)?,
        status: r.try_get(7).map_err(unavailable)?,
    }))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub succeeded: i64,
    pub inflight: i64,
    pub unknown: i64,
}

async fn counters(c: &impl GenericClient, charge: &str, lock: bool) -> Result<Counters, Fail> {
    if lock {
        c.execute(
            "INSERT INTO nodkey.charge_refund_state (charge_id) VALUES ($1) ON CONFLICT (charge_id) DO NOTHING",
            &[&charge],
        )
        .await
        .map_err(dbf("charge state insert"))?;
    }
    let sql = if lock {
        "SELECT succeeded_minor, inflight_minor, unknown_minor FROM nodkey.charge_refund_state WHERE charge_id = $1 FOR UPDATE"
    } else {
        "SELECT succeeded_minor, inflight_minor, unknown_minor FROM nodkey.charge_refund_state WHERE charge_id = $1"
    };
    let row = c
        .query_opt(sql, &[&charge])
        .await
        .map_err(dbf("charge state"))?;
    Ok(match row {
        None => Counters::default(),
        Some(r) => Counters {
            succeeded: r.try_get(0).map_err(unavailable)?,
            inflight: r.try_get(1).map_err(unavailable)?,
            unknown: r.try_get(2).map_err(unavailable)?,
        },
    })
}

/// The record's refund parameters.
struct RefundParams<'a> {
    order_id: u64,
    amount: u64,
    currency: &'a str,
    charge: &'a str,
}

fn refund_params(p: &Params) -> Result<RefundParams<'_>, Fail> {
    Ok(RefundParams {
        order_id: uint_param(p, "order_id")?,
        amount: uint_param(p, "amount_minor")?,
        currency: text_param(p, "currency")?,
        charge: text_param(p, decls::CHARGE_ID)?,
    })
}

/// The §5 approval checks against an order row (ownership first, then the rest).
fn approval_reason(
    o: Option<&Order>,
    ten: &str,
    sub: &str,
    rp: &RefundParams<'_>,
) -> Option<&'static str> {
    let Some(o) = o.filter(|o| o.ten == ten && o.owner_sub == sub && o.charge_id == rp.charge)
    else {
        return Some("not_owner_or_unknown");
    };
    if o.currency != rp.currency {
        return Some("currency");
    }
    if !matches!(o.status.as_str(), "captured" | "partially_refunded") {
        return Some("order_status");
    }
    None
}

/// Approval checks at `grant.deliver`, under the per-charge lock (§5). `false` = rejected.
pub async fn deliver_checks(tx: &Transaction<'_>, rec: &Record) -> Result<bool, Fail> {
    let rp = refund_params(&rec.fields.params)?;
    if !is_charge_id(rp.charge) {
        return Ok(false);
    }
    counters(tx, rp.charge, true).await?;
    let o = read_order(tx, rp.order_id).await?;
    Ok(approval_reason(o.as_ref(), &rec.fields.ten, &rec.fields.approver_sub, &rp).is_none())
}

/// Confirmation-page facts for `payments.refund` (§8; effect-protocol-v2 §5). `None` when the
/// approval checks fail (the gateway shows the uniform error).
pub async fn render_facts(
    c: &impl GenericClient,
    rec: &Record,
    pc: &PaymentsConfig,
    now: u64,
) -> Result<Option<Value>, Fail> {
    let rp = refund_params(&rec.fields.params)?;
    if !is_charge_id(rp.charge) {
        return Ok(None);
    }
    let o = read_order(c, rp.order_id).await?;
    if approval_reason(o.as_ref(), &rec.fields.ten, &rec.fields.approver_sub, &rp).is_some() {
        return Ok(None);
    }
    let Some(o) = o else { return Ok(None) };
    let k = counters(c, rp.charge, false).await?;
    let exp = decls::iso4217_exponent(&o.currency).ok_or_else(|| unavailable("currency table"))?;
    let money = |n: i64| format_amount(n, exp, &o.currency);
    let encumbered = k.inflight + k.unknown;
    let remaining = o.captured - o.external_refunded - (k.succeeded + k.inflight + k.unknown);
    let allowance = match pc.limits_minor.get(&o.currency) {
        None => "no refunds are allowed in this currency".to_owned(),
        Some(limit) => {
            let r = c
                .query_opt(
                    "SELECT spent_minor, count FROM nodkey.refund_budget WHERE ten = $1 AND sub = $2 \
                     AND currency = $3 AND day = $4",
                    &[&rec.fields.ten, &rec.fields.approver_sub, &o.currency, &utc_day(now)],
                )
                .await
                .map_err(dbf("budget"))?;
            let (spent, count): (i64, i32) = match r {
                Some(r) => (
                    r.try_get(0).map_err(unavailable)?,
                    r.try_get(1).map_err(unavailable)?,
                ),
                None => (0, 0),
            };
            let left = i64::try_from(*limit).unwrap_or(i64::MAX) - spent;
            let n = i64::from(pc.max_count_per_day) - i64::from(count);
            format!("{} and {} refund(s)", money(left.max(0)), n.max(0))
        }
    };
    let mut facts = vec![
        json!({"label": "Order", "value": format!("#{}", o.order_id)}),
        json!({"label": "Charge being refunded", "value": o.charge_id}),
        json!({"label": "Captured amount", "value": money(o.captured)}),
        json!({"label": "Already refunded", "value": money(o.external_refunded + k.succeeded)}),
        json!({"label": "Being processed or unresolved", "value": money(encumbered)}),
        json!({"label": "Remaining refundable", "value": money(remaining.max(0))}),
        json!({"label": "Remaining refund allowance today", "value": allowance}),
        json!({"label": "Refunded to", "value": "the original payment method"}),
    ];
    if encumbered > 0 {
        facts.push(
            json!({"label": "Warning", "value": "A refund on this order is being processed"}),
        );
    }
    Ok(Some(Value::Array(facts)))
}

/// `payments.get_order` (§8), filtered by the read grant's tenant and subject.
pub async fn get_order(
    c: &impl GenericClient,
    order_id: u64,
    ten: &str,
    sub: &str,
) -> Result<Option<Value>, Fail> {
    let Some(o) = read_order(c, order_id).await? else {
        return Ok(None);
    };
    if o.ten != ten || o.owner_sub != sub {
        return Ok(None);
    }
    let k = counters(c, &o.charge_id, false).await?;
    Ok(Some(json!({
        "order_id": o.order_id,
        "currency": o.currency,
        "amount_minor": o.captured,
        "refunded_minor": o.external_refunded + k.succeeded,
        "status": o.status,
    })))
}

/// W14 for `payments.refund` (§7.2 T1, steps 0–7) and the reservation. `Ok(Err(reason))` is a
/// business denial (the caller rolls back to the savepoint and records it); `Err` is an
/// infrastructure failure (the whole transaction rolls back).
pub async fn refund_t1(
    tx: &Transaction<'_>,
    rec: &Record,
    p: &Params,
    pc: &PaymentsConfig,
    idem_kid: &str,
    iat: u64,
    now: u64,
) -> Result<Result<(), &'static str>, Fail> {
    let rp = refund_params(p)?;
    let (ten, sub) = (&rec.fields.ten, &rec.fields.approver_sub);
    // 0. Charge pattern: `unresolved` creates no state row.
    if !is_charge_id(rp.charge) {
        return Ok(Err("not_owner_or_unknown"));
    }
    let amount = i64::try_from(rp.amount).map_err(unavailable)?;
    let day = utc_day(now);
    // 1. Budget lock (evaluated at step 7).
    let limit = pc.limits_minor.get(rp.currency).copied();
    if limit.is_some() {
        tx.execute(
            "INSERT INTO nodkey.refund_budget (ten, sub, currency, day) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (ten, sub, currency, day) DO NOTHING",
            &[ten, sub, &rp.currency, &day],
        )
        .await
        .map_err(dbf("budget insert"))?;
        tx.query_one(
            "SELECT spent_minor FROM nodkey.refund_budget WHERE ten = $1 AND sub = $2 AND currency = $3 \
             AND day = $4 FOR UPDATE",
            &[ten, sub, &rp.currency, &day],
        )
        .await
        .map_err(dbf("budget lock"))?;
    }
    // 2. Per-charge lock.
    let k = counters(tx, rp.charge, true).await?;
    // 3–4. Trusted order, read after the lock (a new statement).
    let o = read_order(tx, rp.order_id).await?;
    if let Some(r) = approval_reason(o.as_ref(), ten, sub, &rp) {
        return Ok(Err(r));
    }
    let Some(o) = o else {
        return Ok(Err("not_owner_or_unknown"));
    };
    // 5. One in flight.
    if k.inflight + k.unknown != 0 {
        return Ok(Err("order_busy"));
    }
    // 6. Remaining.
    let remaining = o.captured - o.external_refunded - (k.succeeded + k.inflight + k.unknown);
    if amount < 1 || amount > remaining {
        return Ok(Err("insufficient_refundable"));
    }
    // 7. Budget guarded update.
    let Some(limit) = limit else {
        return Ok(Err("budget"));
    };
    let n = tx
        .execute(
            "UPDATE nodkey.refund_budget SET spent_minor = spent_minor + $5, count = count + 1 \
             WHERE ten = $1 AND sub = $2 AND currency = $3 AND day = $4 \
             AND spent_minor + $5 <= $6 AND count + 1 <= $7",
            &[
                ten,
                sub,
                &rp.currency,
                &day,
                &amount,
                &to_i64(limit),
                &i32::try_from(pc.max_count_per_day).unwrap_or(i32::MAX),
            ],
        )
        .await
        .map_err(dbf("budget update"))?;
    if n != 1 {
        return Ok(Err("budget"));
    }
    // Encumbrance and the RESERVED row with frozen values.
    tx.execute(
        "UPDATE nodkey.charge_refund_state SET inflight_minor = inflight_minor + $2 WHERE charge_id = $1",
        &[&rp.charge, &amount],
    )
    .await
    .map_err(dbf("encumber"))?;
    let deadline = iat.saturating_add(pc.r_max_s).saturating_sub(60);
    tx.execute(
        "INSERT INTO nodkey.payment_effect (pending_id, order_id, charge_id, ten, sub, amount_minor, currency, \
         idem_kid, state, reserved_at, resend_deadline) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'RESERVED',$9,$10)",
        &[
            &rec.fields.pending_id.as_slice(),
            &to_i64(rp.order_id),
            &rp.charge,
            ten,
            sub,
            &amount,
            &rp.currency,
            &idem_kid,
            &to_i64(now),
            &to_i64(deadline),
        ],
    )
    .await
    .map_err(dbf("reserve"))?;
    Ok(Ok(()))
}

/// Records the internal reason of a T1 denial (inside the deciding transaction).
pub async fn record_denial(tx: &Transaction<'_>, pid: &[u8; 16], reason: &str) -> Result<(), Fail> {
    tx.execute(
        "INSERT INTO nodkey.refund_denial (pending_id, reason) VALUES ($1, $2)",
        &[&pid.as_slice(), &reason],
    )
    .await
    .map_err(dbf("refund denial"))?;
    Ok(())
}

/// Workload-facing reason for a `payments.refund` record (§8).
pub async fn status_reason(
    c: &impl GenericClient,
    pid: &[u8; 16],
) -> Result<Option<&'static str>, Fail> {
    if let Some(r) = c
        .query_opt(
            "SELECT reason FROM nodkey.refund_denial WHERE pending_id = $1",
            &[&pid.as_slice()],
        )
        .await
        .map_err(dbf("denial reason"))?
    {
        let s: String = r.try_get(0).map_err(unavailable)?;
        return Ok(workload_reason(&s));
    }
    if let Some(r) = c
        .query_opt(
            "SELECT state, reason FROM nodkey.payment_effect WHERE pending_id = $1",
            &[&pid.as_slice()],
        )
        .await
        .map_err(dbf("effect reason"))?
    {
        let st: String = r.try_get(0).map_err(unavailable)?;
        let reason: Option<String> = r.try_get(1).map_err(unavailable)?;
        if st == "FAILED" {
            return Ok(reason.as_deref().and_then(workload_reason));
        }
    }
    Ok(None)
}

/// A `payment_effect` row with the stored grant.
#[derive(Debug, Clone)]
pub struct EffectRow {
    pub pid: [u8; 16],
    pub charge: String,
    pub amount: i64,
    pub currency: String,
    pub idem_kid: String,
    pub state: String,
    pub resends: i32,
    pub rounds: i32,
    pub resend_deadline: u64,
    pub dispatched_at: Option<u64>,
    pub resend_stopped: bool,
    pub provider_refund_id: Option<String>,
    pub reason: Option<String>,
    /// The derived reference from the first adapter result (audit; checked once known, BP-08).
    pub reference: Option<String>,
    pub grant_text: String,
}

impl EffectRow {
    /// A provider refund matches the frozen, grant-derived values and, once known, the row's
    /// reference.
    fn matches(&self, r: &Refund) -> bool {
        r.charge == self.charge
            && i64::try_from(r.amount_minor).ok() == Some(self.amount)
            && r.currency == self.currency
            && self.reference.as_ref().is_none_or(|x| *x == r.reference)
    }
}

async fn effect_row(c: &impl GenericClient, pid: &[u8; 16]) -> Result<Option<EffectRow>, Fail> {
    let r = c
        .query_opt(
            "SELECT e.charge_id, e.amount_minor, e.currency, e.idem_kid, e.state, e.resends, e.reconcile_rounds, \
             e.resend_deadline, e.dispatched_at, e.resend_stopped, e.provider_refund_id, e.reason, p.grant_bytes, \
             e.reference \
             FROM nodkey.payment_effect e JOIN public.pending_effect p ON p.pending_id = e.pending_id \
             WHERE e.pending_id = $1",
            &[&pid.as_slice()],
        )
        .await
        .map_err(dbf("effect row"))?;
    let Some(r) = r else { return Ok(None) };
    let grant: Vec<u8> = r.try_get(12).map_err(unavailable)?;
    let dispatched: Option<i64> = r.try_get(8).map_err(unavailable)?;
    Ok(Some(EffectRow {
        pid: *pid,
        charge: r.try_get(0).map_err(unavailable)?,
        amount: r.try_get(1).map_err(unavailable)?,
        currency: r.try_get(2).map_err(unavailable)?,
        idem_kid: r.try_get(3).map_err(unavailable)?,
        state: r.try_get(4).map_err(unavailable)?,
        resends: r.try_get(5).map_err(unavailable)?,
        rounds: r.try_get(6).map_err(unavailable)?,
        resend_deadline: to_u64(r.try_get(7).map_err(unavailable)?)?,
        dispatched_at: dispatched.map(to_u64).transpose()?,
        resend_stopped: r.try_get(9).map_err(unavailable)?,
        provider_refund_id: r.try_get(10).map_err(unavailable)?,
        reason: r.try_get(11).map_err(unavailable)?,
        reference: r.try_get(13).map_err(unavailable)?,
        grant_text: encode_transport(&grant),
    }))
}

/// Target of a `payment_effect` transition (§7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayTo {
    Succeeded {
        refund_id: String,
        settlement: RefundStatus,
    },
    Failed {
        reason: &'static str,
    },
    Unknown {
        reason: &'static str,
    },
}

/// Result of a dispatch or a reconciliation round, for logs and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayOutcome {
    /// Another holder has the row, or its state moved on.
    Skipped,
    Applied(PayTo),
    /// The lease was lost before the result could be applied; the result was discarded.
    Discarded,
    /// Reconciler round finished without a resolution.
    StillUnknown,
}

/// A row's lease as held for its adapter calls (state and lease length).
struct Held<'a> {
    row: &'a EffectRow,
    state: &'static str,
    lease_s: u64,
}

enum Gate<'a> {
    Go(tokio::sync::SemaphorePermit<'a>),
    /// No call slot within the bound: no call was made.
    NoSlot,
    /// The lease could not be re-asserted: the caller stops without writing.
    Lost,
}

/// The outcome of a lease-checked call.
enum Called<T> {
    Done(T),
    NoSlot,
    Lost,
}

impl<T> Called<T> {
    fn map<U>(self, f: impl FnOnce(T) -> U) -> Called<U> {
        match self {
            Called::Done(t) => Called::Done(f(t)),
            Called::NoSlot => Called::NoSlot,
            Called::Lost => Called::Lost,
        }
    }
}

/// One unit of work in a payments tick.
#[derive(Debug, Clone, Copy)]
enum Work {
    Stale(u64),
    Lost(u64),
    Reconcile,
    Settle,
}

fn alarm(kind: &str, pid: &[u8; 16], extra: Value) {
    let mut o = json!({"kind": kind, "pending_id": encode_id(pid)});
    if let (Some(m), Value::Object(e)) = (o.as_object_mut(), extra) {
        m.extend(e);
    }
    log_event("alarm", o);
}

impl Broker {
    fn rt(&self) -> Result<&PaymentsRuntime, Fail> {
        self.payments
            .as_ref()
            .ok_or_else(|| unavailable("payments not configured"))
    }

    /// `adapter.hello` and the `idem_kid` rule (§3.3, §9), re-run before every dispatch and every
    /// reconciliation round (BP-01): the adapter may have been restarted with another `K_idem`
    /// while the broker kept running. Any failure clears `ready`, so `payments.refund` records
    /// are not executed (they stay `APPROVED` and expire) and no row is dispatched or reconciled.
    pub async fn ensure_adapter(&self) -> bool {
        let Some(rt) = self.payments.as_ref() else {
            return false;
        };
        let ok = self.check_adapter(rt).await;
        let was = rt.ready.swap(ok.is_some(), Ordering::SeqCst);
        match ok {
            Some(h) => {
                let changed = rt.hello().is_some_and(|old| old.idem_kid != h.idem_kid);
                if changed {
                    log_event("alarm", json!({"kind": "adapter_idem_kid_changed"}));
                }
                if let Ok(mut g) = rt.hello.write() {
                    *g = Some(h);
                }
                if !was {
                    log_event("payments_adapter_ready", json!({}));
                }
                true
            }
            None => false,
        }
    }

    async fn check_adapter(&self, rt: &PaymentsRuntime) -> Option<Hello> {
        let Some(h) = rt.client.hello().await else {
            log_event("payments_adapter_unavailable", json!({}));
            return None;
        };
        if h.r_max_s != rt.cfg.r_max_s {
            log_event(
                "alarm",
                json!({"kind": "adapter_r_max_mismatch", "adapter": h.r_max_s, "broker": rt.cfg.r_max_s}),
            );
            return None;
        }
        // PC-A-02: the adapter answers within its deadline, which must be below our wait.
        if h.deadline_ms >= rt.cfg.call_timeout_ms() {
            log_event(
                "alarm",
                json!({"kind": "adapter_deadline_not_below_broker_wait", "adapter_deadline_ms": h.deadline_ms,
                       "broker_wait_ms": rt.cfg.call_timeout_ms()}),
            );
            return None;
        }
        let kid = h.idem_kid.clone();
        let conn = self.conn().await.ok()?;
        let other = Self::run(conn, async move |c: &mut Client| {
            let r = c
                .query_one(
                    "SELECT count(*) FROM nodkey.payment_effect WHERE state IN ('RESERVED','DISPATCHED','UNKNOWN') \
                     AND idem_kid <> $1",
                    &[&kid],
                )
                .await
                .map_err(dbf("kid check"))?;
            r.try_get::<_, i64>(0).map_err(unavailable)
        })
        .await;
        match other {
            Ok(0) => Some(h),
            Ok(n) => {
                // Never resend under a new key: those rows keep their kid and stay as they are
                // until the operator restores the key they were dispatched under.
                log_event(
                    "alarm",
                    json!({"kind": "idem_kid_rotated_with_open_rows", "rows": n}),
                );
                None
            }
            Err(_) => None,
        }
    }

    /// `idem_kid` for T1, or `None` if payment processing is not ready.
    pub fn payments_kid(&self) -> Option<String> {
        self.payments.as_ref()?.is_ready().map(|h| h.idem_kid)
    }

    async fn take_lease(&self, pid: &[u8; 16], state: &str, secs: u64) -> Result<bool, Fail> {
        let rt = self.rt()?;
        let now = (self.clock)();
        let me = rt.me;
        let state = state.to_owned();
        let pid = *pid;
        let conn = self.conn().await?;
        Self::run(conn, async move |c: &mut Client| {
            let n = c
                .execute(
                    "UPDATE nodkey.payment_effect SET lease_owner = $2, lease_until = $3 WHERE pending_id = $1 \
                     AND state = $4 AND (lease_owner = $2 OR lease_owner IS NULL OR lease_until < $5)",
                    &[&pid.as_slice(), &me.as_slice(), &to_i64(now + secs), &state, &to_i64(now)],
                )
                .await
                .map_err(dbf("lease"))?;
            Ok(n == 1)
        })
        .await
    }

    /// Before every adapter call (BP-03): a call slot, waited for at most one call timeout, then
    /// the row's lease re-asserted (committed) for `secs`. Only then may the call be made.
    async fn gate(&self, g: &Held<'_>) -> Result<Gate<'_>, Fail> {
        let rt = self.rt()?;
        let wait = Duration::from_millis(rt.cfg.call_timeout_ms());
        let permit = match tokio::time::timeout(wait, rt.calls.acquire()).await {
            Ok(Ok(p)) => p,
            _ => return Ok(Gate::NoSlot),
        };
        if !self.take_lease(&g.row.pid, g.state, g.lease_s).await? {
            return Ok(Gate::Lost);
        }
        Ok(Gate::Go(permit))
    }

    /// One call on P for a row, with the row's `idem_kid` (BP-01: the adapter refuses any other
    /// kid, so a resend can never go out under a key the row was not dispatched under).
    async fn p_call(&self, g: &Held<'_>, op: &str, mut args: Value) -> Result<Called<Call>, Fail> {
        let rt = self.rt()?;
        let _permit = match self.gate(g).await? {
            Gate::Go(p) => p,
            Gate::NoSlot => return Ok(Called::NoSlot),
            Gate::Lost => return Ok(Called::Lost),
        };
        if let Value::Object(m) = &mut args {
            m.insert("idem_kid".into(), json!(g.row.idem_kid));
        }
        Ok(Called::Done(rt.client.call(op, args).await))
    }

    async fn call_create(&self, g: &Held<'_>) -> Result<Called<Option<Attempt>>, Fail> {
        let c = self
            .p_call(g, "refund.create", json!({"grant": g.row.grant_text}))
            .await?;
        Ok(c.map(|c| match c {
            Call::Result(o) => parse_attempt(&o).or(Some(Attempt::Ambiguous { reference: None })),
            Call::Refused(code) => Some(Attempt::Refused {
                code: format!("p:{code}"),
                reference: String::new(),
            }),
            Call::NotDelivered(_) | Call::Ambiguous(_) => None,
        }))
    }

    async fn call_lookup(
        &self,
        g: &Held<'_>,
        op: &str,
        args: Value,
    ) -> Result<Called<Lookup>, Fail> {
        Ok(self.p_call(g, op, args).await?.map(|c| match c {
            Call::Result(o) => parse_lookup(&o).unwrap_or(Lookup::Ambiguous),
            _ => Lookup::Ambiguous,
        }))
    }

    async fn call_idem(&self, g: &Held<'_>) -> Result<Called<IdemState>, Fail> {
        Ok(self
            .p_call(g, "idem.status", json!({"grant": g.row.grant_text}))
            .await?
            .map(|c| match c {
                Call::Result(o) => parse_idem(&o).unwrap_or(IdemState::Ambiguous),
                _ => IdemState::Ambiguous,
            }))
    }

    /// `refund.get` of a created/found refund; `Some` only if it is exactly the same refund
    /// (charge, amount, currency and, once known, the reference; BP-08).
    async fn confirm(&self, g: &Held<'_>, r: &Refund) -> Result<Called<Option<Refund>>, Fail> {
        if !g.row.matches(r) {
            return Ok(Called::Done(None));
        }
        let l = self
            .call_lookup(
                g,
                "refund.get",
                json!({"grant": g.row.grant_text, "refund_id": r.id}),
            )
            .await?;
        Ok(l.map(|l| match l {
            Lookup::Found(v)
                if v.len() == 1
                    && v[0].id == r.id
                    && v[0].reference == r.reference
                    && g.row.matches(&v[0]) =>
            {
                Some(v[0].clone())
            }
            _ => None,
        }))
    }

    /// Applies a transition by CAS from `from`, holding the lease if `lease` (§7.2 T3, §7.4).
    /// Both rows and the counters change in one transaction. `false` = discarded.
    pub async fn apply(
        &self,
        pid: &[u8; 16],
        from: &str,
        to: &PayTo,
        lease: bool,
        reference: Option<&str>,
        extra: &str,
    ) -> Result<bool, Fail> {
        let rt = self.rt()?;
        let now = (self.clock)();
        let me = rt.me;
        let pid = *pid;
        let from = from.to_owned();
        let to = to.clone();
        let reference = reference.filter(|r| !r.is_empty()).map(str::to_owned);
        let extra = extra.to_owned();
        let conn = self.conn().await?;
        Self::run(conn, async move |c: &mut Client| {
            let tx = c.transaction().await.map_err(dbf("begin"))?;
            tx.query_opt("SELECT 1 FROM public.pending_effect WHERE pending_id = $1 FOR UPDATE", &[&pid.as_slice()])
                .await
                .map_err(dbf("lock record"))?;
            let Some(row) = effect_row(&tx, &pid).await? else { return Ok(false) };
            if row.state != from {
                return Ok(false);
            }
            counters(&tx, &row.charge, true).await?;
            let (state, reason, released, refund_id, settlement): (&str, Option<&str>, bool, Option<String>, Option<&str>) = match &to {
                PayTo::Succeeded { refund_id, settlement } => ("SUCCEEDED", None, false, Some(refund_id.clone()), Some(settlement.as_str())),
                PayTo::Failed { reason } => ("FAILED", Some(*reason), true, None, None),
                PayTo::Unknown { reason } => ("UNKNOWN", Some(*reason), false, None, None),
            };
            let next_check = (state == "UNKNOWN").then(|| to_i64(now + backoff_s(0)))
                .or_else(|| (state == "SUCCEEDED" && settlement == Some("pending")).then(|| to_i64(now + backoff_s(0))));
            // $9 is always referenced so that its type is known.
            let lease_cond = if lease { " AND lease_owner = $9" } else { " AND $9::bytea IS NOT NULL" };
            let sql = format!(
                "UPDATE nodkey.payment_effect SET state = $2, reason = COALESCE($3, reason), released = $4, \
                 provider_refund_id = $5, settlement = $6, reference = COALESCE(reference, $7), next_check_at = $8, \
                 lease_until = {lease_until} WHERE pending_id = $1 AND state = $10{lease_cond}{extra}",
                lease_until = to_i64(now),
            );
            let n = tx
                .execute(
                    &sql,
                    &[&pid.as_slice(), &state, &reason, &released, &refund_id, &settlement, &reference, &next_check, &me.as_slice(), &from],
                )
                .await
                .map_err(dbf("effect transition"))?;
            if n != 1 {
                return Ok(false);
            }
            let (col_from, col_to) = (
                if from == "UNKNOWN" { "unknown_minor" } else { "inflight_minor" },
                match state { "SUCCEEDED" => Some("succeeded_minor"), "UNKNOWN" => Some("unknown_minor"), _ => None },
            );
            let sql = match col_to {
                Some(t) => format!("UPDATE nodkey.charge_refund_state SET {col_from} = {col_from} - $2, {t} = {t} + $2 WHERE charge_id = $1"),
                None => format!("UPDATE nodkey.charge_refund_state SET {col_from} = {col_from} - $2 WHERE charge_id = $1"),
            };
            tx.execute(&sql, &[&row.charge, &row.amount]).await.map_err(dbf("counters"))?;
            let rec_from = if from == "UNKNOWN" { State::Unknown } else { State::Executing };
            let ok = match state {
                "SUCCEEDED" => finalize(&tx, &pid, rec_from, (State::Succeeded, "succeeded"), now, "", &[]).await?,
                "FAILED" => finalize(&tx, &pid, rec_from, (State::Failed, "failed"), now, "", &[]).await?,
                _ => {
                    tx.execute(
                        "UPDATE public.pending_effect SET state = 'UNKNOWN', outcome_class = 'unknown', state_changed_at = $2 \
                         WHERE pending_id = $1 AND state = 'EXECUTING'",
                        &[&pid.as_slice(), &to_i64(now)],
                    )
                    .await
                    .map_err(dbf("record unknown"))?
                        == 1
                }
            };
            if !ok {
                return Err(unavailable("record transition touched no row"));
            }
            tx.commit().await.map_err(dbf("commit"))?;
            Ok(true)
        })
        .await
    }

    /// T2 + T3 for one `RESERVED` row.
    pub async fn dispatch(&self, pid: [u8; 16]) -> Result<PayOutcome, Fail> {
        let rt = self.rt()?;
        // BP-01: re-learn the adapter's kid before dispatching.
        if !self.ensure_adapter().await {
            return Ok(PayOutcome::Skipped);
        }
        let Some(h) = rt.is_ready() else {
            return Ok(PayOutcome::Skipped);
        };
        let now = (self.clock)();
        let lease = rt.cfg.lease_dispatch_s();
        let me = rt.me;
        let kid = h.idem_kid.clone();
        let conn = self.conn().await?;
        // T2: RESERVED → DISPATCHED with the dispatch lease, committed before any call; only a
        // row reserved under the adapter's current kid is dispatched.
        let row = Self::run(conn, async move |c: &mut Client| {
            let n = c
                .execute(
                    "UPDATE nodkey.payment_effect SET state = 'DISPATCHED', dispatched_at = $2, lease_owner = $3, \
                     lease_until = $4 WHERE pending_id = $1 AND state = 'RESERVED' AND idem_kid = $5",
                    &[&pid.as_slice(), &to_i64(now), &me.as_slice(), &to_i64(now + lease), &kid],
                )
                .await
                .map_err(dbf("dispatch CAS"))?;
            if n != 1 {
                return Ok(None);
            }
            effect_row(&*c, &pid).await
        })
        .await?;
        let Some(row) = row else {
            return Ok(PayOutcome::Skipped);
        };
        let g = Held {
            row: &row,
            state: "DISPATCHED",
            lease_s: lease,
        };
        let mut first = true;
        let mut result: Option<Option<Attempt>> = None;
        for attempt in 0..3u64 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(attempt)).await;
            }
            let a = match self.call_create(&g).await? {
                Called::Done(a) => a,
                Called::Lost => return Ok(PayOutcome::Discarded),
                // No call was made: on the first attempt nothing was ever sent.
                Called::NoSlot if attempt == 0 => Some(Attempt::NotSent),
                Called::NoSlot => break,
            };
            first = attempt == 0;
            let busy = matches!(a, Some(Attempt::Busy { .. }));
            result = Some(a);
            if !busy {
                break;
            }
        }
        let a = result.flatten();
        let (to, reference) = match &a {
            Some(Attempt::Created { refund, reference }) => match self.confirm(&g, refund).await? {
                Called::Lost => return Ok(PayOutcome::Discarded),
                Called::Done(Some(r)) => {
                    if r.status == RefundStatus::Failed {
                        // BP-09: same rule as the reconciler: the refund exists; its settlement
                        // failed; the amount stays encumbered.
                        alarm("refund_settlement_failed", &pid, json!({}));
                    }
                    (
                        PayTo::Succeeded {
                            refund_id: r.id.clone(),
                            settlement: r.status,
                        },
                        Some(reference.clone()),
                    )
                }
                Called::Done(None) | Called::NoSlot => (
                    PayTo::Unknown {
                        reason: "ambiguous",
                    },
                    Some(reference.clone()),
                ),
            },
            Some(Attempt::NotSent) if first => (PayTo::Failed { reason: "not_sent" }, None),
            Some(Attempt::Refused { code, reference }) => {
                let (alarm_kind, reason) = if code == "p:idem_kid_mismatch" {
                    ("adapter_idem_kid_mismatch", "key_mismatch")
                } else if code.starts_with("p:") {
                    ("adapter_refused_grant", "grant_refused")
                } else {
                    ("provider_refused_valid_refund", "refused")
                };
                alarm(alarm_kind, &pid, json!({"code": code}));
                (PayTo::Unknown { reason }, Some(reference.clone()))
            }
            Some(Attempt::Busy { reference }) => {
                (PayTo::Unknown { reason: "busy" }, Some(reference.clone()))
            }
            Some(Attempt::Ambiguous { reference }) => (
                PayTo::Unknown {
                    reason: "ambiguous",
                },
                reference.clone(),
            ),
            Some(Attempt::NotSent) => (
                PayTo::Unknown {
                    reason: "ambiguous",
                },
                None,
            ),
            None => (
                PayTo::Unknown {
                    reason: "adapter_failure",
                },
                None,
            ),
        };
        let applied = self
            .apply(&pid, "DISPATCHED", &to, true, reference.as_deref(), "")
            .await?;
        let out = if applied {
            PayOutcome::Applied(to)
        } else {
            PayOutcome::Discarded
        };
        log_event(
            "payments_dispatch",
            json!({"pending_id": encode_id(&pid), "outcome": format!("{out:?}")}),
        );
        Ok(out)
    }

    /// Finishes a round on a row that stays `UNKNOWN` (bookkeeping under the lease).
    async fn end_round(
        &self,
        row: &EffectRow,
        next: u64,
        stop_resend: bool,
        reason: Option<&str>,
    ) -> Result<(), Fail> {
        let rt = self.rt()?;
        let now = (self.clock)();
        let me = rt.me;
        let pid = row.pid;
        let reason = reason.map(str::to_owned);
        let conn = self.conn().await?;
        Self::run(conn, async move |c: &mut Client| {
            c.execute(
                "UPDATE nodkey.payment_effect SET reconcile_rounds = reconcile_rounds + 1, next_check_at = $3, \
                 lease_until = $4, resend_stopped = resend_stopped OR $5, reason = COALESCE($6, reason) \
                 WHERE pending_id = $1 AND state = 'UNKNOWN' AND lease_owner = $2",
                &[&pid.as_slice(), &me.as_slice(), &to_i64(next), &to_i64(now), &stop_resend, &reason],
            )
            .await
            .map_err(dbf("end round"))?;
            Ok(())
        })
        .await
    }

    /// One reconciler round for an `UNKNOWN` row (§7.3), lookup first.
    pub async fn reconcile(&self, pid: [u8; 16]) -> Result<PayOutcome, Fail> {
        let rt = self.rt()?;
        // BP-01: re-learn the adapter's kid before every round.
        if !self.ensure_adapter().await {
            return Ok(PayOutcome::Skipped);
        }
        let Some(h) = rt.is_ready() else {
            return Ok(PayOutcome::Skipped);
        };
        let lease = rt.cfg.lease_reconcile_s();
        if !self.take_lease(&pid, "UNKNOWN", lease).await? {
            return Ok(PayOutcome::Skipped);
        }
        let conn = self.conn().await?;
        let Some(row) = Self::run(conn, async move |c: &mut Client| {
            effect_row(&*c, &pid).await
        })
        .await?
        else {
            return Ok(PayOutcome::Skipped);
        };
        let now = (self.clock)();
        let rounds = u32::try_from(row.rounds).unwrap_or(u32::MAX);
        if row.idem_kid != h.idem_kid {
            // Never call (and never resend) under a key the row was not dispatched under.
            alarm("idem_kid_mismatch", &pid, json!({}));
            self.end_round(&row, now + backoff_s(rounds + 1), false, None)
                .await?;
            return Ok(PayOutcome::StillUnknown);
        }
        let g = Held {
            row: &row,
            state: "UNKNOWN",
            lease_s: lease,
        };
        macro_rules! done {
            ($e:expr) => {
                match $e {
                    Called::Done(v) => Some(v),
                    Called::NoSlot => None,
                    Called::Lost => return Ok(PayOutcome::Discarded),
                }
            };
        }
        // 1. Lookup.
        if let Some(Lookup::Found(v)) = done!(
            self.call_lookup(&g, "refund.find", json!({"grant": row.grant_text}))
                .await?
        ) && v.len() == 1
            && let Some(Some(r)) = done!(self.confirm(&g, &v[0]).await?)
        {
            let to = PayTo::Succeeded {
                refund_id: r.id.clone(),
                settlement: r.status,
            };
            return Ok(if self.apply(&pid, "UNKNOWN", &to, true, None, "").await? {
                PayOutcome::Applied(to)
            } else {
                PayOutcome::Discarded
            });
        }
        let now = (self.clock)();
        // 2. Resend gate.
        let gate = !row.resend_stopped
            && now < row.resend_deadline
            && u32::try_from(row.resends).unwrap_or(u32::MAX) < rt.cfg.max_resends
            && h.dedup_documented();
        if !gate {
            // 4. Lookups only, daily for 7 days, then the operator.
            let since = row.dispatched_at.unwrap_or(now);
            if now >= since.saturating_add(LOOKUP_ONLY_WINDOW_S) {
                if row.reason.as_deref() != Some("operator_required") {
                    alarm("operator_required", &pid, json!({}));
                }
                self.end_round(
                    &row,
                    now + LOOKUP_ONLY_PERIOD_S,
                    true,
                    Some("operator_required"),
                )
                .await?;
            } else {
                self.end_round(&row, now + LOOKUP_ONLY_PERIOD_S, false, None)
                    .await?;
            }
            return Ok(PayOutcome::StillUnknown);
        }
        let mut resend = true;
        if h.has_cap("idem_status") {
            match done!(self.call_idem(&g).await?) {
                Some(IdemState::Done) => {}
                Some(IdemState::None) if rounds == 0 => {}
                Some(IdemState::None) => {
                    alarm(
                        "operator_required",
                        &pid,
                        json!({"cause": "idempotency key unknown to the provider"}),
                    );
                    self.end_round(
                        &row,
                        now + backoff_s(rounds + 1),
                        true,
                        Some("operator_required"),
                    )
                    .await?;
                    return Ok(PayOutcome::StillUnknown);
                }
                Some(IdemState::InProgress | IdemState::Ambiguous) | None => resend = false,
            }
        }
        if !resend {
            self.end_round(&row, now + backoff_s(rounds + 1), false, None)
                .await?;
            return Ok(PayOutcome::StillUnknown);
        }
        // 3. Same-key resend; the counter is committed (with the lease) before the call.
        let me = rt.me;
        let conn = self.conn().await?;
        let counted = Self::run(conn, async move |c: &mut Client| {
            let n = c
                .execute(
                    "UPDATE nodkey.payment_effect SET resends = resends + 1, lease_until = $3 WHERE pending_id = $1 \
                     AND state = 'UNKNOWN' AND lease_owner = $2",
                    &[&pid.as_slice(), &me.as_slice(), &to_i64(now + lease)],
                )
                .await
                .map_err(dbf("resend count"))?;
            Ok(n == 1)
        })
        .await?;
        if !counted {
            return Ok(PayOutcome::Discarded);
        }
        log_event(
            "payments_resend",
            json!({"pending_id": encode_id(&pid), "resend": row.resends + 1}),
        );
        match done!(self.call_create(&g).await?).flatten() {
            Some(Attempt::Created { refund, reference }) => {
                if let Some(Some(r)) = done!(self.confirm(&g, &refund).await?) {
                    let to = PayTo::Succeeded {
                        refund_id: r.id.clone(),
                        settlement: r.status,
                    };
                    return Ok(
                        if self
                            .apply(&pid, "UNKNOWN", &to, true, Some(&reference), "")
                            .await?
                        {
                            PayOutcome::Applied(to)
                        } else {
                            PayOutcome::Discarded
                        },
                    );
                }
            }
            Some(Attempt::Refused { code, .. })
                if BUSINESS_REFUSALS.contains(&code.as_str()) && h.has_cap("idem_status") =>
            {
                let not_found = done!(
                    self.call_lookup(&g, "refund.find", json!({"grant": row.grant_text}))
                        .await?
                ) == Some(Lookup::NotFound);
                if not_found && done!(self.call_idem(&g).await?) == Some(IdemState::Done) {
                    alarm("provider_contradicts_facts", &pid, json!({"code": code}));
                    let to = PayTo::Failed {
                        reason: "provider_declined",
                    };
                    return Ok(if self.apply(&pid, "UNKNOWN", &to, true, None, "").await? {
                        PayOutcome::Applied(to)
                    } else {
                        PayOutcome::Discarded
                    });
                }
            }
            Some(Attempt::Refused { code, .. }) if code == "p:idem_kid_mismatch" => {
                alarm("adapter_idem_kid_mismatch", &pid, json!({}));
            }
            _ => {}
        }
        self.end_round(&row, (self.clock)() + backoff_s(rounds + 1), false, None)
            .await?;
        Ok(PayOutcome::StillUnknown)
    }

    /// Settlement polling for `SUCCEEDED` rows with `settlement = pending` (§7.3).
    pub async fn poll_settlement(&self, pid: [u8; 16]) -> Result<PayOutcome, Fail> {
        let rt = self.rt()?;
        let Some(h) = rt.is_ready() else {
            return Ok(PayOutcome::Skipped);
        };
        let lease = rt.cfg.lease_reconcile_s();
        if !self.take_lease(&pid, "SUCCEEDED", lease).await? {
            return Ok(PayOutcome::Skipped);
        }
        let conn = self.conn().await?;
        let Some(row) = Self::run(conn, async move |c: &mut Client| {
            effect_row(&*c, &pid).await
        })
        .await?
        else {
            return Ok(PayOutcome::Skipped);
        };
        let Some(id) = row.provider_refund_id.clone() else {
            return Ok(PayOutcome::Skipped);
        };
        let now = (self.clock)();
        let since = row.dispatched_at.unwrap_or(now);
        let rounds = u32::try_from(row.rounds).unwrap_or(u32::MAX);
        let g = Held {
            row: &row,
            state: "SUCCEEDED",
            lease_s: lease,
        };
        let status = if row.idem_kid != h.idem_kid {
            alarm("idem_kid_mismatch", &pid, json!({}));
            None
        } else {
            match self
                .call_lookup(
                    &g,
                    "refund.get",
                    json!({"grant": row.grant_text, "refund_id": id}),
                )
                .await?
            {
                Called::Lost => return Ok(PayOutcome::Discarded),
                Called::Done(Lookup::Found(v))
                    if v.len() == 1 && v[0].id == id && row.matches(&v[0]) =>
                {
                    Some(v[0].status)
                }
                _ => None,
            }
        };
        let (settlement, next): (Option<&str>, Option<u64>) = match status {
            Some(RefundStatus::Succeeded) => (Some("succeeded"), None),
            Some(RefundStatus::Failed) => {
                alarm("refund_settlement_failed", &pid, json!({}));
                (Some("failed"), None)
            }
            _ if now >= since.saturating_add(SETTLEMENT_WINDOW_S) => {
                alarm("settlement_unresolved", &pid, json!({}));
                (None, None)
            }
            _ => (None, Some(now + backoff_s(rounds + 1))),
        };
        let me = rt.me;
        let conn = self.conn().await?;
        Self::run(conn, async move |c: &mut Client| {
            c.execute(
                "UPDATE nodkey.payment_effect SET settlement = COALESCE($3, settlement), next_check_at = $4, \
                 reconcile_rounds = reconcile_rounds + 1, lease_until = $5 WHERE pending_id = $1 AND state = 'SUCCEEDED' \
                 AND settlement = 'pending' AND lease_owner = $2",
                &[&pid.as_slice(), &me.as_slice(), &settlement, &next.map(to_i64), &to_i64(now)],
            )
            .await
            .map_err(dbf("settlement"))?;
            Ok(())
        })
        .await?;
        Ok(PayOutcome::StillUnknown)
    }

    /// One payments pass (start-up, then every 5 s, in its own task; BP-04): stale `RESERVED`
    /// → `FAILED/not_dispatched`, expired `DISPATCHED` → `UNKNOWN/lost_response`, then the
    /// reconciliation and settlement rounds. All scans read one snapshot. Rows are processed at
    /// most [`ROW_CONCURRENCY`] at a time, and a failure on one row is logged, alarmed and
    /// backed off without stopping the others (BP-05).
    pub async fn payments_tick(self: &Arc<Self>) -> Result<Vec<([u8; 16], PayOutcome)>, Fail> {
        if self.payments.is_none() {
            return Ok(vec![]);
        }
        let ready = self.ensure_adapter().await;
        let now = (self.clock)();
        let conn = self.conn().await?;
        let (stale, lost, due, settle) = Self::run(conn, async move |c: &mut Client| {
            let ids = |rows: Vec<tokio_postgres::Row>| -> Result<Vec<[u8; 16]>, Fail> {
                rows.iter()
                    .map(|r| {
                        let b: Vec<u8> = r.try_get(0).map_err(unavailable)?;
                        <[u8; 16]>::try_from(b.as_slice()).map_err(unavailable)
                    })
                    .collect()
            };
            let q = async |sql: &str, p: &[&(dyn tokio_postgres::types::ToSql + Sync)]| {
                c.query(sql, p).await.map_err(dbf("payments scan"))
            };
            let stale = ids(q("SELECT pending_id FROM nodkey.payment_effect WHERE state = 'RESERVED' AND reserved_at + $1 < $2 LIMIT $3",
                &[&to_i64(RESERVED_TIMEOUT_S), &to_i64(now), &BATCH]).await?)?;
            let lost = ids(q("SELECT pending_id FROM nodkey.payment_effect WHERE state = 'DISPATCHED' AND lease_until < $1 LIMIT $2",
                &[&to_i64(now), &BATCH]).await?)?;
            let due = ids(q("SELECT pending_id FROM nodkey.payment_effect WHERE state = 'UNKNOWN' AND next_check_at <= $1 \
                 AND (lease_until IS NULL OR lease_until < $1) ORDER BY next_check_at LIMIT $2", &[&to_i64(now), &BATCH]).await?)?;
            let settle = ids(q("SELECT pending_id FROM nodkey.payment_effect WHERE state = 'SUCCEEDED' AND settlement = 'pending' \
                 AND next_check_at <= $1 AND (lease_until IS NULL OR lease_until < $1) LIMIT $2", &[&to_i64(now), &BATCH]).await?)?;
            Ok((stale, lost, due, settle))
        })
        .await?;
        let mut work: Vec<([u8; 16], Work)> = Vec::new();
        work.extend(stale.into_iter().map(|p| (p, Work::Stale(now))));
        work.extend(lost.into_iter().map(|p| (p, Work::Lost(now))));
        if ready {
            work.extend(due.into_iter().map(|p| (p, Work::Reconcile)));
            work.extend(settle.into_iter().map(|p| (p, Work::Settle)));
        }
        let limit = Arc::new(Semaphore::new(ROW_CONCURRENCY));
        let mut set = tokio::task::JoinSet::new();
        for (pid, w) in work {
            let Ok(permit) = limit.clone().acquire_owned().await else {
                break;
            };
            let me = self.clone();
            set.spawn(async move {
                let r = me.row_work(pid, w).await;
                drop(permit);
                (pid, r)
            });
        }
        let mut out = Vec::new();
        while let Some(j) = set.join_next().await {
            let Ok((pid, r)) = j else { continue };
            match r {
                Ok(Some(o)) => out.push((pid, o)),
                Ok(None) => {}
                Err(f) => {
                    alarm("payments_row_error", &pid, json!({"detail": f.detail}));
                    self.back_off(&pid).await;
                }
            }
        }
        Ok(out)
    }

    async fn row_work(&self, pid: [u8; 16], w: Work) -> Result<Option<PayOutcome>, Fail> {
        match w {
            Work::Stale(now) => {
                let to = PayTo::Failed {
                    reason: "not_dispatched",
                };
                let extra = format!(" AND reserved_at + {RESERVED_TIMEOUT_S} < {}", to_i64(now));
                Ok(self
                    .apply(&pid, "RESERVED", &to, false, None, &extra)
                    .await?
                    .then_some(PayOutcome::Applied(to)))
            }
            Work::Lost(now) => {
                let to = PayTo::Unknown {
                    reason: "lost_response",
                };
                let extra = format!(" AND lease_until < {}", to_i64(now));
                Ok(self
                    .apply(&pid, "DISPATCHED", &to, false, None, &extra)
                    .await?
                    .then_some(PayOutcome::Applied(to)))
            }
            Work::Reconcile => self.reconcile(pid).await.map(Some),
            Work::Settle => self.poll_settlement(pid).await.map(Some),
        }
    }

    /// After a row failed with an error, its next check is pushed back (best effort), so a
    /// persistent failure on one row is retried slowly instead of every tick.
    async fn back_off(&self, pid: &[u8; 16]) {
        let now = (self.clock)();
        let pid = *pid;
        let Ok(conn) = self.conn().await else { return };
        let _ = Self::run(conn, async move |c: &mut Client| {
            c.execute(
                "UPDATE nodkey.payment_effect SET next_check_at = $2 WHERE pending_id = $1 \
                 AND state IN ('UNKNOWN','SUCCEEDED') AND next_check_at IS NOT NULL",
                &[&pid.as_slice(), &to_i64(now + ROW_ERROR_BACKOFF_S)],
            )
            .await
            .map_err(dbf("back off"))
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_map_to_the_workload_enum() {
        assert_eq!(
            workload_reason("not_owner_or_unknown"),
            Some("not_permitted")
        );
        for r in [
            "currency",
            "order_status",
            "order_busy",
            "insufficient_refundable",
        ] {
            assert_eq!(workload_reason(r), Some("not_refundable"));
        }
        assert_eq!(workload_reason("budget"), Some("limit"));
        assert_eq!(workload_reason("grant"), Some("not_permitted"));
        for r in ["not_dispatched", "not_sent", "provider_declined"] {
            assert_eq!(workload_reason(r), Some("not_executed"));
        }
        assert_eq!(workload_reason("ambiguous"), None);
    }

    #[test]
    fn approval_checks_order_ownership_first() {
        let o = Order {
            order_id: 7,
            ten: "acme".into(),
            owner_sub: "user:a".into(),
            charge_id: "ch_aaaaaaaa01".into(),
            currency: "USD".into(),
            captured: 1000,
            external_refunded: 0,
            status: "disputed".into(),
        };
        let rp = |cur: &'static str, ch: &'static str| RefundParams {
            order_id: 7,
            amount: 5,
            currency: cur,
            charge: ch,
        };
        // A foreign order reports ownership even if currency and status would also fail.
        assert_eq!(
            approval_reason(Some(&o), "acme", "user:b", &rp("EUR", "ch_aaaaaaaa01")),
            Some("not_owner_or_unknown")
        );
        assert_eq!(
            approval_reason(Some(&o), "acme", "user:a", &rp("USD", "ch_bbbbbbbb01")),
            Some("not_owner_or_unknown")
        );
        assert_eq!(
            approval_reason(None, "acme", "user:a", &rp("USD", "ch_aaaaaaaa01")),
            Some("not_owner_or_unknown")
        );
        assert_eq!(
            approval_reason(Some(&o), "acme", "user:a", &rp("EUR", "ch_aaaaaaaa01")),
            Some("currency")
        );
        assert_eq!(
            approval_reason(Some(&o), "acme", "user:a", &rp("USD", "ch_aaaaaaaa01")),
            Some("order_status")
        );
        let ok = Order {
            status: "partially_refunded".into(),
            ..o
        };
        assert_eq!(
            approval_reason(Some(&ok), "acme", "user:a", &rp("USD", "ch_aaaaaaaa01")),
            None
        );
    }

    #[test]
    fn backoff_and_days() {
        assert_eq!(
            (
                backoff_s(0),
                backoff_s(1),
                backoff_s(2),
                backoff_s(3),
                backoff_s(9)
            ),
            (10, 60, 300, 1800, 3600)
        );
        assert_eq!(utc_day(86_399), 0);
        assert_eq!(utc_day(86_400), 1);
    }
}
