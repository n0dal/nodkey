// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Method semantics of effect protocol v2 (Draft 2) for the three broker sockets, the execution
//! transaction, and the recovery loop.
//!
//! - Socket W (workload): `effect.propose`, `effect.status`, read operations (§2).
//! - Socket G (gateway): `pending.render`, `pending.deny` (§4.1). No grant is accepted there.
//! - Socket A (authority): `pending.get`, `grant.deliver`, `config.digest` (§4.2, §4.3).
//! - Execution (§4.4): from `APPROVED`, consumption (W10), savepoint, W11–W13, W14 and the effect,
//!   or a recorded denial, all in **one** transaction. Any failure before commit leaves the record
//!   `APPROVED` with nothing consumed; the recovery loop retries until success or expiry.
//!
//! Every state transition is a conditional `UPDATE … WHERE pending_id = $1 AND state = <from>`
//! that must touch exactly one row; the database trigger in `02-effects-v2.sh` additionally
//! rejects any transition not in §3.3 and any change to an immutable column.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nodkey_grant::{
    GrantError, OpKind, Operations, ParamValue, Params, Registry, Request, RevocationScope,
    RevokedBefore, Verified, VerifyContext, decode_transport, verify,
};
use serde_json::{Map, Value, json};
use tokio_postgres::{Client, GenericClient, Row};

use super::config::{ApproverSource, MandateCfg, V2Config, WorkloadReg};
use super::db::{Conn, Pool};
use super::decls::{self, Executor, LEDGER_TRANSFER};
use super::digest::{DisplayValue, PendingFields, json_uint, typed_params};
use super::ids::{decode_id, encode_id, hex, is_id, parse_hex32, random16};
use super::limits::{ConcurrencyGate, RateLimiter};
use super::wire::{Code, Fail, check_keys, str_arg, subject_arg};
use crate::server::log_event;
use crate::strict_json;

/// Bound on one database operation, including lock waits (deadline, spec §4.4).
pub const OP_TIMEOUT: Duration = Duration::from_secs(10);
/// Recovery loop period (spec §4.4).
pub const RECOVERY_PERIOD: Duration = Duration::from_secs(5);
/// Rows handled per recovery pass (bounded work).
pub const RECOVERY_BATCH: i64 = 128;
/// `recent_identical` window (spec §4.1).
pub const RECENT_WINDOW_S: u64 = 30 * 60;
pub const CONTEXT_LIST_MAX: i64 = 16;

/// Wall clock in Unix seconds. Injected so that tests can control time.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// Pending-effect states (spec §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Approved,
    Executing,
    Succeeded,
    Failed,
    Unknown,
    Denied,
    Expired,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Pending => "PENDING",
            State::Approved => "APPROVED",
            State::Executing => "EXECUTING",
            State::Succeeded => "SUCCEEDED",
            State::Failed => "FAILED",
            State::Unknown => "UNKNOWN",
            State::Denied => "DENIED",
            State::Expired => "EXPIRED",
        }
    }
    pub fn parse(s: &str) -> Option<State> {
        Some(match s {
            "PENDING" => State::Pending,
            "APPROVED" => State::Approved,
            "EXECUTING" => State::Executing,
            "SUCCEEDED" => State::Succeeded,
            "FAILED" => State::Failed,
            "UNKNOWN" => State::Unknown,
            "DENIED" => State::Denied,
            "EXPIRED" => State::Expired,
            _ => return None,
        })
    }
    pub fn is_final(self) -> bool {
        matches!(
            self,
            State::Denied | State::Expired | State::Succeeded | State::Failed
        )
    }
}

/// One stored pending-effect record.
#[derive(Debug, Clone)]
pub struct Record {
    pub fields: PendingFields,
    pub digest: [u8; 32],
    pub state: State,
    pub grant: Option<Vec<u8>>,
    pub grant_exp: Option<u64>,
    pub outcome_class: Option<String>,
    pub receipt_id: Option<[u8; 16]>,
}

impl Record {
    /// `outcome` member of `effect.status` (§2.3, T45).
    pub fn outcome_json(&self) -> Value {
        match self.state {
            State::Unknown => json!({"class": "unknown", "receipt_id": null}),
            s if s.is_final() => json!({
                "class": self.outcome_class,
                "receipt_id": self.receipt_id.as_ref().map(encode_id),
            }),
            _ => Value::Null,
        }
    }
}

/// Result of `grant.deliver` (§4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Accepted,
    Rejected(String),
    Expired(String),
    Unavailable(String),
}

/// Result of one execution attempt (§4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Execution {
    /// The record was not `APPROVED` (already decided, or never approved).
    NotApproved,
    /// `now ≥ grant.exp + skew`: `APPROVED → EXPIRED`, nothing consumed.
    Expired,
    /// The stored grant no longer verifies (e.g. key revoked): nothing consumed; the record
    /// stays `APPROVED` until it expires.
    Unverified(&'static str),
    Succeeded,
    /// External effect decided: consumed `ACCEPT`, `RESERVED` row, record `EXECUTING`. The
    /// dispatcher (T2) follows.
    Reserved,
    /// A recorded denial: `FAILED/denied`, `consumed_grant.outcome = DENIED`.
    Denied(String),
}

pub(crate) fn unavailable(d: impl std::fmt::Display) -> Fail {
    Fail::new(Code::Unavailable, d.to_string())
}

pub(crate) fn dbf(what: &'static str) -> impl Fn(tokio_postgres::Error) -> Fail {
    move |e| Fail::new(Code::Unavailable, format!("{what}: {e}"))
}

pub(crate) fn to_i64(n: u64) -> i64 {
    // Every stored number is ≤ 2^53 − 1 (validated), so this never saturates in practice.
    i64::try_from(n).unwrap_or(i64::MAX)
}

pub(crate) fn to_u64(n: i64) -> Result<u64, Fail> {
    u64::try_from(n).map_err(|_| unavailable("negative stored value"))
}

const RECORD_COLS: &str = "pending_id, broker_id, wid, ten, approver_sub, op, opv, params, \
     param_types, display, created_at, expires_at, digest, state, grant_bytes, grant_exp, \
     outcome_class, receipt_id";

fn parse_json_object(text: &str) -> Result<Map<String, Value>, Fail> {
    strict_json::check_strict(text.as_bytes()).map_err(unavailable)?;
    match serde_json::from_str(text).map_err(unavailable)? {
        Value::Object(o) => Ok(o),
        _ => Err(unavailable("stored JSON is not an object")),
    }
}

/// Rebuilds a record from a row and re-verifies its stored digest (integrity check; a mismatch
/// fails closed).
fn record_from_row(r: &Row) -> Result<Record, Fail> {
    let pid: Vec<u8> = r.try_get(0).map_err(unavailable)?;
    let pending_id = <[u8; 16]>::try_from(pid.as_slice()).map_err(unavailable)?;
    let types_obj = parse_json_object(r.try_get(8).map_err(unavailable)?)?;
    let mut param_types = BTreeMap::new();
    for (k, v) in &types_obj {
        param_types.insert(
            k.clone(),
            v.as_str()
                .ok_or_else(|| unavailable("param type"))?
                .to_owned(),
        );
    }
    let params = typed_params(
        &parse_json_object(r.try_get(7).map_err(unavailable)?)?,
        &param_types,
    )
    .map_err(unavailable)?;
    let mut display = BTreeMap::new();
    for (k, v) in parse_json_object(r.try_get(9).map_err(unavailable)?)? {
        let dv = match v {
            Value::String(s) => DisplayValue::Text(s),
            v => DisplayValue::Uint(json_uint(&v).ok_or_else(|| unavailable("display"))?),
        };
        display.insert(k, dv);
    }
    let opv: i32 = r.try_get(6).map_err(unavailable)?;
    let fields = PendingFields {
        pending_id,
        broker_id: r.try_get(1).map_err(unavailable)?,
        wid: r.try_get(2).map_err(unavailable)?,
        ten: r.try_get(3).map_err(unavailable)?,
        approver_sub: r.try_get(4).map_err(unavailable)?,
        op: r.try_get(5).map_err(unavailable)?,
        opv: u64::try_from(opv).map_err(unavailable)?,
        params,
        param_types,
        created_at: to_u64(r.try_get(10).map_err(unavailable)?)?,
        expires_at: to_u64(r.try_get(11).map_err(unavailable)?)?,
        display,
    };
    let stored: Vec<u8> = r.try_get(12).map_err(unavailable)?;
    let digest = <[u8; 32]>::try_from(stored.as_slice()).map_err(unavailable)?;
    let recomputed = fields.digest().map_err(unavailable)?;
    if recomputed != digest {
        log_event(
            "alarm",
            json!({"kind": "pending_digest_mismatch", "pending_id": encode_id(&pending_id)}),
        );
        return Err(unavailable("stored digest does not match the record"));
    }
    let state_s: String = r.try_get(13).map_err(unavailable)?;
    let receipt: Option<Vec<u8>> = r.try_get(17).map_err(unavailable)?;
    let grant_exp: Option<i64> = r.try_get(15).map_err(unavailable)?;
    Ok(Record {
        fields,
        digest,
        state: State::parse(&state_s).ok_or_else(|| unavailable("state"))?,
        grant: r.try_get(14).map_err(unavailable)?,
        grant_exp: grant_exp.map(to_u64).transpose()?,
        outcome_class: r.try_get(16).map_err(unavailable)?,
        receipt_id: receipt
            .map(|b| <[u8; 16]>::try_from(b.as_slice()).map_err(unavailable))
            .transpose()?,
    })
}

pub(crate) async fn select_record(
    c: &impl GenericClient,
    pid: &[u8; 16],
    for_update: bool,
) -> Result<Option<Record>, Fail> {
    let sql = format!(
        "SELECT {RECORD_COLS} FROM public.pending_effect WHERE pending_id = $1{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    let row = c
        .query_opt(&sql, &[&pid.as_slice()])
        .await
        .map_err(dbf("select record"))?;
    row.as_ref().map(record_from_row).transpose()
}

pub(crate) async fn revocations(
    c: &impl GenericClient,
    ten: &str,
) -> Result<Vec<RevokedBefore>, Fail> {
    let rows = c
        .query(
            "SELECT wid, sub, before FROM public.revoked_before WHERE ten = $1",
            &[&ten],
        )
        .await
        .map_err(dbf("revoked_before"))?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let wid: Option<String> = r.try_get(0).map_err(unavailable)?;
        let sub: Option<String> = r.try_get(1).map_err(unavailable)?;
        let before = to_u64(r.try_get(2).map_err(unavailable)?)?;
        let scope = match (wid, sub) {
            (None, None) => RevocationScope::Tenant { ten: ten.into() },
            (Some(wid), None) => RevocationScope::TenantWorkload {
                ten: ten.into(),
                wid,
            },
            (None, Some(sub)) => RevocationScope::TenantSubject {
                ten: ten.into(),
                sub,
            },
            (Some(_), Some(_)) => return Err(unavailable("revoked_before row has wid and sub")),
        };
        out.push(RevokedBefore { scope, before });
    }
    Ok(out)
}

/// Final-state CAS from `from` with an outcome class and a fresh random receipt id.
pub(crate) async fn finalize(
    c: &impl GenericClient,
    pid: &[u8; 16],
    from: State,
    (to, class): (State, &str),
    now: u64,
    extra_cond: &str,
    extra_params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<bool, Fail> {
    let receipt = random16().map_err(unavailable)?;
    let sql = format!(
        "UPDATE public.pending_effect SET state = $3, state_changed_at = $4, outcome_class = $5, \
         receipt_id = $6 WHERE pending_id = $1 AND state = $2{extra_cond}"
    );
    let now_i = to_i64(now);
    let (pid_s, from_s, to_s, receipt_s) = (
        pid.as_slice(),
        from.as_str(),
        to.as_str(),
        receipt.as_slice(),
    );
    let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
        vec![&pid_s, &from_s, &to_s, &now_i, &class, &receipt_s];
    params.extend_from_slice(extra_params);
    let n = c
        .execute(&sql, &params)
        .await
        .map_err(dbf("state update"))?;
    Ok(n == 1)
}

/// Lazy expiry (§3.3): applies `PENDING → EXPIRED` or `APPROVED → EXPIRED` if due. Each is a
/// conditional update, so it races safely with every other transition.
async fn lazy_expire(
    c: &impl GenericClient,
    pid: &[u8; 16],
    now: u64,
    skew: u64,
) -> Result<(), Fail> {
    let now_i = to_i64(now);
    let skew_i = to_i64(skew);
    finalize(
        c,
        pid,
        State::Pending,
        (State::Expired, "expired"),
        now,
        " AND expires_at <= $7",
        &[&now_i],
    )
    .await?;
    finalize(
        c,
        pid,
        State::Approved,
        (State::Expired, "expired"),
        now,
        " AND grant_exp + $7 <= $8",
        &[&skew_i, &now_i],
    )
    .await?;
    Ok(())
}

fn is_grant_mismatch(e: GrantError) -> bool {
    matches!(
        e,
        GrantError::WorkloadMismatch
            | GrantError::TenantMismatch
            | GrantError::OpMismatch
            | GrantError::KindMismatch
            | GrantError::OpvUnsupported
            | GrantError::ConfirmationRequired
            | GrantError::OpSchemaInvalid
            | GrantError::ResourceMismatch
            | GrantError::ConstraintMismatch
            | GrantError::BoundExceeded
    )
}

pub(crate) fn text_param<'a>(p: &'a Params, k: &str) -> Result<&'a str, Fail> {
    match p.get(k) {
        Some(ParamValue::Text(s)) => Ok(s),
        _ => Err(unavailable(format!("param {k}"))),
    }
}

pub(crate) fn uint_param(p: &Params, k: &str) -> Result<u64, Fail> {
    match p.get(k) {
        Some(ParamValue::Uint(n)) => Ok(*n),
        _ => Err(unavailable(format!("param {k}"))),
    }
}

/// Ownership facts for `ledger.transfer` (trusted rows only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransferFacts {
    from_owned: bool,
    from_balance: Option<i64>,
    to_owned_by_approver: bool,
    to_in_tenant: bool,
}

/// Reads ownership and balances. With `lock`, the account rows are locked `FOR UPDATE` in id
/// order first; ownership changes serialize on those locks (trigger in `02-effects-v2.sh`).
async fn transfer_facts(
    c: &impl GenericClient,
    ten: &str,
    approver: &str,
    from: &str,
    to: &str,
    lock: bool,
) -> Result<TransferFacts, Fail> {
    let sql = if lock {
        "SELECT id, balance_cents FROM public.accounts WHERE id = $1 OR id = $2 ORDER BY id FOR UPDATE"
    } else {
        "SELECT id, balance_cents FROM public.accounts WHERE id = $1 OR id = $2"
    };
    let accts = c.query(sql, &[&from, &to]).await.map_err(dbf("accounts"))?;
    let owners = c
        .query(
            "SELECT account_id, ten, owner_sub FROM public.account_owner WHERE account_id = $1 OR account_id = $2",
            &[&from, &to],
        )
        .await
        .map_err(dbf("account_owner"))?;
    let mut f = TransferFacts {
        from_owned: false,
        from_balance: None,
        to_owned_by_approver: false,
        to_in_tenant: false,
    };
    let mut from_exists = false;
    let mut to_exists = false;
    for r in &accts {
        let id: String = r.try_get(0).map_err(unavailable)?;
        let bal: i64 = r.try_get(1).map_err(unavailable)?;
        if id == from {
            from_exists = true;
            f.from_balance = Some(bal);
        }
        if id == to {
            to_exists = true;
        }
    }
    for r in &owners {
        let id: String = r.try_get(0).map_err(unavailable)?;
        let t: String = r.try_get(1).map_err(unavailable)?;
        let s: String = r.try_get(2).map_err(unavailable)?;
        let mine = t == ten && s == approver;
        if id == from && from_exists && mine {
            f.from_owned = true;
        }
        if id == to && to_exists {
            f.to_in_tenant = t == ten;
            f.to_owned_by_approver = mine;
        }
    }
    if !f.from_owned {
        f.from_balance = None;
    }
    Ok(f)
}

/// The broker: configuration, key registry, declarations, store and limits.
pub struct Broker {
    pub cfg: V2Config,
    pub registry: Registry,
    pub ops: Operations,
    pub op_names: Vec<String>,
    /// Workload lane: socket W only, bounded per workload by `workload_gate` (BR-01).
    pub db: Pool,
    /// Control lane: sockets G and A, execution and recovery. A workload can never use it, so a
    /// workload flood cannot starve approvals or approved effects (BR-01).
    pub control_db: Pool,
    config_digest: [u8; 32],
    pub(crate) clock: Clock,
    /// Demo P payments side (payments-adapter-v1); `None` when not configured.
    pub payments: Option<super::payments::PaymentsRuntime>,
    high_water: AtomicU64,
    proposals: RateLimiter,
    statuses: RateLimiter,
    reads: RateLimiter,
    workload_gate: ConcurrencyGate,
    unverifiable_alarmed: std::sync::Mutex<std::collections::HashSet<[u8; 16]>>,
    /// Mandates (agent-interface-v1 §3–§4), from the workloads file; `None` = disabled.
    pub(crate) mandate_cfg: Option<MandateCfg>,
}

/// Wait for a per-workload DB slot before answering `limit_exceeded`.
pub const WORKLOAD_SLOT_WAIT: Duration = Duration::from_secs(1);
const MAX_ALARM_MEMORY: usize = 4096;

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("broker_id", &self.cfg.broker_id)
            .finish()
    }
}

impl Broker {
    pub fn new(
        cfg: V2Config,
        registry: Registry,
        ops: Operations,
        op_names: Vec<String>,
        (db, control_db): (Pool, Pool),
        config_digest: [u8; 32],
        clock: Clock,
    ) -> Broker {
        let wids = || cfg.workloads.iter().map(|w| w.wid.as_str());
        let proposals = RateLimiter::new(
            cfg.limits.proposals_per_min,
            cfg.limits.proposal_burst,
            wids(),
        );
        let statuses =
            RateLimiter::new(cfg.limits.status_per_min, cfg.limits.status_per_min, wids());
        let reads = RateLimiter::new(cfg.limits.reads_per_min, cfg.limits.reads_per_min, wids());
        let workload_gate = ConcurrencyGate::new(cfg.limits.db_conns_per_wid, wids());
        let payments = cfg.payments.clone().map(|p| {
            super::payments::PaymentsRuntime::new(p).expect("OS CSPRNG for the lease owner id")
        });
        Broker {
            payments,
            cfg,
            registry,
            ops,
            op_names,
            db,
            control_db,
            config_digest,
            clock,
            high_water: AtomicU64::new(0),
            proposals,
            statuses,
            reads,
            workload_gate,
            unverifiable_alarmed: std::sync::Mutex::new(std::collections::HashSet::new()),
            mandate_cfg: None,
        }
    }

    /// Enables mandates and the agent operations with the configuration that
    /// `config::check_authority_workloads` returned (needs `04-mandates.sh`).
    pub fn with_mandates(mut self, m: Option<MandateCfg>) -> Broker {
        self.mandate_cfg = m;
        self
    }

    /// The current `config.digest` (a mandate is active only while it equals the mandate's `cfg`).
    pub(crate) fn config_digest_bytes(&self) -> &[u8; 32] {
        &self.config_digest
    }

    fn skew(&self) -> u64 {
        self.cfg.grant_limits.skew()
    }

    /// `now`, refused while behind the clock high-water mark by more than `skew` (grant-v1 §7.6).
    pub fn now_checked(&self) -> Result<u64, Fail> {
        let now = (self.clock)();
        let hw = self.high_water.load(Ordering::SeqCst);
        if now.saturating_add(self.skew()) < hw {
            log_event(
                "alarm",
                json!({"kind": "clock_behind_high_water", "now": now, "mark": hw}),
            );
            return Err(unavailable("clock behind high-water mark"));
        }
        self.high_water.fetch_max(now, Ordering::SeqCst);
        Ok(now)
    }

    /// Control-lane connection (sockets G, A, execution, recovery, start-up).
    pub(crate) async fn conn(&self) -> Result<Conn<'_>, Fail> {
        self.control_db.get().await.map_err(unavailable)
    }

    /// Workload-lane connection for socket W: first a per-workload slot, then a pool slot.
    pub(crate) async fn wl_conn(
        &self,
        wid: &str,
    ) -> Result<(tokio::sync::OwnedSemaphorePermit, Conn<'_>), Fail> {
        let permit = self
            .workload_gate
            .acquire(wid, WORKLOAD_SLOT_WAIT)
            .await
            .ok_or_else(|| Fail::new(Code::LimitExceeded, "workload database concurrency"))?;
        let conn = self.db.get().await.map_err(unavailable)?;
        Ok((permit, conn))
    }

    /// Runs one database operation under the deadline; discards the connection on any
    /// infrastructure failure so the server rolls back whatever was open.
    pub(crate) async fn run<T>(
        mut conn: Conn<'_>,
        fut: impl AsyncFnOnce(&mut Client) -> Result<T, Fail>,
    ) -> Result<T, Fail> {
        let r = tokio::time::timeout(OP_TIMEOUT, fut(conn.client())).await;
        match r {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(f)) => {
                if f.code == Code::Unavailable {
                    conn.discard();
                }
                Err(f)
            }
            Err(_) => {
                conn.discard();
                Err(unavailable("operation deadline exceeded"))
            }
        }
    }

    /// Start-up: claims the database for protocol v2 under this `broker_id` (refuses if a v1
    /// broker or another `broker_id` claimed it, EP-10 / grant-v1 §7.1), and initializes and
    /// checks the persisted clock high-water mark.
    pub async fn startup_checks(&self) -> Result<(), String> {
        let now = (self.clock)();
        let bid = self.cfg.broker_id.as_str().to_owned();
        let conn = self.conn().await.map_err(|f| f.detail)?;
        let bid2 = bid.clone();
        let mark = Self::run(conn, async move |c: &mut Client| {
            let bid = bid2;
            c.execute(
                "INSERT INTO public.broker_claim (singleton, protocol, broker_id) VALUES (true, 2, $1) \
                 ON CONFLICT (singleton) DO NOTHING",
                &[&bid],
            )
            .await
            .map_err(dbf("claim"))?;
            let r = c
                .query_one("SELECT protocol, broker_id FROM public.broker_claim", &[])
                .await
                .map_err(dbf("claim read"))?;
            let p: i32 = r.try_get(0).map_err(unavailable)?;
            let b: String = r.try_get(1).map_err(unavailable)?;
            if p != 2 || b != bid {
                return Err(Fail::new(
                    Code::Unavailable,
                    format!("database already claimed by protocol {p} broker {b:?} (refusing to start)"),
                ));
            }
            c.execute(
                "INSERT INTO public.broker_clock (broker_id, mark) VALUES ($1, $2) ON CONFLICT (broker_id) DO NOTHING",
                &[&bid, &to_i64(now)],
            )
            .await
            .map_err(dbf("clock init"))?;
            let r = c
                .query_one("SELECT mark FROM public.broker_clock WHERE broker_id = $1", &[&bid])
                .await
                .map_err(dbf("clock read"))?;
            to_u64(r.try_get(0).map_err(unavailable)?)
        })
        .await
        .map_err(|f| f.detail)?;
        if now.saturating_add(self.skew()) < mark {
            return Err(format!(
                "clock {now} is behind the persisted high-water mark {mark} (refusing to serve)"
            ));
        }
        self.high_water.fetch_max(mark, Ordering::SeqCst);
        // Persist max(mark, now) at start-up as well, not only in the recovery loop (BR-10).
        let conn = self.conn().await.map_err(|f| f.detail)?;
        Self::run(conn, async |c: &mut Client| {
            c.execute(
                "UPDATE public.broker_clock SET mark = GREATEST(mark, $2) WHERE broker_id = $1",
                &[&bid, &to_i64(now)],
            )
            .await
            .map_err(dbf("clock mark"))
        })
        .await
        .map_err(|f| f.detail)?;
        Ok(())
    }

    // ------------------------------------------------------------------ socket W

    /// Resolves `charge_id` for `payments.refund` by `(ten, order_id)` only, without any ownership
    /// check, so the propose response is identical for every order (Draft 3.1 §2.3, T12).
    async fn resolve_charge(&self, wid: &str, ten: &str, order_id: u64) -> Result<String, Fail> {
        let (_slot, conn) = self.wl_conn(wid).await?;
        let ten = ten.to_owned();
        Self::run(conn, async move |c: &mut Client| {
            let row = c
                .query_opt(
                    "SELECT charge_id FROM nodkey.orders WHERE ten = $1 AND order_id = $2",
                    &[&ten, &to_i64(order_id)],
                )
                .await
                .map_err(dbf("resolve charge"))?;
            Ok(match row {
                Some(r) => r.try_get::<_, String>(0).map_err(unavailable)?,
                None => decls::UNRESOLVED.to_owned(),
            })
        })
        .await
    }

    /// Resolves `(charge_id, owner_sub)` of an order by `(ten, order_id)` only (AI §3).
    async fn resolve_order(
        &self,
        wid: &str,
        ten: &str,
        order_id: u64,
    ) -> Result<Option<(String, String)>, Fail> {
        let (_slot, conn) = self.wl_conn(wid).await?;
        let ten = ten.to_owned();
        Self::run(conn, async move |c: &mut Client| {
            let row = c
                .query_opt(
                    "SELECT charge_id, owner_sub FROM nodkey.orders WHERE ten = $1 AND order_id = $2",
                    &[&ten, &to_i64(order_id)],
                )
                .await
                .map_err(dbf("resolve order"))?;
            row.map(|r| {
                Ok((
                    r.try_get(0).map_err(unavailable)?,
                    r.try_get(1).map_err(unavailable)?,
                ))
            })
            .transpose()
        })
        .await
    }

    /// Resolves a customer's email by `(ten, sub)` only (AI §3, §4.1).
    async fn resolve_email(&self, wid: &str, ten: &str, sub: &str) -> Result<Option<String>, Fail> {
        let (_slot, conn) = self.wl_conn(wid).await?;
        let (ten, sub) = (ten.to_owned(), sub.to_owned());
        Self::run(conn, async move |c: &mut Client| {
            super::mandate::customer_email(&*c, &ten, &sub).await
        })
        .await
    }

    /// `effect.propose` (§2.3): syntax, types and registration only; never trusted state.
    pub async fn propose(
        &self,
        wl: &WorkloadReg,
        args: &Map<String, Value>,
    ) -> Result<Value, Fail> {
        let inv = |d: &str| Fail::new(Code::InvalidArgument, d);
        if !self.proposals.try_take(&wl.wid, (self.clock)()) {
            return Err(Fail::new(Code::LimitExceeded, "proposal rate"));
        }
        check_keys(args, &["op", "params", "approver"], &[]).map_err(|f| inv(&f.detail))?;
        let op = args["op"].as_str().ok_or_else(|| inv("op type"))?;
        if decls::executor_of(&self.ops, op) == Some(Executor::NotImplemented) {
            return Err(Fail::new(
                Code::OperationNotPermitted,
                "not_implemented_legacy_declaration",
            ));
        }
        let decl = self
            .ops
            .get(op)
            .filter(|_| self.op_names.iter().any(|n| n == op))
            .ok_or_else(|| inv("undeclared op"))?;
        if decl.kind != OpKind::Write || !decl.requires_confirmation {
            return Err(inv("op is not a confirmed write"));
        }
        if !wl.allowed_ops.contains(op) {
            return Err(inv("op not allowed for this workload"));
        }
        let Value::Object(raw_params) = &args["params"] else {
            return Err(inv("params type"));
        };
        let param_types: BTreeMap<String, String> = decl
            .params
            .iter()
            .map(|p| (p.name.clone(), param_type_name(p.ty).to_owned()))
            .collect();
        // Broker-resolved parameters (Draft 3.1 §2.3) must be absent from the workload's params.
        let resolved = decls::resolved_by_broker(op);
        let wl_types: BTreeMap<String, String> = param_types
            .iter()
            .filter(|(k, _)| !resolved.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut params = typed_params(raw_params, &wl_types).map_err(|e| inv(&e))?;
        let (ten, sub) = subject_arg(&args["approver"]).map_err(|f| inv(&f.detail))?;
        if !is_id(&ten, 128) || !is_id(&sub, 256) {
            return Err(inv("approver is not an ID"));
        }
        let exec = decls::executor_of(&self.ops, op);
        if exec == Some(Executor::PaymentsRefund) {
            // Syntax first, so that a malformed proposal never touches the database.
            let currency = text_param(&params, "currency")?.to_owned();
            if uint_param(&params, "amount_minor")? < 1
                || decls::iso4217_exponent(&currency).is_none()
            {
                return Err(inv(
                    "amount_minor < 1 or currency not in the ISO 4217 table",
                ));
            }
            let order_id = uint_param(&params, "order_id")?;
            let charge = self.resolve_charge(&wl.wid, &ten, order_id).await?;
            params.insert(
                decls::CHARGE_ID.to_owned(),
                nodkey_grant::ParamValue::Text(charge),
            );
        }
        // Agent operations (AI §3, §4.1): syntax and ceilings first, then resolution by
        // `(ten, resource)` only; the reserved value is " " (one space).
        let space = || nodkey_grant::ParamValue::Text(decls::UNRESOLVED_SPACE.to_owned());
        let text = |s: String| nodkey_grant::ParamValue::Text(s);
        match exec {
            Some(Executor::SupportRefund) => {
                let currency = text_param(&params, "currency")?.to_owned();
                if uint_param(&params, "amount_minor")? < 1
                    || decls::iso4217_exponent(&currency).is_none()
                {
                    return Err(inv(
                        "amount_minor < 1 or currency not in the ISO 4217 table",
                    ));
                }
                let order_id = uint_param(&params, "order_id")?;
                let (charge, owner) = match self.resolve_order(&wl.wid, &ten, order_id).await? {
                    Some((c, o)) => (text(c), text(o)),
                    None => (space(), space()),
                };
                params.insert(decls::CHARGE_ID.to_owned(), charge);
                params.insert(decls::CUSTOMER_SUB.to_owned(), owner);
            }
            Some(Executor::MessageSend) => {
                let cs = text_param(&params, decls::CUSTOMER_SUB)?.to_owned();
                if !is_id(&cs, 64) {
                    return Err(inv("customer_sub is not an ID"));
                }
                let to = match self.resolve_email(&wl.wid, &ten, &cs).await? {
                    Some(e) => text(e),
                    None => space(),
                };
                params.insert(decls::TO.to_owned(), to);
            }
            Some(Executor::MandateTemplate) => {
                let t = self
                    .mandate_cfg
                    .as_ref()
                    .and_then(|m| m.template.as_ref())
                    .ok_or_else(|| inv("no mandate template configured"))?;
                let cs = text_param(&params, decls::CUSTOMER_SUB)?.to_owned();
                let currency = text_param(&params, "currency")?.to_owned();
                let u = |k: &str| uint_param(&params, k);
                let (n, per_call, total, msgs, valid) = (
                    u("refund_max_count")?,
                    u("refund_max_per_call_minor")?,
                    u("refund_max_total_minor")?,
                    u("message_max_count")?,
                    u("valid_for_s")?,
                );
                let ok = is_id(&cs, 64)
                    && decls::iso4217_exponent(&currency).is_some()
                    && n <= t.max_refund_count
                    && msgs <= t.max_message_count
                    && per_call <= total
                    && t.max_refund_total_minor
                        .get(&currency)
                        .is_some_and(|c| total <= *c)
                    && (super::config::MANDATE_MIN_S..=super::config::MANDATE_MAX_S)
                        .contains(&valid);
                if !ok {
                    return Err(inv("mandate terms outside the template ceilings"));
                }
                let email = match self.resolve_email(&wl.wid, &ten, &cs).await? {
                    Some(e) => text(e),
                    None => space(),
                };
                params.insert(decls::CUSTOMER_EMAIL.to_owned(), email);
            }
            _ => {}
        }
        // Grammar check through the same parser the grant verifier uses.
        self.ops
            .parse_request(op, params.clone())
            .map_err(|e| inv(&e.to_string()))?;
        match &wl.approver_source {
            ApproverSource::Enrolled { ten: et, sub: es } => {
                if *et != ten || *es != sub {
                    return Err(inv("approver differs from the enrolment"));
                }
            }
            ApproverSource::Named => {
                if !wl.tenants.contains(&ten) {
                    return Err(inv("approver tenant not registered"));
                }
                if decls::has_destination(decl) {
                    return Err(inv("destination op for a named workload"));
                }
            }
        }
        let display = match exec {
            Some(Executor::MessageSend) => BTreeMap::new(),
            Some(
                Executor::PaymentsRefund | Executor::SupportRefund | Executor::MandateTemplate,
            ) => {
                let currency = text_param(&params, "currency")?.to_owned();
                let exp = decls::iso4217_exponent(&currency).ok_or_else(|| inv("currency"))?;
                BTreeMap::from([
                    ("amount_exponent".to_owned(), DisplayValue::Uint(exp)),
                    ("currency".to_owned(), DisplayValue::Text(currency)),
                ])
            }
            Some(Executor::LedgerTransfer) => {
                if text_param(&params, "from")? == text_param(&params, "to")? {
                    return Err(inv("from == to"));
                }
                if uint_param(&params, "amount_minor")? < 1 {
                    return Err(inv("amount_minor < 1"));
                }
                BTreeMap::from([
                    (
                        "amount_exponent".to_owned(),
                        DisplayValue::Uint(self.cfg.ledger_exponent),
                    ),
                    (
                        "currency".to_owned(),
                        DisplayValue::Text(self.cfg.ledger_currency.clone()),
                    ),
                ])
            }
            _ => return Err(inv("no executor")),
        };
        let now = self.now_checked()?;
        let fields = PendingFields {
            pending_id: random16().map_err(unavailable)?,
            broker_id: self.cfg.broker_id.as_str().to_owned(),
            wid: wl.wid.clone(),
            ten,
            approver_sub: sub,
            op: op.to_owned(),
            opv: u64::from(decl.opv),
            params,
            param_types,
            created_at: now,
            expires_at: now + self.cfg.limits.pending_lifetime_s,
            display,
        };
        let digest = fields.digest().map_err(|e| inv(&e))?;
        let limits = self.cfg.limits;
        let (_slot, conn) = self.wl_conn(&wl.wid).await?;
        let f2 = fields.clone();
        let me = self;
        Self::run(conn, async move |c: &mut Client| {
            let tx = c.transaction().await.map_err(dbf("begin"))?;
            // Serializes proposals of one workload so the outstanding counts are exact.
            tx.execute("SELECT pg_advisory_xact_lock(7302, hashtext($1))", &[&f2.wid])
                .await
                .map_err(dbf("advisory lock"))?;
            let r = tx
                .query_one(
                    "SELECT count(*), count(*) FILTER (WHERE ten = $2 AND approver_sub = $3) \
                     FROM public.pending_effect WHERE wid = $1 AND state = 'PENDING' AND expires_at > $4",
                    &[&f2.wid, &f2.ten, &f2.approver_sub, &to_i64(now)],
                )
                .await
                .map_err(dbf("count"))?;
            let per_wid: i64 = r.try_get(0).map_err(unavailable)?;
            let per_approver: i64 = r.try_get(1).map_err(unavailable)?;
            if per_wid >= limits.pending_per_wid || per_approver >= limits.pending_per_approver {
                return Err(Fail::new(Code::LimitExceeded, "outstanding pending records"));
            }
            // effect-protocol-v2 §12.1: `awaiting` from the read-only coverage check (AI §4.3),
            // only when mandates are configured (the column exists only then).
            let awaiting: Option<&str> = match me.mandates() {
                None => None,
                Some(_) if me.coverage(&tx, &f2, now).await? => Some("mandate"),
                Some(_) => Some("confirmation"),
            };
            let sql = if awaiting.is_some() {
                "INSERT INTO public.pending_effect (pending_id, broker_id, wid, ten, approver_sub, op, opv, \
                 params, param_types, display, created_at, expires_at, digest, state, state_changed_at, awaiting) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'PENDING',$11,$14)"
            } else {
                "INSERT INTO public.pending_effect (pending_id, broker_id, wid, ten, approver_sub, op, opv, \
                 params, param_types, display, created_at, expires_at, digest, state, state_changed_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'PENDING',$11)"
            };
            let (pid_b, opv_i) = (f2.pending_id.as_slice(), f2.opv as i32);
            let (pj, tj, dj) = (
                f2.params_json().to_string(),
                f2.param_types_json().to_string(),
                f2.display_json().to_string(),
            );
            let (ca, ea, dg) = (to_i64(f2.created_at), to_i64(f2.expires_at), digest.as_slice());
            let mut ins: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![
                &pid_b, &f2.broker_id, &f2.wid, &f2.ten, &f2.approver_sub, &f2.op, &opv_i, &pj,
                &tj, &dj, &ca, &ea, &dg,
            ];
            if let Some(a) = &awaiting {
                ins.push(a);
            }
            tx.execute(sql, &ins).await.map_err(dbf("insert pending"))?;
            tx.commit().await.map_err(dbf("commit"))?;
            Ok(())
        })
        .await?;
        let pid = encode_id(&fields.pending_id);
        log_event(
            "v2_proposed",
            json!({"pending_id": pid, "wid": fields.wid, "op": fields.op, "ten": fields.ten,
                   "approver_sub": fields.approver_sub, "digest": hex(&digest)}),
        );
        Ok(json!({
            "pending_id": pid,
            "confirm_url": format!("{}/confirm/{}", self.cfg.auth_origin, pid),
            "expires_at": fields.expires_at,
        }))
    }

    /// `effect.status` (§2.3). Every miss (foreign, unknown, non-canonical) runs the same query
    /// and returns the same `not_found`.
    pub async fn status(&self, wl: &WorkloadReg, args: &Map<String, Value>) -> Result<Value, Fail> {
        if !self.statuses.try_take(&wl.wid, (self.clock)()) {
            return Err(Fail::new(Code::LimitExceeded, "status rate"));
        }
        check_keys(args, &["pending_id"], &[])?;
        let text = str_arg(args, "pending_id")?;
        let pid = decode_id(text).unwrap_or([0u8; 16]);
        let canonical = decode_id(text).is_some();
        let now = self.now_checked()?;
        let skew = self.skew();
        let wid = wl.wid.clone();
        let (_slot, conn) = self.wl_conn(&wl.wid).await?;
        let mandates_on = self.mandates().is_some();
        let rec = Self::run(conn, async move |c: &mut Client| {
            let sql = format!(
                "SELECT {RECORD_COLS} FROM public.pending_effect WHERE pending_id = $1 AND wid = $2"
            );
            let row = c
                .query_opt(&sql, &[&pid.as_slice(), &wid])
                .await
                .map_err(dbf("status"))?;
            let Some(row) = row.filter(|_| canonical) else {
                return Ok(None);
            };
            let mut rec = record_from_row(&row)?;
            if !rec.state.is_final() {
                lazy_expire(c, &pid, now, skew).await?;
                match select_record(c, &pid, false).await? {
                    Some(r) => rec = r,
                    None => return Ok(None),
                }
            }
            // payments-adapter-v1 §8: refunds carry the workload-facing reason enum.
            let is_refund =
                rec.fields.op == decls::PAYMENTS_REFUND || rec.fields.op == decls::SUPPORT_REFUND;
            let reason = if is_refund && rec.state.is_final() {
                Some(super::payments::status_reason(&*c, &pid).await?)
            } else if is_refund {
                Some(None)
            } else {
                None
            };
            // effect-protocol-v2 §12.2: `awaiting` only while PENDING.
            let awaiting: Option<String> = match rec.state {
                State::Pending if mandates_on => c
                    .query_one(
                        "SELECT awaiting FROM public.pending_effect WHERE pending_id = $1",
                        &[&pid.as_slice()],
                    )
                    .await
                    .map_err(dbf("awaiting"))?
                    .try_get(0)
                    .map_err(unavailable)?,
                State::Pending => Some("confirmation".to_owned()),
                _ => None,
            };
            Ok(Some((rec, reason, awaiting)))
        })
        .await?;
        let Some((rec, reason, awaiting)) = rec else {
            return Err(Fail::new(
                Code::NotFound,
                "no such record for this workload",
            ));
        };
        let mut outcome = rec.outcome_json();
        if let (Some(reason), Value::Object(o)) = (reason, &mut outcome) {
            o.insert("reason".into(), json!(reason));
        }
        Ok(json!({
            "pending_id": encode_id(&rec.fields.pending_id),
            "state": rec.state.as_str(),
            "expires_at": rec.fields.expires_at,
            "outcome": outcome,
            "awaiting": awaiting,
        }))
    }

    /// Read operations (§2.3): an authority-signed read grant whose `rop` contains the method,
    /// verified with `peer_wid` = this socket's workload; the query filters by `(ten, sub)`.
    pub async fn read(
        &self,
        wl: &WorkloadReg,
        op: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, Fail> {
        let denied = |d: String| Fail::new(Code::GrantDenied, d);
        if !self.reads.try_take(&wl.wid, (self.clock)()) {
            return Err(Fail::new(Code::LimitExceeded, "read rate"));
        }
        let Some(exec) =
            decls::executor_of(&self.ops, op).filter(|_| self.op_names.iter().any(|n| n == op))
        else {
            return Err(Fail::new(Code::UnknownOperation, "undeclared op"));
        };
        if exec == Executor::NotImplemented {
            return Err(Fail::new(
                Code::OperationNotPermitted,
                "not_implemented_legacy_declaration",
            ));
        }
        if !wl.allowed_ops.contains(op) {
            return Err(Fail::new(Code::OperationNotPermitted, "op not allowed"));
        }
        if exec == Executor::SupportGetOrder {
            // AI §4.6: grantless, mandate-scoped.
            return self.mandate_read(wl, op, args).await;
        }
        let decl = self.ops.get(op).ok_or_else(|| unavailable("decl"))?;
        if decl.kind != OpKind::Read
            || !matches!(
                exec,
                Executor::LedgerGetBalance | Executor::PaymentsGetOrder
            )
        {
            return Err(Fail::new(Code::UnknownOperation, "not a read method"));
        }
        let names: Vec<&str> = decl.params.iter().map(|p| p.name.as_str()).collect();
        check_keys(args, &names, &["grant"])?;
        let grant_text = match args.get("grant") {
            None => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => return Err(Fail::new(Code::MalformedRequest, "grant type")),
        };
        let mut raw = args.clone();
        raw.remove("grant");
        let types: BTreeMap<String, String> = decl
            .params
            .iter()
            .map(|p| (p.name.clone(), param_type_name(p.ty).to_owned()))
            .collect();
        let params = typed_params(&raw, &types).map_err(|e| Fail::new(Code::InvalidArgument, e))?;
        let request: Request = self
            .ops
            .parse_request(op, params)
            .map_err(|e| Fail::new(Code::InvalidArgument, e.to_string()))?;
        let now = self.now_checked()?;
        let bytes = decode_transport(grant_text).map_err(|e| denied(e.as_str().into()))?;
        let ctx = VerifyContext {
            now,
            broker_id: &self.cfg.broker_id,
            workload: &wl.wid,
            workload_tenants: &wl.tenants,
            request: &request,
            operations: &self.ops,
            limits: self.cfg.grant_limits,
        };
        let rg = match verify(&bytes, &self.registry, &ctx) {
            Err(e) => return Err(denied(e.as_str().into())),
            Ok(Verified::Write(_)) => return Err(denied("grant_channel_invalid".into())),
            Ok(Verified::Read(r)) => r,
        };
        let ten = rg.identity().ten.clone();
        if exec == Executor::PaymentsGetOrder {
            let order_id = uint_param(request.params(), "order_id")?;
            let (_slot, conn) = self.wl_conn(&wl.wid).await?;
            let r = Self::run(conn, async move |c: &mut Client| {
                let tx = c
                    .build_transaction()
                    .read_only(true)
                    .start()
                    .await
                    .map_err(dbf("begin read only"))?;
                let rows = revocations(&tx, &ten).await?;
                let a = match rg.decide(&rows) {
                    Ok(a) => a,
                    Err(e) => return Ok(Err(e.as_str().to_owned())),
                };
                let v = super::payments::get_order(&tx, order_id, a.tenant(), a.subject()).await?;
                tx.commit().await.map_err(dbf("commit read"))?;
                Ok(v.ok_or_else(|| "resource not found for subject".to_owned()))
            })
            .await?;
            return r.map_err(denied);
        }
        let account = text_param(request.params(), "account")?.to_owned();
        let (_slot, conn) = self.wl_conn(&wl.wid).await?;
        let r = Self::run(conn, async move |c: &mut Client| {
            let tx = c
                .build_transaction()
                .read_only(true)
                .start()
                .await
                .map_err(dbf("begin read only"))?;
            let rows = revocations(&tx, &ten).await?;
            let a = match rg.decide(&rows) {
                Ok(a) => a,
                Err(e) => return Ok(Err(e.as_str().to_owned())),
            };
            // R14: filtered by the grant's tenant and subject on trusted rows.
            let row = tx
                .query_opt(
                    "SELECT a.balance_cents FROM public.accounts a JOIN public.account_owner o ON o.account_id = a.id \
                     WHERE a.id = $1 AND o.ten = $2 AND o.owner_sub = $3",
                    &[&account, &a.tenant(), &a.subject()],
                )
                .await
                .map_err(dbf("balance"))?;
            tx.commit().await.map_err(dbf("commit read"))?;
            match row {
                Some(r) => Ok(Ok(r.try_get::<_, i64>(0).map_err(unavailable)?)),
                None => Ok(Err("resource not found for subject".to_owned())),
            }
        })
        .await?;
        let account = text_param(request.params(), "account")?;
        match r {
            Ok(bal) => Ok(json!({"account": account, "balance_minor": bal})),
            Err(d) => Err(denied(d)),
        }
    }

    // ------------------------------------------------------------------ socket G

    /// `pending.render` (§4.1). Any failure is `not_available` with one body (PC-03).
    pub async fn render(&self, args: &Map<String, Value>) -> Result<Value, Fail> {
        let na = |d: &str| Fail::new(Code::NotAvailable, d);
        check_keys(args, &["pending_id", "subject"], &[]).map_err(|f| na(&f.detail))?;
        let pid = args["pending_id"]
            .as_str()
            .and_then(decode_id)
            .ok_or_else(|| na("pending_id"))?;
        let (ten, sub) = subject_arg(&args["subject"]).map_err(|f| na(&f.detail))?;
        let now = self.now_checked().map_err(|f| na(&f.detail))?;
        let skew = self.skew();
        let conn = self.conn().await.map_err(|f| na(&f.detail))?;
        let me = self;
        let out = Self::run(conn, async move |c: &mut Client| {
            lazy_expire(c, &pid, now, skew).await?;
            let tx = c
                .build_transaction()
                .read_only(true)
                .start()
                .await
                .map_err(dbf("begin"))?;
            let Some(rec) = select_record(&tx, &pid, false).await? else {
                return Ok(None);
            };
            if rec.fields.ten != ten || rec.fields.approver_sub != sub {
                return Ok(None);
            }
            let Some(wl) = me.cfg.workload(&rec.fields.wid) else {
                return Ok(None);
            };
            let exec = decls::executor_of(&me.ops, &rec.fields.op);
            if matches!(exec, Some(Executor::MessageSend | Executor::MandateTemplate)) {
                let Some(facts) = me.agent_render_facts(&tx, &rec, now).await? else {
                    return Ok(None);
                };
                let ctx = me.render_context(&tx, &rec, wl, now).await?;
                tx.commit().await.map_err(dbf("commit"))?;
                return Ok(Some(json!({
                    "record": rec.fields.to_json(),
                    "digest": hex(&rec.digest),
                    "state": rec.state.as_str(),
                    "facts": facts,
                    "context": ctx,
                })));
            }
            if matches!(exec, Some(Executor::PaymentsRefund | Executor::SupportRefund)) {
                let Some(pc) = me.cfg.payments.as_ref() else {
                    return Ok(None);
                };
                let Some(mut facts) = super::payments::render_facts(&tx, &rec, pc, now).await? else {
                    return Ok(None);
                };
                if exec == Some(Executor::SupportRefund) {
                    let Some(extra) = me.support_refund_facts(&tx, &rec, now).await? else {
                        return Ok(None);
                    };
                    if let Value::Array(a) = &mut facts {
                        a.extend(extra);
                    }
                }
                let ctx = me.render_context(&tx, &rec, wl, now).await?;
                tx.commit().await.map_err(dbf("commit"))?;
                return Ok(Some(json!({
                    "record": rec.fields.to_json(),
                    "digest": hex(&rec.digest),
                    "state": rec.state.as_str(),
                    "facts": facts,
                    "context": ctx,
                })));
            }
            if rec.fields.op != LEDGER_TRANSFER {
                return Ok(None);
            }
            let p = &rec.fields.params;
            let from = text_param(p, "from")?;
            let to = text_param(p, "to")?;
            let facts = transfer_facts(&tx, &ten, &sub, from, to, false).await?;
            if !facts.from_owned {
                return Ok(None);
            }
            let ctx = me.render_context(&tx, &rec, wl, now).await?;
            tx.commit().await.map_err(dbf("commit"))?;
            let money = |n: i64| format_amount(n, me.cfg.ledger_exponent, &me.cfg.ledger_currency);
            let facts = json!([
                {"label": "From", "value": "your account"},
                {"label": "Balance of from", "value": facts.from_balance.map(money).unwrap_or_default()},
                {"label": "To", "value": if facts.to_owned_by_approver { "one of your accounts" } else { "not owned by you" }},
            ]);
            // Gateway wire format (crates/nodkey-gateway README, GW-1).
            let v = json!({
                "record": rec.fields.to_json(),
                "digest": hex(&rec.digest),
                "state": rec.state.as_str(),
                "facts": facts,
                "context": ctx,
            });
            Ok(Some(v))
        })
        .await
        .map_err(|f| na(&f.detail))?;
        out.ok_or_else(|| na("not renderable for this subject"))
    }

    async fn render_context(
        &self,
        c: &impl GenericClient,
        rec: &Record,
        wl: &WorkloadReg,
        now: u64,
    ) -> Result<Value, Fail> {
        let f = &rec.fields;
        let pid = f.pending_id.as_slice();
        let pending: i64 = c
            .query_one(
                "SELECT count(*) FROM public.pending_effect WHERE wid = $1 AND ten = $2 AND approver_sub = $3 \
                 AND state = 'PENDING' AND expires_at > $4",
                &[&f.wid, &f.ten, &f.approver_sub, &to_i64(now)],
            )
            .await
            .map_err(dbf("context count"))?
            .try_get(0)
            .map_err(unavailable)?;
        let recent = c
            .query(
                "SELECT pending_id, state, created_at, params FROM public.pending_effect WHERE wid = $1 AND ten = $2 \
                 AND approver_sub = $3 AND op = $4 AND params = $5 AND created_at >= $6 AND pending_id <> $7 \
                 ORDER BY created_at DESC LIMIT $8",
                &[
                    &f.wid,
                    &f.ten,
                    &f.approver_sub,
                    &f.op,
                    &f.params_json().to_string(),
                    &to_i64(now.saturating_sub(RECENT_WINDOW_S)),
                    &pid,
                    &CONTEXT_LIST_MAX,
                ],
            )
            .await
            .map_err(dbf("recent"))?;
        // The resource parameter: `from` for transfers, `order_id` for refunds, `customer_sub`
        // for messages and mandate templates.
        let (key, resource) = if f.op == LEDGER_TRANSFER {
            ("from", text_param(&f.params, "from")?.to_owned())
        } else if f.op == decls::MESSAGES_SEND || f.op == decls::MANDATE_TEMPLATE {
            (
                decls::CUSTOMER_SUB,
                text_param(&f.params, decls::CUSTOMER_SUB)?.to_owned(),
            )
        } else {
            ("order_id", uint_param(&f.params, "order_id")?.to_string())
        };
        let open = c
            .query(
                "SELECT pending_id, state, created_at, params FROM public.pending_effect WHERE op = $1 AND ten = $2 \
                 AND state IN ('PENDING','APPROVED','EXECUTING') AND (params::jsonb ->> $6) = $3 \
                 AND pending_id <> $4 ORDER BY created_at DESC LIMIT $5",
                &[&f.op, &f.ten, &resource, &pid, &CONTEXT_LIST_MAX, &key],
            )
            .await
            .map_err(dbf("open on resource"))?;
        let related = |rows: &[Row]| -> Result<Vec<Value>, Fail> {
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let id: Vec<u8> = r.try_get(0).map_err(unavailable)?;
                let st: String = r.try_get(1).map_err(unavailable)?;
                let ca: i64 = r.try_get(2).map_err(unavailable)?;
                let params = parse_json_object(r.try_get(3).map_err(unavailable)?)?;
                let id = <[u8; 16]>::try_from(id.as_slice()).map_err(unavailable)?;
                let mut o = json!({"pending_id": encode_id(&id), "state": st, "created_at": ca});
                if let Some(a) = params.get("amount_minor").and_then(json_uint) {
                    o["amount_minor"] = json!(a);
                }
                out.push(o);
            }
            Ok(out)
        };
        let recent_list = related(&recent)?;
        let open_list = related(&open)?;
        Ok(json!({
            "pending_from_workload_for_subject": pending,
            "recent_identical": recent_list,
            "other_open_on_resource": open_list,
            "workload_display_name": wl.display_name,
            "approver_source": wl.approver_source.as_str(),
        }))
    }

    /// `pending.deny` (§4.1, §3.3): `PENDING → DENIED` if the digest and approver match and the
    /// record is unexpired.
    pub async fn deny(&self, args: &Map<String, Value>) -> Result<Value, Fail> {
        let na = |d: &str| Fail::new(Code::NotAvailable, d);
        check_keys(args, &["pending_id", "digest", "subject"], &[]).map_err(|f| na(&f.detail))?;
        let pid = args["pending_id"]
            .as_str()
            .and_then(decode_id)
            .ok_or_else(|| na("pending_id"))?;
        let digest = args["digest"]
            .as_str()
            .and_then(parse_hex32)
            .ok_or_else(|| na("digest"))?;
        let (ten, sub) = subject_arg(&args["subject"]).map_err(|f| na(&f.detail))?;
        let now = self.now_checked().map_err(|f| na(&f.detail))?;
        let skew = self.skew();
        let conn = self.conn().await.map_err(|f| na(&f.detail))?;
        let done = Self::run(conn, async move |c: &mut Client| {
            lazy_expire(c, &pid, now, skew).await?;
            let now_i = to_i64(now);
            finalize(
                c,
                &pid,
                State::Pending,
                (State::Denied, "denied"),
                now,
                " AND digest = $7 AND ten = $8 AND approver_sub = $9 AND expires_at > $10",
                &[&digest.as_slice(), &ten, &sub, &now_i],
            )
            .await
        })
        .await
        .map_err(|f| na(&f.detail))?;
        if done {
            log_event("v2_denied_by_user", json!({"pending_id": encode_id(&pid)}));
            Ok(json!({}))
        } else {
            Err(na("deny precondition failed"))
        }
    }

    // ------------------------------------------------------------------ socket A

    /// `pending.get` (§4.2 step 2): the §3.2 fields, `state` and `digest` for any record.
    pub async fn pending_get(&self, args: &Map<String, Value>) -> Result<Value, Fail> {
        let nf = || Fail::new(Code::NotFound, "no such record");
        check_keys(args, &["pending_id"], &[])?;
        let pid = decode_id(str_arg(args, "pending_id")?).ok_or_else(nf)?;
        let now = self.now_checked()?;
        let skew = self.skew();
        let conn = self.conn().await?;
        let rec = Self::run(conn, async move |c: &mut Client| {
            lazy_expire(c, &pid, now, skew).await?;
            select_record(c, &pid, false).await
        })
        .await?
        .ok_or_else(nf)?;
        let mut v = rec.fields.to_json();
        if let Some(o) = v.as_object_mut() {
            o.insert("digest".into(), json!(hex(&rec.digest)));
            o.insert("state".into(), json!(rec.state.as_str()));
        }
        Ok(v)
    }

    /// `config.digest` (§4.2 step 3) in the authority's format: `{"digest": <hex>}` over the
    /// exact operations and authority-workloads file bytes (spec gap AU-2).
    pub fn config_digest(&self) -> Value {
        json!({"digest": hex(&self.config_digest)})
    }

    /// `grant.deliver` (§4.3). In one transaction: lock, idempotent re-delivery, preconditions,
    /// verification with `peer_wid` := the record's `wid`, equality with the record, approval
    /// checks under lock, `PENDING → APPROVED` storing the grant.
    pub async fn deliver(&self, args: &Map<String, Value>) -> Delivery {
        if let Err(f) = check_keys(args, &["pending_id", "grant"], &[]) {
            return Delivery::Rejected(f.detail);
        }
        let Some(pid) = args["pending_id"].as_str().and_then(decode_id) else {
            return Delivery::Rejected("pending_id".into());
        };
        let Some(text) = args["grant"].as_str() else {
            return Delivery::Rejected("grant type".into());
        };
        let bytes = match decode_transport(Some(text)) {
            Ok(b) => b,
            Err(e) => return Delivery::Rejected(e.as_str().into()),
        };
        let now = match self.now_checked() {
            Ok(n) => n,
            Err(f) => return Delivery::Unavailable(f.detail),
        };
        let conn = match self.conn().await {
            Ok(c) => c,
            Err(f) => return Delivery::Unavailable(f.detail),
        };
        let me = self;
        let r = Self::run(conn, async move |c: &mut Client| {
            let tx = c.transaction().await.map_err(dbf("begin"))?;
            let Some(rec) = select_record(&tx, &pid, true).await? else {
                return Ok(Delivery::Rejected("unknown pending_id".into()));
            };
            // Idempotent re-delivery (§4.3 step 2). Also after the record moved on from APPROVED
            // (executed, expired or failed): the identical bytes were accepted earlier, and an
            // authority retrying after a lost `accepted` must see `accepted` again (T46). This
            // changes no state and never causes a second execution.
            if rec.grant.as_deref() == Some(bytes.as_slice()) {
                return Ok(Delivery::Accepted);
            }
            if rec.grant.is_some() {
                // The authority signs at most one grant per jti (§4.2 step 4): a different grant
                // for a record that already holds one means a faulty or compromised issuer.
                log_event(
                    "alarm",
                    json!({"kind": "second_grant_for_jti", "pending_id": encode_id(&pid),
                           "state": rec.state.as_str()}),
                );
            }
            if rec.state != State::Pending {
                return Ok(Delivery::Expired(format!("state {}", rec.state.as_str())));
            }
            if now >= rec.fields.expires_at {
                finalize(&tx, &pid, State::Pending, (State::Expired, "expired"), now, "", &[]).await?;
                tx.commit().await.map_err(dbf("commit expiry"))?;
                return Ok(Delivery::Expired("past expires_at".into()));
            }
            let alarm = |kind: &str, d: &str| {
                log_event("alarm", json!({"kind": kind, "pending_id": encode_id(&pid), "detail": d}));
            };
            if rec.fields.broker_id != me.cfg.broker_id.as_str() {
                alarm("record_broker_mismatch", "");
                return Ok(Delivery::Rejected("record broker_id".into()));
            }
            let Some(wl) = me.cfg.workload(&rec.fields.wid) else {
                return Ok(Delivery::Rejected("record workload not registered".into()));
            };
            let request = match me.ops.parse_request(&rec.fields.op, rec.fields.params.clone()) {
                Ok(r) => r,
                Err(e) => {
                    alarm("record_request_invalid", &e.to_string());
                    return Ok(Delivery::Rejected("record request".into()));
                }
            };
            let ctx = VerifyContext {
                now,
                broker_id: &me.cfg.broker_id,
                workload: &rec.fields.wid,
                workload_tenants: &wl.tenants,
                request: &request,
                operations: &me.ops,
                limits: me.cfg.grant_limits,
            };
            let w = match verify(&bytes, &me.registry, &ctx) {
                Err(e) => {
                    if is_grant_mismatch(e) {
                        alarm("delivered_grant_mismatch", e.as_str());
                    }
                    return Ok(Delivery::Rejected(e.as_str().into()));
                }
                Ok(Verified::Read(_)) => return Ok(Delivery::Rejected("knd != 1".into())),
                Ok(Verified::Write(w)) => w,
            };
            let id = w.identity();
            if id.jti != pid || id.ten != rec.fields.ten || id.sub != rec.fields.approver_sub {
                alarm("delivered_grant_mismatch", "jti/ten/sub");
                return Ok(Delivery::Rejected("jti/ten/sub differ from the record".into()));
            }
            let grant_exp = id.exp;
            // grant-v1 Draft 4: `cfm = 2` carries the mandate id (W11d checked by `decide`).
            let mid = w.mandate_id();
            let rows = revocations(&tx, &rec.fields.ten).await?;
            // W11–W13 against the record's own params: op, opv, cfm, res/con equality.
            if let Err(e) = w.decide(&rows) {
                if is_grant_mismatch(e) {
                    alarm("delivered_grant_mismatch", e.as_str());
                }
                return Ok(Delivery::Rejected(e.as_str().into()));
            }
            // effect-protocol-v2 §12.4 / AI §4.5: a `cfm = 2` grant also needs the broker's own
            // mandate row (locked first: record → mandate → payments locks) to permit it.
            if let Some(mid) = &mid
                && !me.deliver_mandate_ok(&tx, &rec, mid, now).await?
            {
                return Ok(Delivery::Rejected("mandate check".into()));
            }
            // Approval checks of §5 under lock.
            let p = &rec.fields.params;
            match decls::executor_of(&me.ops, &rec.fields.op) {
                Some(Executor::PaymentsRefund) => {
                    if !super::payments::deliver_checks(&tx, &rec).await? {
                        return Ok(Delivery::Rejected("approval check: order".into()));
                    }
                }
                Some(Executor::SupportRefund) => {
                    if !me.agent_checks(&tx, &rec, now).await?
                        || !super::payments::deliver_checks(&tx, &rec).await?
                    {
                        return Ok(Delivery::Rejected("approval check: support refund".into()));
                    }
                }
                Some(Executor::MessageSend | Executor::MandateTemplate) => {
                    if !me.agent_checks(&tx, &rec, now).await? {
                        return Ok(Delivery::Rejected("approval check: agent operation".into()));
                    }
                }
                Some(Executor::LedgerTransfer) => {
                    let facts = transfer_facts(
                        &tx,
                        &rec.fields.ten,
                        &rec.fields.approver_sub,
                        text_param(p, "from")?,
                        text_param(p, "to")?,
                        true,
                    )
                    .await?;
                    if !facts.from_owned {
                        return Ok(Delivery::Rejected(
                            "approval check: from not owned by approver".into(),
                        ));
                    }
                }
                _ => return Ok(Delivery::Rejected("no executor".into())),
            }
            let n = tx
                .execute(
                    "UPDATE public.pending_effect SET state = 'APPROVED', state_changed_at = $2, grant_bytes = $3, \
                     grant_exp = $4 WHERE pending_id = $1 AND state = 'PENDING' AND expires_at > $2",
                    &[&pid.as_slice(), &to_i64(now), &bytes.as_slice(), &to_i64(grant_exp)],
                )
                .await
                .map_err(dbf("approve"))?;
            if n != 1 {
                return Err(unavailable("approve CAS touched no row"));
            }
            if let Some(mid) = &mid {
                // C6 and the page line (AI §4.3, effect-protocol-v2 §12.6).
                tx.execute(
                    "INSERT INTO public.mandate_use (pending_id, mid, op, params) VALUES ($1, $2, $3, $4)",
                    &[&pid.as_slice(), &mid.as_slice(), &rec.fields.op, &rec.fields.params_json().to_string()],
                )
                .await
                .map_err(dbf("mandate use"))?;
            }
            tx.commit().await.map_err(dbf("commit"))?;
            Ok(Delivery::Accepted)
        })
        .await;
        let d = r.unwrap_or_else(|f| Delivery::Unavailable(f.detail));
        log_event(
            "v2_grant_delivery",
            json!({"pending_id": encode_id(&pid), "result": format!("{d:?}")}),
        );
        d
    }

    // ------------------------------------------------------------------ execution

    /// The execution transaction (§4.4). `Err` means nothing was decided: the transaction was
    /// rolled back, the record stays `APPROVED`, and the recovery loop retries.
    pub async fn execute(&self, pid: [u8; 16], cid: &str) -> Result<Execution, Fail> {
        let now = self.now_checked()?;
        let skew = self.skew();
        let conn = self.conn().await?;
        let me = self;
        let cid_log = cid.to_owned();
        let cid = cid.to_owned();
        let r = Self::run(conn, async move |c: &mut Client| {
            let tx = c.transaction().await.map_err(dbf("begin"))?;
            // 1. Lock the record.
            let Some(rec) = select_record(&tx, &pid, true).await? else {
                return Ok(Execution::NotApproved);
            };
            if rec.state != State::Approved {
                return Ok(Execution::NotApproved);
            }
            let (Some(grant), Some(grant_exp)) = (rec.grant.clone(), rec.grant_exp) else {
                return Err(unavailable("APPROVED record without grant"));
            };
            // 2. Execution window.
            if now >= grant_exp.saturating_add(skew) {
                if !finalize(&tx, &pid, State::Approved, (State::Expired, "expired"), now, "", &[]).await? {
                    return Err(unavailable("expiry CAS touched no row"));
                }
                tx.commit().await.map_err(dbf("commit expiry"))?;
                return Ok(Execution::Expired);
            }
            let exec = decls::executor_of(&me.ops, &rec.fields.op);
            let refund_kid = match exec {
                Some(
                    Executor::LedgerTransfer | Executor::MessageSend | Executor::MandateTemplate,
                ) => None,
                // payments-adapter-v1 §9: without a successful `adapter.hello` (and a consistent
                // idem_kid), refunds are not executed; the record stays APPROVED and expires.
                Some(Executor::PaymentsRefund | Executor::SupportRefund) => match me.payments_kid() {
                    Some(k) => Some(k),
                    None => return Ok(Execution::Unverified("payments_not_ready")),
                },
                _ => return Ok(Execution::Unverified("no_executor")),
            };
            // 3. Verify the stored grant (steps 1–9), peer_wid := the record's wid.
            let Some(wl) = me.cfg.workload(&rec.fields.wid) else {
                return Ok(Execution::Unverified("workload_not_registered"));
            };
            let request = me
                .ops
                .parse_request(&rec.fields.op, rec.fields.params.clone())
                .map_err(|e| unavailable(format!("record request: {e}")))?;
            let ctx = VerifyContext {
                now,
                broker_id: &me.cfg.broker_id,
                workload: &rec.fields.wid,
                workload_tenants: &wl.tenants,
                request: &request,
                operations: &me.ops,
                limits: me.cfg.grant_limits,
            };
            let w = match verify(&grant, &me.registry, &ctx) {
                Ok(Verified::Write(w)) => w,
                Ok(Verified::Read(_)) => return Ok(Execution::Unverified("knd")),
                Err(e) => return Ok(Execution::Unverified(e.as_str())),
            };
            // 4. W10: consumption is the first write of the transaction.
            let cons = w.consumption();
            let n = tx
                .execute(
                    "INSERT INTO public.consumed_grant (iss, jti, exp, request_hash, outcome) \
                     VALUES ($1, $2, $3, $4, 'PENDING') ON CONFLICT (iss, jti) DO NOTHING",
                    &[&cons.iss, &cons.jti.as_slice(), &to_i64(cons.exp), &cons.request_hash.as_slice()],
                )
                .await
                .map_err(dbf("W10 consume"))?;
            if n != 1 {
                // A consumed grant on an APPROVED record cannot arise from this broker: the two
                // change together. Fail closed; the record expires.
                log_event("alarm", json!({"kind": "consumed_grant_without_decision", "pending_id": encode_id(&pid)}));
                return Err(unavailable("grant already consumed"));
            }
            tx.batch_execute("SAVEPOINT decision").await.map_err(dbf("savepoint"))?;
            let rows = revocations(&tx, &rec.fields.ten).await?;
            let iat = w.identity().iat;
            let mid = w.mandate_id();
            let mut refund_reason: Option<&'static str> = None;
            let decision: Result<(), String> = match w.decide(&rows) {
                Err(e) => {
                    refund_reason = Some("grant");
                    Err(e.as_str().to_owned())
                }
                Ok(a) => {
                    // AI §4.5: a `cfm = 2` grant first locks and re-checks the broker's mandate
                    // row against current trusted state and increments its counters (lock order
                    // record → mandate → payments locks). A denial rolls back to the savepoint,
                    // counters included.
                    let mandate = match &mid {
                        Some(m) => me.execute_mandate(&tx, &rec, a.params(), m, now).await?,
                        None => Ok(()),
                    };
                    if let Err(r) = mandate {
                        log_event(
                            "v2_mandate_denied",
                            json!({"pending_id": encode_id(&pid), "detail": r}),
                        );
                        refund_reason = Some("grant");
                        Err("mandate".to_owned())
                    } else if exec == Some(Executor::SupportRefund)
                        && !me.agent_checks(&tx, &rec, now).await?
                    {
                        refund_reason = Some("grant");
                        Err("approval check: support principal".to_owned())
                    } else if exec == Some(Executor::MessageSend) {
                        me.send_message(&tx, &rec, a.params(), now).await?
                    } else if exec == Some(Executor::MandateTemplate) {
                        me.activate_mandate(&tx, &rec, a.params(), iat, now).await?
                    } else if refund_kid.is_some() {
                        // payments-adapter-v1 §7.2 T1, W14 steps 0–7 and the reservation.
                        let pc = me.cfg.payments.as_ref().ok_or_else(|| unavailable("payments config"))?;
                        let kid = refund_kid.as_deref().unwrap_or_default();
                        match super::payments::refund_t1(&tx, &rec, a.params(), pc, kid, iat, now).await? {
                            Ok(()) => Ok(()),
                            Err(r) => {
                                refund_reason = Some(r);
                                Err(r.to_owned())
                            }
                        }
                    } else {
                        // W14: approval checks again under lock, then the effect, reading values
                        // only from the authorized params.
                        let p = a.params();
                        let from = text_param(p, "from")?;
                        let to = text_param(p, "to")?;
                        let amount = uint_param(p, "amount_minor")?;
                        me.transfer_effect(&tx, &rec, from, to, amount, &cid).await?
                    }
                }
            };
            let result = match decision {
                Ok(()) => {
                    let n = tx
                        .execute(
                            "UPDATE public.consumed_grant SET outcome = 'ACCEPT' WHERE iss = $1 AND jti = $2 AND outcome = 'PENDING'",
                            &[&cons.iss, &cons.jti.as_slice()],
                        )
                        .await
                        .map_err(dbf("record accept"))?;
                    if n != 1 {
                        return Err(unavailable("success recording touched no row"));
                    }
                    if refund_kid.is_some() {
                        // External effect: APPROVED → EXECUTING with the RESERVED row (§4.4 step 6).
                        let m = tx
                            .execute(
                                "UPDATE public.pending_effect SET state = 'EXECUTING', state_changed_at = $2 \
                                 WHERE pending_id = $1 AND state = 'APPROVED'",
                                &[&pid.as_slice(), &to_i64(now)],
                            )
                            .await
                            .map_err(dbf("executing"))?;
                        if m != 1 {
                            return Err(unavailable("EXECUTING CAS touched no row"));
                        }
                        Execution::Reserved
                    } else {
                        if !finalize(&tx, &pid, State::Approved, (State::Succeeded, "succeeded"), now, "", &[]).await? {
                            return Err(unavailable("success recording touched no row"));
                        }
                        Execution::Succeeded
                    }
                }
                Err(code) => {
                    tx.batch_execute("ROLLBACK TO SAVEPOINT decision")
                        .await
                        .map_err(dbf("rollback to savepoint"))?;
                    let n = tx
                        .execute(
                            "UPDATE public.consumed_grant SET outcome = 'DENIED' WHERE iss = $1 AND jti = $2 AND outcome = 'PENDING'",
                            &[&cons.iss, &cons.jti.as_slice()],
                        )
                        .await
                        .map_err(dbf("record denial"))?;
                    if n != 1 || !finalize(&tx, &pid, State::Approved, (State::Failed, "denied"), now, "", &[]).await? {
                        return Err(unavailable("denial recording touched no row"));
                    }
                    if let (Some(_), Some(r)) = (&refund_kid, refund_reason) {
                        super::payments::record_denial(&tx, &pid, r).await?;
                    }
                    Execution::Denied(code)
                }
            };
            // Deadline at commit (nodkey-grant D2-4): never commit an effect after exp + skew.
            if matches!(result, Execution::Succeeded | Execution::Reserved)
                && (me.clock)() >= grant_exp.saturating_add(skew)
            {
                return Err(unavailable("execution window closed before commit"));
            }
            tx.commit().await.map_err(dbf("commit"))?;
            Ok(result)
        })
        .await;
        log_event(
            "v2_execution",
            json!({"pending_id": encode_id(&pid), "correlation_id": cid_log,
                   "result": match &r { Ok(e) => format!("{e:?}"), Err(f) => format!("unavailable: {}", f.detail) }}),
        );
        if let Ok(Execution::Unverified(code)) = &r {
            // BR-09: the stored grant no longer verifies (key revoked, workload unregistered).
            // Nothing is consumed (grant-v1 §7.2: unverified grants record nothing); the record
            // stays APPROVED and expires at grant.exp + skew. Alarm once per record.
            let first = self
                .unverifiable_alarmed
                .lock()
                .map(|mut m| {
                    if m.len() >= MAX_ALARM_MEMORY {
                        m.clear();
                    }
                    m.insert(pid)
                })
                .unwrap_or(true);
            if first {
                log_event(
                    "alarm",
                    json!({"kind": "stored_grant_unverifiable", "pending_id": encode_id(&pid), "code": code}),
                );
            }
        }
        r
    }

    /// W14 for `ledger.transfer`: approval checks under lock, funds, then the effect. `Ok(Err)`
    /// is a business denial (recorded); `Err` is an infrastructure failure (rolled back).
    async fn transfer_effect(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        rec: &Record,
        from: &str,
        to: &str,
        amount: u64,
        cid: &str,
    ) -> Result<Result<(), String>, Fail> {
        let f = &rec.fields;
        let facts = transfer_facts(tx, &f.ten, &f.approver_sub, from, to, true).await?;
        if !facts.from_owned {
            return Ok(Err("approval check: from not owned by approver".into()));
        }
        if !facts.to_in_tenant {
            return Ok(Err("to does not exist in tenant".into()));
        }
        let amount = i64::try_from(amount).map_err(unavailable)?;
        let Some(bal) = facts.from_balance else {
            return Ok(Err("from balance".into()));
        };
        if bal < amount {
            return Ok(Err("insufficient funds".into()));
        }
        let to_bal: i64 = tx
            .query_one(
                "SELECT balance_cents FROM public.accounts WHERE id = $1",
                &[&to],
            )
            .await
            .map_err(dbf("to balance"))?
            .try_get(0)
            .map_err(unavailable)?;
        if to_bal.checked_add(amount).is_none() {
            return Ok(Err("credit overflow".into()));
        }
        let key = encode_id(&f.pending_id);
        tx.query_one(
            "INSERT INTO public.transfers (from_account, to_account, amount_cents, workload, correlation_id, \
             idempotency_key, from_balance_after_cents) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
            &[&from, &to, &amount, &f.wid, &cid, &key, &(bal - amount)],
        )
        .await
        .map_err(dbf("journal"))?;
        let n1 = tx
            .execute(
                "UPDATE public.accounts SET balance_cents = balance_cents - $2 WHERE id = $1",
                &[&from, &amount],
            )
            .await
            .map_err(dbf("debit"))?;
        let n2 = tx
            .execute(
                "UPDATE public.accounts SET balance_cents = balance_cents + $2 WHERE id = $1",
                &[&to, &amount],
            )
            .await
            .map_err(dbf("credit"))?;
        if n1 != 1 || n2 != 1 {
            return Err(unavailable("balance update row count"));
        }
        Ok(Ok(()))
    }

    /// One recovery pass (§3.3 sweeper, §4.4 recovery loop): advances the clock mark, expires
    /// due `PENDING` records, and runs the execution transaction for every `APPROVED` record.
    pub async fn recovery_tick(&self) -> Result<Vec<([u8; 16], Result<Execution, Fail>)>, Fail> {
        let now = self.now_checked()?;
        let bid = self.cfg.broker_id.as_str().to_owned();
        let conn = self.conn().await?;
        let (expired, approved) = Self::run(conn, async move |c: &mut Client| {
            c.execute(
                "UPDATE public.broker_clock SET mark = GREATEST(mark, $2) WHERE broker_id = $1",
                &[&bid, &to_i64(now)],
            )
            .await
            .map_err(dbf("clock mark"))?;
            let ids = |rows: Vec<Row>| -> Result<Vec<[u8; 16]>, Fail> {
                rows.iter()
                    .map(|r| {
                        let b: Vec<u8> = r.try_get(0).map_err(unavailable)?;
                        <[u8; 16]>::try_from(b.as_slice()).map_err(unavailable)
                    })
                    .collect()
            };
            let exp = c
                .query(
                    "SELECT pending_id FROM public.pending_effect WHERE state = 'PENDING' AND expires_at <= $1 LIMIT $2",
                    &[&to_i64(now), &RECOVERY_BATCH],
                )
                .await
                .map_err(dbf("sweep"))?;
            let exp = ids(exp)?;
            for pid in &exp {
                finalize(&*c, pid, State::Pending, (State::Expired, "expired"), now, " AND expires_at <= $7", &[&to_i64(now)]).await?;
            }
            let appr = c
                .query(
                    "SELECT pending_id FROM public.pending_effect WHERE state = 'APPROVED' ORDER BY state_changed_at LIMIT $1",
                    &[&RECOVERY_BATCH],
                )
                .await
                .map_err(dbf("approved"))?;
            Ok((exp.len(), ids(appr)?))
        })
        .await?;
        let mut out = Vec::with_capacity(approved.len());
        // A `Reserved` result is dispatched by the caller in its own task (BP-04): payment calls
        // never run inside this loop.
        for pid in approved {
            let r = self.execute(pid, "recovery").await;
            out.push((pid, r));
        }
        if expired > 0 || !out.is_empty() {
            log_event(
                "v2_recovery",
                json!({"expired": expired, "executed": out.len()}),
            );
        }
        Ok(out)
    }
}

/// Formats minor units with the ISO 4217 exponent, e.g. `1234, 2, "EUR"` → `"12.34 EUR"`.
pub fn format_amount(minor: i64, exponent: u64, currency: &str) -> String {
    let neg = minor < 0;
    let m = minor.unsigned_abs();
    let body = if exponent == 0 {
        m.to_string()
    } else {
        let p = 10u64.pow(u32::try_from(exponent).unwrap_or(0).min(9));
        format!("{}.{:0width$}", m / p, m % p, width = exponent as usize)
    };
    format!("{}{body} {currency}", if neg { "-" } else { "" })
}

pub fn param_type_name(t: nodkey_grant::ParamType) -> &'static str {
    use nodkey_grant::ParamType::*;
    match t {
        Uint => "uint",
        AccountId => "account_id",
        Currency => "currency",
        Text64 => "text64",
        Text256 => "text256",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_roundtrip_and_finality() {
        for s in [
            State::Pending,
            State::Approved,
            State::Executing,
            State::Succeeded,
            State::Failed,
            State::Unknown,
            State::Denied,
            State::Expired,
        ] {
            assert_eq!(State::parse(s.as_str()), Some(s));
        }
        assert_eq!(State::parse("pending"), None);
        let finals: Vec<_> = ["DENIED", "EXPIRED", "SUCCEEDED", "FAILED"]
            .iter()
            .map(|s| State::parse(s).unwrap())
            .collect();
        assert!(finals.iter().all(|s| s.is_final()));
        assert!(!State::Unknown.is_final() && !State::Approved.is_final());
    }

    #[test]
    fn amounts_format_with_exponent() {
        assert_eq!(format_amount(1234, 2, "EUR"), "12.34 EUR");
        assert_eq!(format_amount(5, 2, "EUR"), "0.05 EUR");
        assert_eq!(format_amount(1250, 0, "JPY"), "1250 JPY");
        assert_eq!(format_amount(1, 3, "KWD"), "0.001 KWD");
    }

    #[test]
    fn grant_mismatch_classification() {
        assert!(is_grant_mismatch(GrantError::ResourceMismatch));
        assert!(is_grant_mismatch(GrantError::ConstraintMismatch));
        assert!(!is_grant_mismatch(GrantError::SignatureInvalid));
        assert!(!is_grant_mismatch(GrantError::Expired));
    }
}
