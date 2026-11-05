// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Broker side of mandates (agent-interface-v1 Draft 2 §3–§4; effect-protocol-v2 Draft 4 §12;
//! ADR-0006 Amendment 3).
//!
//! - **Coverage** ([`Broker::coverage`]): the read-only pre-filter C1–C6 run at propose; it only
//!   sets `awaiting`. It never authorizes anything: the authority decides with its own mandate
//!   record and counters, and the broker re-checks under lock at delivery and execution.
//! - **Delivery** ([`Broker::deliver_mandate_ok`]) and **execution** ([`Broker::execute_mandate`])
//!   of `cfm = 2` grants: C1–C5 against the broker's mandate row whose `mid` equals the grant's,
//!   under `SELECT … FOR UPDATE` of that row (lock order record → mandate → payments locks). At
//!   execution the counters are incremented in the same transaction as the effect (after the
//!   decision savepoint, so a denial increments nothing). Counters never decrease.
//! - **Activation** ([`Broker::activate_mandate`]): the internal effect of the template operation,
//!   serialized per `(wid, ten, sub)` on an advisory lock; refused while a mandate is active (no
//!   replacement, AI-04).
//! - **Messages** ([`Broker::send_message`]): the internal effect of `messages.send`.
//! - **Reads** ([`Broker::mandate_read`]): `payments.support_get_order` without a grant, only under
//!   the caller's active mandate and its customer scope; every refusal is one `grant_denied`.
//! - **Control messages**: `mandate.candidates`, `mandate.declined` (socket A); `mandate.revoke`,
//!   `mandate.list`, `pending.list` (socket G).
//!
//! None of this runs unless the workloads file configures `support_principals`, so deployments
//! without mandates (Demo 1, 2, P) never touch the tables of `04-mandates.sh`.

use nodkey_grant::{ParamValue, Params, RevocationScope, RevokedBefore};
use serde_json::{Map, Value, json};
use tokio_postgres::{Client, GenericClient, Row, Transaction};

use super::config::{ApproverSource, MandateCfg, TemplateCfg, WorkloadReg};
use super::decls::{self, Executor};
use super::digest::PendingFields;
use super::ids::{decode_id, encode_id, is_id};
use super::service::{
    Broker, Record, State, dbf, finalize, revocations, text_param, to_i64, to_u64, uint_param,
    unavailable,
};
use super::wire::{Code, Fail, check_keys, subject_arg};
use crate::server::log_event;

/// `mandate.candidates` answers at most this many ids (effect-protocol-v2 §12.3).
pub const CANDIDATES_MAX: i64 = 16;
/// `mandate.list` / `pending.list` page size.
pub const LIST_MAX: i64 = 64;
/// Advisory-lock class for the `(wid, ten, sub)` mandate key.
const MANDATE_KEY_LOCK: i32 = 7303;

const MANDATE_COLS: &str = "mid, wid, ten, sub, customer_sub, customer_email, currency, \
     refund_max_count, refund_max_per_call_minor, refund_max_total_minor, message_max_count, \
     nbf, exp, cfg, state, refund_count, refund_total_minor, message_count";

/// One `public.mandate` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandateRow {
    pub mid: [u8; 16],
    pub wid: String,
    pub ten: String,
    pub sub: String,
    pub customer_sub: String,
    pub customer_email: String,
    pub currency: String,
    pub refund_max_count: u64,
    pub refund_max_per_call_minor: u64,
    pub refund_max_total_minor: u64,
    pub message_max_count: u64,
    pub nbf: u64,
    pub exp: u64,
    pub cfg: [u8; 32],
    pub state: String,
    pub refund_count: u64,
    pub refund_total_minor: u64,
    pub message_count: u64,
}

fn mandate_from_row(r: &Row) -> Result<MandateRow, Fail> {
    let u = |i: usize| -> Result<u64, Fail> { to_u64(r.try_get(i).map_err(unavailable)?) };
    let s = |i: usize| -> Result<String, Fail> { r.try_get(i).map_err(unavailable) };
    let mid: Vec<u8> = r.try_get(0).map_err(unavailable)?;
    let cfg: Vec<u8> = r.try_get(13).map_err(unavailable)?;
    Ok(MandateRow {
        mid: <[u8; 16]>::try_from(mid.as_slice()).map_err(unavailable)?,
        wid: s(1)?,
        ten: s(2)?,
        sub: s(3)?,
        customer_sub: s(4)?,
        customer_email: s(5)?,
        currency: s(6)?,
        refund_max_count: u(7)?,
        refund_max_per_call_minor: u(8)?,
        refund_max_total_minor: u(9)?,
        message_max_count: u(10)?,
        nbf: u(11)?,
        exp: u(12)?,
        cfg: <[u8; 32]>::try_from(cfg.as_slice()).map_err(unavailable)?,
        state: s(14)?,
        refund_count: u(15)?,
        refund_total_minor: u(16)?,
        message_count: u(17)?,
    })
}

pub async fn select_mandate(
    c: &impl GenericClient,
    mid: &[u8; 16],
    lock: bool,
) -> Result<Option<MandateRow>, Fail> {
    let sql = format!(
        "SELECT {MANDATE_COLS} FROM public.mandate WHERE mid = $1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = c
        .query_opt(&sql, &[&mid.as_slice()])
        .await
        .map_err(dbf("mandate"))?;
    row.as_ref().map(mandate_from_row).transpose()
}

/// The row with `state = active` for the key (at most one: unique partial index).
async fn select_active_for(
    c: &impl GenericClient,
    wid: &str,
    ten: &str,
    sub: &str,
) -> Result<Option<MandateRow>, Fail> {
    let sql = format!(
        "SELECT {MANDATE_COLS} FROM public.mandate WHERE wid = $1 AND ten = $2 AND sub = $3 \
         AND state = 'active'"
    );
    let row = c
        .query_opt(&sql, &[&wid, &ten, &sub])
        .await
        .map_err(dbf("active mandate"))?;
    row.as_ref().map(mandate_from_row).transpose()
}

/// `revoked_before` covers the mandate when a row for `(ten)`, `(ten, wid)` or `(ten, sub)` has
/// `mandate iat (= nbf) < before` (AI §4.3 C2).
pub fn revoked_by(m: &MandateRow, revs: &[RevokedBefore]) -> bool {
    revs.iter().any(|r| {
        let scope = match &r.scope {
            RevocationScope::Tenant { ten } => *ten == m.ten,
            RevocationScope::TenantWorkload { ten, wid } => *ten == m.ten && *wid == m.wid,
            RevocationScope::TenantSubject { ten, sub } => *ten == m.ten && *sub == m.sub,
        };
        scope && m.nbf < r.before
    })
}

/// C2 for one row: `state = active`, `nbf ≤ now < exp`, `cfg` = current `config.digest`, no
/// covering `revoked_before` row.
pub fn is_active(m: &MandateRow, now: u64, cfg: &[u8; 32], revs: &[RevokedBefore]) -> bool {
    m.state == "active" && m.nbf <= now && now < m.exp && m.cfg == *cfg && !revoked_by(m, revs)
}

/// What a covered effect would consume (AI §4.3 C3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terms {
    Refund {
        customer_sub: String,
        currency: String,
        amount: u64,
    },
    Message {
        customer_sub: String,
        to: String,
    },
}

/// C3: `op` is the template's `refund_op` or `message_op`; the values come from the record's
/// (or the grant's) params.
pub fn terms_of(op: &str, p: &Params, t: &TemplateCfg) -> Result<Option<Terms>, Fail> {
    Ok(if op == t.refund_op {
        Some(Terms::Refund {
            customer_sub: text_param(p, decls::CUSTOMER_SUB)?.to_owned(),
            currency: text_param(p, "currency")?.to_owned(),
            amount: uint_param(p, "amount_minor")?,
        })
    } else if op == t.message_op {
        Some(Terms::Message {
            customer_sub: text_param(p, decls::CUSTOMER_SUB)?.to_owned(),
            to: text_param(p, decls::TO)?.to_owned(),
        })
    } else {
        None
    })
}

/// C4 and C5 against the row's terms and counters.
pub fn within(m: &MandateRow, t: &Terms) -> bool {
    match t {
        Terms::Refund {
            customer_sub,
            currency,
            amount,
        } => {
            *customer_sub == m.customer_sub
                && *currency == m.currency
                && *amount <= m.refund_max_per_call_minor
                && m.refund_count < m.refund_max_count
                && m.refund_total_minor
                    .checked_add(*amount)
                    .is_some_and(|t| t <= m.refund_max_total_minor)
        }
        Terms::Message { customer_sub, to } => {
            *customer_sub == m.customer_sub
                && *to == m.customer_email
                && m.message_count < m.message_max_count
        }
    }
}

/// C1: an `enrolled` workload whose record approver is the enrolment and a support principal.
pub fn c1(wl: &WorkloadReg, m: &MandateCfg, ten: &str, sub: &str) -> bool {
    matches!(&wl.approver_source, ApproverSource::Enrolled { ten: et, sub: es } if et == ten && es == sub)
        && m.is_support_principal(ten, sub)
}

/// The trusted email of a customer (`nodkey.customers`), by `(ten, sub)` only.
pub async fn customer_email(
    c: &impl GenericClient,
    ten: &str,
    sub: &str,
) -> Result<Option<String>, Fail> {
    let r = c
        .query_opt(
            "SELECT email FROM nodkey.customers WHERE ten = $1 AND sub = $2",
            &[&ten, &sub],
        )
        .await
        .map_err(dbf("customer"))?;
    r.map(|r| r.try_get(0).map_err(unavailable)).transpose()
}

/// C6 and the page line: the latest record of this workload with identical op and params that
/// received a `cfm = 2` grant under `mid` (any mandate if `None`).
async fn identical_mandated(
    c: &impl GenericClient,
    f: &PendingFields,
    mid: Option<&[u8; 16]>,
    executed_only: bool,
) -> Result<Option<([u8; 16], u64)>, Fail> {
    let states = if executed_only {
        "('SUCCEEDED','EXECUTING','UNKNOWN')"
    } else {
        "('PENDING','APPROVED','EXECUTING','SUCCEEDED','FAILED','UNKNOWN','DENIED','EXPIRED')"
    };
    let sql = format!(
        "SELECT u.mid, p.state_changed_at FROM public.mandate_use u \
         JOIN public.pending_effect p ON p.pending_id = u.pending_id \
         WHERE p.wid = $1 AND u.op = $2 AND u.params = $3 AND p.pending_id <> $4 \
         AND ($5::bytea IS NULL OR u.mid = $5) AND p.state IN {states} \
         ORDER BY p.state_changed_at DESC LIMIT 1"
    );
    let mid_v: Option<Vec<u8>> = mid.map(|m| m.to_vec());
    let r = c
        .query_opt(
            &sql,
            &[
                &f.wid,
                &f.op,
                &f.params_json().to_string(),
                &f.pending_id.as_slice(),
                &mid_v,
            ],
        )
        .await
        .map_err(dbf("identical mandated"))?;
    let Some(r) = r else { return Ok(None) };
    let m: Vec<u8> = r.try_get(0).map_err(unavailable)?;
    Ok(Some((
        <[u8; 16]>::try_from(m.as_slice()).map_err(unavailable)?,
        to_u64(r.try_get(1).map_err(unavailable)?)?,
    )))
}

impl Broker {
    /// Mandate configuration, or `None` (mandates disabled; no mandate table is touched).
    pub fn mandates(&self) -> Option<&MandateCfg> {
        self.mandate_cfg.as_ref()
    }

    fn template(&self) -> Option<&TemplateCfg> {
        self.mandate_cfg.as_ref().and_then(|m| m.template.as_ref())
    }

    /// The read-only coverage pre-filter (AI §4.3 C1–C6) for a record about to be created.
    /// `true` → `awaiting = mandate`. Never an authorization.
    pub(crate) async fn coverage(
        &self,
        c: &impl GenericClient,
        f: &PendingFields,
        now: u64,
    ) -> Result<bool, Fail> {
        let (Some(m), Some(t)) = (self.mandates(), self.template()) else {
            return Ok(false);
        };
        let Some(wl) = self.cfg.workload(&f.wid) else {
            return Ok(false);
        };
        if !c1(wl, m, &f.ten, &f.approver_sub) {
            return Ok(false);
        }
        let Some(terms) = terms_of(&f.op, &f.params, t)? else {
            return Ok(false);
        };
        let Some(row) = select_active_for(c, &f.wid, &f.ten, &f.approver_sub).await? else {
            return Ok(false);
        };
        let revs = revocations(c, &f.ten).await?;
        if !is_active(&row, now, self.config_digest_bytes(), &revs) || !within(&row, &terms) {
            return Ok(false);
        }
        Ok(identical_mandated(c, f, Some(&row.mid), false)
            .await?
            .is_none())
    }

    /// Approval checks of the agent operations (AI §3) that do not involve an order: C1-style
    /// principal checks, and the customer's current email. Used at render (read-only), delivery
    /// and execution. `Ok(false)` = not approvable.
    pub(crate) async fn agent_checks(
        &self,
        c: &impl GenericClient,
        rec: &Record,
        now: u64,
    ) -> Result<bool, Fail> {
        let f = &rec.fields;
        let (Some(m), Some(wl)) = (self.mandates(), self.cfg.workload(&f.wid)) else {
            return Ok(false);
        };
        if !c1(wl, m, &f.ten, &f.approver_sub) {
            return Ok(false);
        }
        let p = &f.params;
        match decls::executor_of(&self.ops, &f.op) {
            Some(Executor::MessageSend) => {
                let cs = text_param(p, decls::CUSTOMER_SUB)?;
                let to = text_param(p, decls::TO)?;
                let email = customer_email(c, &f.ten, cs).await?;
                Ok(is_id(to, 256) && email.as_deref() == Some(to))
            }
            Some(Executor::MandateTemplate) => {
                if self.template().is_none() {
                    return Ok(false);
                }
                let cs = text_param(p, decls::CUSTOMER_SUB)?;
                let ce = text_param(p, decls::CUSTOMER_EMAIL)?;
                let email = customer_email(c, &f.ten, cs).await?;
                if !is_id(ce, 256) || email.as_deref() != Some(ce) {
                    return Ok(false);
                }
                // No replacement (AI-04): no mandate may be active for (wid, ten, sub).
                Ok(self
                    .active_mandate(c, &f.wid, &f.ten, &f.approver_sub, now)
                    .await?
                    .is_none())
            }
            Some(Executor::SupportRefund) => Ok(true),
            _ => Ok(false),
        }
    }

    /// The effectively active mandate for the key, if any (C2).
    pub(crate) async fn active_mandate(
        &self,
        c: &impl GenericClient,
        wid: &str,
        ten: &str,
        sub: &str,
        now: u64,
    ) -> Result<Option<MandateRow>, Fail> {
        let Some(row) = select_active_for(c, wid, ten, sub).await? else {
            return Ok(None);
        };
        let revs = revocations(c, ten).await?;
        Ok(is_active(&row, now, self.config_digest_bytes(), &revs).then_some(row))
    }

    /// `grant.deliver` of a `cfm = 2` grant (AI §4.5, effect-protocol-v2 §12.4): C1–C5 against
    /// the broker's row whose `mid` equals the grant's, read under that row's lock.
    pub(crate) async fn deliver_mandate_ok(
        &self,
        tx: &Transaction<'_>,
        rec: &Record,
        mid: &[u8; 16],
        now: u64,
    ) -> Result<bool, Fail> {
        Ok(self
            .locked_mandate_check(tx, rec, &rec.fields.params, mid, now)
            .await?
            .is_ok())
    }

    /// Locks the mandate row and runs C1–C5 for `params`. `Ok(Err)` = denied (reason for the
    /// audit log); the locked row on success.
    async fn locked_mandate_check(
        &self,
        tx: &Transaction<'_>,
        rec: &Record,
        params: &Params,
        mid: &[u8; 16],
        now: u64,
    ) -> Result<Result<(MandateRow, Terms), &'static str>, Fail> {
        let f = &rec.fields;
        let (Some(m), Some(t), Some(wl)) =
            (self.mandates(), self.template(), self.cfg.workload(&f.wid))
        else {
            return Ok(Err("mandates not configured"));
        };
        if !c1(wl, m, &f.ten, &f.approver_sub) {
            return Ok(Err("C1"));
        }
        let Some(row) = select_mandate(tx, mid, true).await? else {
            return Ok(Err("unknown mid"));
        };
        if row.wid != f.wid || row.ten != f.ten || row.sub != f.approver_sub {
            return Ok(Err("mandate of another workload or principal"));
        }
        let revs = revocations(tx, &f.ten).await?;
        if !is_active(&row, now, self.config_digest_bytes(), &revs) {
            return Ok(Err("mandate inactive"));
        }
        let Some(terms) = terms_of(&f.op, params, t)? else {
            return Ok(Err("C3"));
        };
        if !within(&row, &terms) {
            return Ok(Err("C4/C5"));
        }
        Ok(Ok((row, terms)))
    }

    /// Execution of a `cfm = 2` grant (AI §4.5): after the decision savepoint, lock the mandate
    /// row, re-check C1–C5 against it and the **current** trusted state, then increment the
    /// broker counters. `Ok(Err)` = business denial (the caller rolls back to the savepoint).
    pub(crate) async fn execute_mandate(
        &self,
        tx: &Transaction<'_>,
        rec: &Record,
        params: &Params,
        mid: &[u8; 16],
        now: u64,
    ) -> Result<Result<(), String>, Fail> {
        let (row, terms) = match self.locked_mandate_check(tx, rec, params, mid, now).await? {
            Ok(v) => v,
            Err(r) => return Ok(Err(format!("mandate: {r}"))),
        };
        let ten = &rec.fields.ten;
        // Current trusted state: the customer's email still equals the mandate's.
        if customer_email(tx, ten, &row.customer_sub).await?.as_deref()
            != Some(row.customer_email.as_str())
        {
            return Ok(Err("mandate: customer email changed".into()));
        }
        let n = match &terms {
            Terms::Refund { amount, .. } => {
                // The order's owner must still be the mandate's customer.
                let order_id = uint_param(params, "order_id")?;
                let owner = super::payments::read_order(tx, order_id)
                    .await?
                    .filter(|o| o.ten == *ten)
                    .map(|o| o.owner_sub);
                if owner.as_deref() != Some(row.customer_sub.as_str()) {
                    return Ok(Err("mandate: order owner changed".into()));
                }
                tx.execute(
                    "UPDATE public.mandate SET refund_count = refund_count + 1, \
                     refund_total_minor = refund_total_minor + $2 WHERE mid = $1 AND state = 'active' \
                     AND refund_count + 1 <= refund_max_count \
                     AND refund_total_minor + $2 <= refund_max_total_minor",
                    &[&row.mid.as_slice(), &to_i64(*amount)],
                )
                .await
                .map_err(dbf("mandate refund counters"))?
            }
            Terms::Message { .. } => tx
                .execute(
                    "UPDATE public.mandate SET message_count = message_count + 1 WHERE mid = $1 \
                     AND state = 'active' AND message_count + 1 <= message_max_count",
                    &[&row.mid.as_slice()],
                )
                .await
                .map_err(dbf("mandate message counter"))?,
        };
        if n != 1 {
            return Ok(Err("mandate: counter guard".into()));
        }
        Ok(Ok(()))
    }

    /// Internal effect of `messages.send` (AI §3): the current email must equal the signed `to`;
    /// then one `outbox` row with the signed values. `params` are the authorized ones.
    pub(crate) async fn send_message(
        &self,
        tx: &Transaction<'_>,
        rec: &Record,
        params: &Params,
        now: u64,
    ) -> Result<Result<(), String>, Fail> {
        let ten = &rec.fields.ten;
        let cs = text_param(params, decls::CUSTOMER_SUB)?;
        let to = text_param(params, decls::TO)?;
        let body = match params.get("body") {
            Some(ParamValue::Text(b)) => b.clone(),
            // `free` parameters are not in the grant; the record's own value is the effect.
            _ => text_param(&rec.fields.params, "body")?.to_owned(),
        };
        if !self.agent_checks(tx, rec, now).await? {
            return Ok(Err("message: approval checks".into()));
        }
        if customer_email(tx, ten, cs).await?.as_deref() != Some(to) {
            return Ok(Err(
                "message: recipient is not the customer's current email".into(),
            ));
        }
        tx.execute(
            "INSERT INTO public.outbox (message_id, ten, \"to\", body, created_at) VALUES ($1, $2, $3, $4, $5)",
            &[
                &rec.fields.pending_id.as_slice(),
                ten,
                &to,
                &body,
                &to_i64(now),
            ],
        )
        .await
        .map_err(dbf("outbox"))?;
        Ok(Ok(()))
    }

    /// Internal effect of the template operation (AI §4.2 step 4): under the `(wid, ten, sub)`
    /// lock, require no active mandate, then insert the row with fresh counters, window from the
    /// grant's `iat`, `cfg` = current `config.digest`.
    pub(crate) async fn activate_mandate(
        &self,
        tx: &Transaction<'_>,
        rec: &Record,
        params: &Params,
        iat: u64,
        now: u64,
    ) -> Result<Result<(), String>, Fail> {
        let f = &rec.fields;
        // IDs never contain a space, so the key is unambiguous.
        let key = format!("{} {} {}", f.wid, f.ten, f.approver_sub);
        tx.execute(
            "SELECT pg_advisory_xact_lock($1, hashtext($2))",
            &[&MANDATE_KEY_LOCK, &key],
        )
        .await
        .map_err(dbf("mandate key lock"))?;
        if !self.agent_checks(tx, rec, now).await? {
            return Ok(Err(
                "activation: approval checks or a mandate is active".into()
            ));
        }
        // An `active` row that is no longer effective (window, cfg, revoked_before) is ended
        // first, so the unique index admits the new one.
        if let Some(old) = select_active_for(tx, &f.wid, &f.ten, &f.approver_sub).await? {
            tx.execute(
                "UPDATE public.mandate SET state = 'expired', state_changed_at = $2 WHERE mid = $1 AND state = 'active'",
                &[&old.mid.as_slice(), &to_i64(now)],
            )
            .await
            .map_err(dbf("expire old mandate"))?;
        }
        let u = |k: &str| uint_param(params, k);
        let valid = u("valid_for_s")?;
        let exp = iat.saturating_add(valid);
        if now >= exp {
            return Ok(Err("activation: window already over".into()));
        }
        tx.execute(
            "INSERT INTO public.mandate (mid, wid, ten, sub, customer_sub, customer_email, currency, \
             refund_max_count, refund_max_per_call_minor, refund_max_total_minor, message_max_count, \
             nbf, exp, cfg, state, state_changed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'active',$15)",
            &[
                &f.pending_id.as_slice(),
                &f.wid,
                &f.ten,
                &f.approver_sub,
                &text_param(params, decls::CUSTOMER_SUB)?,
                &text_param(params, decls::CUSTOMER_EMAIL)?,
                &text_param(params, "currency")?,
                &to_i64(u("refund_max_count")?),
                &to_i64(u("refund_max_per_call_minor")?),
                &to_i64(u("refund_max_total_minor")?),
                &to_i64(u("message_max_count")?),
                &to_i64(iat),
                &to_i64(exp),
                &self.config_digest_bytes().as_slice(),
                &to_i64(now),
            ],
        )
        .await
        .map_err(dbf("mandate insert"))?;
        log_event(
            "v2_mandate_activated",
            json!({"mid": encode_id(&f.pending_id), "wid": f.wid, "ten": f.ten, "sub": f.approver_sub,
                   "nbf": iat, "exp": exp}),
        );
        Ok(Ok(()))
    }

    /// Render facts of `messages.send` and the template (AI §3, §4.2). `None` = not renderable.
    pub(crate) async fn agent_render_facts(
        &self,
        c: &impl GenericClient,
        rec: &Record,
        now: u64,
    ) -> Result<Option<Value>, Fail> {
        if !self.agent_checks(c, rec, now).await? {
            return Ok(None);
        }
        let p = &rec.fields.params;
        let cs = text_param(p, decls::CUSTOMER_SUB)?;
        let mut facts = vec![json!({"label": "Customer", "value": cs})];
        match decls::executor_of(&self.ops, &rec.fields.op) {
            Some(Executor::MessageSend) => {
                facts.push(
                    json!({"label": "Recipient address", "value": text_param(p, decls::TO)?}),
                );
            }
            Some(Executor::MandateTemplate) => {
                facts.push(json!({"label": "Customer email", "value": text_param(p, decls::CUSTOMER_EMAIL)?}));
            }
            _ => return Ok(None),
        }
        if let Some(line) = self.identical_line(c, &rec.fields).await? {
            facts.push(line);
        }
        Ok(Some(Value::Array(facts)))
    }

    /// Facts added for `payments.support_refund` (customer id and email, identical line).
    pub(crate) async fn support_refund_facts(
        &self,
        c: &impl GenericClient,
        rec: &Record,
        now: u64,
    ) -> Result<Option<Vec<Value>>, Fail> {
        let f = &rec.fields;
        let (Some(m), Some(wl)) = (self.mandates(), self.cfg.workload(&f.wid)) else {
            return Ok(None);
        };
        if !c1(wl, m, &f.ten, &f.approver_sub) {
            return Ok(None);
        }
        let _ = now;
        let cs = text_param(&f.params, decls::CUSTOMER_SUB)?;
        let email = customer_email(c, &f.ten, cs).await?;
        let mut v = vec![
            json!({"label": "Customer", "value": cs}),
            json!({"label": "Customer email", "value": email.unwrap_or_else(|| "(none on file)".into())}),
        ];
        if let Some(line) = self.identical_line(c, f).await? {
            v.push(line);
        }
        Ok(Some(v))
    }

    /// "an identical effect executed at `<t>` under mandate `<mid>`" (effect-protocol-v2 §12.6).
    async fn identical_line(
        &self,
        c: &impl GenericClient,
        f: &PendingFields,
    ) -> Result<Option<Value>, Fail> {
        if self.mandates().is_none() {
            return Ok(None);
        }
        Ok(identical_mandated(c, f, None, true).await?.map(|(mid, t)| {
            json!({"label": "Identical effect", "value": format!(
                "an identical effect executed at {t} (Unix time) under mandate {}", encode_id(&mid))})
        }))
    }

    // ------------------------------------------------------------------ reads (socket W)

    /// `payments.support_get_order{order_id}` (AI §4.6): no grant; answered only under the
    /// caller's active mandate whose template lists the read op, for an order of the mandate's
    /// customer in its tenant, in a `READ ONLY` transaction. Every refusal is `grant_denied`.
    pub async fn mandate_read(
        &self,
        wl: &WorkloadReg,
        op: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, Fail> {
        let denied = |d: &str| Fail::new(Code::GrantDenied, d);
        check_keys(args, &["order_id"], &[]).map_err(|f| denied(&f.detail))?;
        let order_id = args["order_id"]
            .as_u64()
            .filter(|n| *n <= super::digest::MAX_UINT && !args["order_id"].is_f64())
            .ok_or_else(|| denied("order_id"))?;
        let (Some(m), Some(t)) = (self.mandates(), self.template()) else {
            return Err(denied("mandates not configured"));
        };
        if !t.read_ops.iter().any(|r| r == op) {
            return Err(denied("read op not in template"));
        }
        let ApproverSource::Enrolled { ten, sub } = &wl.approver_source else {
            return Err(denied("not enrolled"));
        };
        if !c1(wl, m, ten, sub) {
            return Err(denied("C1"));
        }
        let now = self.now_checked()?;
        let (ten, sub, wid) = (ten.clone(), sub.clone(), wl.wid.clone());
        let (_slot, conn) = self.wl_conn(&wl.wid).await?;
        let me = self;
        let r = Self::run(conn, async move |c: &mut Client| {
            let tx = c
                .build_transaction()
                .read_only(true)
                .start()
                .await
                .map_err(dbf("begin read only"))?;
            let Some(row) = me.active_mandate(&tx, &wid, &ten, &sub, now).await? else {
                return Ok(None);
            };
            let Some(o) = super::payments::read_order(&tx, order_id).await? else {
                return Ok(None);
            };
            if o.ten != ten || o.owner_sub != row.customer_sub {
                return Ok(None);
            }
            let v = super::payments::get_order(&tx, order_id, &ten, &row.customer_sub).await?;
            tx.commit().await.map_err(dbf("commit read"))?;
            Ok(v.map(|mut v| {
                v["customer_sub"] = json!(row.customer_sub);
                v
            }))
        })
        .await?;
        r.ok_or_else(|| denied("no active mandate, or order out of scope"))
    }

    // ------------------------------------------------------------------ socket A

    /// `mandate.candidates{}` (§12.3): `PENDING`, unexpired records with `awaiting = mandate`.
    pub async fn mandate_candidates(&self, args: &Map<String, Value>) -> Result<Value, Fail> {
        check_keys(args, &[], &[])?;
        if self.mandates().is_none() {
            return Ok(json!({"pending_ids": []}));
        }
        let now = self.now_checked()?;
        let conn = self.conn().await?;
        let ids = Self::run(conn, async move |c: &mut Client| {
            let rows = c
                .query(
                    "SELECT pending_id FROM public.pending_effect WHERE state = 'PENDING' \
                     AND awaiting = 'mandate' AND expires_at > $1 ORDER BY created_at LIMIT $2",
                    &[&to_i64(now), &CANDIDATES_MAX],
                )
                .await
                .map_err(dbf("candidates"))?;
            rows.iter()
                .map(|r| {
                    let b: Vec<u8> = r.try_get(0).map_err(unavailable)?;
                    Ok(encode_id(
                        &<[u8; 16]>::try_from(b.as_slice()).map_err(unavailable)?,
                    ))
                })
                .collect::<Result<Vec<String>, Fail>>()
        })
        .await?;
        Ok(json!({"pending_ids": ids}))
    }

    /// `mandate.declined{pending_id, final}` (§12.3). `final = false`: `awaiting → confirmation`.
    /// `final = true`: `PENDING → DENIED` (unexpired). A non-`PENDING` record is left unchanged.
    pub async fn mandate_declined(&self, args: &Map<String, Value>) -> Result<Value, Fail> {
        let nf = || Fail::new(Code::NotFound, "no such record");
        check_keys(args, &["pending_id", "final"], &[])?;
        let pid = args["pending_id"]
            .as_str()
            .and_then(decode_id)
            .ok_or_else(nf)?;
        let Some(fin) = args["final"].as_bool() else {
            return Err(Fail::new(Code::MalformedRequest, "final type"));
        };
        if self.mandates().is_none() {
            return Err(nf());
        }
        let now = self.now_checked()?;
        let conn = self.conn().await?;
        let found = Self::run(conn, async move |c: &mut Client| {
            let tx = c.transaction().await.map_err(dbf("begin"))?;
            let Some(rec) = super::service::select_record(&tx, &pid, true).await? else {
                return Ok(false);
            };
            if rec.state == State::Pending {
                if fin {
                    finalize(
                        &tx,
                        &pid,
                        State::Pending,
                        (State::Denied, "denied"),
                        now,
                        " AND expires_at > $7",
                        &[&to_i64(now)],
                    )
                    .await?;
                } else {
                    tx.execute(
                        "UPDATE public.pending_effect SET awaiting = 'confirmation' WHERE pending_id = $1 \
                         AND state = 'PENDING' AND awaiting = 'mandate'",
                        &[&pid.as_slice()],
                    )
                    .await
                    .map_err(dbf("declined"))?;
                }
            }
            tx.commit().await.map_err(dbf("commit"))?;
            Ok(true)
        })
        .await?;
        if !found {
            return Err(nf());
        }
        log_event(
            "v2_mandate_declined",
            json!({"pending_id": encode_id(&pid), "final": fin}),
        );
        Ok(json!({}))
    }

    // ------------------------------------------------------------------ socket G

    /// `mandate.revoke{mid, subject}` (§12.3): `{}` once the row is not active (idempotent);
    /// `not_available` for an unknown `mid` or another subject's mandate.
    pub async fn mandate_revoke(&self, args: &Map<String, Value>) -> Result<Value, Fail> {
        let na = |d: &str| Fail::new(Code::NotAvailable, d);
        check_keys(args, &["mid", "subject"], &[]).map_err(|f| na(&f.detail))?;
        let mid = args["mid"]
            .as_str()
            .and_then(decode_id)
            .ok_or_else(|| na("mid"))?;
        let (ten, sub) = subject_arg(&args["subject"]).map_err(|f| na(&f.detail))?;
        if self.mandates().is_none() {
            return Err(na("mandates not configured"));
        }
        let now = self.now_checked().map_err(|f| na(&f.detail))?;
        let conn = self.conn().await.map_err(|f| na(&f.detail))?;
        let ok = Self::run(conn, async move |c: &mut Client| {
            let tx = c.transaction().await.map_err(dbf("begin"))?;
            let Some(m) = select_mandate(&tx, &mid, true).await? else {
                return Ok(false);
            };
            if m.ten != ten || m.sub != sub {
                return Ok(false);
            }
            if m.state == "active" {
                tx.execute(
                    "UPDATE public.mandate SET state = 'revoked', state_changed_at = $2 WHERE mid = $1 AND state = 'active'",
                    &[&mid.as_slice(), &to_i64(now)],
                )
                .await
                .map_err(dbf("revoke"))?;
            }
            tx.commit().await.map_err(dbf("commit"))?;
            Ok(true)
        })
        .await
        .map_err(|f| na(&f.detail))?;
        if !ok {
            return Err(na("unknown mid or other subject"));
        }
        log_event("v2_mandate_revoked", json!({"mid": encode_id(&mid)}));
        Ok(json!({}))
    }

    /// `mandate.list{subject}` (§12.3), newest first. `state` is the effective state.
    pub async fn mandate_list(&self, args: &Map<String, Value>) -> Result<Value, Fail> {
        let na = |d: &str| Fail::new(Code::NotAvailable, d);
        check_keys(args, &["subject"], &[]).map_err(|f| na(&f.detail))?;
        let (ten, sub) = subject_arg(&args["subject"]).map_err(|f| na(&f.detail))?;
        if self.mandates().is_none() {
            return Ok(json!({"mandates": []}));
        }
        let now = self.now_checked().map_err(|f| na(&f.detail))?;
        let conn = self.conn().await.map_err(|f| na(&f.detail))?;
        let me = self;
        Self::run(conn, async move |c: &mut Client| {
            let sql = format!(
                "SELECT {MANDATE_COLS} FROM public.mandate WHERE ten = $1 AND sub = $2 \
                 ORDER BY nbf DESC LIMIT $3"
            );
            let rows = c
                .query(&sql, &[&ten, &sub, &LIST_MAX])
                .await
                .map_err(dbf("mandate list"))?;
            let revs = revocations(&*c, &ten).await?;
            let mut out = Vec::with_capacity(rows.len());
            for r in &rows {
                let m = mandate_from_row(r)?;
                let state = if m.state != "active" {
                    m.state.clone()
                } else if is_active(&m, now, me.config_digest_bytes(), &revs) {
                    "active".into()
                } else {
                    "expired".into()
                };
                let wname = me
                    .cfg
                    .workload(&m.wid)
                    .map(|w| w.display_name.clone())
                    .unwrap_or_else(|| "(unregistered workload)".into());
                out.push(json!({
                    "mid": encode_id(&m.mid),
                    "workload_display_name": wname,
                    "terms": {
                        "customer_sub": m.customer_sub, "customer_email": m.customer_email,
                        "currency": m.currency, "refund_max_count": m.refund_max_count,
                        "refund_max_per_call_minor": m.refund_max_per_call_minor,
                        "refund_max_total_minor": m.refund_max_total_minor,
                        "message_max_count": m.message_max_count,
                    },
                    "counters": {"refund_count": m.refund_count, "refund_total_minor": m.refund_total_minor,
                                 "message_count": m.message_count},
                    "nbf": m.nbf, "exp": m.exp, "state": state,
                }));
            }
            Ok(json!({"mandates": out}))
        })
        .await
        .map_err(|f| na(&f.detail))
    }

    /// `pending.list{subject}` (§12.3): the subject's unexpired `PENDING` records.
    pub async fn pending_list(&self, args: &Map<String, Value>) -> Result<Value, Fail> {
        let na = |d: &str| Fail::new(Code::NotAvailable, d);
        check_keys(args, &["subject"], &[]).map_err(|f| na(&f.detail))?;
        let (ten, sub) = subject_arg(&args["subject"]).map_err(|f| na(&f.detail))?;
        let now = self.now_checked().map_err(|f| na(&f.detail))?;
        let conn = self.conn().await.map_err(|f| na(&f.detail))?;
        Self::run(conn, async move |c: &mut Client| {
            let rows = c
                .query(
                    "SELECT pending_id, op, created_at, expires_at FROM public.pending_effect \
                     WHERE ten = $1 AND approver_sub = $2 AND state = 'PENDING' AND expires_at > $3 \
                     ORDER BY created_at DESC LIMIT $4",
                    &[&ten, &sub, &to_i64(now), &LIST_MAX],
                )
                .await
                .map_err(dbf("pending list"))?;
            let mut out = Vec::with_capacity(rows.len());
            for r in &rows {
                let b: Vec<u8> = r.try_get(0).map_err(unavailable)?;
                out.push(json!({
                    "pending_id": encode_id(&<[u8; 16]>::try_from(b.as_slice()).map_err(unavailable)?),
                    "op": r.try_get::<_, String>(1).map_err(unavailable)?,
                    "created_at": to_u64(r.try_get(2).map_err(unavailable)?)?,
                    "expires_at": to_u64(r.try_get(3).map_err(unavailable)?)?,
                }));
            }
            Ok(json!({"pending": out}))
        })
        .await
        .map_err(|f| na(&f.detail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> MandateRow {
        MandateRow {
            mid: [1; 16],
            wid: "w".into(),
            ten: "shop1".into(),
            sub: "op_ana".into(),
            customer_sub: "c42".into(),
            customer_email: "alice@customer.test".into(),
            currency: "EUR".into(),
            refund_max_count: 3,
            refund_max_per_call_minor: 2500,
            refund_max_total_minor: 5000,
            message_max_count: 3,
            nbf: 100,
            exp: 200,
            cfg: [7; 32],
            state: "active".into(),
            refund_count: 0,
            refund_total_minor: 0,
            message_count: 0,
        }
    }

    fn refund(cs: &str, cur: &str, amount: u64) -> Terms {
        Terms::Refund {
            customer_sub: cs.into(),
            currency: cur.into(),
            amount,
        }
    }

    /// AT-11: exact boundaries of per-call, count, total and currency.
    #[test]
    fn terms_boundaries() {
        let mut m = row();
        assert!(within(&m, &refund("c42", "EUR", 2500)));
        assert!(!within(&m, &refund("c42", "EUR", 2501)));
        assert!(!within(&m, &refund("c42", "USD", 1)));
        assert!(!within(&m, &refund("c9", "EUR", 1)));
        m.refund_total_minor = 4000;
        assert!(within(&m, &refund("c42", "EUR", 1000)));
        assert!(!within(&m, &refund("c42", "EUR", 1001)));
        m.refund_count = 2;
        assert!(within(&m, &refund("c42", "EUR", 1)));
        m.refund_count = 3;
        assert!(!within(&m, &refund("c42", "EUR", 1)));
        let msg = |cs: &str, to: &str| Terms::Message {
            customer_sub: cs.into(),
            to: to.into(),
        };
        let mut m = row();
        assert!(within(&m, &msg("c42", "alice@customer.test")));
        assert!(!within(&m, &msg("c42", "x@evil.example")));
        assert!(!within(&m, &msg("c9", "alice@customer.test")));
        m.message_count = 3;
        assert!(!within(&m, &msg("c42", "alice@customer.test")));
    }

    /// AT-16: window `nbf ≤ now < exp`, `cfg`, state and every `revoked_before` scope.
    #[test]
    fn activity() {
        let m = row();
        let cfg = [7; 32];
        assert!(is_active(&m, 100, &cfg, &[]));
        assert!(is_active(&m, 199, &cfg, &[]));
        assert!(!is_active(&m, 200, &cfg, &[]));
        assert!(!is_active(&m, 99, &cfg, &[]));
        assert!(!is_active(&m, 150, &[8; 32], &[]));
        let mut r = m.clone();
        r.state = "revoked".into();
        assert!(!is_active(&r, 150, &cfg, &[]));
        let rb = |scope: RevocationScope, before: u64| RevokedBefore { scope, before };
        for scope in [
            RevocationScope::Tenant {
                ten: "shop1".into(),
            },
            RevocationScope::TenantWorkload {
                ten: "shop1".into(),
                wid: "w".into(),
            },
            RevocationScope::TenantSubject {
                ten: "shop1".into(),
                sub: "op_ana".into(),
            },
        ] {
            assert!(!is_active(&m, 150, &cfg, &[rb(scope.clone(), 101)]));
            // A mandate approved at or after `before` is not covered.
            assert!(is_active(&m, 150, &cfg, &[rb(scope, 100)]));
        }
        for scope in [
            RevocationScope::Tenant {
                ten: "other".into(),
            },
            RevocationScope::TenantWorkload {
                ten: "shop1".into(),
                wid: "w2".into(),
            },
            RevocationScope::TenantSubject {
                ten: "shop1".into(),
                sub: "op_bob".into(),
            },
        ] {
            assert!(is_active(&m, 150, &cfg, &[rb(scope, 1000)]));
        }
    }
}
