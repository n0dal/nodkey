// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! The admin (control-plane) listener: fault plan, clock, settlement transitions,
//! webhook endpoints and replays, ledger inspection, snapshots.
//!
//! It runs on a separate listener that only the test harness should be able to reach.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::Shared;
use crate::config::{EndpointFixture, validate_endpoint};
use crate::faults::Rule;
use crate::http::{Request, Response};
use crate::state::{RefundStatus, Store, refund_object};
use crate::webhook;

fn ok(v: Value) -> Response {
    Response::json(200, &v)
}

fn err(status: u16, msg: &str) -> Response {
    Response::json(status, &json!({"error": msg, "simulator": true}))
}

fn body<T: for<'de> Deserialize<'de>>(req: &Request) -> Result<T, Response> {
    serde_json::from_slice(&req.body).map_err(|e| err(400, &format!("bad JSON body: {e}")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultsBody {
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enabled {
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Advance {
    seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusBody {
    status: RefundStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoints {
    endpoints: Vec<EndpointFixture>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resend {
    index: usize,
}

fn ledger(st: &Store) -> Value {
    let mut per: BTreeMap<&str, (u64, u64, u64, u64)> = BTreeMap::new();
    for r in st.refunds.values() {
        let e = per.entry(r.charge.as_str()).or_default();
        e.0 += 1;
        e.1 += r.amount_minor;
        if r.status != RefundStatus::Failed {
            e.2 += 1;
            e.3 += r.amount_minor;
        }
    }
    let charges: Vec<Value> = st
        .charges
        .values()
        .map(|c| {
            let (n, sum, n_live, sum_live) = per.get(c.id.as_str()).copied().unwrap_or_default();
            json!({
                "id": c.id, "account": c.account, "amount": c.amount_minor,
                "currency": c.currency, "amount_refunded": c.refunded_minor,
                "refund_count": n, "refund_sum": sum,
                "refund_count_not_failed": n_live, "refund_sum_not_failed": sum_live,
            })
        })
        .collect();
    let mut refunds: Vec<_> = st.refunds.values().collect();
    refunds.sort_by_key(|r| r.seq);
    let refunds: Vec<Value> = refunds.into_iter().map(refund_object).collect();
    json!({"simulator": true, "charges": charges, "refunds": refunds})
}

pub async fn handle(shared: &Arc<Shared>, req: &Request) -> Response {
    if let Some(tok) = &shared.cfg.admin_token {
        let want = format!("Bearer {tok}");
        if req.header("authorization").ok().flatten() != Some(want.as_str()) {
            return err(401, "admin token required");
        }
    }
    let segs: Vec<&str> = match req.path.strip_prefix("/admin/") {
        Some(p) => p.split('/').collect(),
        None => return err(404, "not found"),
    };
    let m = req.method.as_str();
    match (m, segs.as_slice()) {
        ("GET", ["health"]) => ok(json!({"status": "ok", "simulator": true,
            "notice": "SIMULATED payment provider - not a real payment API"})),
        ("GET", ["state"]) => {
            let st = shared.lock();
            ok(serde_json::to_value(&*st).unwrap_or(Value::Null))
        }
        ("GET", ["ledger"]) => {
            let st = shared.lock();
            ok(ledger(&st))
        }
        ("GET", ["faults"]) => {
            let st = shared.lock();
            ok(json!({"malicious_mode": st.malicious_mode, "rules": st.faults.rules}))
        }
        ("PUT", ["faults"]) => {
            let b: FaultsBody = match body(req) {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut st = shared.lock();
            let mal = st.malicious_mode;
            match st.faults.install(b.rules, mal) {
                Ok(()) => {
                    crate::log(&format!(
                        "fault plan installed ({} rules)",
                        st.faults.rules.len()
                    ));
                    ok(json!({"installed": st.faults.rules.len()}))
                }
                Err(e) => err(400, &e),
            }
        }
        ("DELETE", ["faults"]) => {
            shared.lock().faults.rules.clear();
            ok(json!({"installed": 0}))
        }
        ("PUT", ["malicious"]) => {
            let b: Enabled = match body(req) {
                Ok(b) => b,
                Err(r) => return r,
            };
            let mut st = shared.lock();
            st.malicious_mode = b.enabled;
            if !b.enabled {
                st.faults.rules.retain(|r| !r.rule.fault.is_malicious());
            }
            crate::log(&format!(
                "MALICIOUS-PROVIDER MODE {}",
                if b.enabled { "ENABLED" } else { "disabled" }
            ));
            ok(json!({"malicious_mode": b.enabled}))
        }
        ("GET", ["clock"]) => {
            let st = shared.lock();
            ok(json!({"now": st.now(), "mode": st.clock.mode}))
        }
        ("POST", ["clock", "advance"]) => {
            let b: Advance = match body(req) {
                Ok(b) => b,
                Err(r) => return r,
            };
            if b.seconds > 10 * 365 * 86_400 {
                return err(400, "advance too large");
            }
            let (now, evs) = {
                let mut st = shared.lock();
                st.clock.value = st.clock.value.saturating_add(b.seconds as i64);
                let evs = st.process_due();
                (st.now(), evs)
            };
            webhook::dispatch(shared, evs);
            ok(json!({"now": now}))
        }
        ("POST", ["refunds", id, "status"]) => {
            let b: StatusBody = match body(req) {
                Ok(b) => b,
                Err(r) => return r,
            };
            let res = shared.lock().set_refund_status(id, b.status);
            match res {
                Ok(evs) => {
                    webhook::dispatch(shared, evs);
                    let st = shared.lock();
                    ok(st
                        .refunds
                        .get(*id)
                        .map(refund_object)
                        .unwrap_or(Value::Null))
                }
                Err(e) => err(400, &e),
            }
        }
        ("PUT", ["accounts", acct, "webhook_endpoints"]) => {
            let b: Endpoints = match body(req) {
                Ok(b) => b,
                Err(r) => return r,
            };
            for e in &b.endpoints {
                if let Err(e) = validate_endpoint(e) {
                    return err(400, &e);
                }
            }
            let mut st = shared.lock();
            match st.accounts.get_mut(*acct) {
                Some(a) => {
                    a.webhook_endpoints = b.endpoints;
                    ok(json!({"endpoints": a.webhook_endpoints.len()}))
                }
                None => err(404, "no such account"),
            }
        }
        ("GET", ["webhooks", "deliveries"]) => {
            let st = shared.lock();
            ok(json!({"deliveries": st.deliveries}))
        }
        ("POST", ["webhooks", "resend"]) => {
            let b: Resend = match body(req) {
                Ok(b) => b,
                Err(r) => return r,
            };
            let d = shared
                .lock()
                .deliveries
                .iter()
                .find(|d| d.index == b.index)
                .cloned();
            let Some(d) = d else {
                return err(404, "no such delivery");
            };
            let res = webhook::send_verbatim(
                shared,
                &d.url,
                &d.event_id,
                &d.event_type,
                d.body.as_bytes(),
                &d.signature_header,
                "resend",
            )
            .await;
            ok(json!({"result": match res { Ok(s) => s.to_string(), Err(e) => e }}))
        }
        ("POST", ["snapshot"]) => match &shared.cfg.snapshot_path {
            Some(p) => {
                let res = shared.lock().write_snapshot(p);
                match res {
                    Ok(()) => ok(json!({"written": p})),
                    Err(e) => err(500, &e),
                }
            }
            None => err(400, "no snapshot_path configured"),
        },
        ("POST", ["reset"]) => {
            let mut st = shared.lock();
            *st = Store::from_config(&shared.cfg);
            crate::log("state reset to fixture");
            ok(json!({"reset": true}))
        }
        _ => err(404, "not found"),
    }
}
