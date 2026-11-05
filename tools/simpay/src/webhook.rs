// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Webhook signing and at-least-once, unordered delivery.
//!
//! Signature scheme (modelled on Stripe's): header
//! `Simpay-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>." ‖ raw_body)>`.
//! Each delivery attempt is signed with a fresh timestamp from the simulated clock.

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::Shared;
use crate::config::EndpointFixture;
use crate::faults::{Ctx, Fault, Op, Stage};
use crate::http::{self, parse_http_url};
use crate::log;
use crate::state::{Delivery, Event};

pub const SIGNATURE_HEADER: &str = "Simpay-Signature";

pub fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

/// Returns the full header value `t=…,v1=…`.
pub fn sign(secret: &str, t: u64, body: &[u8]) -> String {
    // HMAC accepts keys of any length; `new_from_slice` cannot fail for HMAC.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("t={t},v1={}", hex(&mac.finalize().into_bytes()))
}

/// Flips what a malicious provider would lie about in an event.
fn contradict(obj: &mut Value) {
    if let Some(m) = obj.as_object_mut() {
        let flipped = match m.get("status").and_then(Value::as_str) {
            Some("failed") => "succeeded",
            _ => "failed",
        };
        m.insert("status".into(), Value::from(flipped));
        if let Some(a) = m.get("amount").and_then(Value::as_u64) {
            m.insert("amount".into(), Value::from(a.saturating_mul(2).max(1)));
        }
    }
}

/// Spawns delivery of each event to every endpoint of its account.
pub fn dispatch(shared: &Arc<Shared>, events: Vec<Event>) {
    for ev in events {
        let (endpoints, fault) = {
            let mut st = shared.lock();
            let eps = st
                .accounts
                .get(&ev.account)
                .map(|a| a.webhook_endpoints.clone())
                .unwrap_or_default();
            let f = st.faults.take(
                Stage::Webhook,
                Ctx {
                    op: Op::Webhook,
                    idempotency_key: None,
                    charge: ev.charge(),
                    event_type: Some(&ev.event_type),
                },
            );
            (eps, f)
        };
        if let Some(f) = &fault {
            log(&format!(
                "fault {f:?} on event {} ({})",
                ev.id, ev.event_type
            ));
        }
        if matches!(fault, Some(Fault::WebhookSuppress)) {
            continue;
        }
        let mut json = ev.to_json();
        if matches!(fault, Some(Fault::WebhookContradict))
            && let Some(o) = json.pointer_mut("/data/object")
        {
            contradict(o);
        }
        let body = serde_json::to_vec(&json).unwrap_or_default();
        let copies = match fault {
            Some(Fault::WebhookDuplicate { n }) => n,
            _ => 1,
        };
        let replay = match fault {
            Some(Fault::WebhookReplay { after_ms }) => Some(after_ms),
            _ => None,
        };
        for ep in endpoints {
            let shared = shared.clone();
            let body = body.clone();
            let (id, ty) = (ev.id.clone(), ev.event_type.clone());
            tokio::spawn(async move {
                deliver(shared, ep, id, ty, body, copies, replay).await;
            });
        }
    }
}

async fn deliver(
    shared: Arc<Shared>,
    ep: EndpointFixture,
    event_id: String,
    event_type: String,
    body: Vec<u8>,
    copies: u32,
    replay: Option<u64>,
) {
    let cfg = shared.cfg.webhook_delivery.clone();
    let Ok(url) = parse_http_url(&ep.url) else {
        return;
    };
    let limit = Duration::from_millis(cfg.timeout_ms);
    let mut first_ok: Option<String> = None;
    for copy in 0..copies {
        let kind = if copy == 0 { "normal" } else { "duplicate" };
        for attempt in 1..=cfg.max_attempts {
            let t = shared.lock().now();
            let sig = sign(&ep.secret, t, &body);
            let headers = vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                (SIGNATURE_HEADER.to_string(), sig.clone()),
                ("Simpay-Event-Id".to_string(), event_id.clone()),
            ];
            let res = http::post(&url, &headers, &body, limit).await;
            let ok = matches!(res, Ok(s) if (200..300).contains(&s));
            let result = match &res {
                Ok(s) => s.to_string(),
                Err(e) => format!("error: {e}"),
            };
            shared.lock().push_delivery(Delivery {
                index: 0,
                event_id: event_id.clone(),
                event_type: event_type.clone(),
                url: ep.url.clone(),
                kind: kind.into(),
                attempt,
                timestamp: t,
                signature_header: sig.clone(),
                result: result.clone(),
                body: String::from_utf8_lossy(&body).into_owned(),
            });
            log(&format!(
                "webhook {event_id} {event_type} -> {} attempt {attempt} ({kind}): {result}",
                ep.url
            ));
            if ok {
                if first_ok.is_none() {
                    first_ok = Some(sig);
                }
                break;
            }
            if attempt < cfg.max_attempts {
                let backoff = cfg
                    .retry_base_ms
                    .saturating_mul(1u64 << (attempt - 1).min(16));
                tokio::time::sleep(Duration::from_millis(backoff)).await;
            }
        }
    }
    if let (Some(ms), Some(sig)) = (replay, first_ok) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        let _ = send_verbatim(
            &shared,
            &ep.url,
            &event_id,
            &event_type,
            &body,
            &sig,
            "replay",
        )
        .await;
    }
}

/// Re-sends the exact bytes and signature header of an earlier delivery (replay).
pub async fn send_verbatim(
    shared: &Arc<Shared>,
    url_s: &str,
    event_id: &str,
    event_type: &str,
    body: &[u8],
    sig: &str,
    kind: &str,
) -> Result<u16, String> {
    let url = parse_http_url(url_s)?;
    let headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        (SIGNATURE_HEADER.to_string(), sig.to_string()),
        ("Simpay-Event-Id".to_string(), event_id.to_string()),
    ];
    let limit = Duration::from_millis(shared.cfg.webhook_delivery.timeout_ms);
    let res = http::post(&url, &headers, body, limit).await;
    let ts = sig
        .strip_prefix("t=")
        .and_then(|r| r.split(',').next())
        .and_then(|t| t.parse().ok())
        .unwrap_or(0);
    let result = match &res {
        Ok(s) => s.to_string(),
        Err(e) => format!("error: {e}"),
    };
    log(&format!(
        "webhook {event_id} {event_type} -> {url_s} ({kind}): {result}"
    ));
    shared.lock().push_delivery(Delivery {
        index: 0,
        event_id: event_id.to_string(),
        event_type: event_type.to_string(),
        url: url_s.to_string(),
        kind: kind.into(),
        attempt: 1,
        timestamp: ts,
        signature_header: sig.to_string(),
        result,
        body: String::from_utf8_lossy(body).into_owned(),
    });
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_case_2() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        // Our message is "<t>." ‖ body, so split the data as t="what do ya want for nothing?" is
        // not numeric; instead check the raw primitive and then the framing separately.
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let a = sign("k", 12, b"body");
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"k").unwrap();
        mac.update(b"12.body");
        assert_eq!(a, format!("t=12,v1={}", hex(&mac.finalize().into_bytes())));
    }
}
