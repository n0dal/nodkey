// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Server-rendered auth-origin pages. No scripts; every dynamic value goes through [`esc`].

use crate::digest::CheckedRecord;
use crate::ipc::Render;
use crate::util::{esc, fmt_amount, fmt_utc, hex_lower};

pub const CSS: &str = include_str!("../static/nodkey.css");

pub const UNIFORM_ERROR: &str = "This request is not available.";

/// The template operation (agent-interface-v1 §4.1).
pub const MANDATE_TEMPLATE: &str = "mandate.support_ticket";
/// Label of an agent-written message body (effect-protocol-v2 §12.6).
pub const AGENT_TEXT_LABEL: &str = "Written by the agent \u{2014} unverified";

/// The static mandate template of agent-interface-v1 §4.2 step 2, filled from the record's own
/// (digest-checked) params; amounts use display key 11. `None` if a value is missing.
pub fn mandate_summary(r: &CheckedRecord, workload: &str) -> Option<String> {
    use crate::json::Scalar;
    let p = &r.rec.params.0;
    let u = |k: &str| match p.get(k) {
        Some(Scalar::Uint(n)) => Some(*n),
        _ => None,
    };
    let t = |k: &str| match p.get(k) {
        Some(Scalar::Text(v)) => Some(v.clone()),
        _ => None,
    };
    let (cs, ce, cur) = (t("customer_sub")?, t("customer_email")?, t("currency")?);
    let money = |n: u64| display_amount(r, n);
    Some(format!(
        "Allow <strong>{w}</strong>, for <strong>{v} seconds</strong> from approval, to: refund at most \
         <strong>{n}</strong> times, at most <strong>{pc}</strong> each and <strong>{tot}</strong> in \
         total (<code>{cur}</code>), only orders of customer <code>{cs}</code> (<code>{ce}</code>); \
         send at most <strong>{m}</strong> messages to <code>{ce}</code>; read that customer's orders. \
         <strong>These will happen without asking you again.</strong>",
        w = esc(workload),
        v = u("valid_for_s")?,
        n = u("refund_max_count")?,
        pc = esc(&money(u("refund_max_per_call_minor")?)?),
        tot = esc(&money(u("refund_max_total_minor")?)?),
        cur = esc(&cur),
        cs = esc(&cs),
        ce = esc(&ce),
        m = u("message_max_count")?,
    ))
}

/// Banner shown on every auth-origin page while the test login is active (R3B-11).
const TEST_BANNER: &str = "<div class=\"test-banner\" role=\"alert\"><strong>TEST LOGIN</strong> \
     — this gateway runs with a local test login that asks for no credential. \
     Never use it outside local development.</div>";

pub fn page(title: &str, body: &str, test_login: bool) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{t} — Nodkey</title><link rel=\"stylesheet\" href=\"/static/nodkey.css\"></head>\
         <body>{banner}<main>{body}</main></body></html>\n",
        t = esc(title),
        banner = if test_login { TEST_BANNER } else { "" },
    )
}

fn op_label(op: &str) -> &'static str {
    match op {
        "payments.refund" => "Refund a payment",
        "ledger.transfer" => "Transfer money",
        "payments.support_refund" => "Refund a customer's payment",
        "messages.send" => "Send a message to a customer",
        MANDATE_TEMPLATE => "Approve a mandate",
        _ => "Perform an operation",
    }
}

fn state_label(s: &str) -> &'static str {
    match s {
        "PENDING" => "waiting for your decision",
        "APPROVED" => "approved",
        "EXECUTING" => "in progress",
        "SUCCEEDED" => "completed",
        "FAILED" => "failed",
        "UNKNOWN" => "outcome unknown (being reconciled)",
        "DENIED" => "denied",
        "EXPIRED" => "expired",
        _ => "unknown",
    }
}

/// States the gateway accepts in a render response.
pub fn is_state(s: &str) -> bool {
    matches!(
        s,
        "PENDING"
            | "APPROVED"
            | "EXECUTING"
            | "SUCCEEDED"
            | "FAILED"
            | "UNKNOWN"
            | "DENIED"
            | "EXPIRED"
    )
}

/// Amount formatting uses display key 11 only.
fn display_amount(r: &CheckedRecord, minor: u64) -> Option<String> {
    use crate::json::Scalar;
    let d = &r.rec.display.0;
    let (Some(Scalar::Uint(e)), Some(Scalar::Text(cur))) =
        (d.get("amount_exponent"), d.get("currency"))
    else {
        return None;
    };
    Some(format!("{} {}", fmt_amount(minor, *e)?, cur))
}

/// Amount parameters (declared `uint`, name ending in `_minor`) the user must type to approve, as
/// `(form field, exact expected text)`: the major-unit value formatted with display key 11 (for
/// example `12.50`), or the raw integer when there is no display data (GW-R-01 ruling).
pub fn typed_amounts(r: &CheckedRecord) -> Vec<(String, String)> {
    use crate::json::Scalar;
    let d = &r.rec.display.0;
    let exp = match d.get("amount_exponent") {
        Some(Scalar::Uint(e)) => Some(*e),
        _ => None,
    };
    r.rec
        .params
        .0
        .iter()
        .filter_map(|(name, v)| match v {
            Scalar::Uint(n)
                if name.ends_with("_minor")
                    && r.rec.param_types.0.get(name).map(String::as_str) == Some("uint") =>
            {
                let want = exp
                    .and_then(|e| fmt_amount(*n, e))
                    .unwrap_or_else(|| n.to_string());
                Some((format!("confirm_{name}"), want))
            }
            _ => None,
        })
        .collect()
}

fn related_list(items: &[crate::ipc::Related], r: &CheckedRecord) -> String {
    if items.is_empty() {
        return "<p>None.</p>".into();
    }
    let mut s = String::from(
        "<table><thead><tr><th scope=\"col\">Request</th><th scope=\"col\">State</th>\
         <th scope=\"col\">Created</th><th scope=\"col\">Amount</th></tr></thead><tbody>",
    );
    for it in items {
        let amount = it
            .amount_minor
            .map(|m| display_amount(r, m).unwrap_or_else(|| format!("{m} (minor units)")))
            .unwrap_or_else(|| "—".into());
        s.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&it.pending_id),
            esc(state_label(&it.state)),
            esc(&fmt_utc(it.created_at)),
            esc(&amount)
        ));
    }
    s.push_str("</tbody></table>");
    s
}

/// The confirmation page (spec §7.1). `form` is `Some(token)` only for a `PENDING` record.
pub fn confirm_page(
    rd: &Render,
    r: &CheckedRecord,
    form: Option<&str>,
    error: Option<&str>,
    test_login: bool,
) -> String {
    use crate::json::Scalar;
    let rec = &r.rec;
    let ctx = &rd.context;
    let mut b = String::new();
    b.push_str(&format!("<h1>{}</h1>", esc(op_label(&rec.op))));
    b.push_str(&format!(
        "<p class=\"lead\">Requested by <strong>{}</strong>. Status: <strong>{}</strong>.</p>",
        esc(&ctx.workload_display_name),
        esc(state_label(&rd.state))
    ));
    if rec.op == MANDATE_TEMPLATE {
        match mandate_summary(r, &ctx.workload_display_name) {
            Some(text) => b.push_str(&format!("<p class=\"mandate\">{text}</p>")),
            None => {
                return page(
                    UNIFORM_ERROR,
                    &format!("<p>{UNIFORM_ERROR}</p>"),
                    test_login,
                );
            }
        }
    }
    b.push_str("<h2>What will happen</h2><dl class=\"params\">");
    b.push_str(&format!(
        "<dt>Operation</dt><dd><code>{}</code></dd>",
        esc(&rec.op)
    ));
    for (name, value) in &rec.params.0 {
        let shown = match value {
            Scalar::Uint(n) => {
                let ty = rec.param_types.0.get(name).map(String::as_str);
                match (ty, name.ends_with("_minor")) {
                    (Some("uint"), true) => match display_amount(r, *n) {
                        Some(a) => format!("{a} ({n} minor units)"),
                        None => format!("{n} (minor units; no currency data)"),
                    },
                    _ => n.to_string(),
                }
            }
            Scalar::Text(t) => t.clone(),
        };
        // §12.6: the message body is the effect; shown in full, escaped, monospace, labelled.
        if rec.op == "messages.send" && name == "body" {
            b.push_str(&format!(
                "<dt>{} ({})</dt><dd><pre class=\"value unverified\">{}</pre></dd>",
                esc(name),
                esc(AGENT_TEXT_LABEL),
                esc(&shown)
            ));
            continue;
        }
        b.push_str(&format!(
            "<dt>{}</dt><dd><code class=\"value\">{}</code></dd>",
            esc(name),
            esc(&shown)
        ));
    }
    b.push_str("</dl>");

    if !rd.facts.is_empty() {
        b.push_str("<h2>Facts checked by Nodkey</h2><dl class=\"facts\">");
        for f in &rd.facts {
            b.push_str(&format!(
                "<dt>{}</dt><dd>{}</dd>",
                esc(&f.label),
                esc(&f.value)
            ));
        }
        b.push_str("</dl>");
    }

    b.push_str("<h2>Other requests</h2>");
    b.push_str(&format!(
        "<p>Open requests from this application waiting for you: <strong>{}</strong>.</p>",
        ctx.pending_from_workload_for_subject
    ));
    b.push_str("<h3>Identical requests in the last 30 minutes</h3>");
    b.push_str(&related_list(&ctx.recent_identical, r));
    b.push_str("<h3>Other open requests on the same resource</h3>");
    b.push_str(&related_list(&ctx.other_open_on_resource, r));

    b.push_str("<h2>Details</h2><dl class=\"meta\">");
    b.push_str(&format!(
        "<dt>Request id</dt><dd><code>{}</code></dd>",
        esc(&rec.pending_id)
    ));
    b.push_str(&format!(
        "<dt>Application</dt><dd>{} (<code>{}</code>)</dd>",
        esc(&ctx.workload_display_name),
        esc(&rec.wid)
    ));
    b.push_str(&format!(
        "<dt>Acting as</dt><dd><code>{}</code> in <code>{}</code></dd>",
        esc(&rec.approver_sub),
        esc(&rec.ten)
    ));
    b.push_str(&format!(
        "<dt>Created</dt><dd>{}</dd>",
        esc(&fmt_utc(rec.created_at))
    ));
    b.push_str(&format!(
        "<dt>Expires</dt><dd>{}</dd>",
        esc(&fmt_utc(rec.expires_at))
    ));
    b.push_str(&format!(
        "<dt>Digest</dt><dd><code class=\"value\">{}</code></dd></dl>",
        hex_lower(&r.digest)
    ));

    match form {
        Some(token) => {
            b.push_str(&format!(
                "<form method=\"post\" action=\"/confirm/{pid}/decision\" class=\"decision\">\
                 <input type=\"hidden\" name=\"token\" value=\"{tok}\">\
                 <input type=\"hidden\" name=\"digest\" value=\"{dg}\">",
                pid = esc(&rec.pending_id),
                tok = esc(token),
                dg = hex_lower(&r.digest)
            ));
            if let Some(e) = error {
                b.push_str(&format!(
                    "<p class=\"error\" role=\"alert\"><strong>{}</strong></p>",
                    esc(e)
                ));
            }
            let cur = match rec.display.0.get("currency") {
                Some(crate::json::Scalar::Text(c)) => format!(" ({})", esc(c)),
                _ => String::new(),
            };
            for (field, _) in typed_amounts(r) {
                let param = field.strip_prefix("confirm_").unwrap_or(&field);
                b.push_str(&format!(
                    "<p class=\"typed\"><label for=\"{f}\">To approve, type the <code>{p}</code> \
                     amount{cur} exactly as shown above:</label>\
                     <input type=\"text\" id=\"{f}\" name=\"{f}\" inputmode=\"decimal\" \
                     autocomplete=\"off\" spellcheck=\"false\" size=\"16\" maxlength=\"32\"></p>",
                    f = esc(&field),
                    p = esc(param),
                ));
            }
            if ctx.approver_source == "named" {
                b.push_str(&format!(
                    "<p class=\"warning\" role=\"note\"><strong>Approve only if you just asked {} to do this.</strong></p>",
                    esc(&ctx.workload_display_name)
                ));
            }
            // The buttons stay hidden and inert for 1.5 s after rendering (CSS only, GW-R-01); the
            // server rejects an earlier approval as well. Deny comes first.
            b.push_str(
                "<div class=\"buttons delayed\">\
                 <button type=\"submit\" name=\"decision\" value=\"deny\" class=\"deny\">Deny</button>\
                 <button type=\"submit\" name=\"decision\" value=\"approve\" class=\"approve\">Approve</button>\
                 </div></form>",
            );
        }
        None => b.push_str(
            "<p>No decision is needed: this request is no longer waiting for approval.</p>",
        ),
    }
    page(op_label(&rec.op), &b, test_login)
}

/// `/pending` (effect-protocol-v2 §12.6): the subject's `PENDING` records.
pub fn pending_page(items: &[crate::ipc::PendingItem], test_login: bool) -> String {
    let mut b = String::from("<h1>Requests waiting for you</h1>");
    if items.is_empty() {
        b.push_str("<p>None.</p>");
    } else {
        b.push_str(
            "<table><thead><tr><th scope=\"col\">Request</th><th scope=\"col\">Operation</th>\
             <th scope=\"col\">Created</th><th scope=\"col\">Expires</th></tr></thead><tbody>",
        );
        for it in items {
            b.push_str(&format!(
                "<tr><td><a href=\"/confirm/{id}\"><code>{id}</code></a></td><td>{op}</td>\
                 <td>{c}</td><td>{e}</td></tr>",
                id = esc(&it.pending_id),
                op = esc(op_label(&it.op)),
                c = esc(&fmt_utc(it.created_at)),
                e = esc(&fmt_utc(it.expires_at)),
            ));
        }
        b.push_str("</tbody></table>");
    }
    page("Requests waiting for you", &b, test_login)
}

/// `/mandates` (effect-protocol-v2 §12.6): every mandate of the subject; each active one with a
/// Revoke form carrying its single-use token. Amounts are shown in minor units (the list carries
/// no display data).
pub fn mandates_page(
    items: &[(crate::ipc::MandateItem, Option<String>)],
    test_login: bool,
) -> String {
    let mut b = String::from("<h1>Your mandates</h1>");
    if items.is_empty() {
        b.push_str("<p>None.</p>");
    }
    for (m, tok) in items {
        let t = &m.terms;
        let c = &m.counters;
        b.push_str(&format!(
            "<section class=\"mandate\"><h2>{w}: customer <code>{cs}</code></h2><dl class=\"params\">\
             <dt>State</dt><dd>{st}</dd>\
             <dt>Valid</dt><dd>{nbf} to {exp}</dd>\
             <dt>Refunds</dt><dd>{rc} of {rn} used; {rt} of {rtot} minor units {cur} used; at most {pc} each</dd>\
             <dt>Messages</dt><dd>{mc} of {mn} sent, only to <code>{ce}</code></dd>\
             <dt>Mandate id</dt><dd><code>{mid}</code></dd></dl>",
            w = esc(&m.workload_display_name),
            cs = esc(&t.customer_sub),
            st = esc(&m.state),
            nbf = esc(&fmt_utc(m.nbf)),
            exp = esc(&fmt_utc(m.exp)),
            rc = c.refund_count,
            rn = t.refund_max_count,
            rt = c.refund_total_minor,
            rtot = t.refund_max_total_minor,
            cur = esc(&t.currency),
            pc = t.refund_max_per_call_minor,
            mc = c.message_count,
            mn = t.message_max_count,
            ce = esc(&t.customer_email),
            mid = esc(&m.mid),
        ));
        if let (Some(tok), "active") = (tok, m.state.as_str()) {
            b.push_str(&format!(
                "<form method=\"post\" action=\"/mandates/{mid}/revoke\">\
                 <input type=\"hidden\" name=\"token\" value=\"{tok}\">\
                 <button type=\"submit\" class=\"deny\">Revoke</button></form>",
                mid = esc(&m.mid),
                tok = esc(tok),
            ));
        }
        b.push_str("</section>");
    }
    page("Your mandates", &b, test_login)
}

/// Result of a revoke POST (§12.6): "revoked" only after the broker's acknowledgement.
pub fn revoke_page(confirmed: bool, test_login: bool) -> String {
    let body = if confirmed {
        "<h1>Mandate revoked</h1><p>The mandate is revoked. Nothing more will happen under it.</p>"
    } else {
        "<h1>Revocation not confirmed</h1><p>Revocation not confirmed \u{2014} retrying. \
         Nodkey keeps retrying in the background; check <a href=\"/mandates\">your mandates</a> again.</p>"
    };
    page("Mandate revocation", body, test_login)
}

pub fn submitted_page(state: Option<&str>, test_login: bool) -> String {
    let st = match state {
        Some(s) => format!(
            "<p>Current status: <strong>{}</strong>.</p>",
            esc(state_label(s))
        ),
        None => String::new(),
    };
    page(
        "Decision submitted",
        &format!("<h1>Decision submitted</h1><p>Your decision has been submitted.</p>{st}"),
        test_login,
    )
}
