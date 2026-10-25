//! Server-rendered auth-origin pages. No scripts; every dynamic value goes through [`esc`].

use crate::digest::CheckedRecord;
use crate::ipc::Render;
use crate::util::{esc, fmt_amount, fmt_utc, hex_lower};

pub const CSS: &str = include_str!("../static/nodkey.css");

pub const UNIFORM_ERROR: &str = "This request is not available.";

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
                        None => n.to_string(),
                    },
                    _ => n.to_string(),
                }
            }
            Scalar::Text(t) => t.clone(),
        };
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
            if ctx.approver_source == "named" {
                b.push_str(&format!(
                    "<p class=\"warning\" role=\"note\"><strong>Approve only if you just asked {} to do this.</strong></p>",
                    esc(&ctx.workload_display_name)
                ));
            }
            b.push_str(
                "<div class=\"buttons\">\
                 <button type=\"submit\" name=\"decision\" value=\"approve\" class=\"approve\">Approve</button>\
                 <button type=\"submit\" name=\"decision\" value=\"deny\" class=\"deny\">Deny</button>\
                 </div></form>",
            );
        }
        None => b.push_str(
            "<p>No decision is needed: this request is no longer waiting for approval.</p>",
        ),
    }
    page(op_label(&rec.op), &b, test_login)
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
