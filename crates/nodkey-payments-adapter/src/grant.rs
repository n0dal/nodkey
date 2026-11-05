// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Grant check in the adapter (payments-adapter-v1 §3.1).
//!
//! The adapter verifies the grant bytes itself with `nodkey_grant::verify_retransmission`
//! (creates and resends), then applies the adapter rules the declaration format cannot express
//! (step 6: `amount_minor ≥ 1`, the charge-id pattern, the ISO 4217 table). Every failure is
//! `grant_refused` on socket P; the precise reason goes to the audit log only.
//!
//! Lookups (`refund.find`, `refund.get`, `idem.status`) use `nodkey_grant::verify_binding`
//! (signature and bindings, no age rule; PA-18). Its result type differs from the create path's,
//! so a lookup verification can never authorize a create.

use nodkey_grant::{
    Binding, BrokerId, Limits, OpKind, OperationDecl, Operations, ParamDecl, ParamType, ParamValue,
    Params, RMax, Registry, RetransmissionContext, verify_binding, verify_retransmission,
};

/// The operation this adapter serves (compiled in; effect-protocol-v2 Draft 3.1).
pub const OP: &str = "payments.refund";
/// payments-adapter-v1 Draft 4 §16 (agent-interface-v1 §3): ownership on the signed con3.
pub const SUPPORT_OP: &str = "payments.support_refund";
pub const OPV: u16 = 1;

/// Largest amount simpay accepts and the adapter's response validation range (§6.1).
pub const MAX_AMOUNT: u64 = 999_999_999_999;

/// `payments.refund` and `payments.support_refund` opv 1 placements (§2, §16: compiled into the
/// adapter, not configurable).
pub fn operations() -> Operations {
    let p = |name: &str, binding, ty| ParamDecl {
        name: name.into(),
        binding,
        ty,
        destination: false,
        justification: None,
    };
    let base = vec![
        p("order_id", Binding::Resource(0), ParamType::Uint),
        p("amount_minor", Binding::Exact(0), ParamType::Uint),
        p("currency", Binding::Exact(1), ParamType::Currency),
        p("charge_id", Binding::Exact(2), ParamType::Text64),
    ];
    let mut support = base.clone();
    support.push(p("customer_sub", Binding::Exact(3), ParamType::Text64));
    Operations::new(vec![
        OperationDecl {
            name: OP.into(),
            kind: OpKind::Write,
            opv: OPV,
            requires_confirmation: true,
            mandate_eligible: false,
            params: base,
        },
        // §16.2: `cfm` 1, or 2 with `mid` (grant-v1 Draft 4 W11d); the adapter does not evaluate
        // the mandate.
        OperationDecl {
            name: SUPPORT_OP.into(),
            kind: OpKind::Write,
            opv: OPV,
            requires_confirmation: true,
            mandate_eligible: true,
            params: support,
        },
    ])
    .expect("compiled-in declarations are valid")
}

/// ISO 4217 codes this prototype accepts (the same table as the broker's
/// `broker/src/v2/decls.rs::iso4217_exponent`, so both sides refuse the same codes).
pub fn iso4217_known(code: &str) -> bool {
    matches!(
        code,
        "EUR"
            | "USD"
            | "GBP"
            | "CHF"
            | "SEK"
            | "NOK"
            | "DKK"
            | "CAD"
            | "AUD"
            | "JPY"
            | "KRW"
            | "ISK"
            | "BHD"
            | "KWD"
            | "JOD"
            | "OMR"
            | "TND"
    )
}

fn is_alnum_run(s: &[u8], min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.iter().all(u8::is_ascii_alphanumeric)
}

/// `^ch_[A-Za-z0-9]{8,61}$` (PA-19; at most 64 bytes, the grant's `text64`).
pub fn is_charge_id(s: &str) -> bool {
    s.as_bytes()
        .strip_prefix(b"ch_")
        .is_some_and(|r| is_alnum_run(r, 8, 61))
}

/// `^re_[A-Za-z0-9]{8,64}$` (§5).
pub fn is_refund_id(s: &str) -> bool {
    s.as_bytes()
        .strip_prefix(b"re_")
        .is_some_and(|r| is_alnum_run(r, 8, 64))
}

/// Static inputs for grant verification, built once at start-up from §2 inputs.
#[derive(Debug)]
pub struct GrantInputs {
    pub registry: Registry,
    pub operations: Operations,
    pub broker_id: BrokerId,
    pub wid: String,
    pub tenants: Vec<String>,
    pub r_max: RMax,
    /// §16.1; `None` refuses every `payments.support_refund` grant.
    pub support: Option<crate::config::Support>,
}

/// The signed values of a verified `payments.refund` grant, after the adapter rules. Every
/// provider value is taken from here (and from the derivation over `iss`/`jti`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundGrant {
    pub iss: String,
    pub jti: [u8; 16],
    pub op: String,
    pub opv: u16,
    pub iat: u64,
    pub ten: String,
    pub sub: String,
    pub order_id: u64,
    pub amount_minor: u64,
    pub currency: String,
    pub charge_id: String,
    /// `payments.support_refund` con3 (§16.2); `None` for `payments.refund`.
    pub customer_sub: Option<String>,
}

impl RefundGrant {
    pub fn jti_hex(&self) -> String {
        self.jti.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Why a grant was refused (audit log only; the broker sees `grant_refused`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub &'static str);

fn context<'a>(
    g: &'a GrantInputs,
    wid: &'a str,
    op: &'a str,
) -> Result<RetransmissionContext<'a>, Refusal> {
    RetransmissionContext::new(
        &g.registry,
        &g.broker_id,
        wid,
        &g.tenants,
        &g.operations,
        op,
        Limits::default(),
    )
    .ok_or(Refusal("context_invalid"))
}

/// The `(wid, op)` pairs a grant may be verified against: `payments.refund` for the configured
/// `wid`; `payments.support_refund` for each `support.wids` entry (§16.2). The grant's own `wid`
/// and `op` are checked by the crate in each context, so at most one can succeed.
fn contexts(g: &GrantInputs) -> Vec<(&str, &'static str)> {
    let mut v = vec![(g.wid.as_str(), OP)];
    if let Some(s) = &g.support {
        v.extend(s.wids.iter().map(|w| (w.as_str(), SUPPORT_OP)));
    }
    v
}

/// Runs `f` in each context; the first success wins, otherwise the first context's refusal.
fn first_ok<T>(
    g: &GrantInputs,
    mut f: impl FnMut(&RetransmissionContext<'_>) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    let mut first = None;
    for (wid, op) in contexts(g) {
        match context(g, wid, op).and_then(|c| f(&c)) {
            Ok(v) => return Ok(v),
            Err(r) => {
                first.get_or_insert(r);
            }
        }
    }
    Err(first.unwrap_or(Refusal("context_invalid")))
}

/// The claims both crate result types expose, gathered into one value.
struct Claims<'a> {
    iss: &'a str,
    jti: &'a [u8; 16],
    op: &'a str,
    opv: u16,
    iat: u64,
    ten: &'a str,
    sub: &'a str,
    params: &'a Params,
}

fn extract(g: &GrantInputs, c: Claims<'_>) -> Result<RefundGrant, Refusal> {
    let uint = |k: &str| match c.params.get(k) {
        Some(ParamValue::Uint(n)) => Some(*n),
        _ => None,
    };
    let text = |k: &str| match c.params.get(k) {
        Some(ParamValue::Text(t)) => Some(t.clone()),
        _ => None,
    };
    let (Some(order_id), Some(amount_minor), Some(currency), Some(charge_id)) = (
        uint("order_id"),
        uint("amount_minor"),
        text("currency"),
        text("charge_id"),
    ) else {
        return Err(Refusal("params_shape"));
    };
    // §16.2: `sub` ∈ support_principals[ten]; con3 an ID (the reserved " " fails).
    let customer_sub = if c.op == SUPPORT_OP {
        let s = g
            .support
            .as_ref()
            .ok_or(Refusal("support_not_configured"))?;
        if !s.is_principal(c.ten, c.sub) {
            return Err(Refusal("support_sub_not_principal"));
        }
        match text("customer_sub") {
            Some(cs) if crate::config::is_id(&cs, 64) => Some(cs),
            _ => return Err(Refusal("support_customer_sub")),
        }
    } else {
        None
    };
    let rg = RefundGrant {
        iss: c.iss.to_owned(),
        jti: *c.jti,
        op: c.op.to_owned(),
        opv: c.opv,
        iat: c.iat,
        ten: c.ten.to_owned(),
        sub: c.sub.to_owned(),
        order_id,
        amount_minor,
        currency,
        charge_id,
        customer_sub,
    };
    adapter_rules(&rg)?;
    Ok(rg)
}

fn decode(grant_text: &str) -> Result<Vec<u8>, Refusal> {
    nodkey_grant::decode_transport(Some(grant_text)).map_err(|e| Refusal(e.as_str()))
}

/// Verification for `refund.create` (initial dispatch and resend): grant-v1 §7.2 steps with the
/// age rule (`verify_retransmission`), then the adapter rules. The order check (§3.2) follows in
/// the caller.
pub fn verify_create(g: &GrantInputs, grant_text: &str, now: u64) -> Result<RefundGrant, Refusal> {
    let bytes = decode(grant_text)?;
    first_ok(g, |ctx| {
        let a =
            verify_retransmission(ctx, &bytes, now, g.r_max).map_err(|e| Refusal(e.as_str()))?;
        let (iss, jti) = a.idempotency_identity();
        extract(
            g,
            Claims {
                iss,
                jti,
                op: a.op(),
                opv: a.opv(),
                iat: a.iat(),
                ten: a.tenant(),
                sub: a.subject(),
                params: a.params(),
            },
        )
    })
}

/// Verification for lookups (`refund.find`, `refund.get`, `idem.status`): every check of the
/// create path except the age rule (`verify_binding`), then the same adapter rules (PA-19: the
/// charge pattern on every op). No order check: lookups cannot cause an effect.
pub fn verify_lookup(g: &GrantInputs, grant_text: &str, now: u64) -> Result<RefundGrant, Refusal> {
    let bytes = decode(grant_text)?;
    first_ok(g, |ctx| {
        let b = verify_binding(ctx, &bytes, now).map_err(|e| Refusal(e.as_str()))?;
        let (iss, jti) = b.idempotency_identity();
        extract(
            g,
            Claims {
                iss,
                jti,
                op: b.op(),
                opv: b.opv(),
                iat: b.iat(),
                ten: b.tenant(),
                sub: b.subject(),
                params: b.params(),
            },
        )
    })
}

/// §3.1 step 6: rules on the crate's output that the declaration format cannot express.
pub fn adapter_rules(g: &RefundGrant) -> Result<(), Refusal> {
    if (g.op != OP && g.op != SUPPORT_OP) || g.opv != OPV {
        return Err(Refusal("adapter_op"));
    }
    if g.amount_minor < 1 {
        return Err(Refusal("adapter_amount_zero")); // RX-3
    }
    if g.amount_minor > MAX_AMOUNT {
        return Err(Refusal("adapter_amount_range"));
    }
    if !is_charge_id(&g.charge_id) {
        return Err(Refusal("adapter_charge_pattern")); // PA-19, RX-6
    }
    if !iso4217_known(&g.currency) {
        return Err(Refusal("adapter_currency_unknown"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_patterns() {
        assert!(is_charge_id("ch_ABCDEFGH"));
        assert!(is_charge_id(&format!("ch_{}", "a".repeat(61))));
        for bad in [
            "unresolved",
            "ch_x",
            "ch_ABCDEFG",
            "ch_ABCDEFGH/",
            "ch_ABCD?FGH",
            "ch_ABCDEFGH&amount=1",
            "ch_ABCDEFG%2F",
            "CH_ABCDEFGH",
            "ch_ABCDEFGHé",
            "",
        ] {
            assert!(!is_charge_id(bad), "{bad}");
        }
        assert!(!is_charge_id(&format!("ch_{}", "a".repeat(62))));
        assert!(is_refund_id("re_12345678"));
        assert!(!is_refund_id("re_1234567"));
        assert!(!is_refund_id("re_../../x1"));
        assert!(!is_refund_id("ch_12345678"));
    }

    fn rg() -> RefundGrant {
        RefundGrant {
            iss: "i".into(),
            jti: [0; 16],
            op: OP.into(),
            opv: 1,
            iat: 0,
            ten: "acme".into(),
            sub: "u".into(),
            order_id: 1,
            amount_minor: 1,
            currency: "USD".into(),
            charge_id: "ch_ABCDEFGH".into(),
            customer_sub: None,
        }
    }

    #[test]
    fn adapter_rules_rx3_pa19_currency() {
        assert!(adapter_rules(&rg()).is_ok());
        let mut g = rg();
        g.amount_minor = 0;
        assert_eq!(adapter_rules(&g), Err(Refusal("adapter_amount_zero")));
        let mut g = rg();
        g.amount_minor = MAX_AMOUNT + 1;
        assert!(adapter_rules(&g).is_err());
        let mut g = rg();
        g.charge_id = "unresolved".into();
        assert_eq!(adapter_rules(&g), Err(Refusal("adapter_charge_pattern")));
        let mut g = rg();
        g.currency = "XYZ".into();
        assert_eq!(adapter_rules(&g), Err(Refusal("adapter_currency_unknown")));
    }

    #[test]
    fn compiled_declaration_is_refund_v1() {
        let ops = operations();
        let d = ops.get(OP).unwrap();
        assert_eq!((d.kind, d.opv, d.params.len()), (OpKind::Write, 1, 4));
        assert!(!d.mandate_eligible);
        let s = ops.get(SUPPORT_OP).unwrap();
        assert_eq!((s.kind, s.opv, s.params.len()), (OpKind::Write, 1, 5));
        assert!(s.mandate_eligible && s.requires_confirmation);
    }
}
