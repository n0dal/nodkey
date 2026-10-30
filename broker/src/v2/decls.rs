// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Operation declarations implemented by this broker (effect protocol v2 §5).
//!
//! The declarations are loaded from the operator's file in the grant-v1 §6.1 format (validated
//! by `nodkey_grant::Operations::load`). The broker refuses to start unless every declared
//! operation is one it knows and its declaration equals the one below exactly, so the grant
//! checks and the broker's executors can never disagree about parameters or classes.

use nodkey_grant::{Binding, OpKind, OperationDecl, Operations, ParamDecl, ParamType};
use serde_json::Value;

pub const LEDGER_TRANSFER: &str = "ledger.transfer";
pub const LEDGER_GET_BALANCE: &str = "ledger.get_balance";
pub const PAYMENTS_REFUND: &str = "payments.refund";
pub const PAYMENTS_GET_ORDER: &str = "payments.get_order";
/// agent-interface-v1 §3 (Demo A).
pub const SUPPORT_REFUND: &str = "payments.support_refund";
pub const SUPPORT_GET_ORDER: &str = "payments.support_get_order";
pub const MESSAGES_SEND: &str = "messages.send";
pub const MANDATE_TEMPLATE: &str = "mandate.support_ticket";
/// Resolved parameter names of the agent operations (AI §3, §4.1).
pub const CUSTOMER_SUB: &str = "customer_sub";
pub const CUSTOMER_EMAIL: &str = "customer_email";
pub const TO: &str = "to";
/// Reserved value of an unresolved agent-operation parameter (AI §3): one space. It fails the ID
/// grammar, so it matches no trusted row, and the authority refuses to sign it.
pub const UNRESOLVED_SPACE: &str = " ";

/// The parameter of `payments.refund` that the broker resolves from `nodkey.orders` at
/// propose (effect-protocol-v2 Draft 3.1 §2.3); never supplied by the workload.
pub const CHARGE_ID: &str = "charge_id";
/// Reserved value for an order with no trusted row; matches no charge (and is never signed).
pub const UNRESOLVED: &str = "unresolved";

/// How the broker serves a declared operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Executor {
    LedgerTransfer,
    LedgerGetBalance,
    /// `payments.refund` with the Draft 3.1 declaration (`charge_id` con2), payments-adapter-v1.
    PaymentsRefund,
    PaymentsGetOrder,
    /// `payments.support_refund` (AI §3, payments-adapter-v1 §16): ownership on con3.
    SupportRefund,
    /// `payments.support_get_order`: grantless read under a mandate (AI §4.6).
    SupportGetOrder,
    /// `messages.send`: internal effect, one `outbox` row (AI §3).
    MessageSend,
    /// `mandate.support_ticket`: internal effect, activates a mandate (AI §4.2 step 4).
    MandateTemplate,
    /// The legacy Phase 3 `payments.refund` declaration (no `charge_id`): loadable, so existing
    /// operation files still start, but always denied (`operation_not_permitted`, audit detail
    /// `not_implemented_legacy_declaration`).
    NotImplemented,
}

/// The executor for `op` under the loaded declarations.
pub fn executor_of(ops: &Operations, op: &str) -> Option<Executor> {
    let d = ops.get(op)?;
    match op {
        LEDGER_TRANSFER => Some(Executor::LedgerTransfer),
        LEDGER_GET_BALANCE => Some(Executor::LedgerGetBalance),
        PAYMENTS_GET_ORDER => Some(Executor::PaymentsGetOrder),
        PAYMENTS_REFUND if Some(d) == refund_v31().as_ref() => Some(Executor::PaymentsRefund),
        PAYMENTS_REFUND => Some(Executor::NotImplemented),
        SUPPORT_REFUND => Some(Executor::SupportRefund),
        SUPPORT_GET_ORDER => Some(Executor::SupportGetOrder),
        MESSAGES_SEND => Some(Executor::MessageSend),
        MANDATE_TEMPLATE => Some(Executor::MandateTemplate),
        _ => None,
    }
}

/// Parameters the broker sets itself (absent from the workload's `params`).
pub fn resolved_by_broker(op: &str) -> &'static [&'static str] {
    match op {
        PAYMENTS_REFUND => &[CHARGE_ID],
        SUPPORT_REFUND => &[CHARGE_ID, CUSTOMER_SUB],
        MESSAGES_SEND => &[TO],
        MANDATE_TEMPLATE => &[CUSTOMER_EMAIL],
        _ => &[],
    }
}

/// True for the agent operations that only `enrolled` workloads whose principal is a support
/// principal may use (AI §3 loader refusals).
pub fn is_support_op(op: &str) -> bool {
    matches!(
        op,
        SUPPORT_REFUND | SUPPORT_GET_ORDER | MESSAGES_SEND | MANDATE_TEMPLATE
    )
}

fn refund_v31() -> Option<OperationDecl> {
    use Binding::*;
    use ParamType::*;
    Some(OperationDecl {
        name: PAYMENTS_REFUND.into(),
        kind: OpKind::Write,
        opv: 1,
        requires_confirmation: true,
        mandate_eligible: false,
        params: vec![
            p("order_id", Resource(0), Uint, false),
            p("amount_minor", Exact(0), Uint, false),
            p("currency", Exact(1), Currency, false),
            p(CHARGE_ID, Exact(2), Text64, false),
        ],
    })
}

fn p(name: &str, binding: Binding, ty: ParamType, destination: bool) -> ParamDecl {
    ParamDecl {
        name: name.into(),
        binding,
        ty,
        destination,
        justification: None,
    }
}

/// The exact declarations of spec §5 (`opv: 1`, every write `requires_confirmation`). For
/// `payments.refund` this is the legacy Phase 3 form; [`expected_all`] adds Draft 3.1.
pub fn expected(op: &str) -> Option<OperationDecl> {
    use Binding::*;
    use ParamType::*;
    let (kind, rc, params) = match op {
        LEDGER_TRANSFER => (
            OpKind::Write,
            true,
            vec![
                p("from", Resource(0), AccountId, false),
                p("to", Exact(0), AccountId, true),
                p("amount_minor", Exact(1), Uint, false),
            ],
        ),
        PAYMENTS_REFUND => (
            OpKind::Write,
            true,
            vec![
                p("order_id", Resource(0), Uint, false),
                p("amount_minor", Exact(0), Uint, false),
                p("currency", Exact(1), Currency, false),
            ],
        ),
        LEDGER_GET_BALANCE => (
            OpKind::Read,
            false,
            vec![p("account", OwnerScoped, AccountId, false)],
        ),
        PAYMENTS_GET_ORDER | SUPPORT_GET_ORDER => (
            OpKind::Read,
            false,
            vec![p("order_id", OwnerScoped, Uint, false)],
        ),
        SUPPORT_REFUND => (
            OpKind::Write,
            true,
            vec![
                p("order_id", Resource(0), Uint, false),
                p("amount_minor", Exact(0), Uint, false),
                p("currency", Exact(1), Currency, false),
                p(CHARGE_ID, Exact(2), Text64, false),
                p(CUSTOMER_SUB, Exact(3), Text64, false),
            ],
        ),
        MESSAGES_SEND => (
            OpKind::Write,
            true,
            vec![
                p(CUSTOMER_SUB, Resource(0), Text64, false),
                p(TO, Exact(0), Text256, true),
                p("body", Free, Text256, false),
            ],
        ),
        MANDATE_TEMPLATE => (
            OpKind::Write,
            true,
            vec![
                p(CUSTOMER_SUB, Resource(0), Text64, false),
                p("currency", Exact(0), Currency, false),
                p("refund_max_count", Exact(1), Uint, false),
                p("refund_max_per_call_minor", Exact(2), Uint, false),
                p("refund_max_total_minor", Exact(3), Uint, false),
                p("message_max_count", Exact(4), Uint, false),
                p("valid_for_s", Exact(5), Uint, false),
                p(CUSTOMER_EMAIL, Exact(6), Text256, false),
            ],
        ),
        _ => return None,
    };
    Some(OperationDecl {
        name: op.into(),
        kind,
        opv: 1,
        requires_confirmation: rc,
        // AI §3: the two agent writes are mandate-eligible; the template never is (AI-08).
        mandate_eligible: matches!(op, SUPPORT_REFUND | MESSAGES_SEND),
        params,
    })
}

/// Loads and checks the operations file. Returns the validated declarations and the declared
/// operation names (in file order).
pub fn load(json: &str) -> Result<(Operations, Vec<String>), String> {
    let ops = Operations::load(json).map_err(|e| format!("ops_declaration_invalid: {e}"))?;
    let doc: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let mut names = Vec::new();
    for o in doc["operations"].as_array().ok_or("operations")? {
        let name = o["op"].as_str().ok_or("op")?.to_owned();
        let want = expected_all(&name);
        if want.is_empty() {
            return Err(format!(
                "operation {name} is not implemented by this broker"
            ));
        }
        if !want
            .iter()
            .any(|w| ops.get(&name).is_some_and(|d| same_decl(d, w)))
        {
            return Err(format!(
                "operation {name} differs from the declaration this broker implements"
            ));
        }
        names.push(name);
    }
    if names.is_empty() {
        return Err("no operations declared".into());
    }
    Ok((ops, names))
}

/// Declaration equality, except that a `free` parameter's justification text is the operator's
/// (the grant crate requires it to be present and non-empty).
fn same_decl(loaded: &OperationDecl, want: &OperationDecl) -> bool {
    let mut l = loaded.clone();
    for p in &mut l.params {
        if p.binding == Binding::Free {
            p.justification = None;
        }
    }
    &l == want
}

/// Every declaration accepted for `op`.
pub fn expected_all(op: &str) -> Vec<OperationDecl> {
    let mut v: Vec<OperationDecl> = expected(op).into_iter().collect();
    if op == PAYMENTS_REFUND {
        v.extend(refund_v31());
    }
    v
}

/// True if the operation has a `destination: true` parameter (spec §2.4: never for `named`).
pub fn has_destination(d: &OperationDecl) -> bool {
    d.params.iter().any(|p| p.destination)
}

/// Decimal exponents from ISO 4217 for the currencies this prototype may display (key 11).
/// Unknown codes are refused at start-up.
pub fn iso4217_exponent(code: &str) -> Option<u64> {
    Some(match code {
        "EUR" | "USD" | "GBP" | "CHF" | "SEK" | "NOK" | "DKK" | "CAD" | "AUD" => 2,
        "JPY" | "KRW" | "ISK" => 0,
        "BHD" | "KWD" | "JOD" | "OMR" | "TND" => 3,
        _ => return None,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const OPS_JSON: &str = r#"{"format":"nodkey.operations.v1","operations":[
 {"op":"ledger.transfer","kind":"write","opv":1,"requires_confirmation":true,"params":[
  {"name":"from","in":"res","key":0,"class":"exact","type":"account_id","destination":false},
  {"name":"to","in":"con","key":0,"class":"exact","type":"account_id","destination":true},
  {"name":"amount_minor","in":"con","key":1,"class":"exact","type":"uint","destination":false}]},
 {"op":"payments.refund","kind":"write","opv":1,"requires_confirmation":true,"params":[
  {"name":"order_id","in":"res","key":0,"class":"exact","type":"uint","destination":false},
  {"name":"amount_minor","in":"con","key":0,"class":"exact","type":"uint","destination":false},
  {"name":"currency","in":"con","key":1,"class":"exact","type":"currency","destination":false}]},
 {"op":"ledger.get_balance","kind":"read","opv":1,"requires_confirmation":false,"params":[
  {"name":"account","in":"request","key":null,"class":"owner_scoped","type":"account_id","destination":false}]},
 {"op":"payments.get_order","kind":"read","opv":1,"requires_confirmation":false,"params":[
  {"name":"order_id","in":"request","key":null,"class":"owner_scoped","type":"uint","destination":false}]}]}"#;

    #[test]
    fn loads_spec_declarations() {
        let (ops, names) = load(OPS_JSON).unwrap();
        assert_eq!(names.len(), 4);
        assert!(ops.get(LEDGER_TRANSFER).unwrap().requires_confirmation);
        assert!(has_destination(ops.get(LEDGER_TRANSFER).unwrap()));
        assert!(!has_destination(ops.get(PAYMENTS_REFUND).unwrap()));
    }

    #[test]
    fn refuses_divergent_declarations() {
        for (from, to) in [
            (
                r#""requires_confirmation":true"#,
                r#""requires_confirmation":false"#,
            ),
            (r#""destination":true"#, r#""destination":false"#),
            (
                r#""name":"amount_minor","in":"con","key":1,"class":"exact""#,
                r#""name":"amount_minor","in":"con","key":1,"class":"bounded""#,
            ),
            (
                r#""op":"ledger.transfer","kind":"write","opv":1"#,
                r#""op":"ledger.transfer","kind":"write","opv":2"#,
            ),
            (
                r#""op":"payments.get_order""#,
                r#""op":"payments.list_orders""#,
            ),
            (r#""type":"currency""#, r#""type":"text64""#),
        ] {
            let bad = OPS_JSON.replacen(from, to, 1);
            assert_ne!(bad, OPS_JSON);
            assert!(load(&bad).is_err(), "{to}");
        }
        assert!(load(r#"{"format":"nodkey.operations.v1","operations":[]}"#).is_err());
    }

    /// The agent operations of agent-interface-v1 §3 (Demo A), appended to the Draft 3.1 set.
    pub fn ops_agent() -> String {
        ops_v31().replace(
            r#"{"op":"ledger.get_balance","#,
            r#"{"op":"payments.support_refund","kind":"write","opv":1,"requires_confirmation":true,"mandate_eligible":true,"params":[
  {"name":"order_id","in":"res","key":0,"class":"exact","type":"uint","destination":false},
  {"name":"amount_minor","in":"con","key":0,"class":"exact","type":"uint","destination":false},
  {"name":"currency","in":"con","key":1,"class":"exact","type":"currency","destination":false},
  {"name":"charge_id","in":"con","key":2,"class":"exact","type":"text64","destination":false},
  {"name":"customer_sub","in":"con","key":3,"class":"exact","type":"text64","destination":false}]},
 {"op":"payments.support_get_order","kind":"read","opv":1,"requires_confirmation":false,"params":[
  {"name":"order_id","in":"request","key":null,"class":"owner_scoped","type":"uint","destination":false}]},
 {"op":"messages.send","kind":"write","opv":1,"requires_confirmation":true,"mandate_eligible":true,"params":[
  {"name":"customer_sub","in":"res","key":0,"class":"exact","type":"text64","destination":false},
  {"name":"to","in":"con","key":0,"class":"exact","type":"text256","destination":true},
  {"name":"body","in":"con","key":null,"class":"free","type":"text256","destination":false,"justification":"message content (R-A2)"}]},
 {"op":"mandate.support_ticket","kind":"write","opv":1,"requires_confirmation":true,"params":[
  {"name":"customer_sub","in":"res","key":0,"class":"exact","type":"text64","destination":false},
  {"name":"currency","in":"con","key":0,"class":"exact","type":"currency","destination":false},
  {"name":"refund_max_count","in":"con","key":1,"class":"exact","type":"uint","destination":false},
  {"name":"refund_max_per_call_minor","in":"con","key":2,"class":"exact","type":"uint","destination":false},
  {"name":"refund_max_total_minor","in":"con","key":3,"class":"exact","type":"uint","destination":false},
  {"name":"message_max_count","in":"con","key":4,"class":"exact","type":"uint","destination":false},
  {"name":"valid_for_s","in":"con","key":5,"class":"exact","type":"uint","destination":false},
  {"name":"customer_email","in":"con","key":6,"class":"exact","type":"text256","destination":false}]},
 {"op":"ledger.get_balance","#,
        )
    }

    /// AI §3: the agent declarations load; eligibility and resolution are as specified, and a
    /// template declared `mandate_eligible` (AI-08) or a covered op without it is refused.
    #[test]
    fn agent_declarations() {
        let text = ops_agent();
        let (ops, names) = load(&text).unwrap();
        assert_eq!(names.len(), 8);
        assert!(ops.get(SUPPORT_REFUND).unwrap().mandate_eligible);
        assert!(ops.get(MESSAGES_SEND).unwrap().mandate_eligible);
        assert!(!ops.get(MANDATE_TEMPLATE).unwrap().mandate_eligible);
        assert!(has_destination(ops.get(MESSAGES_SEND).unwrap()));
        assert_eq!(
            executor_of(&ops, SUPPORT_REFUND),
            Some(Executor::SupportRefund)
        );
        assert_eq!(
            executor_of(&ops, MANDATE_TEMPLATE),
            Some(Executor::MandateTemplate)
        );
        assert_eq!(
            resolved_by_broker(SUPPORT_REFUND),
            &[CHARGE_ID, CUSTOMER_SUB]
        );
        assert_eq!(resolved_by_broker(MESSAGES_SEND), &[TO]);
        assert_eq!(resolved_by_broker(MANDATE_TEMPLATE), &[CUSTOMER_EMAIL]);
        for (from, to) in [
            (
                r#""op":"mandate.support_ticket","kind":"write","opv":1,"requires_confirmation":true,"#,
                r#""op":"mandate.support_ticket","kind":"write","opv":1,"requires_confirmation":true,"mandate_eligible":true,"#,
            ),
            (
                r#""op":"messages.send","kind":"write","opv":1,"requires_confirmation":true,"mandate_eligible":true,"#,
                r#""op":"messages.send","kind":"write","opv":1,"requires_confirmation":true,"#,
            ),
            (
                r#""name":"to","in":"con","key":0,"class":"exact","type":"text256","destination":true"#,
                r#""name":"to","in":"con","key":0,"class":"exact","type":"text256","destination":false"#,
            ),
            (
                r#""name":"customer_sub","in":"con","key":3"#,
                r#""name":"customer_sub","in":"con","key":4"#,
            ),
        ] {
            let bad = text.replacen(from, to, 1);
            assert_ne!(bad, text, "{from}");
            assert!(load(&bad).is_err(), "{to}");
        }
    }

    /// Draft 3.1 `payments.refund` (broker-resolved `charge_id` con2).
    pub fn ops_v31() -> String {
        OPS_JSON.replace(
            r#"{"name":"currency","in":"con","key":1,"class":"exact","type":"currency","destination":false}]}"#,
            r#"{"name":"currency","in":"con","key":1,"class":"exact","type":"currency","destination":false},
  {"name":"charge_id","in":"con","key":2,"class":"exact","type":"text64","destination":false}]}"#,
        )
    }

    #[test]
    fn executors() {
        let (legacy, _) = load(OPS_JSON).unwrap();
        assert_eq!(
            executor_of(&legacy, PAYMENTS_REFUND),
            Some(Executor::NotImplemented)
        );
        assert_eq!(
            executor_of(&legacy, PAYMENTS_GET_ORDER),
            Some(Executor::PaymentsGetOrder)
        );
        assert_eq!(executor_of(&legacy, "sql.query"), None);
        let v31 = ops_v31();
        assert_ne!(v31, OPS_JSON);
        let (ops, _) = load(&v31).unwrap();
        assert_eq!(
            executor_of(&ops, PAYMENTS_REFUND),
            Some(Executor::PaymentsRefund)
        );
        assert_eq!(resolved_by_broker(PAYMENTS_REFUND), &[CHARGE_ID]);
        assert!(resolved_by_broker(LEDGER_TRANSFER).is_empty());
        // charge_id with another class or type is refused.
        for (from, to) in [
            (
                r#""key":2,"class":"exact","type":"text64""#,
                r#""key":2,"class":"exact","type":"text256""#,
            ),
            (
                r#""name":"charge_id","in":"con","key":2"#,
                r#""name":"charge_id","in":"con","key":3"#,
            ),
        ] {
            assert!(load(&v31.replacen(from, to, 1)).is_err(), "{to}");
        }
        assert_eq!(iso4217_exponent("JPY"), Some(0));
        assert_eq!(iso4217_exponent("XXX"), None);
    }
}
