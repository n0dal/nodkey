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
        _ => None,
    }
}

/// Parameters the broker sets itself (absent from the workload's `params`).
pub fn resolved_by_broker(op: &str) -> &'static [&'static str] {
    if op == PAYMENTS_REFUND {
        &[CHARGE_ID]
    } else {
        &[]
    }
}

fn refund_v31() -> Option<OperationDecl> {
    use Binding::*;
    use ParamType::*;
    Some(OperationDecl {
        name: PAYMENTS_REFUND.into(),
        kind: OpKind::Write,
        opv: 1,
        requires_confirmation: true,
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
        PAYMENTS_GET_ORDER => (
            OpKind::Read,
            false,
            vec![p("order_id", OwnerScoped, Uint, false)],
        ),
        _ => return None,
    };
    Some(OperationDecl {
        name: op.into(),
        kind,
        opv: 1,
        requires_confirmation: rc,
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
        if !want.iter().any(|w| ops.get(&name) == Some(w)) {
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
