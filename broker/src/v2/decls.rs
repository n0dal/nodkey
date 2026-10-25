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

/// How the broker serves a declared operation in Phase 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Executor {
    LedgerTransfer,
    LedgerGetBalance,
    /// Declared per spec §5 but not implemented in Phase 3: always denied
    /// (`operation_not_permitted`, audit detail `not_implemented_phase3`).
    NotImplemented,
}

pub fn executor(op: &str) -> Option<Executor> {
    match op {
        LEDGER_TRANSFER => Some(Executor::LedgerTransfer),
        LEDGER_GET_BALANCE => Some(Executor::LedgerGetBalance),
        PAYMENTS_REFUND | PAYMENTS_GET_ORDER => Some(Executor::NotImplemented),
        _ => None,
    }
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

/// The exact declarations of spec §5 (`opv: 1`, every write `requires_confirmation`).
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
        let want = expected(&name)
            .ok_or_else(|| format!("operation {name} is not implemented by this broker"))?;
        if ops.get(&name) != Some(&want) {
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

    #[test]
    fn executors() {
        assert_eq!(executor(PAYMENTS_REFUND), Some(Executor::NotImplemented));
        assert_eq!(executor(PAYMENTS_GET_ORDER), Some(Executor::NotImplemented));
        assert_eq!(executor("sql.query"), None);
        assert_eq!(iso4217_exponent("JPY"), Some(0));
        assert_eq!(iso4217_exponent("XXX"), None);
    }
}
