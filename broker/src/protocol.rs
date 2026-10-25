//! Wire protocol v1: one JSON object per line.
//!
//! Request:
//! ```json
//! {"v":1,"id":"<client request id>","op":"ledger.transfer","args":{"from":"alice","to":"bob","amount_cents":100,"idempotency_key":"<16..64 of [A-Za-z0-9_-]>"}}
//! ```
//! `ledger.transfer` requires an `idempotency_key` (SI-09, SI-15): a retry with the same key and the
//! same arguments returns the original result (`"replayed": true`) without a second effect; the same
//! key with different arguments is denied with `idempotency_conflict`.
//! Parsing is strict: duplicate keys, unknown fields, wrong types, and missing fields are all
//! rejected. Operations form a closed enum; any other `op` value is an `unknown_operation` deny.
//!
//! Forward compatibility: a later protocol version will add an optional `grant` member to the
//! request envelope ([`RawRequest`]). Version 1 rejects it as an unknown field, so a v1 broker
//! can never silently ignore a grant that a newer client believes is being enforced.

use crate::strict_json;
use serde::Deserialize;
use serde_json::{Map, Value};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_ACCOUNT_ID_LEN: usize = 32;
pub const MAX_REQUEST_ID_LEN: usize = 64;
pub const MIN_IDEMPOTENCY_KEY_LEN: usize = 16;
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 64;

/// Client-facing error codes. The set is closed and the messages are static, so no internal
/// detail (SQL errors, file paths, parser positions) is ever sent to the workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    MalformedRequest,
    UnsupportedVersion,
    RequestTooLarge,
    UnknownOperation,
    OperationNotPermitted,
    InvalidArgument,
    LimitExceeded,
    UnknownAccount,
    InsufficientFunds,
    Unauthenticated,
    /// Nothing was executed: the failure happened before any write reached the database.
    Unavailable,
    /// The idempotency key was already used with different arguments.
    IdempotencyConflict,
    /// The effect may or may not have committed (e.g. connection lost during COMMIT).
    /// Clients must not blindly retry.
    OutcomeUnknown,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::MalformedRequest => "malformed_request",
            ErrorCode::UnsupportedVersion => "unsupported_version",
            ErrorCode::RequestTooLarge => "request_too_large",
            ErrorCode::UnknownOperation => "unknown_operation",
            ErrorCode::OperationNotPermitted => "operation_not_permitted",
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::LimitExceeded => "limit_exceeded",
            ErrorCode::UnknownAccount => "unknown_account",
            ErrorCode::InsufficientFunds => "insufficient_funds",
            ErrorCode::Unauthenticated => "unauthenticated",
            ErrorCode::Unavailable => "unavailable",
            ErrorCode::IdempotencyConflict => "idempotency_conflict",
            ErrorCode::OutcomeUnknown => "outcome_unknown",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            ErrorCode::MalformedRequest => "request is not a valid v1 request",
            ErrorCode::UnsupportedVersion => "protocol version not supported",
            ErrorCode::RequestTooLarge => "request exceeds maximum size",
            ErrorCode::UnknownOperation => "operation is not declared",
            ErrorCode::OperationNotPermitted => "operation not permitted for this workload",
            ErrorCode::InvalidArgument => "invalid argument",
            ErrorCode::LimitExceeded => "amount exceeds configured limit",
            ErrorCode::UnknownAccount => "unknown account",
            ErrorCode::InsufficientFunds => "insufficient funds",
            ErrorCode::Unauthenticated => "peer not authorized for this socket",
            ErrorCode::Unavailable => "service unavailable; nothing was executed",
            ErrorCode::IdempotencyConflict => {
                "idempotency key already used with different arguments"
            }
            ErrorCode::OutcomeUnknown => {
                "outcome unknown; retry only with the same idempotency key"
            }
        }
    }
}

/// A rejected request. `detail` is for the server-side log only and is never sent to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deny {
    pub code: ErrorCode,
    pub detail: String,
}

impl Deny {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        let mut detail: String = detail.into();
        if detail.len() > 200 {
            let mut cut = 200;
            while !detail.is_char_boundary(cut) {
                cut -= 1;
            }
            detail.truncate(cut);
        }
        Deny { code, detail }
    }
}

/// Validated account identifier: 1..=32 chars of `[a-z0-9_]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountId(String);

impl AccountId {
    pub fn parse(s: &str) -> Result<Self, Deny> {
        let ok = !s.is_empty()
            && s.len() <= MAX_ACCOUNT_ID_LEN
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if ok {
            Ok(AccountId(s.to_owned()))
        } else {
            Err(Deny::new(ErrorCode::InvalidArgument, "account id format"))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Client-chosen request id, echoed back: 1..=64 chars of `[A-Za-z0-9._-]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    pub fn parse(s: &str) -> Option<Self> {
        let ok = !s.is_empty()
            && s.len() <= MAX_REQUEST_ID_LEN
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        ok.then(|| RequestId(s.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Client-chosen idempotency key for effectful operations: 16..=64 chars of `[A-Za-z0-9_-]`.
/// The lower bound makes accidental collisions between unrelated requests of one workload
/// unlikely; keys are scoped per workload, so one workload cannot collide with another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn parse(s: &str) -> Result<Self, Deny> {
        let ok = (MIN_IDEMPOTENCY_KEY_LEN..=MAX_IDEMPOTENCY_KEY_LEN).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if ok {
            Ok(IdempotencyKey(s.to_owned()))
        } else {
            Err(Deny::new(
                ErrorCode::InvalidArgument,
                "idempotency key format",
            ))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The closed set of operation kinds the broker knows. Adding an operation means adding a
/// variant here, its typed arguments, validation, and an executor; nothing is dispatched by name
/// at runtime beyond this table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpKind {
    GetBalance,
    Transfer,
}

impl OpKind {
    pub const ALL: [OpKind; 2] = [OpKind::GetBalance, OpKind::Transfer];

    pub fn wire_name(self) -> &'static str {
        match self {
            OpKind::GetBalance => "ledger.get_balance",
            OpKind::Transfer => "ledger.transfer",
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        OpKind::ALL.into_iter().find(|k| k.wire_name() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBalance {
    pub account: AccountId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub from: AccountId,
    pub to: AccountId,
    /// Always > 0 after validation.
    pub amount_cents: i64,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    GetBalance(GetBalance),
    Transfer(Transfer),
}

impl Operation {
    pub fn kind(&self) -> OpKind {
        match self {
            Operation::GetBalance(_) => OpKind::GetBalance,
            Operation::Transfer(_) => OpKind::Transfer,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: RequestId,
    pub op: Operation,
}

/// Envelope as it appears on the wire. `deny_unknown_fields` makes any extra member (including
/// a future `grant`) a parse error under v1.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest {
    v: u32,
    id: String,
    op: String,
    args: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetBalanceArgs {
    account: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferArgs {
    from: String,
    to: String,
    amount_cents: i64,
    idempotency_key: String,
}

/// Result of parsing: on failure, the request id is returned when it could be recovered so the
/// response can still be correlated by the client. `op_name` is for logging only.
#[derive(Debug)]
pub struct ParseFailure {
    pub id: Option<RequestId>,
    pub op_name: Option<String>,
    pub deny: Deny,
}

fn fail(
    id: Option<RequestId>,
    op_name: Option<String>,
    code: ErrorCode,
    detail: impl Into<String>,
) -> ParseFailure {
    ParseFailure {
        id,
        op_name,
        deny: Deny::new(code, detail),
    }
}

/// Parse and statically validate one request line (without the trailing newline).
/// Static validation covers everything that does not depend on configuration or state.
pub fn parse_request(line: &[u8]) -> Result<Request, ParseFailure> {
    strict_json::check_strict(line)
        .map_err(|e| fail(None, None, ErrorCode::MalformedRequest, e))?;

    let raw: RawRequest = serde_json::from_slice(line)
        .map_err(|e| fail(None, None, ErrorCode::MalformedRequest, e.to_string()))?;

    let id = RequestId::parse(&raw.id)
        .ok_or_else(|| fail(None, None, ErrorCode::MalformedRequest, "request id format"))?;

    let op_name: String = raw.op.chars().take(64).collect();

    if raw.v != PROTOCOL_VERSION {
        return Err(fail(
            Some(id),
            Some(op_name),
            ErrorCode::UnsupportedVersion,
            format!("v={}", raw.v),
        ));
    }

    let Some(kind) = OpKind::from_wire(&raw.op) else {
        return Err(fail(
            Some(id),
            Some(op_name),
            ErrorCode::UnknownOperation,
            "undeclared op",
        ));
    };

    let args = Value::Object(raw.args);
    let op = match kind {
        OpKind::GetBalance => {
            let a: GetBalanceArgs = serde_json::from_value(args).map_err(|e| {
                fail(
                    Some(id.clone()),
                    Some(op_name.clone()),
                    ErrorCode::MalformedRequest,
                    e.to_string(),
                )
            })?;
            let account = AccountId::parse(&a.account).map_err(|d| ParseFailure {
                id: Some(id.clone()),
                op_name: Some(op_name.clone()),
                deny: d,
            })?;
            Operation::GetBalance(GetBalance { account })
        }
        OpKind::Transfer => {
            let a: TransferArgs = serde_json::from_value(args).map_err(|e| {
                fail(
                    Some(id.clone()),
                    Some(op_name.clone()),
                    ErrorCode::MalformedRequest,
                    e.to_string(),
                )
            })?;
            let wrap = |d: Deny| ParseFailure {
                id: Some(id.clone()),
                op_name: Some(op_name.clone()),
                deny: d,
            };
            let from = AccountId::parse(&a.from).map_err(wrap)?;
            let to = AccountId::parse(&a.to).map_err(wrap)?;
            if from == to {
                return Err(wrap(Deny::new(ErrorCode::InvalidArgument, "from == to")));
            }
            if a.amount_cents <= 0 {
                return Err(wrap(Deny::new(
                    ErrorCode::InvalidArgument,
                    "amount must be positive",
                )));
            }
            let idempotency_key = IdempotencyKey::parse(&a.idempotency_key).map_err(wrap)?;
            Operation::Transfer(Transfer {
                from,
                to,
                amount_cents: a.amount_cents,
                idempotency_key,
            })
        }
    };

    Ok(Request { id, op })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(line: &str) -> ErrorCode {
        parse_request(line.as_bytes()).unwrap_err().deny.code
    }

    #[test]
    fn parses_get_balance() {
        let r = parse_request(
            br#"{"v":1,"id":"r1","op":"ledger.get_balance","args":{"account":"alice"}}"#,
        )
        .unwrap();
        assert_eq!(r.id.as_str(), "r1");
        assert_eq!(
            r.op,
            Operation::GetBalance(GetBalance {
                account: AccountId("alice".into())
            })
        );
    }

    #[test]
    fn parses_transfer_any_member_order() {
        let r = parse_request(
            br#"{"args":{"amount_cents":250,"idempotency_key":"kAbc_0123-456789","to":"bob","from":"alice"},"op":"ledger.transfer","id":"a-b.c_1","v":1}"#,
        )
        .unwrap();
        match r.op {
            Operation::Transfer(t) => {
                assert_eq!(t.from.as_str(), "alice");
                assert_eq!(t.to.as_str(), "bob");
                assert_eq!(t.amount_cents, 250);
                assert_eq!(t.idempotency_key.as_str(), "kAbc_0123-456789");
            }
            _ => panic!("wrong op"),
        }
    }

    #[test]
    fn unknown_operation_is_denied_with_id_echoed() {
        let f = parse_request(br#"{"v":1,"id":"x","op":"ledger.delete_account","args":{}}"#)
            .unwrap_err();
        assert_eq!(f.deny.code, ErrorCode::UnknownOperation);
        assert_eq!(f.id.unwrap().as_str(), "x");
        assert_eq!(
            code(r#"{"v":1,"id":"x","op":"sql.query","args":{"sql":"DROP TABLE accounts"}}"#),
            ErrorCode::UnknownOperation
        );
        // Case and whitespace variants are not aliases.
        assert_eq!(
            code(r#"{"v":1,"id":"x","op":"Ledger.Transfer","args":{}}"#),
            ErrorCode::UnknownOperation
        );
        assert_eq!(
            code(r#"{"v":1,"id":"x","op":"ledger.transfer ","args":{}}"#),
            ErrorCode::UnknownOperation
        );
        assert_eq!(
            code(r#"{"v":1,"id":"x","op":"","args":{}}"#),
            ErrorCode::UnknownOperation
        );
    }

    #[test]
    fn duplicate_keys_rejected_everywhere() {
        // The classic smuggling case: a validator that keeps the first value and an executor
        // that keeps the last would disagree on the amount.
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.transfer","args":{"from":"alice","to":"bob","amount_cents":1,"amount_cents":999999,"idempotency_key":"kAbc_0123-456789"}}"#
            ),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.get_balance","op":"ledger.transfer","args":{"account":"alice"}}"#
            ),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.get_balance","args":{"account":"alice","account":"bob"}}"#
            ),
            ErrorCode::MalformedRequest
        );
    }

    #[test]
    fn unknown_fields_rejected() {
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.get_balance","args":{"account":"alice"},"grant":"x"}"#
            ),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.get_balance","args":{"account":"alice"},"admin":true}"#
            ),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.get_balance","args":{"account":"alice","sql":"x"}}"#
            ),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.transfer","args":{"from":"alice","to":"bob","amount_cents":1,"idempotency_key":"kAbc_0123-456789","memo":"hi"}}"#
            ),
            ErrorCode::MalformedRequest
        );
    }

    #[test]
    fn missing_fields_rejected() {
        assert_eq!(
            code(r#"{"id":"x","op":"ledger.get_balance","args":{"account":"alice"}}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1,"op":"ledger.get_balance","args":{"account":"alice"}}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1,"id":"x","args":{"account":"alice"}}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1,"id":"x","op":"ledger.get_balance"}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1,"id":"x","op":"ledger.get_balance","args":{}}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1,"id":"x","op":"ledger.transfer","args":{"from":"alice","to":"bob"}}"#),
            ErrorCode::MalformedRequest
        );
    }

    #[test]
    fn wrong_types_rejected() {
        let t = |amount: &str| {
            code(&format!(
                r#"{{"v":1,"id":"x","op":"ledger.transfer","args":{{"from":"alice","to":"bob","amount_cents":{amount},"idempotency_key":"kAbc_0123-456789"}}}}"#
            ))
        };
        assert_eq!(t(r#""100""#), ErrorCode::MalformedRequest);
        assert_eq!(t("1.5"), ErrorCode::MalformedRequest);
        assert_eq!(t("1e2"), ErrorCode::MalformedRequest);
        assert_eq!(t("true"), ErrorCode::MalformedRequest);
        assert_eq!(t("null"), ErrorCode::MalformedRequest);
        assert_eq!(t("[1]"), ErrorCode::MalformedRequest);
        assert_eq!(t("9223372036854775808"), ErrorCode::MalformedRequest); // i64::MAX + 1
        assert_eq!(t("99999999999999999999999"), ErrorCode::MalformedRequest);
        assert_eq!(
            code(r#"{"v":"1","id":"x","op":"ledger.get_balance","args":{"account":"alice"}}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1.0,"id":"x","op":"ledger.get_balance","args":{"account":"alice"}}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1,"id":7,"op":"ledger.get_balance","args":{"account":"alice"}}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1,"id":"x","op":["ledger.get_balance"],"args":{"account":"alice"}}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1,"id":"x","op":"ledger.get_balance","args":[]}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1,"id":"x","op":"ledger.get_balance","args":{"account":1}}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(code(r#"["v",1]"#), ErrorCode::MalformedRequest);
        assert_eq!(code(r#""just a string""#), ErrorCode::MalformedRequest);
    }

    #[test]
    fn malformed_json_rejected() {
        assert_eq!(code("not json"), ErrorCode::MalformedRequest);
        assert_eq!(code(r#"{"v":1,"id":"x""#), ErrorCode::MalformedRequest);
        assert_eq!(code(""), ErrorCode::MalformedRequest);
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.get_balance","args":{"account":"alice"}} trailing"#
            ),
            ErrorCode::MalformedRequest
        );
    }

    #[test]
    fn version_checked() {
        let f = parse_request(
            br#"{"v":2,"id":"x","op":"ledger.get_balance","args":{"account":"alice"}}"#,
        )
        .unwrap_err();
        assert_eq!(f.deny.code, ErrorCode::UnsupportedVersion);
        assert_eq!(
            code(r#"{"v":0,"id":"x","op":"ledger.get_balance","args":{"account":"alice"}}"#),
            ErrorCode::UnsupportedVersion
        );
        assert_eq!(
            code(r#"{"v":-1,"id":"x","op":"ledger.get_balance","args":{"account":"alice"}}"#),
            ErrorCode::MalformedRequest
        );
    }

    #[test]
    fn request_id_validated() {
        assert_eq!(
            code(r#"{"v":1,"id":"","op":"ledger.get_balance","args":{"account":"alice"}}"#),
            ErrorCode::MalformedRequest
        );
        assert_eq!(
            code(r#"{"v":1,"id":"a b","op":"ledger.get_balance","args":{"account":"alice"}}"#),
            ErrorCode::MalformedRequest
        );
        let long = "a".repeat(65);
        assert_eq!(
            code(&format!(
                r#"{{"v":1,"id":"{long}","op":"ledger.get_balance","args":{{"account":"alice"}}}}"#
            )),
            ErrorCode::MalformedRequest
        );
        let ok = "a".repeat(64);
        assert!(parse_request(format!(r#"{{"v":1,"id":"{ok}","op":"ledger.get_balance","args":{{"account":"alice"}}}}"#).as_bytes()).is_ok());
    }

    #[test]
    fn account_ids_validated() {
        for bad in [
            "",
            "Alice",
            "al ice",
            "alice;--",
            "alice'",
            "../etc",
            "a\u{0}",
            "ålice",
            &"a".repeat(33),
        ] {
            let line = serde_json::json!({"v":1,"id":"x","op":"ledger.get_balance","args":{"account":bad}}).to_string();
            assert_eq!(code(&line), ErrorCode::InvalidArgument, "{bad:?}");
        }
        assert!(AccountId::parse(&"a".repeat(32)).is_ok());
        assert!(AccountId::parse("acct_01").is_ok());
    }

    #[test]
    fn transfer_semantics_validated() {
        let t = |from: &str, to: &str, amount: i64| {
            code(&serde_json::json!({"v":1,"id":"x","op":"ledger.transfer","args":{"from":from,"to":to,"amount_cents":amount,"idempotency_key":"kAbc_0123-456789"}}).to_string())
        };
        assert_eq!(t("alice", "bob", 0), ErrorCode::InvalidArgument);
        assert_eq!(t("alice", "bob", -1), ErrorCode::InvalidArgument);
        assert_eq!(t("alice", "bob", i64::MIN), ErrorCode::InvalidArgument);
        assert_eq!(t("alice", "alice", 5), ErrorCode::InvalidArgument);
        assert_eq!(t("alice", "BOB", 5), ErrorCode::InvalidArgument);
        assert!(parse_request(
            serde_json::json!({"v":1,"id":"x","op":"ledger.transfer","args":{"from":"alice","to":"bob","amount_cents":i64::MAX,"idempotency_key":"kAbc_0123-456789"}})
                .to_string()
                .as_bytes()
        )
        .is_ok());
    }

    fn transfer_with_key(key: &serde_json::Value) -> String {
        serde_json::json!({"v":1,"id":"x","op":"ledger.transfer","args":{"from":"alice","to":"bob","amount_cents":5,"idempotency_key":key}}).to_string()
    }

    #[test]
    fn transfer_requires_idempotency_key() {
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.transfer","args":{"from":"alice","to":"bob","amount_cents":5}}"#
            ),
            ErrorCode::MalformedRequest
        );
        // Duplicate key member is a smuggling attempt like any other duplicate.
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.transfer","args":{"from":"alice","to":"bob","amount_cents":5,"idempotency_key":"aaaaaaaaaaaaaaaa","idempotency_key":"bbbbbbbbbbbbbbbb"}}"#
            ),
            ErrorCode::MalformedRequest
        );
        for wrong_type in [
            serde_json::json!(null),
            serde_json::json!(1234567890123456_i64),
            serde_json::json!(["aaaaaaaaaaaaaaaa"]),
            serde_json::json!({"k": "aaaaaaaaaaaaaaaa"}),
            serde_json::json!(true),
        ] {
            assert_eq!(
                code(&transfer_with_key(&wrong_type)),
                ErrorCode::MalformedRequest,
                "{wrong_type}"
            );
        }
    }

    #[test]
    fn idempotency_key_format_validated() {
        for bad in [
            String::new(),
            "a".repeat(15),
            "a".repeat(65),
            "aaaaaaaaaaaaaaa.".into(), // '.' allowed in request ids, not in keys
            "aaaaaaaaaaaaaaa ".into(),
            "aaaaaaaaaaaaaaa/".into(),
            "aaaaaaaaaaaaaaa+".into(),
            "aaaaaaaaaaaaaaa=".into(),
            "aaaaaaaaaaaaaa\u{e9}".into(), // 16 bytes, non-ASCII
            "aaaaaaaaaaaaaaa\n".into(),
            "aaaaaaaaaaaaaaa\u{0}".into(),
        ] {
            assert_eq!(
                code(&transfer_with_key(&serde_json::json!(bad))),
                ErrorCode::InvalidArgument,
                "{bad:?}"
            );
            assert!(IdempotencyKey::parse(&bad).is_err(), "{bad:?}");
        }
        for good in [
            "a".repeat(16),
            "Z".repeat(64),
            "0123456789abcdef".into(),
            "AZaz09_-AZaz09_-".into(),
        ] {
            let r = parse_request(transfer_with_key(&serde_json::json!(good)).as_bytes()).unwrap();
            match r.op {
                Operation::Transfer(t) => assert_eq!(t.idempotency_key.as_str(), good),
                _ => panic!("wrong op"),
            }
        }
    }

    #[test]
    fn get_balance_rejects_idempotency_key() {
        assert_eq!(
            code(
                r#"{"v":1,"id":"x","op":"ledger.get_balance","args":{"account":"alice","idempotency_key":"aaaaaaaaaaaaaaaa"}}"#
            ),
            ErrorCode::MalformedRequest
        );
    }

    #[test]
    fn deny_detail_is_bounded() {
        let d = Deny::new(ErrorCode::MalformedRequest, "é".repeat(500));
        assert!(d.detail.len() <= 200);
    }

    #[test]
    fn error_codes_are_stable_strings() {
        assert_eq!(ErrorCode::UnknownOperation.as_str(), "unknown_operation");
        assert_eq!(ErrorCode::MalformedRequest.as_str(), "malformed_request");
        assert_eq!(ErrorCode::RequestTooLarge.as_str(), "request_too_large");
        assert_eq!(ErrorCode::Unavailable.as_str(), "unavailable");
        assert_eq!(ErrorCode::OutcomeUnknown.as_str(), "outcome_unknown");
        assert_eq!(
            ErrorCode::IdempotencyConflict.as_str(),
            "idempotency_conflict"
        );
    }
}
