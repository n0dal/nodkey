// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! v2 framing and envelope (spec §1.2, §2.2): one strict JSON object per line,
//! `{"v":2,"id":…,"op":…,"args":{…}}`; duplicate, unknown and wrongly typed members are rejected.
//! Error messages are static per code; details go to the audit log only.

use serde_json::{Map, Value, json};

use crate::protocol::RequestId;
use crate::strict_json;

pub const VERSION: u64 = 2;

/// Every code any v2 channel can return. Workload-facing codes are the §2.6 set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    MalformedRequest,
    UnsupportedVersion,
    RequestTooLarge,
    UnknownOperation,
    OperationNotPermitted,
    InvalidArgument,
    LimitExceeded,
    NotFound,
    GrantDenied,
    Unavailable,
    /// Socket G: one body for every cause (PC-03).
    NotAvailable,
    /// Wrong peer uid on any socket.
    Unauthenticated,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::MalformedRequest => "malformed_request",
            Code::UnsupportedVersion => "unsupported_version",
            Code::RequestTooLarge => "request_too_large",
            Code::UnknownOperation => "unknown_operation",
            Code::OperationNotPermitted => "operation_not_permitted",
            Code::InvalidArgument => "invalid_argument",
            Code::LimitExceeded => "limit_exceeded",
            Code::NotFound => "not_found",
            Code::GrantDenied => "grant_denied",
            Code::Unavailable => "unavailable",
            Code::NotAvailable => "not_available",
            Code::Unauthenticated => "unauthenticated",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Code::MalformedRequest => "request is not a valid v2 request",
            Code::UnsupportedVersion => "protocol version not supported",
            Code::RequestTooLarge => "request exceeds maximum size",
            Code::UnknownOperation => "operation is not declared",
            Code::OperationNotPermitted => "operation not permitted for this workload",
            Code::InvalidArgument => "invalid argument",
            Code::LimitExceeded => "limit exceeded",
            Code::NotFound => "not found",
            Code::GrantDenied => "authorization denied",
            Code::Unavailable => "service unavailable; nothing was executed",
            Code::NotAvailable => "This request is not available.",
            Code::Unauthenticated => "peer not authorized for this socket",
        }
    }
}

/// A failure with a broker-side detail for the audit log (never sent to the client).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    pub code: Code,
    pub detail: String,
}

impl Fail {
    pub fn new(code: Code, detail: impl Into<String>) -> Fail {
        let mut detail: String = detail.into();
        if detail.len() > 300 {
            let mut cut = 300;
            while !detail.is_char_boundary(cut) {
                cut -= 1;
            }
            detail.truncate(cut);
        }
        Fail { code, detail }
    }
}

#[derive(Debug)]
pub struct Envelope {
    pub id: RequestId,
    pub op: String,
    pub args: Map<String, Value>,
}

#[derive(Debug)]
pub struct EnvelopeError {
    pub id: Option<RequestId>,
    pub fail: Fail,
}

/// Parses one line strictly. `expected_v` is the socket's version (spec §2.1).
pub fn parse_envelope(line: &[u8]) -> Result<Envelope, EnvelopeError> {
    let bad = |id: Option<RequestId>, code: Code, d: &str| EnvelopeError {
        id,
        fail: Fail::new(code, d),
    };
    strict_json::check_strict(line).map_err(|e| bad(None, Code::MalformedRequest, &e))?;
    let v: Value = serde_json::from_slice(line)
        .map_err(|e| bad(None, Code::MalformedRequest, &e.to_string()))?;
    let Value::Object(mut o) = v else {
        return Err(bad(None, Code::MalformedRequest, "not an object"));
    };
    if o.len() != 4 || !["v", "id", "op", "args"].iter().all(|k| o.contains_key(*k)) {
        return Err(bad(None, Code::MalformedRequest, "envelope member set"));
    }
    let id = o["id"]
        .as_str()
        .and_then(RequestId::parse)
        .ok_or_else(|| bad(None, Code::MalformedRequest, "request id"))?;
    let Some(ver) = o["v"].as_u64().filter(|_| o["v"].is_u64()) else {
        return Err(bad(Some(id), Code::MalformedRequest, "v is not an integer"));
    };
    if ver != VERSION {
        return Err(bad(Some(id), Code::UnsupportedVersion, &format!("v={ver}")));
    }
    let Some(op) = o["op"].as_str().map(str::to_owned) else {
        return Err(bad(Some(id), Code::MalformedRequest, "op type"));
    };
    let Some(Value::Object(args)) = o.remove("args") else {
        return Err(bad(Some(id), Code::MalformedRequest, "args type"));
    };
    Ok(Envelope { id, op, args })
}

/// Requires `args` to have exactly `required` plus any of `optional`.
pub fn check_keys(
    args: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), Fail> {
    for k in required {
        if !args.contains_key(*k) {
            return Err(Fail::new(Code::MalformedRequest, format!("missing {k}")));
        }
    }
    for k in args.keys() {
        if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
            return Err(Fail::new(Code::MalformedRequest, "unknown member"));
        }
    }
    Ok(())
}

pub fn str_arg<'a>(args: &'a Map<String, Value>, k: &str) -> Result<&'a str, Fail> {
    args.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| Fail::new(Code::MalformedRequest, format!("{k} type")))
}

/// `{"ten": ID, "sub": ID}` with exactly those members.
pub fn subject_arg(v: &Value) -> Result<(String, String), Fail> {
    let Value::Object(o) = v else {
        return Err(Fail::new(Code::MalformedRequest, "subject type"));
    };
    check_keys(o, &["ten", "sub"], &[])?;
    Ok((str_arg(o, "ten")?.to_owned(), str_arg(o, "sub")?.to_owned()))
}

pub fn ok_response(id: &RequestId, cid: &str, result: Value) -> Value {
    json!({"v": VERSION, "id": id.as_str(), "correlation_id": cid, "ok": true, "result": result})
}

pub fn err_response(id: Option<&RequestId>, cid: &str, code: Code) -> Value {
    json!({
        "v": VERSION,
        "id": id.map(RequestId::as_str),
        "correlation_id": cid,
        "ok": false,
        "error": {"code": code.as_str(), "message": code.message()}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(line: &str) -> Code {
        parse_envelope(line.as_bytes()).unwrap_err().fail.code
    }

    #[test]
    fn envelope_strictness() {
        let ok =
            parse_envelope(br#"{"v":2,"id":"r1","op":"effect.status","args":{"pending_id":"x"}}"#)
                .unwrap();
        assert_eq!(ok.op, "effect.status");
        // T27: v1 message on a v2 socket.
        assert_eq!(
            code(r#"{"v":1,"id":"r1","op":"ledger.transfer","args":{}}"#),
            Code::UnsupportedVersion
        );
        assert_eq!(
            code(r#"{"v":3,"id":"r1","op":"x","args":{}}"#),
            Code::UnsupportedVersion
        );
        for bad in [
            r#"{"v":2,"id":"r1","op":"x","args":{},"grant":"g"}"#,
            r#"{"v":2,"id":"r1","op":"x"}"#,
            r#"{"v":2,"v":2,"id":"r1","op":"x","args":{}}"#,
            r#"{"v":"2","id":"r1","op":"x","args":{}}"#,
            r#"{"v":2.0,"id":"r1","op":"x","args":{}}"#,
            r#"{"v":-2,"id":"r1","op":"x","args":{}}"#,
            r#"{"v":2,"id":"a b","op":"x","args":{}}"#,
            r#"{"v":2,"id":"r1","op":1,"args":{}}"#,
            r#"{"v":2,"id":"r1","op":"x","args":[]}"#,
            r#"[]"#,
            "",
        ] {
            assert_eq!(code(bad), Code::MalformedRequest, "{bad}");
        }
    }

    #[test]
    fn keys_and_subject() {
        let m: Map<String, Value> = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        assert!(check_keys(&m, &["a", "b"], &[]).is_ok());
        assert!(check_keys(&m, &["a"], &[]).is_err());
        assert!(check_keys(&m, &["a", "b", "c"], &[]).is_err());
        assert!(check_keys(&m, &["a"], &["b"]).is_ok());
        assert!(subject_arg(&json!({"ten":"t","sub":"s"})).is_ok());
        assert!(subject_arg(&json!({"ten":"t","sub":"s","x":1})).is_err());
        assert!(subject_arg(&json!({"ten":"t","sub":1})).is_err());
    }

    #[test]
    fn errors_are_static() {
        let v = err_response(None, "c", Code::NotFound);
        assert_eq!(v["error"].as_object().unwrap().len(), 2);
        assert_eq!(v["error"]["message"], "not found");
    }
}
