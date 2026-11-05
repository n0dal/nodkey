// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! MCP 2026-07-28, tools only (agent-interface-v1 Draft 2 §2): message validation, the static
//! tool catalogue, and the mapping of tool calls onto socket W.
//!
//! Protocol facts used (MCP `schema/2026-07-28/schema.ts`, fetched 2026-10-28):
//! - every request carries `params._meta["io.modelcontextprotocol/protocolVersion"]` and
//!   `params._meta["io.modelcontextprotocol/clientCapabilities"]` (both required);
//! - an unsupported version is error `-32022` with `data: {supported, requested}`;
//! - `server/discover` is mandatory; its result and `tools/list`'s are cacheable results
//!   (`ttlMs`, `cacheScope`); every result carries `resultType`;
//! - tool execution errors are results with `isError: true`; an unknown tool is `-32602`.
//!
//! Nothing here is a security control: the broker re-applies every rule (§1, §2.4).

use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::broker::{BrokerClient, Reply};
use crate::config::{EFFECT_STATUS_TOOL, FrontConfig, Kind, OpDecl, Param, ParamType};
use crate::json::{self, J, MAX_UINT};

pub const PROTOCOL_VERSION: &str = "2026-07-28";
pub const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_CAPS: &str = "io.modelcontextprotocol/clientCapabilities";
/// Line cap on the MCP side (§2.2, §2.4).
pub const MAX_LINE: usize = 64 * 1024;
/// Largest `wait_s` of `nodkey.effect_status` (§2.5).
pub const MAX_WAIT_S: u64 = 20;

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// Poll intervals and bounds (§2.5). Tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Interval of `effect.status` after a write proposal (250 ms).
    pub write_poll: Duration,
    /// How long a write call waits for a settled status (`settle_ms` = 3000).
    pub settle: Duration,
    /// Interval of `effect.status` inside `nodkey.effect_status` (1 s).
    pub status_poll: Duration,
    /// Length of one `wait_s` unit (1 s).
    pub second: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            write_poll: Duration::from_millis(250),
            settle: Duration::from_millis(3000),
            status_poll: Duration::from_secs(1),
            second: Duration::from_secs(1),
        }
    }
}

pub struct Front {
    cfg: FrontConfig,
    broker: BrokerClient,
    timing: Timing,
    tools: Value,
}

fn rpc_error(id: Value, code: i64, message: &str, data: Option<Value>) -> String {
    let mut e = json!({"code": code, "message": message});
    if let (Some(d), Some(o)) = (data, e.as_object_mut()) {
        o.insert("data".into(), d);
    }
    json!({"jsonrpc": "2.0", "id": id, "error": e}).to_string()
}

fn rpc_result(id: Value, mut result: Value) -> String {
    if let Some(o) = result.as_object_mut() {
        o.insert("resultType".into(), json!("complete"));
    }
    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
}

/// A tool result: `structuredContent` and the same JSON as one text item.
pub fn tool_result(structured: Value, is_error: bool) -> Value {
    json!({
        "content": [{"type": "text", "text": structured.to_string()}],
        "structuredContent": structured,
        "isError": is_error,
    })
}

fn tool_error(code: &str) -> Value {
    tool_result(json!({"error": code}), true)
}

/// `id`: a string of 1–64 `[A-Za-z0-9._-]` or an integer 0 … 2^53 − 1 (§2.4).
fn request_id(v: &J) -> Option<Value> {
    match v {
        J::Str(s)
            if (1..=64).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) =>
        {
            Some(json!(s))
        }
        J::Num(_) => v.as_uint().map(Value::from),
        _ => None,
    }
}

/// Canonical `pending_id`: 22 characters of unpadded base64url (16 bytes; the last character
/// carries 2 bits, so it is one of `AQgw`).
pub fn is_pending_id(s: &str) -> bool {
    s.len() == 22
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && s.ends_with(['A', 'Q', 'g', 'w'])
}

fn check_value(ty: ParamType, v: &J) -> Option<Value> {
    let printable =
        |s: &str, max: usize| s.len() <= max && s.bytes().all(|b| (0x20..=0x7e).contains(&b));
    match (ty, v) {
        (ParamType::Uint, J::Num(_)) => v.as_uint().map(Value::from),
        (ParamType::Currency, J::Str(s))
            if s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase()) =>
        {
            Some(json!(s))
        }
        (ParamType::AccountId, J::Str(s))
            if (1..=32).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') =>
        {
            Some(json!(s))
        }
        (ParamType::Text64, J::Str(s)) if printable(s, 64) => Some(json!(s)),
        (ParamType::Text256, J::Str(s)) if printable(s, 256) => Some(json!(s)),
        _ => None,
    }
}

/// Exactly the declared (non-resolved) parameters, each of its type; no coercion.
pub fn check_arguments(params: &[Param], args: &J) -> Option<Map<String, Value>> {
    let members = args.as_obj()?;
    if members.len() != params.len() {
        return None;
    }
    let mut out = Map::new();
    for (k, v) in members {
        let p = params.iter().find(|p| &p.name == k)?;
        out.insert(k.clone(), check_value(p.ty, v)?);
    }
    Some(out)
}

fn schema_for(ty: ParamType) -> Value {
    match ty {
        ParamType::Uint => json!({"type": "integer", "minimum": 0, "maximum": MAX_UINT}),
        ParamType::Currency => json!({"type": "string", "pattern": "^[A-Z]{3}$"}),
        ParamType::AccountId => json!({"type": "string", "pattern": "^[a-z0-9_]{1,32}$"}),
        ParamType::Text64 => {
            json!({"type": "string", "maxLength": 64, "pattern": "^[\\x20-\\x7E]*$"})
        }
        ParamType::Text256 => {
            json!({"type": "string", "maxLength": 256, "pattern": "^[\\x20-\\x7E]*$"})
        }
    }
}

fn input_schema(params: &[Param]) -> Value {
    let mut props = Map::new();
    for p in params {
        props.insert(p.name.clone(), schema_for(p.ty));
    }
    let required: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    json!({"type": "object", "properties": props, "required": required, "additionalProperties": false})
}

/// The `status` values of §2.5.
pub const STATUSES: [&str; 8] = [
    "in_progress",
    "pending_confirmation",
    "succeeded",
    "outcome_unknown",
    "failed",
    "denied",
    "rejected",
    "expired",
];

fn effect_output_schema() -> Value {
    json!({"type": "object", "properties": {
        "status": {"type": "string", "enum": STATUSES},
        "pending_id": {"type": "string"},
        "expires_at": {"type": "integer"},
        "confirm_url": {"type": "string"},
        "receipt_id": {"type": "string"},
        "error": {"type": "string"}
    }, "additionalProperties": false})
}

fn read_output_schema(op: &str) -> Value {
    match op {
        // agent-interface-v1 §3.
        "payments.support_get_order" => json!({"type": "object", "properties": {
            "order_id": {"type": "integer"}, "customer_sub": {"type": "string"},
            "currency": {"type": "string"}, "amount_minor": {"type": "integer"},
            "refunded_minor": {"type": "integer"}, "status": {"type": "string"},
            "error": {"type": "string"}
        }, "additionalProperties": false}),
        _ => json!({"type": "object"}),
    }
}

fn tool_entry(d: &OpDecl) -> Value {
    let (description, out, read_only) = match d.kind {
        Kind::Write => (
            format!(
                "Proposes the operation {}. It takes effect only after the enrolled principal approves it \
                 on the auth origin, or under an active mandate; the result reports the status.",
                d.op
            ),
            effect_output_schema(),
            false,
        ),
        Kind::Read => (
            format!("Reads {} through the Nodkey broker.", d.op),
            read_output_schema(&d.op),
            true,
        ),
    };
    json!({
        "name": d.op,
        "description": description,
        "inputSchema": input_schema(&d.params),
        "outputSchema": out,
        "annotations": {"readOnlyHint": read_only},
    })
}

fn effect_status_entry() -> Value {
    json!({
        "name": EFFECT_STATUS_TOOL,
        "description": "Returns the status of an earlier proposal by pending_id, waiting up to wait_s \
                        seconds while it is pending. A pending_id is a name, not a capability.",
        "inputSchema": {"type": "object", "properties": {
            "pending_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{21}[AQgw]$"},
            "wait_s": {"type": "integer", "minimum": 0, "maximum": MAX_WAIT_S}
        }, "required": ["pending_id", "wait_s"], "additionalProperties": false},
        "outputSchema": effect_output_schema(),
        "annotations": {"readOnlyHint": true},
    })
}

/// A settled view of `effect.status` (§2.5 mapping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub status: &'static str,
    pub is_error: bool,
    pub pending_id: String,
    pub expires_at: u64,
    pub receipt_id: Option<String>,
}

/// Maps an `effect.status` result (effect-protocol-v2 §2.3, §12.2) onto §2.5. Any shape outside
/// the protocol is `None` (reported as `unavailable`).
pub fn map_status(r: &J) -> Option<Status> {
    let pending_id = r.get("pending_id")?.as_str()?.to_owned();
    if !is_pending_id(&pending_id) {
        return None;
    }
    let expires_at = r.get("expires_at")?.as_uint()?;
    let awaiting = match r.get("awaiting") {
        None | Some(J::Null) => None,
        Some(J::Str(s)) if s == "mandate" || s == "confirmation" => Some(s.as_str()),
        _ => return None,
    };
    let (class, receipt_id) = match r.get("outcome")? {
        J::Null => (None, None),
        o @ J::Obj(_) => {
            let class = o.get("class")?.as_str()?;
            let receipt = match o.get("receipt_id")? {
                J::Null => None,
                J::Str(s) if is_pending_id(s) => Some(s.clone()),
                _ => return None,
            };
            (Some(class), receipt)
        }
        _ => return None,
    };
    let (status, is_error) = match (r.get("state")?.as_str()?, awaiting) {
        ("PENDING", Some("mandate")) => ("in_progress", false),
        ("PENDING", Some("confirmation")) => ("pending_confirmation", false),
        ("APPROVED" | "EXECUTING", None) => ("in_progress", false),
        ("SUCCEEDED", None) => ("succeeded", false),
        ("UNKNOWN", None) => ("outcome_unknown", false),
        ("FAILED", None) if class == Some("denied") => ("denied", true),
        ("FAILED", None) => ("failed", true),
        ("DENIED", None) => ("rejected", true),
        ("EXPIRED", None) => ("expired", true),
        _ => return None,
    };
    Some(Status {
        status,
        is_error,
        pending_id,
        expires_at,
        receipt_id,
    })
}

impl Front {
    pub fn new(cfg: FrontConfig, timing: Timing) -> Front {
        let broker = BrokerClient::new(
            cfg.broker_socket.clone(),
            cfg.broker_uid,
            Duration::from_secs(10),
        );
        let mut tools: Vec<Value> = cfg.tools.iter().map(tool_entry).collect();
        tools.push(effect_status_entry());
        Front {
            cfg,
            broker,
            timing,
            tools: Value::Array(tools),
        }
    }

    fn status_json(&self, s: &Status) -> Value {
        let mut o =
            json!({"status": s.status, "pending_id": s.pending_id, "expires_at": s.expires_at});
        if let Some(m) = o.as_object_mut() {
            if s.status == "pending_confirmation" {
                m.insert(
                    "confirm_url".into(),
                    json!(format!("{}/confirm/{}", self.cfg.auth_origin, s.pending_id)),
                );
            }
            if let Some(r) = &s.receipt_id {
                m.insert("receipt_id".into(), json!(r));
            }
        }
        o
    }

    fn status_result(&self, s: &Status) -> Value {
        tool_result(self.status_json(s), s.is_error)
    }

    async fn effect_status(&self, pid: &str) -> Result<Status, &'static str> {
        match self
            .broker
            .call("effect.status", json!({"pending_id": pid}))
            .await
        {
            Reply::Ok(r) => match map_status(&r) {
                Some(s) if s.pending_id == pid => Ok(s),
                _ => Err("unavailable"),
            },
            Reply::Err(c) => Err(c),
        }
    }

    async fn call_write(&self, op: &str, params: Map<String, Value>) -> Value {
        let a = &self.cfg.approver;
        let args = json!({"op": op, "params": params, "approver": {"ten": a.ten, "sub": a.sub}});
        let r = match self.broker.call("effect.propose", args).await {
            Reply::Ok(r) => r,
            Reply::Err(c) => return tool_error(c),
        };
        let (Some(pid), Some(expires_at)) = (
            r.get("pending_id").and_then(J::as_str),
            r.get("expires_at").and_then(J::as_uint),
        ) else {
            return tool_error("unavailable");
        };
        if !is_pending_id(pid) {
            return tool_error("unavailable");
        }
        // Until the first status answer the proposal is only known to exist.
        let mut last = Status {
            status: "in_progress",
            is_error: false,
            pending_id: pid.to_owned(),
            expires_at,
            receipt_id: None,
        };
        let deadline = Instant::now() + self.timing.settle;
        loop {
            match self.effect_status(pid).await {
                Ok(s) => {
                    last = s;
                    if last.status != "in_progress" {
                        break;
                    }
                }
                Err(_) => break,
            }
            if Instant::now() + self.timing.write_poll > deadline {
                break;
            }
            tokio::time::sleep(self.timing.write_poll).await;
        }
        self.status_result(&last)
    }

    async fn call_status(&self, args: &J) -> Value {
        let ok = args.as_obj().is_some_and(|m| m.len() == 2);
        let pid = args.get("pending_id").and_then(J::as_str);
        let wait = args.get("wait_s").and_then(J::as_uint);
        let (true, Some(pid), Some(wait)) = (ok, pid, wait) else {
            return tool_error("invalid_argument");
        };
        if !is_pending_id(pid) || wait > MAX_WAIT_S {
            return tool_error("invalid_argument");
        }
        let deadline = Instant::now() + self.timing.second * (wait as u32);
        loop {
            let s = match self.effect_status(pid).await {
                Ok(s) => s,
                Err(c) => return tool_error(c),
            };
            let waiting = matches!(s.status, "in_progress" | "pending_confirmation");
            if !waiting || Instant::now() + self.timing.status_poll > deadline {
                return self.status_result(&s);
            }
            tokio::time::sleep(self.timing.status_poll).await;
        }
    }

    async fn call_read(&self, op: &str, args: Map<String, Value>) -> Value {
        match self.broker.call(op, Value::Object(args)).await {
            Reply::Ok(r) => match r.to_value() {
                Some(v) => tool_result(v, false),
                None => tool_error("unavailable"),
            },
            Reply::Err(c) => tool_error(c),
        }
    }

    /// Handles one MCP line. `None` for notifications (no response).
    pub async fn handle_line(&self, line: &[u8]) -> Option<String> {
        if line.len() > MAX_LINE {
            return Some(rpc_error(
                Value::Null,
                INVALID_REQUEST,
                "Request too large",
                None,
            ));
        }
        let msg = match json::parse(line) {
            Ok(m) => m,
            Err(_) => return Some(rpc_error(Value::Null, PARSE_ERROR, "Parse error", None)),
        };
        let Some(members) = msg.as_obj() else {
            let m = if matches!(msg, J::Arr(_)) {
                "Batches are not supported"
            } else {
                "Invalid request"
            };
            return Some(rpc_error(Value::Null, INVALID_REQUEST, m, None));
        };
        let invalid = || {
            Some(rpc_error(
                Value::Null,
                INVALID_REQUEST,
                "Invalid request",
                None,
            ))
        };
        if members
            .iter()
            .any(|(k, _)| !matches!(k.as_str(), "jsonrpc" | "id" | "method" | "params"))
            || msg.get("jsonrpc").and_then(J::as_str) != Some("2.0")
        {
            return invalid();
        }
        let Some(method) = msg.get("method").and_then(J::as_str) else {
            return invalid();
        };
        let id = match msg.get("id") {
            // A notification: nothing is answered (the front acts on none).
            None => return None,
            Some(v) => match request_id(v) {
                Some(id) => id,
                None => return invalid(),
            },
        };
        let allowed: &[&str] = match method {
            "server/discover" | "ping" => &["_meta"],
            "tools/list" => &["_meta", "cursor"],
            "tools/call" => &["_meta", "name", "arguments"],
            _ => return Some(rpc_error(id, METHOD_NOT_FOUND, "Method not found", None)),
        };
        let bad_params = |id: Value, m: &str| Some(rpc_error(id, INVALID_PARAMS, m, None));
        let Some(params) = msg.get("params").filter(|p| p.as_obj().is_some()) else {
            return bad_params(id, "Invalid params");
        };
        if params
            .as_obj()
            .is_some_and(|m| m.iter().any(|(k, _)| !allowed.contains(&k.as_str())))
        {
            return bad_params(id, "Invalid params");
        }
        let Some(meta) = params.get("_meta").filter(|m| m.as_obj().is_some()) else {
            return bad_params(id, "Missing _meta");
        };
        match meta.get(META_VERSION) {
            Some(J::Str(v)) if v == PROTOCOL_VERSION => {}
            Some(J::Str(v)) => {
                return Some(rpc_error(
                    id,
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "Unsupported protocol version",
                    Some(json!({"supported": [PROTOCOL_VERSION], "requested": v})),
                ));
            }
            _ => return bad_params(id, "Missing protocol version"),
        }
        if !matches!(meta.get(META_CAPS), Some(J::Obj(_))) {
            return bad_params(id, "Missing client capabilities");
        }
        let result = match method {
            "ping" => json!({}),
            "server/discover" => json!({
                "supportedVersions": [PROTOCOL_VERSION],
                "capabilities": {"tools": {"listChanged": false}},
                "ttlMs": 0,
                "cacheScope": "private",
                "_meta": {"io.modelcontextprotocol/serverInfo":
                    {"name": "nodkey-mcp", "version": env!("CARGO_PKG_VERSION")}},
            }),
            "tools/list" => {
                if params.get("cursor").is_some() {
                    return bad_params(id, "Invalid cursor");
                }
                json!({"tools": self.tools, "ttlMs": 0, "cacheScope": "private"})
            }
            _ => {
                let Some(name) = params.get("name").and_then(J::as_str) else {
                    return bad_params(id, "Invalid params");
                };
                let empty = J::Obj(Vec::new());
                let args = match params.get("arguments") {
                    None => &empty,
                    Some(a @ J::Obj(_)) => a,
                    Some(_) => return bad_params(id, "Invalid params"),
                };
                if name == EFFECT_STATUS_TOOL {
                    self.call_status(args).await
                } else {
                    let Some(d) = self.cfg.tools.iter().find(|d| d.op == name) else {
                        return bad_params(id, "Unknown tool");
                    };
                    match (check_arguments(&d.params, args), d.kind) {
                        (None, _) => tool_error("invalid_argument"),
                        (Some(p), Kind::Write) => self.call_write(&d.op, p).await,
                        (Some(p), Kind::Read) => self.call_read(&d.op, p).await,
                    }
                }
            }
        };
        Some(rpc_result(id, result))
    }
}
