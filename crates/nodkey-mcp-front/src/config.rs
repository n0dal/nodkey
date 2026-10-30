// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Front configuration (`nodkey.mcp-front.v1`) and the operation declarations it reads.
//!
//! Nothing here is secret. The configuration names the agent's two sockets, the uids to check on
//! them, the enrolment sent as `approver`, the tools to expose, and the auth origin used to form
//! `confirm_url`. The declarations are the grant-v1 §6.1 operations file the broker also loads;
//! the front only reads each operation's `op`, `kind` and parameter `name`/`type`.

use std::path::{Path, PathBuf};

use crate::json::{self, J};

pub const FORMAT: &str = "nodkey.mcp-front.v1";
pub const OPERATIONS_FORMAT: &str = "nodkey.operations.v1";
/// The front's own tool (agent-interface-v1 §2.3).
pub const EFFECT_STATUS_TOOL: &str = "nodkey.effect_status";
/// Largest configuration or operations file accepted.
const MAX_FILE: u64 = 1024 * 1024;

/// Parameter types (grant-v1 §6.2, closed set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    Uint,
    AccountId,
    Currency,
    Text64,
    Text256,
}

impl ParamType {
    fn parse(s: &str) -> Option<ParamType> {
        Some(match s {
            "uint" => ParamType::Uint,
            "account_id" => ParamType::AccountId,
            "currency" => ParamType::Currency,
            "text64" => ParamType::Text64,
            "text256" => ParamType::Text256,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Write,
    Read,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub ty: ParamType,
}

/// One declared operation, as far as the front needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpDecl {
    pub op: String,
    pub kind: Kind,
    /// Declared parameters minus those the broker resolves (they are never agent input).
    pub params: Vec<Param>,
}

/// Parameters the broker resolves itself (effect-protocol-v2 Draft 3.1 and agent-interface-v1 §3).
/// The operations file does not mark them, so the front keeps this copy of the broker's table
/// (`broker/src/v2/decls.rs`, `resolved_by_broker`). A drift only changes the advertised schema:
/// the broker rejects a resolved parameter supplied by the workload (`invalid_argument`).
pub fn resolved_by_broker(op: &str) -> &'static [&'static str] {
    match op {
        "payments.refund" => &["charge_id"],
        "payments.support_refund" => &["charge_id", "customer_sub"],
        "messages.send" => &["to"],
        "mandate.support_ticket" => &["customer_email"],
        _ => &[],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approver {
    pub ten: String,
    pub sub: String,
}

#[derive(Debug, Clone)]
pub struct FrontConfig {
    pub listen_socket: PathBuf,
    pub agent_uid: u32,
    pub broker_socket: PathBuf,
    pub broker_uid: u32,
    pub approver: Approver,
    /// `https://<auth origin>`, without a trailing slash.
    pub auth_origin: String,
    /// Exposed operations, in declaration order (writes and reads).
    pub tools: Vec<OpDecl>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

fn err<T>(m: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(m.into()))
}

fn read_file(p: &Path) -> Result<Vec<u8>, ConfigError> {
    let meta =
        std::fs::symlink_metadata(p).map_err(|e| ConfigError(format!("{}: {e}", p.display())))?;
    if !meta.file_type().is_file() {
        return err(format!("{}: not a regular file", p.display()));
    }
    if meta.len() > MAX_FILE {
        return err(format!("{}: too large", p.display()));
    }
    std::fs::read(p).map_err(|e| ConfigError(format!("{}: {e}", p.display())))
}

fn exact_members(v: &J, required: &[&str]) -> Result<(), ConfigError> {
    let m = v
        .as_obj()
        .ok_or_else(|| ConfigError("not an object".into()))?;
    for (k, _) in m {
        if !required.contains(&k.as_str()) {
            return err(format!("unknown member {k}"));
        }
    }
    for r in required {
        if v.get(r).is_none() {
            return err(format!("missing member {r}"));
        }
    }
    Ok(())
}

fn string(v: &J, k: &str) -> Result<String, ConfigError> {
    v.get(k)
        .and_then(J::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ConfigError(format!("member {k}: string expected")))
}

fn uid(v: &J, k: &str) -> Result<u32, ConfigError> {
    v.get(k)
        .and_then(J::as_uint)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| ConfigError(format!("member {k}: uid expected")))
}

fn string_list(v: &J, k: &str) -> Result<Vec<String>, ConfigError> {
    let J::Arr(a) = v.get(k).ok_or_else(|| ConfigError(format!("member {k}")))? else {
        return err(format!("member {k}: array expected"));
    };
    let mut out: Vec<String> = Vec::new();
    for x in a {
        let s = x
            .as_str()
            .ok_or_else(|| ConfigError(format!("member {k}: strings expected")))?;
        if out.iter().any(|o| o == s) {
            return err(format!("member {k}: duplicate {s}"));
        }
        out.push(s.to_owned());
    }
    Ok(out)
}

/// ID grammar as the broker applies it (`broker/src/v2/ids.rs`): 1–`max` bytes of `0x21–0x7E`.
pub fn is_id(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| (0x21..=0x7e).contains(&c))
}

/// MCP 2026-07-28 tool-name rule: 1–128 of `[A-Za-z0-9_.-]`.
pub fn is_tool_name(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// Parses a grant-v1 §6.1 operations document (only the members the front uses are read; the
/// broker validates the whole file).
pub fn parse_operations(bytes: &[u8]) -> Result<Vec<OpDecl>, ConfigError> {
    let doc = json::parse(bytes).map_err(|e| ConfigError(format!("operations: {}", e.0)))?;
    if doc.get("format").and_then(J::as_str) != Some(OPERATIONS_FORMAT) {
        return err("operations: format");
    }
    let Some(J::Arr(ops)) = doc.get("operations") else {
        return err("operations: operations array");
    };
    let mut out: Vec<OpDecl> = Vec::new();
    for o in ops {
        let op = string(o, "op")?;
        if out.iter().any(|d| d.op == op) {
            return err(format!("operations: duplicate {op}"));
        }
        let kind = match string(o, "kind")?.as_str() {
            "write" => Kind::Write,
            "read" => Kind::Read,
            _ => return err(format!("operations: {op}: kind")),
        };
        let Some(J::Arr(ps)) = o.get("params") else {
            return err(format!("operations: {op}: params"));
        };
        let resolved = resolved_by_broker(&op);
        let mut params: Vec<Param> = Vec::new();
        for p in ps {
            let name = string(p, "name")?;
            let ty = ParamType::parse(&string(p, "type")?)
                .ok_or_else(|| ConfigError(format!("operations: {op}.{name}: type")))?;
            if params.iter().any(|q| q.name == name) {
                return err(format!("operations: {op}: duplicate parameter {name}"));
            }
            if !resolved.contains(&name.as_str()) {
                params.push(Param { name, ty });
            }
        }
        out.push(OpDecl { op, kind, params });
    }
    Ok(out)
}

impl FrontConfig {
    /// Loads and checks the configuration file and the operations file it names.
    pub fn load(path: &Path) -> Result<FrontConfig, ConfigError> {
        let v =
            json::parse(&read_file(path)?).map_err(|e| ConfigError(format!("config: {}", e.0)))?;
        let ops_path = PathBuf::from(string(&v, "operations_path")?);
        let ops = parse_operations(&read_file(&ops_path)?)?;
        FrontConfig::from_parts(&v, &ops)
    }

    /// Builds the configuration from a parsed configuration document and the declarations.
    pub fn from_parts(v: &J, ops: &[OpDecl]) -> Result<FrontConfig, ConfigError> {
        exact_members(
            v,
            &[
                "format",
                "listen_socket",
                "agent_uid",
                "broker_socket",
                "broker_uid",
                "operations_path",
                "write_ops",
                "read_ops",
                "approver",
                "auth_origin",
            ],
        )?;
        if string(v, "format")? != FORMAT {
            return err("format");
        }
        let approver_v = v
            .get("approver")
            .ok_or_else(|| ConfigError("approver".into()))?;
        exact_members(approver_v, &["ten", "sub"])?;
        let approver = Approver {
            ten: string(approver_v, "ten")?,
            sub: string(approver_v, "sub")?,
        };
        if !is_id(&approver.ten, 128) || !is_id(&approver.sub, 64) {
            return err("approver: ID grammar");
        }
        let auth_origin = string(v, "auth_origin")?;
        let host = auth_origin.strip_prefix("https://").unwrap_or("");
        if host.is_empty()
            || host.len() > 253
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
        {
            return err("auth_origin: https://<host[:port]> expected");
        }
        let write_ops = string_list(v, "write_ops")?;
        let read_ops = string_list(v, "read_ops")?;
        for (list, kind) in [(&write_ops, Kind::Write), (&read_ops, Kind::Read)] {
            for name in list {
                if name == EFFECT_STATUS_TOOL || !is_tool_name(name) {
                    return err(format!("tool name {name}"));
                }
                match ops.iter().find(|d| &d.op == name) {
                    Some(d) if d.kind == kind => {}
                    Some(_) => return err(format!("{name}: declared with another kind")),
                    None => return err(format!("{name}: not declared")),
                }
            }
        }
        let tools: Vec<OpDecl> = ops
            .iter()
            .filter(|d| write_ops.contains(&d.op) || read_ops.contains(&d.op))
            .cloned()
            .collect();
        Ok(FrontConfig {
            listen_socket: PathBuf::from(string(v, "listen_socket")?),
            agent_uid: uid(v, "agent_uid")?,
            broker_socket: PathBuf::from(string(v, "broker_socket")?),
            broker_uid: uid(v, "broker_uid")?,
            approver,
            auth_origin,
            tools,
        })
    }
}
