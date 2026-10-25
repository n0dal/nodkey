//! Operation declarations (spec §6) and validated requests (spec §6.2, §7.1).

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::cbor::{self, Value};
use crate::error::{DeclarationError, RequestError};
use crate::json::json_uint;
use crate::text::is_op_name;
use crate::{MAX_TIME, RQH_LABEL};

/// Declared kind of an operation (spec D-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Write,
    Read,
}

/// Placement and class of a parameter (spec §5.3, §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// Write op: `res` key n (always `exact`).
    Resource(u8),
    /// Write op: `con` key n, class `exact`.
    Exact(u8),
    /// Write op: `con` key n, class `bounded` (inclusive uint ceiling).
    Bounded(u8),
    /// Write op: not bound by the grant (published residual; needs a justification).
    Free,
    /// Read op: ownership checked by the broker against `(ten, sub)` (spec D-3).
    OwnerScoped,
}

/// The closed parameter type set of spec §6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    /// 0 ..= 2^53 − 1.
    Uint,
    /// 1–32 bytes of `[a-z0-9_]`.
    AccountId,
    /// Exactly 3 bytes of `[A-Z]`.
    Currency,
    /// 0–64 bytes of 0x20–0x7E.
    Text64,
    /// 0–256 bytes of 0x20–0x7E.
    Text256,
}

impl ParamType {
    pub fn from_name(s: &str) -> Option<ParamType> {
        Some(match s {
            "uint" => ParamType::Uint,
            "account_id" => ParamType::AccountId,
            "currency" => ParamType::Currency,
            "text64" => ParamType::Text64,
            "text256" => ParamType::Text256,
            _ => return None,
        })
    }

    fn accepts_text(self, s: &str) -> bool {
        let b = s.as_bytes();
        let printable = |b: &[u8]| b.iter().all(|c| (0x20..=0x7e).contains(c));
        match self {
            ParamType::Uint => false,
            ParamType::AccountId => {
                (1..=32).contains(&b.len())
                    && b.iter()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
            }
            ParamType::Currency => b.len() == 3 && b.iter().all(u8::is_ascii_uppercase),
            ParamType::Text64 => b.len() <= 64 && printable(b),
            ParamType::Text256 => b.len() <= 256 && printable(b),
        }
    }

    pub(crate) fn accepts(self, v: &Scalar) -> bool {
        match v {
            Scalar::Uint(n) => self == ParamType::Uint && *n <= MAX_TIME,
            Scalar::Text(s) => self.accepts_text(s),
        }
    }

    /// Whether a request value satisfies the grammar.
    pub fn accepts_value(self, v: &ParamValue) -> bool {
        match v {
            ParamValue::Uint(n) => self == ParamType::Uint && *n <= MAX_TIME,
            ParamValue::Text(s) => self.accepts_text(s),
        }
    }
}

/// One declared parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamDecl {
    /// `[a-z0-9_]{1,64}`, unique within the operation.
    pub name: String,
    pub binding: Binding,
    pub ty: ParamType,
    /// Destination-like (account, URL, recipient): must be `exact` (res or exact con).
    pub destination: bool,
    /// Required for `Free`, forbidden otherwise.
    pub justification: Option<String>,
}

/// One declared operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationDecl {
    pub name: String,
    pub kind: OpKind,
    /// The single supported schema version (1..=65535).
    pub opv: u16,
    /// Write ops only: the grant must carry `cfm = 1`.
    pub requires_confirmation: bool,
    pub params: Vec<ParamDecl>,
}

/// A validated set of operation declarations.
#[derive(Debug, Clone)]
pub struct Operations {
    by_name: BTreeMap<String, OperationDecl>,
}

fn is_param_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

impl Operations {
    /// Validates declarations (spec §6.1, §6.3). An error means the broker must refuse to start.
    ///
    /// In addition to §6.3, a write operation must bind at least one parameter (`res` or
    /// `con`), so that a grant never binds only the operation name (review GC-05; see
    /// SPEC_ISSUES.md).
    pub fn new(decls: Vec<OperationDecl>) -> Result<Operations, DeclarationError> {
        let mut by_name = BTreeMap::new();
        for d in decls {
            let e = |m: &str| DeclarationError::new(format!("{}: {m}", d.name));
            if !is_op_name(d.name.as_bytes()) {
                return Err(e("op name is not [a-z0-9_.]{1,64}"));
            }
            if d.opv == 0 {
                return Err(e("opv must be 1..=65535"));
            }
            if d.kind == OpKind::Read && d.requires_confirmation {
                return Err(e("requires_confirmation on a read operation"));
            }
            let mut names = BTreeSet::new();
            let mut res_keys = BTreeSet::new();
            let mut con_keys = BTreeSet::new();
            for p in &d.params {
                if !is_param_name(&p.name) {
                    return Err(e("param name is not [a-z0-9_]{1,64}"));
                }
                if !names.insert(p.name.as_str()) {
                    return Err(e("duplicate parameter name"));
                }
                let is_free = p.binding == Binding::Free;
                match &p.justification {
                    Some(j) if is_free && !j.is_empty() => {}
                    None if !is_free => {}
                    _ => return Err(e("justification required for free, forbidden otherwise")),
                }
                match (d.kind, p.binding) {
                    (OpKind::Write, Binding::Resource(n)) => {
                        if n > 15 || !res_keys.insert(n) {
                            return Err(e("res key out of range or shared"));
                        }
                    }
                    (OpKind::Write, Binding::Exact(n)) => {
                        if n > 15 || !con_keys.insert(n) {
                            return Err(e("con key out of range or shared"));
                        }
                    }
                    (OpKind::Write, Binding::Bounded(n)) => {
                        if n > 15 || !con_keys.insert(n) {
                            return Err(e("con key out of range or shared"));
                        }
                        if p.ty != ParamType::Uint {
                            return Err(e("bounded parameter must be uint"));
                        }
                    }
                    (OpKind::Write, Binding::Free) | (OpKind::Read, Binding::OwnerScoped) => {}
                    _ => return Err(e("parameter class not valid for the operation kind")),
                }
                if p.destination && !matches!(p.binding, Binding::Resource(_) | Binding::Exact(_)) {
                    return Err(e("destination parameter must be exact"));
                }
            }
            if d.kind == OpKind::Write && res_keys.is_empty() && con_keys.is_empty() {
                return Err(e("write operation binds no parameter"));
            }
            if by_name.contains_key(&d.name) {
                return Err(e("declared twice"));
            }
            by_name.insert(d.name.clone(), d);
        }
        Ok(Operations { by_name })
    }

    /// Loads the reference JSON format of spec §6.1 (strict: unknown, missing, duplicate
    /// members, wrong types, JSON string escapes and non-canonical integers are errors).
    pub fn load(json: &str) -> Result<Operations, DeclarationError> {
        let bad = |m: &str| DeclarationError::new(m.to_owned());
        let raw: RawOps<'_> = serde_json::from_str(json).map_err(|e| bad(&e.to_string()))?;
        if raw.format != "nodkey.operations.v1" {
            return Err(bad("format"));
        }
        let mut decls = Vec::with_capacity(raw.operations.len());
        for o in raw.operations {
            let kind = match o.kind {
                "write" => OpKind::Write,
                "read" => OpKind::Read,
                _ => return Err(bad("kind")),
            };
            let opv = json_uint(o.opv)
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| bad("opv must be one integer 1..=65535"))?;
            let mut params = Vec::with_capacity(o.params.len());
            for p in o.params {
                let key = match p.key.get() {
                    "null" => None,
                    _ => Some(
                        json_uint(p.key)
                            .filter(|k| *k <= 15)
                            .ok_or_else(|| bad("key"))? as u8,
                    ),
                };
                let binding = match (kind, p.placement, p.class, key) {
                    (OpKind::Write, "res", "exact", Some(k)) => Binding::Resource(k),
                    (OpKind::Write, "con", "exact", Some(k)) => Binding::Exact(k),
                    (OpKind::Write, "con", "bounded", Some(k)) => Binding::Bounded(k),
                    (OpKind::Write, "con", "free", None) => Binding::Free,
                    (OpKind::Read, "request", "owner_scoped", None) => Binding::OwnerScoped,
                    _ => return Err(bad("in/class/key combination")),
                };
                params.push(ParamDecl {
                    name: p.name.to_owned(),
                    binding,
                    ty: ParamType::from_name(p.ty).ok_or_else(|| bad("unknown type"))?,
                    destination: p.destination,
                    justification: p.justification.map(str::to_owned),
                });
            }
            decls.push(OperationDecl {
                name: o.op.to_owned(),
                kind,
                opv,
                requires_confirmation: o.requires_confirmation,
                params,
            });
        }
        Operations::new(decls)
    }

    pub fn get(&self, name: &str) -> Option<&OperationDecl> {
        self.by_name.get(name)
    }

    /// Strictly validates a request against the requested operation's declaration (spec §6.2,
    /// §7.1): the operation is declared, every declared parameter is present, no other
    /// parameter is present, and every value matches its declared type. The returned [`Request`]
    /// is the only form `verify` accepts, and carries the normative request hash (§5.4).
    pub fn parse_request(&self, op: &str, params: Params) -> Result<Request, RequestError> {
        let decl = self.get(op).ok_or(RequestError::UnknownOperation)?;
        for name in params.keys() {
            if !decl.params.iter().any(|p| p.name == *name) {
                return Err(RequestError::UnknownParameter(name.clone()));
            }
        }
        for p in &decl.params {
            match params.get(&p.name) {
                None => return Err(RequestError::MissingParameter(p.name.clone())),
                Some(v) if !p.ty.accepts_value(v) => {
                    return Err(RequestError::InvalidValue(p.name.clone()));
                }
                Some(_) => {}
            }
        }
        Request::build(op, params)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOps<'a> {
    #[serde(borrow)]
    format: &'a str,
    #[serde(borrow)]
    operations: Vec<RawOp<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOp<'a> {
    #[serde(borrow)]
    op: &'a str,
    #[serde(borrow)]
    kind: &'a str,
    #[serde(borrow)]
    opv: &'a RawValue,
    requires_confirmation: bool,
    #[serde(borrow)]
    params: Vec<RawParam<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawParam<'a> {
    #[serde(borrow)]
    name: &'a str,
    #[serde(borrow, rename = "in")]
    placement: &'a str,
    #[serde(borrow)]
    key: &'a RawValue,
    #[serde(borrow)]
    class: &'a str,
    #[serde(borrow, rename = "type")]
    ty: &'a str,
    destination: bool,
    #[serde(borrow, default)]
    justification: Option<&'a str>,
}

/// A typed request parameter value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParamValue {
    Uint(u64),
    Text(String),
}

/// Request parameters by name.
pub type Params = BTreeMap<String, ParamValue>;

/// A request validated against its operation's declaration, with its request hash (§5.4).
///
/// Effect code must read parameters only from here (or from the [`crate::Authorized`] that
/// borrows it), so that what is executed is exactly what was checked and hashed. Not `Clone`.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    op: String,
    params: Params,
    hash: [u8; 32],
}

impl Request {
    fn build(op: &str, params: Params) -> Result<Request, RequestError> {
        let hash = request_hash(op, &params)?;
        Ok(Request {
            op: op.to_owned(),
            params,
            hash,
        })
    }

    /// **Conformance testing only.** Builds a request without validating it against the
    /// declaration, so that vectors CON-20..23 can reach steps W12b/W12c. Never enable the
    /// `conformance-unvalidated-requests` feature in a broker build.
    #[cfg(feature = "conformance-unvalidated-requests")]
    pub fn unvalidated_for_conformance(op: &str, params: Params) -> Result<Request, RequestError> {
        Request::build(op, params)
    }

    pub fn op(&self) -> &str {
        &self.op
    }
    pub fn params(&self) -> &Params {
        &self.params
    }
    /// `SHA-256("nodkey.rqh.v1" || 0x00 || dcbor([op, {name: value}]))` (spec §5.4).
    pub fn request_hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

fn request_hash(op: &str, params: &Params) -> Result<[u8; 32], RequestError> {
    let entries = params
        .iter()
        .map(|(k, v)| {
            let val = match v {
                ParamValue::Uint(n) => Value::Uint(*n),
                ParamValue::Text(s) => Value::Text(s),
            };
            (Value::Text(k), val)
        })
        .collect();
    let v = Value::Array(vec![Value::Text(op), Value::Map(entries)]);
    let mut enc = Vec::new();
    // Map keys come from a BTreeMap and are unique; an error is still propagated, never hashed.
    cbor::encode(&v, &mut enc).map_err(|_| RequestError::Encoding)?;
    let mut h = Sha256::new();
    h.update(RQH_LABEL.as_bytes());
    h.update([0u8]);
    h.update(&enc);
    Ok(h.finalize().into())
}

/// A uint-or-text value from a grant payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scalar {
    Uint(u64),
    Text(String),
}

impl Scalar {
    /// Same type, byte-exact text, equal integer.
    pub(crate) fn equals(&self, p: &ParamValue) -> bool {
        match (self, p) {
            (Scalar::Uint(a), ParamValue::Uint(b)) => a == b,
            (Scalar::Text(a), ParamValue::Text(b)) => a.as_bytes() == b.as_bytes(),
            _ => false,
        }
    }
}
