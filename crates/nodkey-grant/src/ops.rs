//! Operation declarations (spec §6) and request parameters.
//!
//! The declaration format belongs to the broker; this module holds the semantic content the
//! verifier needs and enforces the start-up rules of §6.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::DeclarationError;
use crate::text::is_op_name;

/// Declared kind of an operation (spec D-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Write,
    Read,
}

/// Which issuer role may sign grants for an operation (spec §6 `authority`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// Registry role `user_authority`.
    UserGrant,
    /// Registry role `scheduler` (provisional, spec D-9).
    SchedulerGrant,
}

/// Placement and class of a parameter (spec §5.3, §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// Write op: `res` key n (always `exact`).
    Resource(u8),
    /// Write op: `con` key n, class `exact`.
    Exact(u8),
    /// Write op: `con` key n, class `bounded` (inclusive uint ceiling).
    Bounded(u8),
    /// Write op: not bound by the grant (published residual). Must never be destination-like;
    /// that judgement is the declaring operator's, it cannot be checked here.
    Free,
    /// Read op: ownership checked by the broker against `(ten, sub)` (spec D-3).
    OwnerScoped,
}

/// Value type of a text parameter: length bounds and an allowed-byte predicate.
#[derive(Debug, Clone, Copy)]
pub struct TextRule {
    pub min_len: usize,
    pub max_len: usize,
    pub allowed: fn(u8) -> bool,
}

impl TextRule {
    pub fn accepts(&self, s: &str) -> bool {
        let b = s.as_bytes();
        b.len() >= self.min_len && b.len() <= self.max_len && b.iter().all(|c| (self.allowed)(*c))
    }
}

/// Declared value type of a parameter. The spec leaves concrete types to the broker
/// (see SPEC_ISSUES.md, SI-1).
#[derive(Debug, Clone, Copy)]
pub enum ParamType {
    Uint,
    Text(TextRule),
}

impl ParamType {
    pub(crate) fn accepts(&self, v: &Scalar<'_>) -> bool {
        match (self, v) {
            (ParamType::Uint, Scalar::Uint(_)) => true,
            (ParamType::Text(r), Scalar::Text(s)) => r.accepts(s),
            _ => false,
        }
    }
}

/// One declared parameter.
#[derive(Debug, Clone)]
pub struct ParamDecl {
    pub name: String,
    pub binding: Binding,
    pub ty: ParamType,
}

/// One declared operation.
#[derive(Debug, Clone)]
pub struct OperationDecl {
    pub name: String,
    pub kind: OpKind,
    /// Supported `opv` values (1..=65535).
    pub versions: Vec<u16>,
    pub authority: Authority,
    /// Write ops only: the grant must carry `cfm = 1`.
    pub requires_confirmation: bool,
    pub params: Vec<ParamDecl>,
}

/// A validated set of operation declarations.
#[derive(Debug, Clone)]
pub struct Operations {
    by_name: BTreeMap<String, OperationDecl>,
}

impl Operations {
    /// Validates the declarations (spec §6); an error means the broker must refuse to start.
    pub fn new(decls: Vec<OperationDecl>) -> Result<Operations, DeclarationError> {
        let mut by_name = BTreeMap::new();
        for d in decls {
            let e = |m: &str| DeclarationError(format!("{}: {m}", d.name));
            if !is_op_name(d.name.as_bytes()) {
                return Err(e("name is not [a-z0-9_.]{1,64}"));
            }
            if d.versions.is_empty() || d.versions.contains(&0) {
                return Err(e("versions must be non-empty and in 1..=65535"));
            }
            let mut names = BTreeSet::new();
            let mut res_keys = BTreeSet::new();
            let mut con_keys = BTreeSet::new();
            for p in &d.params {
                if !names.insert(p.name.as_str()) {
                    return Err(e("duplicate parameter name"));
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
                        if !matches!(p.ty, ParamType::Uint) {
                            return Err(e("bounded parameter must be an unsigned integer"));
                        }
                    }
                    (OpKind::Write, Binding::Free) => {}
                    (OpKind::Read, Binding::OwnerScoped) => {}
                    _ => return Err(e("parameter class not valid for the operation kind")),
                }
                if let ParamType::Text(r) = p.ty {
                    if r.min_len > r.max_len || r.max_len > 256 {
                        return Err(e("text rule length bounds invalid (max 256)"));
                    }
                }
            }
            if d.kind == OpKind::Read && d.requires_confirmation {
                return Err(e("read operations cannot require confirmation"));
            }
            if by_name.contains_key(&d.name) {
                return Err(e("declared twice"));
            }
            by_name.insert(d.name.clone(), d);
        }
        Ok(Operations { by_name })
    }

    pub fn get(&self, name: &str) -> Option<&OperationDecl> {
        self.by_name.get(name)
    }
}

/// A typed request parameter value, as produced by the broker's strict request parser.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParamValue {
    Uint(u64),
    Text(String),
}

/// Request parameters by name.
pub type Params = BTreeMap<String, ParamValue>;

/// A uint-or-text value borrowed from a grant payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scalar<'a> {
    Uint(u64),
    Text(&'a str),
}

impl Scalar<'_> {
    /// Same type, byte-exact text, equal integer.
    pub(crate) fn equals(&self, p: &ParamValue) -> bool {
        match (self, p) {
            (Scalar::Uint(a), ParamValue::Uint(b)) => a == b,
            (Scalar::Text(a), ParamValue::Text(b)) => a.as_bytes() == b.as_bytes(),
            _ => false,
        }
    }
}
