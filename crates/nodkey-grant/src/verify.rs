//! The verification procedure of spec §7.2, steps 1c–11.
//!
//! Steps 0–1b (transport) are in [`crate::decode_transport`]. Step 12 (consumption) and step 13
//! (revocation) need the broker's database and run inside its effect transaction; this module
//! returns what they need ([`GrantIdentity`], [`request_hash`], [`GrantIdentity::is_revoked`]).

use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};

use crate::cbor::{self, Value};
use crate::error::GrantError;
use crate::ops::{Authority, Binding, OpKind, Operations, ParamValue, Params};
use crate::payload::{self, Body, Constraint, GrantKind, Payload};
use crate::registry::{KeyStatus, Registry, Role};
use crate::{AAD_TAG, MAX_GRANT_BYTES, MAX_SKEW, MAX_TTL, TYP};

/// Clock skew tolerance, 0..=5 seconds (spec §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Skew(u64);

impl Skew {
    /// `None` if `seconds > 5`.
    pub const fn new(seconds: u64) -> Option<Skew> {
        if seconds <= MAX_SKEW {
            Some(Skew(seconds))
        } else {
            None
        }
    }
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

impl Default for Skew {
    fn default() -> Self {
        Skew(MAX_SKEW)
    }
}

/// Trusted inputs for one verification (spec §7.1). Everything here comes from the broker's own
/// configuration, clock, socket identity, or strict request parser, never from the grant.
#[derive(Debug, Clone, Copy)]
pub struct VerifyContext<'a> {
    /// Broker UTC clock, whole seconds (floor).
    pub now: u64,
    /// This broker's identifier (`broker_id`): used for `external_aad` and the `aud` check.
    pub audience: &'a str,
    /// Workload identity of the socket or mTLS peer (`peer_wid`).
    pub workload: &'a str,
    /// Tenants registered for `workload` (spec D-4). Empty if the workload is unregistered.
    pub workload_tenants: &'a [String],
    /// Operation requested.
    pub requested_op: &'a str,
    /// Request parameters, already strictly parsed.
    pub requested_params: &'a Params,
    /// Operation declarations.
    pub operations: &'a Operations,
    pub skew: Skew,
}

/// Identity and sourced claims of a grant that passed steps 1–9 ("verified", spec §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantIdentity {
    pub kind: GrantKind,
    pub kid: [u8; 16],
    pub iss: String,
    /// Consumption key, together with `iss` (write grants); audit only for read grants.
    pub jti: [u8; 16],
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub wid: String,
    pub ten: String,
    pub sub: String,
    /// Write grants: the grant's `op` and `opv`. Read grants: `None`.
    pub write_op: Option<(String, u16)>,
    /// Write grants: `cfm`. Read grants: false.
    pub confirmed: bool,
}

/// A `revoked_before` row (ADR-0006 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationScope {
    Tenant { ten: String },
    TenantWorkload { ten: String, wid: String },
    TenantSubject { ten: String, sub: String },
}

/// A `revoked_before` row: grants in `scope` with `iat < before` are revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedBefore {
    pub scope: RevocationScope,
    pub before: u64,
}

impl GrantIdentity {
    /// Step 13: true if any row matches `(ten)`, `(ten, wid)` or `(ten, sub)` with
    /// `iat < before`. The broker must evaluate this inside the effect (or read) transaction.
    pub fn is_revoked(&self, rows: &[RevokedBefore]) -> bool {
        rows.iter().any(|r| {
            let applies = match &r.scope {
                RevocationScope::Tenant { ten } => *ten == self.ten,
                RevocationScope::TenantWorkload { ten, wid } => {
                    *ten == self.ten && *wid == self.wid
                }
                RevocationScope::TenantSubject { ten, sub } => *ten == self.ten && *sub == self.sub,
            };
            applies && self.iat < r.before
        })
    }
}

/// A grant that passed steps 1–11 for the requested operation. Only [`verify`] constructs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrant {
    identity: GrantIdentity,
    op: String,
    opv: u16,
}

impl VerifiedGrant {
    pub fn identity(&self) -> &GrantIdentity {
        &self.identity
    }
    pub fn kind(&self) -> GrantKind {
        self.identity.kind
    }
    pub fn iss(&self) -> &str {
        &self.identity.iss
    }
    pub fn jti(&self) -> &[u8; 16] {
        &self.identity.jti
    }
    pub fn tenant(&self) -> &str {
        &self.identity.ten
    }
    pub fn subject(&self) -> &str {
        &self.identity.sub
    }
    /// The authorized operation (equal to the requested one).
    pub fn op(&self) -> &str {
        &self.op
    }
    /// The schema version the grant names for `op`.
    pub fn opv(&self) -> u16 {
        self.opv
    }
    /// True if this is a write grant, which the broker must consume (step 12) before any effect.
    pub fn must_consume(&self) -> bool {
        self.identity.kind == GrantKind::Write
    }
}

/// A denial. `verified` is `Some` iff the grant passed steps 1–9: a verified **write** grant
/// denied at steps 10–11 must be recorded as `DENIED` under `(iss, jti)` (spec §7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub code: GrantError,
    pub verified: Option<Box<GrantIdentity>>,
}

impl Rejection {
    fn unverified(code: GrantError) -> Self {
        Rejection {
            code,
            verified: None,
        }
    }
}

impl From<GrantError> for Rejection {
    fn from(code: GrantError) -> Self {
        Rejection::unverified(code)
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code.as_str())
    }
}

impl std::error::Error for Rejection {}

/// `external_aad = "nodkey.grant.v1" || 0x00 || UTF-8(audience)` (spec §3.4).
pub(crate) fn external_aad(audience: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_TAG.len() + 1 + audience.len());
    a.extend_from_slice(AAD_TAG.as_bytes());
    a.push(0);
    a.extend_from_slice(audience.as_bytes());
    a
}

/// `["Signature1", protected, external_aad, payload]` (spec §3.4), definite, shortest heads.
pub(crate) fn sig_structure(protected: &[u8], aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(16 + protected.len() + aad.len() + payload.len());
    s.push(0x84);
    cbor::write_head(&mut s, 3, 10);
    s.extend_from_slice(b"Signature1");
    for b in [protected, aad, payload] {
        cbor::write_head(&mut s, 2, b.len() as u64);
        s.extend_from_slice(b);
    }
    s
}

/// Step 3 on the protected header bytes: returns (alg, kid).
fn parse_protected(protected: &[u8]) -> Result<(Value<'_>, [u8; 16]), GrantError> {
    const BAD: GrantError = GrantError::HeaderInvalid;
    let Value::Map(entries) = cbor::decode(protected, cbor::HEADER).map_err(|_| BAD)? else {
        return Err(BAD);
    };
    match entries.as_slice() {
        [
            (Value::Uint(1), alg @ (Value::Uint(_) | Value::Nint(_))),
            (Value::Uint(4), Value::Bytes(kid)),
            (Value::Uint(16), Value::Text(typ)),
        ] if *typ == TYP => {
            let kid = <[u8; 16]>::try_from(*kid).map_err(|_| BAD)?;
            Ok((alg.clone(), kid))
        }
        _ => Err(BAD),
    }
}

/// Runs spec §7.2 steps 1c–11 on the grant bytes `grant` (after transport decoding).
///
/// On success, a write grant must still be consumed (step 12) and checked for revocation
/// (step 13) inside the broker's effect transaction; a read grant must be checked for revocation.
pub fn verify(
    grant: &[u8],
    registry: &Registry,
    ctx: &VerifyContext<'_>,
) -> Result<VerifiedGrant, Rejection> {
    let (identity, p, role) = verify_binding(grant, registry, ctx)?;
    match authorize(role, &p, ctx) {
        Ok((op, opv)) => Ok(VerifiedGrant {
            identity,
            op: op.to_owned(),
            opv,
        }),
        Err(code) => Err(Rejection {
            code,
            verified: Some(Box::new(identity)),
        }),
    }
}

/// Steps 1c–9.
fn verify_binding<'g>(
    grant: &'g [u8],
    registry: &Registry,
    ctx: &VerifyContext<'_>,
) -> Result<(GrantIdentity, Payload<'g>, Role), GrantError> {
    use GrantError::*;
    // 1c
    if grant.len() > MAX_GRANT_BYTES {
        return Err(TooLarge);
    }
    // 2: tag 18 as the single byte 0xd2, then the envelope rules.
    let rest = match grant.split_first() {
        Some((0xd2, rest)) => rest,
        _ => return Err(Malformed),
    };
    let env = cbor::decode(rest, cbor::ENVELOPE).map_err(|_| Malformed)?;
    let Value::Array(items) = env else {
        return Err(Malformed);
    };
    let [
        Value::Bytes(protected),
        Value::Map(unprotected),
        Value::Bytes(payload_bytes),
        Value::Bytes(sig),
    ] = items.as_slice()
    else {
        return Err(Malformed);
    };
    let sig: [u8; 64] = <[u8; 64]>::try_from(*sig).map_err(|_| Malformed)?;

    // 3
    if !unprotected.is_empty() {
        return Err(HeaderInvalid);
    }
    let (alg, kid) = parse_protected(protected)?;

    // 4
    let entry = registry.get(&kid).ok_or(UnknownKid)?;
    let alg = match alg {
        Value::Uint(n) => i128::from(n),
        Value::Nint(n) => -1 - i128::from(n),
        _ => return Err(HeaderInvalid),
    };
    if alg != i128::from(entry.alg()) {
        return Err(AlgMismatch);
    }
    if entry.status() != KeyStatus::Active {
        return Err(KeyRevoked);
    }
    if !(entry.not_before() <= ctx.now && ctx.now < entry.not_after()) {
        return Err(KeyInactive);
    }

    // 5
    let msg = sig_structure(protected, &external_aad(ctx.audience), payload_bytes);
    entry
        .public_key()
        .verify_strict(&msg, &Signature::from_bytes(&sig))
        .map_err(|_| SignatureInvalid)?;

    // 6, 7
    let pv = cbor::decode(payload_bytes, cbor::PAYLOAD).map_err(|_| PayloadMalformed)?;
    let p = payload::parse(&pv)?;

    // 8
    if p.iss != entry.iss() {
        return Err(IssuerMismatch);
    }
    if !(p.nbf >= p.iat && p.exp > p.nbf) {
        return Err(TimeInvalid);
    }
    if p.exp - p.nbf > MAX_TTL {
        return Err(TtlExceeded);
    }
    // Times are <= 2^53 - 1 and skew <= 5: no overflow; saturating keeps `now` safe too.
    let skew = ctx.skew.seconds();
    if ctx.now.saturating_add(skew) < p.nbf {
        return Err(NotYetValid);
    }
    if ctx.now >= p.exp + skew {
        return Err(Expired);
    }

    // 9
    if p.aud.as_bytes() != ctx.audience.as_bytes() {
        return Err(AudienceMismatch);
    }
    if p.wid.as_bytes() != ctx.workload.as_bytes() {
        return Err(WorkloadMismatch);
    }
    if !ctx
        .workload_tenants
        .iter()
        .any(|t| t.as_bytes() == p.ten.as_bytes())
    {
        return Err(TenantMismatch);
    }

    let (kind, write_op, confirmed) = match &p.body {
        Body::Write { op, opv, cfm, .. } => {
            (GrantKind::Write, Some(((*op).to_owned(), *opv)), *cfm)
        }
        Body::Read { .. } => (GrantKind::Read, None, false),
    };
    let identity = GrantIdentity {
        kind,
        kid,
        iss: p.iss.to_owned(),
        jti: p.jti,
        iat: p.iat,
        nbf: p.nbf,
        exp: p.exp,
        wid: p.wid.to_owned(),
        ten: p.ten.to_owned(),
        sub: p.sub.to_owned(),
        write_op,
        confirmed,
    };
    Ok((identity, p, entry.role()))
}

fn role_permits(role: Role, authority: Authority) -> bool {
    matches!(
        (role, authority),
        (Role::UserAuthority, Authority::UserGrant) | (Role::Scheduler, Authority::SchedulerGrant)
    )
}

/// Steps 10–11. Returns the authorized (op, opv).
fn authorize<'p>(
    role: Role,
    p: &Payload<'p>,
    ctx: &VerifyContext<'_>,
) -> Result<(&'p str, u16), GrantError> {
    use GrantError::*;
    let ops = ctx.operations;
    match &p.body {
        Body::Write {
            op,
            opv,
            res,
            con,
            cfm,
        } => {
            // 10a
            let decl = match ops.get(op) {
                Some(d) if *op == ctx.requested_op => d,
                _ => return Err(OpMismatch),
            };
            // 10b
            if decl.kind != OpKind::Write {
                return Err(KindMismatch);
            }
            // 10c
            if !decl.versions.contains(opv) {
                return Err(OpvUnsupported);
            }
            // 10d
            if !role_permits(role, decl.authority) {
                return Err(IssuerNotPermitted);
            }
            // 10e
            if decl.requires_confirmation && !*cfm {
                return Err(ConfirmationRequired);
            }
            // 11a: key sets, classes and types match the declaration.
            let mut res_decl: Vec<(u8, &crate::ops::ParamDecl)> = Vec::new();
            let mut con_decl: Vec<(u8, &crate::ops::ParamDecl)> = Vec::new();
            for pd in &decl.params {
                match pd.binding {
                    Binding::Resource(n) => res_decl.push((n, pd)),
                    Binding::Exact(n) | Binding::Bounded(n) => con_decl.push((n, pd)),
                    Binding::Free | Binding::OwnerScoped => {}
                }
            }
            res_decl.sort_by_key(|(n, _)| *n);
            con_decl.sort_by_key(|(n, _)| *n);
            if res.len() != res_decl.len() || con.len() != con_decl.len() {
                return Err(OpSchemaInvalid);
            }
            for ((k, v), (n, pd)) in res.iter().zip(&res_decl) {
                if k != n || !pd.ty.accepts(v) {
                    return Err(OpSchemaInvalid);
                }
            }
            for ((k, c), (n, pd)) in con.iter().zip(&con_decl) {
                let ok = k == n
                    && match (c, pd.binding) {
                        (Constraint::Exact(v), Binding::Exact(_)) => pd.ty.accepts(v),
                        (Constraint::Bounded(_), Binding::Bounded(_)) => true,
                        _ => false,
                    };
                if !ok {
                    return Err(OpSchemaInvalid);
                }
            }
            // 11b
            for ((_, v), (_, pd)) in res.iter().zip(&res_decl) {
                match ctx.requested_params.get(&pd.name) {
                    Some(rv) if v.equals(rv) => {}
                    _ => return Err(ResourceMismatch),
                }
            }
            // 11c, ascending key order
            for ((_, c), (_, pd)) in con.iter().zip(&con_decl) {
                let rv = ctx.requested_params.get(&pd.name);
                match c {
                    Constraint::Exact(v) => {
                        if !rv.is_some_and(|rv| v.equals(rv)) {
                            return Err(ConstraintMismatch);
                        }
                    }
                    Constraint::Bounded(ceiling) => match rv {
                        Some(ParamValue::Uint(x)) if x <= ceiling => {}
                        _ => return Err(BoundExceeded),
                    },
                }
            }
            Ok((op, *opv))
        }
        Body::Read { rop } => {
            // 10a
            let decl = ops.get(ctx.requested_op).ok_or(OpMismatch)?;
            // 10b
            if decl.kind != OpKind::Read {
                return Err(KindMismatch);
            }
            // 10c, in map order
            for (name, _) in rop {
                match ops.get(name) {
                    None => return Err(OpMismatch),
                    Some(d) if d.kind != OpKind::Read => return Err(KindMismatch),
                    Some(_) => {}
                }
            }
            // 10d
            let (name, opv) = rop
                .iter()
                .find(|(name, _)| *name == ctx.requested_op)
                .ok_or(OpMismatch)?;
            // 10e
            if !decl.versions.contains(opv) {
                return Err(OpvUnsupported);
            }
            // 10f
            if !role_permits(role, decl.authority) {
                return Err(IssuerNotPermitted);
            }
            Ok((name, *opv))
        }
    }
}

/// §5.4 request hash (RECOMMENDED construction):
/// `SHA-256("nodkey.rqh.v1" || 0x00 || cbor([op, opv, {name: value}]))` over every request
/// parameter, including `free` ones.
pub fn request_hash(op: &str, opv: u16, params: &Params) -> [u8; 32] {
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
    let v = Value::Array(vec![
        Value::Text(op),
        Value::Uint(u64::from(opv)),
        Value::Map(entries),
    ]);
    let mut enc = Vec::new();
    // Keys come from a map, so they are unique: encoding cannot fail.
    let _ = cbor::encode(&v, &mut enc);
    let mut h = Sha256::new();
    h.update(b"nodkey.rqh.v1");
    h.update([0u8]);
    h.update(&enc);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
