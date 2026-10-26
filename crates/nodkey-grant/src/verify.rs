//! The verification procedure of spec §7 (Draft 2).
//!
//! - [`verify`] runs steps 1c–9. Failures there are *unverified*: nothing is consumed or recorded.
//! - A verified write grant ([`WriteGrant`]) gives the broker its consumption record (W10,
//!   [`WriteGrant::consumption`]); after inserting it, the broker calls [`WriteGrant::decide`]
//!   (W11–W13) inside the same transaction. Every `Err` from `decide` must be recorded as DENIED.
//! - A verified read grant ([`ReadGrant`]) is decided by [`ReadGrant::decide`] (R11, R13).
//!   Nothing is recorded for read grants.

use ed25519_dalek::Signature;

use crate::cbor::{self, Value};
use crate::error::GrantError;
use crate::ops::{Binding, OpKind, Operations, ParamDecl, ParamValue, Params, Request, Scalar};
use crate::payload::{self, Body, Constraint, GrantKind, Payload};
use crate::registry::{KeyEntry, KeyStatus, Registry};
use crate::text::is_id;
use crate::{AAD_TAG, MAX_GRANT_BYTES, MAX_SKEW, MAX_TTL, TYP};

/// This broker's identifier: an ID of 1–128 bytes (spec §7.1). One `broker_id` must map to
/// exactly one replay store and one `revoked_before` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerId(String);

impl BrokerId {
    /// `None` if `id` is not an ID of 1–128 bytes (the broker must refuse to start).
    pub fn new(id: &str) -> Option<BrokerId> {
        is_id(id.as_bytes(), 128).then(|| BrokerId(id.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Time configuration (spec §7.1): `skew` 0–5 s (default 5), `max_ttl` 1–30 s (default 30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    skew: u64,
    max_ttl: u64,
}

impl Limits {
    pub const fn new(skew: u64, max_ttl: u64) -> Option<Limits> {
        if skew <= MAX_SKEW && max_ttl >= 1 && max_ttl <= MAX_TTL {
            Some(Limits { skew, max_ttl })
        } else {
            None
        }
    }
    pub const fn skew(self) -> u64 {
        self.skew
    }
    pub const fn max_ttl(self) -> u64 {
        self.max_ttl
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            skew: MAX_SKEW,
            max_ttl: MAX_TTL,
        }
    }
}

/// Trusted inputs for one verification (spec §7.1). Everything here comes from the broker's
/// configuration, clock, socket identity, or the strictly validated request, never from the grant.
#[derive(Debug, Clone, Copy)]
pub struct VerifyContext<'a> {
    /// Broker UTC clock, whole seconds (floor).
    pub now: u64,
    pub broker_id: &'a BrokerId,
    /// Workload identity of the socket or mTLS peer (`peer_wid`).
    pub workload: &'a str,
    /// Tenants registered for `workload` (spec D-4); empty if unregistered.
    pub workload_tenants: &'a [String],
    /// The request, validated by [`Operations::parse_request`].
    pub request: &'a Request,
    pub operations: &'a Operations,
    pub limits: Limits,
}

/// Identity and sourced claims of a verified grant (steps 1–9 passed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantIdentity {
    pub kind: GrantKind,
    pub kid: [u8; 16],
    pub iss: String,
    /// Consumption key with `iss` (write grants); audit only for read grants.
    pub jti: [u8; 16],
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub wid: String,
    pub ten: String,
    pub sub: String,
}

/// A `revoked_before` scope (ADR-0006 §6).
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
    fn is_revoked(&self, rows: &[RevokedBefore]) -> bool {
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

/// Result of steps 1–9.
#[derive(Debug)]
pub enum Verified<'a> {
    Write(WriteGrant<'a>),
    Read(ReadGrant<'a>),
}

/// The W10 consumption row: `consumed_grant(iss, jti, exp, request_hash, outcome = PENDING)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumption {
    pub iss: String,
    pub jti: [u8; 16],
    pub exp: u64,
    /// Hash of the validated request this grant was verified with (spec §5.4).
    pub request_hash: [u8; 32],
}

/// A verified write grant, not yet decided. Not `Clone`.
#[derive(Debug)]
pub struct WriteGrant<'a> {
    identity: GrantIdentity,
    op: String,
    opv: u16,
    cfm: bool,
    res: Vec<(u8, Scalar)>,
    con: Vec<(u8, Constraint)>,
    request: &'a Request,
    operations: &'a Operations,
}

/// A verified read grant, not yet decided. Not `Clone`.
#[derive(Debug)]
pub struct ReadGrant<'a> {
    identity: GrantIdentity,
    rop: Vec<(String, u16)>,
    request: &'a Request,
    operations: &'a Operations,
}

/// A grant that passed every check of this spec for exactly `request` (ACCEPT, before the
/// broker's W14/R14 preconditions). Effect code reads parameters only through [`Self::params`].
/// Not `Clone`.
#[derive(Debug)]
pub struct Authorized<'a> {
    identity: GrantIdentity,
    opv: u16,
    request: &'a Request,
}

impl Authorized<'_> {
    pub fn identity(&self) -> &GrantIdentity {
        &self.identity
    }
    pub fn kind(&self) -> GrantKind {
        self.identity.kind
    }
    /// The authorized operation (the requested one).
    pub fn op(&self) -> &str {
        self.request.op()
    }
    pub fn opv(&self) -> u16 {
        self.opv
    }
    /// The exact parameters that were checked and hashed.
    pub fn params(&self) -> &Params {
        self.request.params()
    }
    pub fn request_hash(&self) -> &[u8; 32] {
        self.request.request_hash()
    }
    /// Read grants: the query must filter by this tenant and subject (R14).
    pub fn tenant(&self) -> &str {
        &self.identity.ten
    }
    pub fn subject(&self) -> &str {
        &self.identity.sub
    }
}

/// `external_aad = "nodkey.grant.v1" || 0x00 || UTF-8(broker_id)` (spec §3.4).
pub(crate) fn external_aad(broker_id: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_TAG.len() + 1 + broker_id.len());
    a.extend_from_slice(AAD_TAG.as_bytes());
    a.push(0);
    a.extend_from_slice(broker_id.as_bytes());
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
fn parse_protected(protected: &[u8]) -> Result<(i128, [u8; 16]), GrantError> {
    const BAD: GrantError = GrantError::HeaderInvalid;
    let Value::Map(entries) = cbor::decode(protected, cbor::HEADER).map_err(|_| BAD)? else {
        return Err(BAD);
    };
    match entries.as_slice() {
        [
            (Value::Uint(1), alg),
            (Value::Uint(4), Value::Bytes(kid)),
            (Value::Uint(16), Value::Text(typ)),
        ] if *typ == TYP => {
            let alg = match alg {
                Value::Uint(n) => i128::from(*n),
                Value::Nint(n) => -1 - i128::from(*n),
                _ => return Err(BAD),
            };
            let kid = <[u8; 16]>::try_from(*kid).map_err(|_| BAD)?;
            Ok((alg, kid))
        }
        _ => Err(BAD),
    }
}

/// When step 4d evaluates the key's validity window.
#[derive(Debug, Clone, Copy)]
pub(crate) enum KeyWindowAt {
    /// At the broker clock, in step 4d (grant-v1 §7.2).
    Now(u64),
    /// At the grant's `iat`; the caller checks it after step 7 (payments-adapter-v1 §3.1).
    Iat,
}

/// Steps 1c–7 (with 4d per `key_window`): structure, header, key, signature, payload schema.
pub(crate) fn verify_signed<'r>(
    grant: &[u8],
    registry: &'r Registry,
    broker_id: &BrokerId,
    key_window: KeyWindowAt,
) -> Result<(Payload, [u8; 16], &'r KeyEntry), GrantError> {
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
    if alg != i128::from(entry.alg()) {
        return Err(AlgMismatch);
    }
    if entry.status() != KeyStatus::Active {
        return Err(KeyRevoked);
    }
    if let KeyWindowAt::Now(now) = key_window {
        if !(entry.not_before() <= now && now < entry.not_after()) {
            return Err(KeyInactive);
        }
    }

    // 5
    let msg = sig_structure(protected, &external_aad(broker_id.as_str()), payload_bytes);
    entry
        .public_key()
        .verify_strict(&msg, &Signature::from_bytes(&sig))
        .map_err(|_| SignatureInvalid)?;

    // 6, 7
    let pv = cbor::decode(payload_bytes, cbor::PAYLOAD).map_err(|_| PayloadMalformed)?;
    let p: Payload = payload::parse(&pv)?;
    Ok((p, kid, entry))
}

/// Steps 1c–9 on the grant bytes (after [`crate::decode_transport`]).
///
/// An `Err` is an unverified denial: the broker answers `grant_denied`, consumes and records
/// nothing.
pub fn verify<'a>(
    grant: &[u8],
    registry: &Registry,
    ctx: &VerifyContext<'a>,
) -> Result<Verified<'a>, GrantError> {
    use GrantError::*;
    let (p, kid, entry) = verify_signed(grant, registry, ctx.broker_id, KeyWindowAt::Now(ctx.now))?;

    // 8 (times are <= 2^53 - 1 after step 7; `now` saturates)
    let skew = ctx.limits.skew();
    if p.iss != entry.iss() {
        return Err(IssuerMismatch);
    }
    if !(p.iat <= p.nbf && p.nbf < p.exp && p.nbf - p.iat <= skew) {
        return Err(TimeInvalid);
    }
    if p.exp - p.iat > ctx.limits.max_ttl() {
        return Err(TtlExceeded);
    }
    let horizon = ctx.now.saturating_add(skew);
    if p.iat > horizon || p.nbf > horizon {
        return Err(NotYetValid);
    }
    if ctx.now >= p.exp + skew {
        return Err(Expired);
    }

    // 9
    if p.aud.as_bytes() != ctx.broker_id.as_str().as_bytes() {
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

    let kind = match p.body {
        Body::Write { .. } => GrantKind::Write,
        Body::Read { .. } => GrantKind::Read,
    };
    let identity = GrantIdentity {
        kind,
        kid,
        iss: p.iss,
        jti: p.jti,
        iat: p.iat,
        nbf: p.nbf,
        exp: p.exp,
        wid: p.wid,
        ten: p.ten,
        sub: p.sub,
    };
    Ok(match p.body {
        Body::Write {
            op,
            opv,
            res,
            con,
            cfm,
        } => Verified::Write(WriteGrant {
            identity,
            op,
            opv,
            cfm,
            res,
            con,
            request: ctx.request,
            operations: ctx.operations,
        }),
        Body::Read { rop } => Verified::Read(ReadGrant {
            identity,
            rop,
            request: ctx.request,
            operations: ctx.operations,
        }),
    })
}

impl<'a> WriteGrant<'a> {
    pub fn identity(&self) -> &GrantIdentity {
        &self.identity
    }

    /// W10: the row the broker inserts as the **first statement** of the effect transaction
    /// (unique key `(iss, jti)`), followed by `SAVEPOINT decision`. On conflict: same
    /// `request_hash` → return the stored outcome; different → `grant_replayed`, row unchanged.
    pub fn consumption(&self) -> Consumption {
        Consumption {
            iss: self.identity.iss.clone(),
            jti: self.identity.jti,
            exp: self.identity.exp,
            request_hash: *self.request.request_hash(),
        }
    }

    /// W11–W13, after the W10 insert succeeded. `revoked` must be the `revoked_before` rows for
    /// the grant's tenant, read inside the same transaction.
    ///
    /// On `Err`, the broker MUST roll back to the savepoint, set the row's outcome to DENIED and
    /// commit; if that fails, answer `unavailable` (spec §7.3). On `Ok`, W14 follows.
    pub fn decide(self, revoked: &[RevokedBefore]) -> Result<Authorized<'a>, GrantError> {
        use GrantError::*;
        let req = self.request;
        // W11a
        let decl = match self.operations.get(&self.op) {
            Some(d) if self.op == req.op() => d,
            _ => return Err(OpMismatch),
        };
        // W11b
        if decl.kind != OpKind::Write {
            return Err(KindMismatch);
        }
        // W11c
        if self.opv != decl.opv {
            return Err(OpvUnsupported);
        }
        // W11d
        if decl.requires_confirmation && !self.cfm {
            return Err(ConfirmationRequired);
        }
        // W12a: key sets, classes and declared types.
        let mut res_decl: Vec<(u8, &ParamDecl)> = Vec::new();
        let mut con_decl: Vec<(u8, &ParamDecl)> = Vec::new();
        for pd in &decl.params {
            match pd.binding {
                Binding::Resource(n) => res_decl.push((n, pd)),
                Binding::Exact(n) | Binding::Bounded(n) => con_decl.push((n, pd)),
                Binding::Free | Binding::OwnerScoped => {}
            }
        }
        res_decl.sort_by_key(|(n, _)| *n);
        con_decl.sort_by_key(|(n, _)| *n);
        if self.res.len() != res_decl.len() || self.con.len() != con_decl.len() {
            return Err(OpSchemaInvalid);
        }
        for ((k, v), (n, pd)) in self.res.iter().zip(&res_decl) {
            if k != n || !pd.ty.accepts(v) {
                return Err(OpSchemaInvalid);
            }
        }
        for ((k, c), (n, pd)) in self.con.iter().zip(&con_decl) {
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
        let params = req.params();
        // W12b
        for ((_, v), (_, pd)) in self.res.iter().zip(&res_decl) {
            if !params.get(&pd.name).is_some_and(|rv| v.equals(rv)) {
                return Err(ResourceMismatch);
            }
        }
        // W12c, ascending key order
        for ((_, c), (_, pd)) in self.con.iter().zip(&con_decl) {
            let rv = params.get(&pd.name);
            match c {
                Constraint::Exact(v) => {
                    if !rv.is_some_and(|rv| v.equals(rv)) {
                        return Err(ConstraintMismatch);
                    }
                }
                Constraint::Bounded(ceiling) => match rv {
                    Some(ParamValue::Uint(x)) => {
                        if x > ceiling {
                            return Err(BoundExceeded);
                        }
                    }
                    _ => return Err(ConstraintMismatch),
                },
            }
        }
        // W13
        if self.identity.is_revoked(revoked) {
            return Err(Revoked);
        }
        Ok(Authorized {
            identity: self.identity,
            opv: self.opv,
            request: req,
        })
    }
}

impl<'a> ReadGrant<'a> {
    pub fn identity(&self) -> &GrantIdentity {
        &self.identity
    }

    /// R11 and R13. `revoked` must be the `revoked_before` rows for the grant's tenant, read in
    /// the `READ ONLY` transaction. Nothing is consumed or recorded, whatever the result.
    pub fn decide(self, revoked: &[RevokedBefore]) -> Result<Authorized<'a>, GrantError> {
        use GrantError::*;
        let ops = self.operations;
        // R11a: the whole grant, every rop entry in map order.
        for (name, opv) in &self.rop {
            match ops.get(name) {
                None => return Err(OpMismatch),
                Some(d) if d.kind != OpKind::Read => return Err(KindMismatch),
                Some(d) if d.opv != *opv => return Err(OpvUnsupported),
                Some(_) => {}
            }
        }
        let requested = self.request.op();
        // R11b
        let decl = ops.get(requested).ok_or(OpMismatch)?;
        // R11c
        if decl.kind != OpKind::Read {
            return Err(KindMismatch);
        }
        // R11d
        let opv = self
            .rop
            .iter()
            .find(|(name, _)| name == requested)
            .map(|(_, v)| *v)
            .ok_or(OpMismatch)?;
        // R13
        if self.identity.is_revoked(revoked) {
            return Err(Revoked);
        }
        Ok(Authorized {
            identity: self.identity,
            opv,
            request: self.request,
        })
    }
}
