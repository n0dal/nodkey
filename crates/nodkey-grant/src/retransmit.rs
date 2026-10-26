//! Adapter-side, non-consuming verification of a stored write grant (payments-adapter-v1
//! Draft 3 §3.1): `verify_retransmission` for (re)transmission of an effect the broker already
//! decided (with the age cap), and `verify_binding` for lookup-only operations (no age cap).
//!
//! This is deliberately a different entry point, context, result and error type from
//! [`crate::verify`]: it never consumes, never yields a [`crate::WriteGrant`] or
//! [`crate::Authorized`], and replaces the `exp` check with an age cap (`now − iat ≤ R_max`),
//! because a resend may legitimately happen after `exp`. A broker must never use it.
//!
//! Checks, in order (first failure wins; the adapter answers `grant_refused` for all of them):
//! clock floor; grant-v1 steps 1c–7 with the key window evaluated at `iat` (§3.1 "key validity at
//! `iat`"); 8a issuer; 8b time order; 8c lifetime; 8d `iat`/`nbf ≤ now + skew`; **no 8e**; age;
//! 9a audience; 9b workload; 9c tenant (see SPEC_ISSUES.md RX-1); kind = write; `cfm = 1`;
//! `op`/`opv` equal the adapter's compiled-in operation; `res`/`con` exactly match its
//! declaration (keys, class exact, declared types).
//!
//! Not checked here (by design): consumption and revocation (broker), the adapter's own order
//! view (§3.2), and operation-specific value rules not expressible in a declaration, such as
//! `amount_minor ≥ 1` (SPEC_ISSUES.md RX-3).

use std::fmt;

use crate::error::GrantError;
use crate::ops::{Binding, OpKind, OperationDecl, Operations, ParamValue, Params, Scalar};
use crate::payload::{Body, Constraint};
use crate::registry::Registry;
use crate::verify::{BrokerId, KeyWindowAt, Limits, verify_signed};

/// The adapter refuses to verify while its clock reads below 2024-01-01T00:00:00Z
/// (payments-adapter-v1 §2, Clock).
pub const CLOCK_FLOOR: u64 = 1_704_067_200;

/// The `R_max` age cap in seconds, validated against the start-up rule of payments-adapter-v1
/// §3.1: `resend_margin < provider_retention` and `R_max < provider_retention − resend_margin`.
/// (Whether `provider_retention` is within the provider profile's documented minimum is the
/// adapter's configuration check.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RMax(u64);

impl RMax {
    /// `None` if the start-up rule fails or `r_max_s == 0`: the adapter must refuse to start.
    pub const fn new(
        r_max_s: u64,
        provider_retention_s: u64,
        resend_margin_s: u64,
    ) -> Option<RMax> {
        if r_max_s >= 1
            && resend_margin_s < provider_retention_s
            && r_max_s < provider_retention_s - resend_margin_s
        {
            Some(RMax(r_max_s))
        } else {
            None
        }
    }
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

/// Why a retransmission was refused. Never shown to the broker beyond `grant_refused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetransmissionError {
    /// A grant-v1 check failed (same codes as the broker's path).
    Grant(GrantError),
    /// `now − iat > R_max`.
    AgeExceeded,
    /// The adapter clock reads below [`CLOCK_FLOOR`].
    ClockBelowFloor,
}

impl RetransmissionError {
    /// Audit-log code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grant(g) => g.as_str(),
            Self::AgeExceeded => "retransmission_age_exceeded",
            Self::ClockBelowFloor => "retransmission_clock_below_floor",
        }
    }
    /// The only code returned on socket P (payments-adapter-v1 §3.1).
    pub const CLIENT_FACING: &'static str = "grant_refused";
}

impl From<GrantError> for RetransmissionError {
    fn from(g: GrantError) -> Self {
        Self::Grant(g)
    }
}

impl fmt::Display for RetransmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for RetransmissionError {}

/// Adapter configuration for retransmission checks. Built once at start-up.
#[derive(Debug)]
pub struct RetransmissionContext<'a> {
    registry: &'a Registry,
    broker_id: &'a BrokerId,
    workload: &'a str,
    workload_tenants: &'a [String],
    decl: &'a OperationDecl,
    limits: Limits,
}

impl<'a> RetransmissionContext<'a> {
    /// `op` is the single write operation this adapter serves (compiled in). It must be declared
    /// in `operations` as a write operation whose parameters are all `res` or exact `con`
    /// (a bounded or free value is not in the grant, so a request cannot be derived from it).
    /// `None` means the adapter must refuse to start.
    pub fn new(
        registry: &'a Registry,
        broker_id: &'a BrokerId,
        workload: &'a str,
        workload_tenants: &'a [String],
        operations: &'a Operations,
        op: &str,
        limits: Limits,
    ) -> Option<RetransmissionContext<'a>> {
        let decl = operations.get(op)?;
        let derivable = decl
            .params
            .iter()
            .all(|p| matches!(p.binding, Binding::Resource(_) | Binding::Exact(_)));
        // An empty tenant list is a start-up refusal (payments-adapter-v1 Draft 3 §3.1 step 4).
        if decl.kind != OpKind::Write || !derivable || workload_tenants.is_empty() {
            return None;
        }
        Some(RetransmissionContext {
            registry,
            broker_id,
            workload,
            workload_tenants,
            decl,
            limits,
        })
    }
}

/// Claims of a stored write grant that passed the adapter checks (private; exposed only through
/// the two distinct result types).
#[derive(Debug)]
struct Checked {
    iss: String,
    jti: [u8; 16],
    kid: [u8; 16],
    op: String,
    opv: u16,
    iat: u64,
    exp: u64,
    ten: String,
    sub: String,
    params: Params,
}

macro_rules! claim_accessors {
    () => {
        /// `(iss, jti)` for the idempotency-key derivation (payments-adapter-v1 §3.3).
        pub fn idempotency_identity(&self) -> (&str, &[u8; 16]) {
            (&self.c.iss, &self.c.jti)
        }
        pub fn kid(&self) -> &[u8; 16] {
            &self.c.kid
        }
        pub fn op(&self) -> &str {
            &self.c.op
        }
        pub fn opv(&self) -> u16 {
            self.c.opv
        }
        pub fn iat(&self) -> u64 {
            self.c.iat
        }
        /// Informational only: `exp` is not enforced on the adapter paths.
        pub fn exp(&self) -> u64 {
            self.c.exp
        }
        /// For the adapter's own order-view check (§3.2).
        pub fn tenant(&self) -> &str {
            &self.c.ten
        }
        pub fn subject(&self) -> &str {
            &self.c.sub
        }
        /// The signed `res`/`con` values by declared parameter name.
        pub fn params(&self) -> &Params {
            &self.c.params
        }
    };
}

/// A stored write grant that may be (re)transmitted (`refund.create`): passed every check
/// including the age cap. Not `Clone`; cannot be turned into a broker-side decision. All provider
/// request values must be taken from [`Self::params`].
#[derive(Debug)]
pub struct RetransmissionAuthorized {
    c: Checked,
}

impl RetransmissionAuthorized {
    claim_accessors!();
}

/// A stored write grant verified for **lookups only** (no age cap). Deliberately has no
/// conversion to [`RetransmissionAuthorized`]: it must never be used to send a create.
#[derive(Debug)]
pub struct BindingVerified {
    c: Checked,
}

impl BindingVerified {
    claim_accessors!();
}

fn to_value(s: &Scalar) -> ParamValue {
    match s {
        Scalar::Uint(n) => ParamValue::Uint(*n),
        Scalar::Text(t) => ParamValue::Text(t.clone()),
    }
}

/// Verifies a stored write grant for (re)transmission (`refund.create`) without consuming it.
/// See the module documentation for the exact checks, including the age cap.
pub fn verify_retransmission(
    ctx: &RetransmissionContext<'_>,
    grant: &[u8],
    now: u64,
    r_max: RMax,
) -> Result<RetransmissionAuthorized, RetransmissionError> {
    adapter_check(ctx, grant, now, Some(r_max)).map(|c| RetransmissionAuthorized { c })
}

/// Verifies a stored write grant for **lookup-only** operations (`refund.find`, `refund.get`,
/// `idem.status`; payments-adapter-v1 Draft 3 §3.1, PA-18): every check of
/// [`verify_retransmission`] except the age cap (and, like it, no `exp` and no consumption).
/// The result, [`BindingVerified`], cannot be used where a [`RetransmissionAuthorized`] is
/// required, so it can never authorize a create.
pub fn verify_binding(
    ctx: &RetransmissionContext<'_>,
    grant: &[u8],
    now: u64,
) -> Result<BindingVerified, RetransmissionError> {
    adapter_check(ctx, grant, now, None).map(|c| BindingVerified { c })
}

fn adapter_check(
    ctx: &RetransmissionContext<'_>,
    grant: &[u8],
    now: u64,
    r_max: Option<RMax>,
) -> Result<Checked, RetransmissionError> {
    use GrantError::*;
    if now < CLOCK_FLOOR {
        return Err(RetransmissionError::ClockBelowFloor);
    }
    // 1c–7, key window deferred to `iat`.
    let (p, kid, entry) = verify_signed(grant, ctx.registry, ctx.broker_id, KeyWindowAt::Iat)?;
    // Status (4c) was checked in `verify_signed`; the window (4d) is evaluated at `iat`.
    if !(entry.not_before() <= p.iat && p.iat < entry.not_after()) {
        return Err(KeyInactive.into());
    }
    // 8a–8d (8e deliberately omitted).
    let skew = ctx.limits.skew();
    if p.iss != entry.iss() {
        return Err(IssuerMismatch.into());
    }
    if !(p.iat <= p.nbf && p.nbf < p.exp && p.nbf - p.iat <= skew) {
        return Err(TimeInvalid.into());
    }
    if p.exp - p.iat > ctx.limits.max_ttl() {
        return Err(TtlExceeded.into());
    }
    let horizon = now.saturating_add(skew);
    if p.iat > horizon || p.nbf > horizon {
        return Err(NotYetValid.into());
    }
    // Age cap replaces `exp`. iat may lead `now` by up to `skew` (age 0 then).
    if let Some(r_max) = r_max {
        if now.saturating_sub(p.iat) > r_max.seconds() {
            return Err(RetransmissionError::AgeExceeded);
        }
    }
    // 9a–9c.
    if p.aud.as_bytes() != ctx.broker_id.as_str().as_bytes() {
        return Err(AudienceMismatch.into());
    }
    if p.wid.as_bytes() != ctx.workload.as_bytes() {
        return Err(WorkloadMismatch.into());
    }
    if !ctx
        .workload_tenants
        .iter()
        .any(|t| t.as_bytes() == p.ten.as_bytes())
    {
        return Err(TenantMismatch.into());
    }
    // Kind, confirmation, operation.
    let Body::Write {
        op,
        opv,
        res,
        con,
        cfm,
    } = p.body
    else {
        return Err(KindMismatch.into());
    };
    if !cfm {
        return Err(ConfirmationRequired.into());
    }
    let decl = ctx.decl;
    if op != decl.name {
        return Err(OpMismatch.into());
    }
    if opv != decl.opv {
        return Err(OpvUnsupported.into());
    }
    // res/con exactly as declared (every parameter is res or exact con, see the context).
    let mut params = Params::new();
    let (mut n_res, mut n_con) = (0, 0);
    for pd in &decl.params {
        let v = match pd.binding {
            Binding::Resource(k) => {
                n_res += 1;
                res.iter().find(|(rk, _)| *rk == k).map(|(_, v)| v)
            }
            Binding::Exact(k) => {
                n_con += 1;
                con.iter()
                    .find(|(ck, _)| *ck == k)
                    .and_then(|(_, c)| match c {
                        Constraint::Exact(v) => Some(v),
                        Constraint::Bounded(_) => None,
                    })
            }
            _ => None,
        };
        match v {
            Some(v) if pd.ty.accepts(v) => {
                params.insert(pd.name.clone(), to_value(v));
            }
            _ => return Err(OpSchemaInvalid.into()),
        }
    }
    if res.len() != n_res || con.len() != n_con {
        return Err(OpSchemaInvalid.into());
    }
    Ok(Checked {
        iss: p.iss,
        jti: p.jti,
        kid,
        op,
        opv,
        iat: p.iat,
        exp: p.exp,
        ten: p.ten,
        sub: p.sub,
        params,
    })
}
