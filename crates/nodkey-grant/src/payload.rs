//! Payload schema (spec §5, §7.2 steps 7a–7b).

use crate::MAX_TIME;
use crate::cbor::Value;
use crate::error::GrantError;
use crate::ops::Scalar;
use crate::text::{is_id, is_op_name, is_value_text};

/// Signed kind of a grant (`knd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    Write,
    Read,
}

/// The signed confirmation marker of a write grant: key 18 `cfm` and, for `cfm = 2`, key 20
/// `mid` (spec §5.1, Draft 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// `cfm = 0`: not confirmed.
    None,
    /// `cfm = 1`: the user confirmed exactly the bound values on the auth origin.
    User,
    /// `cfm = 2`: issued by the Authority under the mandate `mid` without per-effect approval.
    /// Valid only for `mandate_eligible` operations (W11d). The mandate itself (active, terms,
    /// counters) is **not** checked by this crate: it is a W14 precondition of the broker.
    Mandate {
        /// The mandate id (the `jti` of the mandate's own grant), exactly 16 bytes.
        mid: [u8; 16],
    },
}

impl Confirmation {
    /// The `cfm` value (0, 1 or 2).
    pub fn cfm(&self) -> u8 {
        match self {
            Confirmation::None => 0,
            Confirmation::User => 1,
            Confirmation::Mandate { .. } => 2,
        }
    }
    /// The mandate id, for `cfm = 2` only.
    pub fn mandate_id(&self) -> Option<[u8; 16]> {
        match self {
            Confirmation::Mandate { mid } => Some(*mid),
            _ => None,
        }
    }
}

/// `con` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Constraint {
    Exact(Scalar),
    Bounded(u64),
}

#[derive(Debug, Clone)]
pub(crate) enum Body {
    Write {
        op: String,
        opv: u16,
        /// Ascending key order.
        res: Vec<(u8, Scalar)>,
        /// Ascending key order.
        con: Vec<(u8, Constraint)>,
        cfm: Confirmation,
    },
    Read {
        /// Map order (C8 order).
        rop: Vec<(String, u16)>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct Payload {
    pub iss: String,
    pub aud: String,
    pub jti: [u8; 16],
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub wid: String,
    pub ten: String,
    pub sub: String,
    pub body: Body,
}

pub(crate) const K_VER: usize = 0;
pub(crate) const K_ISS: usize = 1;
pub(crate) const K_AUD: usize = 2;
pub(crate) const K_JTI: usize = 3;
pub(crate) const K_IAT: usize = 4;
pub(crate) const K_NBF: usize = 5;
pub(crate) const K_EXP: usize = 6;
pub(crate) const K_WID: usize = 7;
pub(crate) const K_TEN: usize = 8;
pub(crate) const K_SUB: usize = 9;
pub(crate) const K_OP: usize = 10;
pub(crate) const K_OPV: usize = 11;
pub(crate) const K_RES: usize = 12;
pub(crate) const K_CON: usize = 13;
pub(crate) const K_USE: usize = 14;
pub(crate) const K_KND: usize = 17;
pub(crate) const K_CFM: usize = 18;
pub(crate) const K_ROP: usize = 19;
/// Draft 4: present exactly when `cfm = 2`.
pub(crate) const K_MID: usize = 20;
/// Keys 0..=20 are defined; every key from 21 on is unknown.
const N_KEYS: usize = 21;

const fn mask(keys: &[usize]) -> u32 {
    let mut m = 0u32;
    let mut i = 0;
    while i < keys.len() {
        m |= 1 << keys[i];
        i += 1;
    }
    m
}

const COMMON: [usize; 10] = [
    K_VER, K_ISS, K_AUD, K_JTI, K_IAT, K_NBF, K_EXP, K_WID, K_TEN, K_SUB,
];
const WRITE_KEYS: u32 = mask(&COMMON) | mask(&[K_OP, K_OPV, K_RES, K_CON, K_USE, K_KND, K_CFM]);
const READ_KEYS: u32 = mask(&COMMON) | mask(&[K_KND, K_ROP]);

const INVALID: GrantError = GrantError::PayloadInvalid;

fn uint(v: &Value<'_>) -> Result<u64, GrantError> {
    match v {
        Value::Uint(n) => Ok(*n),
        _ => Err(INVALID),
    }
}

/// A uint ≤ 2^53 − 1 (times, and every uint in `res`/`con`).
fn uint53(v: &Value<'_>) -> Result<u64, GrantError> {
    let t = uint(v)?;
    if t > MAX_TIME { Err(INVALID) } else { Ok(t) }
}

fn id(v: &Value<'_>, max: usize) -> Result<String, GrantError> {
    match v {
        Value::Text(s) if is_id(s.as_bytes(), max) => Ok((*s).to_owned()),
        _ => Err(INVALID),
    }
}

fn op_name(v: &Value<'_>) -> Result<String, GrantError> {
    match v {
        Value::Text(s) if is_op_name(s.as_bytes()) => Ok((*s).to_owned()),
        _ => Err(INVALID),
    }
}

fn opv(v: &Value<'_>) -> Result<u16, GrantError> {
    match uint(v)? {
        n @ 1..=65535 => Ok(n as u16),
        _ => Err(INVALID),
    }
}

fn scalar(v: &Value<'_>) -> Result<Scalar, GrantError> {
    match v {
        Value::Uint(_) => Ok(Scalar::Uint(uint53(v)?)),
        Value::Text(s) if is_value_text(s.as_bytes()) => Ok(Scalar::Text((*s).to_owned())),
        _ => Err(INVALID),
    }
}

/// `res`/`con` map: uint keys 0..=15 (so at most 16 entries; order and uniqueness come from C8).
fn param_map<T>(
    v: &Value<'_>,
    f: impl Fn(&Value<'_>) -> Result<T, GrantError>,
) -> Result<Vec<(u8, T)>, GrantError> {
    let Value::Map(entries) = v else {
        return Err(INVALID);
    };
    if entries.len() > 16 {
        return Err(INVALID);
    }
    entries
        .iter()
        .map(|(k, val)| match k {
            Value::Uint(n) if *n <= 15 => Ok((*n as u8, f(val)?)),
            _ => Err(INVALID),
        })
        .collect()
}

fn constraint(v: &Value<'_>) -> Result<Constraint, GrantError> {
    let Value::Array(items) = v else {
        return Err(INVALID);
    };
    match items.as_slice() {
        [Value::Uint(0), val] => Ok(Constraint::Exact(scalar(val)?)),
        [Value::Uint(1), c] => Ok(Constraint::Bounded(uint53(c)?)),
        _ => Err(INVALID),
    }
}

/// Steps 7a and 7b.
pub(crate) fn parse(v: &Value<'_>) -> Result<Payload, GrantError> {
    let Value::Map(entries) = v else {
        return Err(INVALID);
    };
    // 7a: key 0 present as a uint other than 1.
    for (k, val) in entries {
        if let (Value::Uint(0), Value::Uint(ver)) = (k, val) {
            if *ver != 1 {
                return Err(GrantError::VersionUnsupported);
            }
        }
    }
    // 7b: keys are uints < 21 (uniqueness is guaranteed by C8).
    let mut slot: [Option<&Value<'_>>; N_KEYS] = [None; N_KEYS];
    let mut present = 0u32;
    for (k, val) in entries {
        match k {
            Value::Uint(n) if *n < N_KEYS as u64 => {
                slot[*n as usize] = Some(val);
                present |= 1 << *n;
            }
            _ => return Err(INVALID),
        }
    }
    let kind = match slot[K_KND].map(uint).transpose()? {
        Some(1) => GrantKind::Write,
        Some(2) => GrantKind::Read,
        _ => return Err(INVALID),
    };
    // Write grants: key 20 (`mid`) belongs to the key set exactly when `cfm` is the uint 2
    // (spec §5.2, Draft 4). A `cfm` of any other value or type leaves 20 outside the set; the
    // `cfm` value itself is checked below, so the result is `grant_payload_invalid` either way.
    let expected = match kind {
        GrantKind::Write if matches!(slot[K_CFM], Some(Value::Uint(2))) => {
            WRITE_KEYS | mask(&[K_MID])
        }
        GrantKind::Write => WRITE_KEYS,
        GrantKind::Read => READ_KEYS,
    };
    if present != expected {
        return Err(INVALID);
    }
    let get = |k: usize| slot[k].ok_or(INVALID);

    if uint(get(K_VER)?)? != 1 {
        return Err(INVALID);
    }
    let jti = match get(K_JTI)? {
        Value::Bytes(b) => <[u8; 16]>::try_from(*b).map_err(|_| INVALID)?,
        _ => return Err(INVALID),
    };
    let body = match kind {
        GrantKind::Write => {
            if uint(get(K_USE)?)? != 1 {
                return Err(INVALID);
            }
            let cfm = match uint(get(K_CFM)?)? {
                0 => Confirmation::None,
                1 => Confirmation::User,
                2 => match get(K_MID)? {
                    Value::Bytes(b) => Confirmation::Mandate {
                        mid: <[u8; 16]>::try_from(*b).map_err(|_| INVALID)?,
                    },
                    _ => return Err(INVALID),
                },
                _ => return Err(INVALID),
            };
            Body::Write {
                op: op_name(get(K_OP)?)?,
                opv: opv(get(K_OPV)?)?,
                res: param_map(get(K_RES)?, scalar)?,
                con: param_map(get(K_CON)?, constraint)?,
                cfm,
            }
        }
        GrantKind::Read => {
            let Value::Map(rop) = get(K_ROP)? else {
                return Err(INVALID);
            };
            if rop.is_empty() || rop.len() > 16 {
                return Err(INVALID);
            }
            let rop = rop
                .iter()
                .map(|(k, v)| Ok((op_name(k)?, opv(v)?)))
                .collect::<Result<Vec<_>, GrantError>>()?;
            Body::Read { rop }
        }
    };
    Ok(Payload {
        iss: id(get(K_ISS)?, 128)?,
        aud: id(get(K_AUD)?, 128)?,
        jti,
        iat: uint53(get(K_IAT)?)?,
        nbf: uint53(get(K_NBF)?)?,
        exp: uint53(get(K_EXP)?)?,
        wid: id(get(K_WID)?, 256)?,
        ten: id(get(K_TEN)?, 128)?,
        sub: id(get(K_SUB)?, 256)?,
        body,
    })
}
