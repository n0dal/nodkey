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

impl GrantKind {
    pub const fn as_u8(self) -> u8 {
        match self {
            GrantKind::Write => 1,
            GrantKind::Read => 2,
        }
    }
}

/// `con` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Constraint<'a> {
    Exact(Scalar<'a>),
    Bounded(u64),
}

#[derive(Debug, Clone)]
pub(crate) enum Body<'a> {
    Write {
        op: &'a str,
        opv: u16,
        /// Ascending key order.
        res: Vec<(u8, Scalar<'a>)>,
        /// Ascending key order.
        con: Vec<(u8, Constraint<'a>)>,
        cfm: bool,
    },
    Read {
        /// Map order (the deterministic encoding order).
        rop: Vec<(&'a str, u16)>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct Payload<'a> {
    pub iss: &'a str,
    pub aud: &'a str,
    pub jti: [u8; 16],
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub wid: &'a str,
    pub ten: &'a str,
    pub sub: &'a str,
    pub body: Body<'a>,
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

fn time(v: &Value<'_>) -> Result<u64, GrantError> {
    let t = uint(v)?;
    if t > MAX_TIME { Err(INVALID) } else { Ok(t) }
}

fn id<'a>(v: &Value<'a>, max: usize) -> Result<&'a str, GrantError> {
    match v {
        Value::Text(s) if is_id(s.as_bytes(), max) => Ok(s),
        _ => Err(INVALID),
    }
}

fn op_name<'a>(v: &Value<'a>) -> Result<&'a str, GrantError> {
    match v {
        Value::Text(s) if is_op_name(s.as_bytes()) => Ok(s),
        _ => Err(INVALID),
    }
}

fn opv(v: &Value<'_>) -> Result<u16, GrantError> {
    match uint(v)? {
        n @ 1..=65535 => Ok(n as u16),
        _ => Err(INVALID),
    }
}

fn scalar<'a>(v: &Value<'a>) -> Result<Scalar<'a>, GrantError> {
    match v {
        Value::Uint(n) => Ok(Scalar::Uint(*n)),
        Value::Text(s) if is_value_text(s.as_bytes()) => Ok(Scalar::Text(s)),
        _ => Err(INVALID),
    }
}

/// `res`/`con` map: uint keys 0..=15 (so at most 16 entries; order and uniqueness come from C8).
fn param_map<'a, 'v, T>(
    v: &'v Value<'a>,
    mut f: impl FnMut(&'v Value<'a>) -> Result<T, GrantError>,
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

fn constraint<'a>(v: &Value<'a>) -> Result<Constraint<'a>, GrantError> {
    let Value::Array(items) = v else {
        return Err(INVALID);
    };
    match items.as_slice() {
        [Value::Uint(0), val] => Ok(Constraint::Exact(scalar(val)?)),
        [Value::Uint(1), Value::Uint(c)] => Ok(Constraint::Bounded(*c)),
        _ => Err(INVALID),
    }
}

/// Steps 7a and 7b.
pub(crate) fn parse<'a>(v: &Value<'a>) -> Result<Payload<'a>, GrantError> {
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
    // 7b: keys are uints < 20; collect slots (uniqueness is guaranteed by C8).
    let mut slot: [Option<&Value<'a>>; 20] = [None; 20];
    let mut present = 0u32;
    for (k, val) in entries {
        match k {
            Value::Uint(n) if *n < 20 => {
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
    let expected = match kind {
        GrantKind::Write => WRITE_KEYS,
        GrantKind::Read => READ_KEYS,
    };
    if present != expected {
        return Err(INVALID);
    }
    // All required keys are present from here on.
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
                0 => false,
                1 => true,
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
        iat: time(get(K_IAT)?)?,
        nbf: time(get(K_NBF)?)?,
        exp: time(get(K_EXP)?)?,
        wid: id(get(K_WID)?, 256)?,
        ten: id(get(K_TEN)?, 128)?,
        sub: id(get(K_SUB)?, 256)?,
        body,
    })
}
