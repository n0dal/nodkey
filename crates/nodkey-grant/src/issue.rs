// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Issuer side (spec §9): builds canonical grants and refuses to sign non-conforming ones.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};

use crate::cbor::{self, Value};
use crate::error::BuildError;
use crate::ops::ParamValue;
use crate::payload::{self, Confirmation, GrantKind};
use crate::registry::{ALG_ED25519, derive_kid};
use crate::verify::{external_aad, sig_structure};
use crate::{MAX_GRANT_BYTES, MAX_SKEW, MAX_TTL, TYP};

#[derive(Debug, Clone)]
enum ConEntry {
    Exact(ParamValue),
    Bounded(u64),
}

#[derive(Debug, Clone)]
enum Body {
    Write {
        op: String,
        opv: u16,
        res: BTreeMap<u8, ParamValue>,
        con: BTreeMap<u8, ConEntry>,
        cfm: Confirmation,
    },
    Read {
        rop: BTreeMap<String, u16>,
    },
}

/// Builder for one grant. Every field is required; `sign` validates the result against the
/// payload schema (spec §5) and the time rules of §9 / steps 8b–8c. The Authority should use
/// `nbf = iat` with `iat` from its own clock (spec §9).
///
/// `jti` must come from a CSPRNG and never be reused (spec §9); this crate does not generate it.
#[derive(Debug, Clone)]
pub struct GrantBuilder {
    iss: Option<String>,
    aud: Option<String>,
    jti: Option<[u8; 16]>,
    times: Option<(u64, u64, u64)>,
    wid: Option<String>,
    ten: Option<String>,
    sub: Option<String>,
    body: Body,
    misuse: Option<&'static str>,
}

impl GrantBuilder {
    fn new(body: Body) -> Self {
        GrantBuilder {
            iss: None,
            aud: None,
            jti: None,
            times: None,
            wid: None,
            ten: None,
            sub: None,
            body,
            misuse: None,
        }
    }

    /// A write grant (`knd = 1`) for one operation. `cfm` defaults to 0.
    pub fn write(op: &str, opv: u16) -> Self {
        Self::new(Body::Write {
            op: op.to_owned(),
            opv,
            res: BTreeMap::new(),
            con: BTreeMap::new(),
            cfm: Confirmation::None,
        })
    }

    /// A read grant (`knd = 2`); add operations with [`GrantBuilder::read_op`].
    pub fn read() -> Self {
        Self::new(Body::Read {
            rop: BTreeMap::new(),
        })
    }

    pub fn kind(&self) -> GrantKind {
        match self.body {
            Body::Write { .. } => GrantKind::Write,
            Body::Read { .. } => GrantKind::Read,
        }
    }

    pub fn issuer(mut self, iss: &str) -> Self {
        self.iss = Some(iss.to_owned());
        self
    }
    pub fn audience(mut self, aud: &str) -> Self {
        self.aud = Some(aud.to_owned());
        self
    }
    pub fn jti(mut self, jti: [u8; 16]) -> Self {
        self.jti = Some(jti);
        self
    }
    /// Sets `iat`, `nbf`, `exp`.
    pub fn times(mut self, iat: u64, nbf: u64, exp: u64) -> Self {
        self.times = Some((iat, nbf, exp));
        self
    }
    pub fn workload(mut self, wid: &str) -> Self {
        self.wid = Some(wid.to_owned());
        self
    }
    pub fn tenant(mut self, ten: &str) -> Self {
        self.ten = Some(ten.to_owned());
        self
    }
    pub fn subject(mut self, sub: &str) -> Self {
        self.sub = Some(sub.to_owned());
        self
    }

    /// Write grants: binds resource parameter `key` (exact). On a read grant, `sign` fails.
    pub fn resource(mut self, key: u8, value: ParamValue) -> Self {
        match &mut self.body {
            Body::Write { res, .. } => {
                res.insert(key, value);
            }
            Body::Read { .. } => self.misuse = Some("write-grant field set on a read grant"),
        }
        self
    }
    /// Write grants: binds `con` key `key` to an exact value.
    pub fn exact(mut self, key: u8, value: ParamValue) -> Self {
        match &mut self.body {
            Body::Write { con, .. } => {
                con.insert(key, ConEntry::Exact(value));
            }
            Body::Read { .. } => self.misuse = Some("write-grant field set on a read grant"),
        }
        self
    }
    /// Write grants: binds `con` key `key` to an inclusive ceiling.
    pub fn bounded(mut self, key: u8, ceiling: u64) -> Self {
        match &mut self.body {
            Body::Write { con, .. } => {
                con.insert(key, ConEntry::Bounded(ceiling));
            }
            Body::Read { .. } => self.misuse = Some("write-grant field set on a read grant"),
        }
        self
    }
    /// Write grants: `cfm = 1` — only when the user approved exactly these values on the auth
    /// origin (spec §9, D-2).
    /// `confirmed(false)` sets `cfm = 0`. Either call replaces an earlier [`Self::mandated`].
    pub fn confirmed(mut self, cfm: bool) -> Self {
        match &mut self.body {
            Body::Write { cfm: c, .. } => {
                *c = if cfm {
                    Confirmation::User
                } else {
                    Confirmation::None
                }
            }
            Body::Read { .. } => self.misuse = Some("write-grant field set on a read grant"),
        }
        self
    }
    /// Write grants (Draft 4): `cfm = 2` with key 20 `mid` — only for a `mandate_eligible`
    /// operation whose effect the Authority found within the active mandate `mid` on its **own**
    /// mandate record and counters, never on a caller's word (spec §9). Replaces an earlier
    /// [`Self::confirmed`].
    pub fn mandated(mut self, mid: [u8; 16]) -> Self {
        match &mut self.body {
            Body::Write { cfm: c, .. } => *c = Confirmation::Mandate { mid },
            Body::Read { .. } => self.misuse = Some("write-grant field set on a read grant"),
        }
        self
    }
    /// Read grants: adds an operation to `rop`.
    pub fn read_op(mut self, op: &str, opv: u16) -> Self {
        match &mut self.body {
            Body::Read { rop } => {
                rop.insert(op.to_owned(), opv);
            }
            Body::Write { .. } => self.misuse = Some("read-grant field set on a write grant"),
        }
        self
    }

    /// Encodes the payload (deterministic CBOR).
    fn payload(&self) -> Result<Vec<u8>, BuildError> {
        if let Some(m) = self.misuse {
            return Err(BuildError(m));
        }
        let missing = BuildError("missing field");
        let iss = self.iss.as_deref().ok_or(missing.clone())?;
        let aud = self.aud.as_deref().ok_or(missing.clone())?;
        let jti = self.jti.as_ref().ok_or(missing.clone())?;
        let (iat, nbf, exp) = self.times.ok_or(missing.clone())?;
        let wid = self.wid.as_deref().ok_or(missing.clone())?;
        let ten = self.ten.as_deref().ok_or(missing.clone())?;
        let sub = self.sub.as_deref().ok_or(missing)?;
        // Spec §9 and steps 8b/8c: nbf - iat <= skew (5), exp - iat <= max_ttl (30).
        if !(iat <= nbf && nbf - iat <= MAX_SKEW && nbf < exp && exp - iat <= MAX_TTL) {
            return Err(BuildError(
                "times must satisfy iat <= nbf <= iat + 5 and nbf < exp <= iat + 30",
            ));
        }
        let u = |n: usize| Value::Uint(n as u64);
        fn scalar(v: &ParamValue) -> Value<'_> {
            match v {
                ParamValue::Uint(n) => Value::Uint(*n),
                ParamValue::Text(s) => Value::Text(s.as_str()),
            }
        }
        let mut m: Vec<(Value<'_>, Value<'_>)> = vec![
            (u(payload::K_VER), Value::Uint(1)),
            (u(payload::K_ISS), Value::Text(iss)),
            (u(payload::K_AUD), Value::Text(aud)),
            (u(payload::K_JTI), Value::Bytes(jti)),
            (u(payload::K_IAT), Value::Uint(iat)),
            (u(payload::K_NBF), Value::Uint(nbf)),
            (u(payload::K_EXP), Value::Uint(exp)),
            (u(payload::K_WID), Value::Text(wid)),
            (u(payload::K_TEN), Value::Text(ten)),
            (u(payload::K_SUB), Value::Text(sub)),
        ];
        match &self.body {
            Body::Write {
                op,
                opv,
                res,
                con,
                cfm,
            } => {
                let res = res
                    .iter()
                    .map(|(k, v)| (Value::Uint(u64::from(*k)), scalar(v)))
                    .collect();
                let con = con
                    .iter()
                    .map(|(k, c)| {
                        let entry = match c {
                            ConEntry::Exact(v) => Value::Array(vec![Value::Uint(0), scalar(v)]),
                            ConEntry::Bounded(n) => {
                                Value::Array(vec![Value::Uint(1), Value::Uint(*n)])
                            }
                        };
                        (Value::Uint(u64::from(*k)), entry)
                    })
                    .collect();
                m.extend([
                    (u(payload::K_OP), Value::Text(op)),
                    (u(payload::K_OPV), Value::Uint(u64::from(*opv))),
                    (u(payload::K_RES), Value::Map(res)),
                    (u(payload::K_CON), Value::Map(con)),
                    (u(payload::K_USE), Value::Uint(1)),
                    (u(payload::K_KND), Value::Uint(1)),
                    (u(payload::K_CFM), Value::Uint(u64::from(cfm.cfm()))),
                ]);
                if let Confirmation::Mandate { mid } = cfm {
                    m.push((u(payload::K_MID), Value::Bytes(mid)));
                }
            }
            Body::Read { rop } => {
                let rop = rop
                    .iter()
                    .map(|(k, v)| (Value::Text(k), Value::Uint(u64::from(*v))))
                    .collect();
                m.extend([
                    (u(payload::K_KND), Value::Uint(2)),
                    (u(payload::K_ROP), Value::Map(rop)),
                ]);
            }
        }
        let mut out = Vec::new();
        cbor::encode(&Value::Map(m), &mut out).map_err(|_| BuildError("duplicate key"))?;
        // Self-check: the payload must pass the verifier's own decoding and schema (steps 6–7).
        let decoded = cbor::decode(&out, cbor::PAYLOAD).map_err(|_| BuildError("encoding"))?;
        payload::parse(&decoded).map_err(|_| BuildError("payload violates spec §5"))?;
        Ok(out)
    }

    /// Signs the grant with `key` for this builder's audience and returns the grant bytes:
    /// `0xd2` + `[protected, {}, payload, signature]`.
    pub fn sign(&self, key: &SigningKey) -> Result<Vec<u8>, BuildError> {
        let payload = self.payload()?;
        let kid = derive_kid(&key.verifying_key().to_bytes());
        let mut protected = Vec::with_capacity(53);
        cbor::encode(
            &Value::Map(vec![
                (Value::Uint(1), Value::Nint((-1 - ALG_ED25519) as u64)),
                (Value::Uint(4), Value::Bytes(&kid)),
                (Value::Uint(16), Value::Text(TYP)),
            ]),
            &mut protected,
        )
        .map_err(|_| BuildError("duplicate key"))?;
        let aud = self.aud.as_deref().unwrap_or_default();
        let msg = sig_structure(&protected, &external_aad(aud), &payload);
        let sig = key.sign(&msg).to_bytes();

        let mut g = vec![0xd2];
        cbor::encode(
            &Value::Array(vec![
                Value::Bytes(&protected),
                Value::Map(vec![]),
                Value::Bytes(&payload),
                Value::Bytes(&sig),
            ]),
            &mut g,
        )
        .map_err(|_| BuildError("duplicate key"))?;
        if g.len() > MAX_GRANT_BYTES {
            return Err(BuildError("grant exceeds 2048 bytes"));
        }
        Ok(g)
    }
}
