// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Broker configuration (trusted, operator-supplied) and the per-workload operation check.
//!
//! The configuration file is parsed with the same strictness as requests (duplicate keys and
//! unknown fields rejected) and validated before any socket is opened. Any error aborts startup.

use crate::protocol::{Deny, ErrorCode, OpKind, Operation};
use crate::strict_json;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::PathBuf;

pub const MIN_REQUEST_BYTES: usize = 256;
pub const MAX_REQUEST_BYTES: usize = 1 << 20;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// Protocol v1 exists only for the explicit Demo 1 profile (effect protocol v2 §2.1): the
    /// member is required and must be exactly "demo1" (BR-02).
    profile: String,
    max_request_bytes: usize,
    db: DbConfig,
    workloads: Vec<RawWorkload>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbConfig {
    pub host: String,
    pub port: u16,
    pub dbname: String,
    pub user: String,
    pub password_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkload {
    name: String,
    socket_path: PathBuf,
    uid: u32,
    allowed_ops: Vec<String>,
    max_transfer_cents: i64,
}

#[derive(Debug, Clone)]
pub struct Workload {
    pub name: String,
    pub socket_path: PathBuf,
    pub uid: u32,
    pub allowed_ops: HashSet<OpKind>,
    pub max_transfer_cents: i64,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub max_request_bytes: usize,
    pub db: DbConfig,
    pub workloads: Vec<Workload>,
}

impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Config, String> {
        strict_json::check_strict(bytes).map_err(|e| format!("config: {e}"))?;
        let raw: RawConfig = serde_json::from_slice(bytes).map_err(|e| format!("config: {e}"))?;
        if raw.profile != "demo1" {
            return Err("config: protocol v1 is allowed only in the demo1 profile".into());
        }

        if !(MIN_REQUEST_BYTES..=MAX_REQUEST_BYTES).contains(&raw.max_request_bytes) {
            return Err(format!(
                "config: max_request_bytes must be in {MIN_REQUEST_BYTES}..={MAX_REQUEST_BYTES}"
            ));
        }
        if raw.workloads.is_empty() {
            return Err("config: at least one workload required".into());
        }
        let mut names = HashSet::new();
        let mut sockets = HashSet::new();
        let mut workloads = Vec::with_capacity(raw.workloads.len());
        for w in raw.workloads {
            let name_ok = !w.name.is_empty()
                && w.name.len() <= 32
                && w.name.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
                });
            if !name_ok {
                return Err(format!("config: invalid workload name {:?}", w.name));
            }
            if !names.insert(w.name.clone()) {
                return Err(format!("config: duplicate workload name {}", w.name));
            }
            if !w.socket_path.is_absolute() {
                return Err(format!(
                    "config: socket_path for {} must be absolute",
                    w.name
                ));
            }
            if !sockets.insert(w.socket_path.clone()) {
                return Err(format!("config: duplicate socket_path for {}", w.name));
            }
            if w.uid == 0 {
                return Err(format!("config: workload {} must not be uid 0", w.name));
            }
            let mut allowed = HashSet::new();
            for op in &w.allowed_ops {
                let kind = OpKind::from_wire(op)
                    .ok_or_else(|| format!("config: unknown op {op:?} for {}", w.name))?;
                if !allowed.insert(kind) {
                    return Err(format!("config: duplicate op {op} for {}", w.name));
                }
            }
            if allowed.contains(&OpKind::Transfer) && w.max_transfer_cents <= 0 {
                return Err(format!(
                    "config: {} allows ledger.transfer but max_transfer_cents <= 0",
                    w.name
                ));
            }
            if w.max_transfer_cents < 0 {
                return Err(format!("config: {} max_transfer_cents negative", w.name));
            }
            workloads.push(Workload {
                name: w.name,
                socket_path: w.socket_path,
                uid: w.uid,
                allowed_ops: allowed,
                max_transfer_cents: w.max_transfer_cents,
            });
        }
        Ok(Config {
            max_request_bytes: raw.max_request_bytes,
            db: raw.db,
            workloads,
        })
    }
}

impl Workload {
    /// Configuration-dependent checks. State-dependent checks (account existence, funds) happen
    /// inside the database transaction.
    pub fn authorize(&self, op: &Operation) -> Result<(), Deny> {
        if !self.allowed_ops.contains(&op.kind()) {
            return Err(Deny::new(
                ErrorCode::OperationNotPermitted,
                op.kind().wire_name(),
            ));
        }
        if let Operation::Transfer(t) = op
            && t.amount_cents > self.max_transfer_cents
        {
            return Err(Deny::new(
                ErrorCode::LimitExceeded,
                format!(
                    "amount {} > max {}",
                    t.amount_cents, self.max_transfer_cents
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::parse_request;

    fn sample(workloads: &str) -> String {
        format!(
            r#"{{"profile":"demo1","max_request_bytes":16384,
                "db":{{"host":"db","port":5432,"dbname":"ledger","user":"nodkey_broker","password_file":"/run/secrets/p"}},
                "workloads":[{workloads}]}}"#
        )
    }

    const APP1: &str = r#"{"name":"app1","socket_path":"/run/nodkey/app1/broker.sock","uid":10001,
        "allowed_ops":["ledger.get_balance","ledger.transfer"],"max_transfer_cents":50000}"#;
    const APP2: &str = r#"{"name":"app2","socket_path":"/run/nodkey/app2/broker.sock","uid":10003,
        "allowed_ops":["ledger.get_balance"],"max_transfer_cents":0}"#;

    #[test]
    fn parses_valid_config() {
        let c = Config::parse(sample(&format!("{APP1},{APP2}")).as_bytes()).unwrap();
        assert_eq!(c.workloads.len(), 2);
        assert_eq!(c.workloads[0].uid, 10001);
        assert!(c.workloads[1].allowed_ops.contains(&OpKind::GetBalance));
        assert!(!c.workloads[1].allowed_ops.contains(&OpKind::Transfer));
    }

    /// T32 (v1 side): v1 only under the demo1 profile.
    #[test]
    fn v1_profile_must_be_demo1() {
        assert!(Config::parse(sample(APP1).as_bytes()).is_ok());
        // BR-02: the explicit profile is required.
        let absent = sample(APP1).replace(r#""profile":"demo1","#, "");
        assert!(Config::parse(absent.as_bytes()).is_err());
        for p in ["phase3", "Demo1", "demo1 ", ""] {
            let bad = sample(APP1).replace(r#""profile":"demo1""#, &format!(r#""profile":"{p}""#));
            assert!(Config::parse(bad.as_bytes()).is_err(), "{p}");
        }
    }

    #[test]
    fn rejects_bad_configs() {
        let bad = [
            sample(&APP1.replace("ledger.transfer", "ledger.delete")),
            sample(&format!("{APP1},{APP1}")),
            sample(&APP1.replace("10001", "0")),
            sample(&APP1.replace("50000", "0")),
            sample(&APP1.replace("/run/nodkey", "run/nodkey")),
            sample(&APP1.replace(r#""uid":10001"#, r#""uid":10001,"uid":10002"#)),
            sample(&APP1.replace(r#""uid":10001"#, r#""uid":10001,"extra":1"#)),
            sample(&APP1.replace("app1", "App 1")),
            sample(""),
            sample(APP1).replace("16384", "10"),
            sample(APP1).replace(r#""profile":"demo1""#, r#""profile":"phase3""#),
        ];
        for b in bad {
            assert!(Config::parse(b.as_bytes()).is_err(), "should reject: {b}");
        }
    }

    fn op(line: &str) -> Operation {
        parse_request(line.as_bytes()).unwrap().op
    }

    #[test]
    fn authorize_checks_allowed_ops_and_limits() {
        let c = Config::parse(sample(&format!("{APP1},{APP2}")).as_bytes()).unwrap();
        let (app1, app2) = (&c.workloads[0], &c.workloads[1]);
        let tr = |n: i64| {
            op(&format!(
                r#"{{"v":1,"id":"x","op":"ledger.transfer","args":{{"from":"alice","to":"bob","amount_cents":{n},"idempotency_key":"aaaaaaaaaaaaaaaa"}}}}"#
            ))
        };
        let gb = op(r#"{"v":1,"id":"x","op":"ledger.get_balance","args":{"account":"alice"}}"#);

        assert!(app1.authorize(&gb).is_ok());
        assert!(app1.authorize(&tr(1)).is_ok());
        assert!(app1.authorize(&tr(50000)).is_ok());
        assert_eq!(
            app1.authorize(&tr(50001)).unwrap_err().code,
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            app1.authorize(&tr(i64::MAX)).unwrap_err().code,
            ErrorCode::LimitExceeded
        );

        assert!(app2.authorize(&gb).is_ok());
        assert_eq!(
            app2.authorize(&tr(1)).unwrap_err().code,
            ErrorCode::OperationNotPermitted
        );
    }
}
