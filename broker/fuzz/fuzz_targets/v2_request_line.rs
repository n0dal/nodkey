// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: protocol v2 request-line parsing (effect-protocol-v2 §2.1) and the pure argument
//! decoders the socket handlers apply to `args` before any database access.
//!
//! Path exercised: `wire::parse_envelope` (strict_json::check_strict + serde_json + envelope
//! shape) -> `wire::check_keys` / `wire::subject_arg` -> `digest::typed_params` with the
//! declared types of the named operation (`decls::expected`) -> `PendingFields::from_json` /
//! `validate` / `digest`; and the broker-side parsers of adapter replies (`adapter::parse_*`).
//!
//! Property checked: no panic / timeout / OOM.
#![no_main]

use std::collections::BTreeMap;

use nodkey_broker::v2::{adapter, decls, digest, service, wire};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let _ = nodkey_broker::strict_json::check_strict(data);
    let Ok(env) = wire::parse_envelope(data) else { return };
    let args = &env.args;
    let _ = wire::check_keys(args, &["op", "params", "approver"], &[]);
    let _ = wire::str_arg(args, "op");
    if let Some(a) = args.get("approver") {
        let _ = wire::subject_arg(a);
    }
    if let (Some(op), Some(Value::Object(raw))) =
        (args.get("op").and_then(Value::as_str), args.get("params"))
    {
        if let Some(decl) = decls::expected(op) {
            let types: BTreeMap<String, String> = decl
                .params
                .iter()
                .map(|p| (p.name.clone(), service::param_type_name(p.ty).to_owned()))
                .collect();
            let _ = digest::typed_params(raw, &types);
        }
        let _ = decls::is_support_op(op);
    }
    if let Some(rec) = args.get("record") {
        if let Ok(pf) = digest::PendingFields::from_json(rec) {
            if pf.validate().is_ok() {
                let _ = pf.digest();
            }
        }
    }
    let whole = Value::Object(args.clone());
    let _ = adapter::parse_refund(&whole);
    let _ = adapter::parse_attempt(args);
    let _ = adapter::parse_lookup(args);
    let _ = adapter::parse_idem(args);
});
