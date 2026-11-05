// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! Nodkey-Grant v1 test-vector tool (TEST-ONLY keys).
//!
//!   nodkey-grant-v1-vectors generate <dir>   write manifest.json, registry.json, grants/, registries/
//!   nodkey-grant-v1-vectors check <dir>      run every vector through the reference verifier

mod cbor;
mod check;
mod generate;
mod verify;

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("generate"), Some(dir)) => {
            generate::run(Path::new(dir));
            ExitCode::SUCCESS
        }
        (Some("check"), Some(dir)) => {
            if check::run(Path::new(dir)) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        _ => {
            eprintln!("usage: {} generate|check <vector-dir>", args[0]);
            ExitCode::from(2)
        }
    }
}
