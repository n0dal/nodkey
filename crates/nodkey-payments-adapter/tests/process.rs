// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! PT-24 (process level): the binary refuses to start (exit 2, `refuse_start` log line) when an
//! operator file is not owned by root (here: owned by the adapter's own uid), when the config is invalid, or when it is
//! missing. Test files are necessarily owned by the test user, which is the adapter's uid here, so
//! the success path of `load` cannot run unprivileged; the individual checks are unit-tested in
//! `src/config.rs` with explicit uids.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use common::*;
use serde_json::Value;

fn run(args: &[&str]) -> (i32, Vec<Value>) {
    let out = Command::new(env!("CARGO_BIN_EXE_nodkey-payments-adapter"))
        .args(args)
        .output()
        .unwrap();
    let lines = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    (out.status.code().unwrap_or(-1), lines)
}

fn refusal(lines: &[Value]) -> String {
    lines
        .iter()
        .find(|v| v["event"] == "refuse_start")
        .map(|v| v["reason"].as_str().unwrap().to_owned())
        .expect("refuse_start line")
}

#[test]
fn usage_and_missing_config() {
    assert_eq!(run(&[]).0, 2);
    assert_eq!(run(&["--config"]).0, 2);
    let (code, lines) = run(&["--config", "/nonexistent/nodkey/config.json"]);
    assert_eq!(code, 2);
    assert!(refusal(&lines).contains("missing"));
}

#[test]
fn config_owned_by_adapter_uid_is_refused() {
    let d = tmpdir("proc");
    let cfg = d.join("config.json");
    let o = Opts::new("127.0.0.1:9".parse().unwrap());
    std::fs::write(&cfg, adapter_config(&o, &d.join("p.sock")).to_string()).unwrap();
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o444)).unwrap();
    let (code, lines) = run(&["--config", cfg.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(refusal(&lines).contains("not owned by root"), "{lines:?}");
    // A symlinked config is refused before anything else.
    let link = d.join("link.json");
    std::os::unix::fs::symlink(&cfg, &link).unwrap();
    let (code, lines) = run(&["--config", link.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(refusal(&lines).contains("symlink"));
}
