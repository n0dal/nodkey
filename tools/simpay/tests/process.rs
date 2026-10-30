// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Process-level behaviour: bind policy, config loading, snapshots.

mod common;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use simpay::{Config, StartOptions};

static N: AtomicUsize = AtomicUsize::new(0);

fn tmpdir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "simpay-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_config(extra: Value) -> PathBuf {
    let mut v = base_json();
    merge(&mut v, extra);
    let p = tmpdir().join("config.json");
    std::fs::write(&p, v.to_string()).unwrap();
    p
}

fn run(config: &PathBuf, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_simpay"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Spawns the binary and waits for the "api listening" line.
fn spawn_until_listening(config: &PathBuf, args: &[&str]) -> (std::process::Child, Vec<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_simpay"))
        .arg("--config")
        .arg(config)
        .args(args)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            // Keep draining even after the receiver is gone.
            let _ = tx.send(line);
        }
    });
    let mut lines = vec![];
    while let Ok(l) = rx.recv_timeout(Duration::from_secs(10)) {
        let done = l.contains("admin (fault control) listening");
        lines.push(l);
        if done {
            break;
        }
    }
    (child, lines)
}

#[test]
fn refuses_unspecified_bind_without_container_flag() {
    let cfg = write_config(json!({"api_listen": "0.0.0.0:0"}));
    let (code, err) = run(&cfg, &[]);
    assert_eq!(code, 2);
    assert!(
        err.contains("[simpay SIMULATOR] refusing to start"),
        "{err}"
    );
    assert!(err.contains("--container-bind"));
    let cfg = write_config(json!({"admin_listen": "[::]:0"}));
    assert_eq!(run(&cfg, &[]).0, 2);
}

#[test]
fn container_flag_allows_unspecified_bind() {
    let cfg = write_config(json!({"api_listen": "0.0.0.0:0", "admin_listen": "127.0.0.1:0"}));
    let (mut child, lines) = spawn_until_listening(&cfg, &["--container-bind"]);
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("api listening on 0.0.0.0:")),
        "{lines:?}"
    );
    assert!(lines.iter().all(|l| l.starts_with("[simpay SIMULATOR]")));
    assert!(lines.iter().any(|l| l.contains("NOT a real payment API")));
}

#[test]
fn refuses_public_address_even_with_container_flag() {
    let cfg = write_config(json!({"api_listen": "8.8.8.8:0"}));
    let (code, err) = run(&cfg, &["--container-bind"]);
    assert_eq!(code, 2);
    assert!(err.contains("public address"), "{err}");
}

#[test]
fn refuses_bad_configuration() {
    for (extra, why) in [
        (
            json!({"fixture": {"accounts": [{"id": "acct_demo0001", "keys": [{"secret": "sk_live_0123456789abcdef"}]}]}}),
            "API keys must start",
        ),
        (
            json!({"fixture": {"accounts": [{"id": "acct_demo0001", "keys": [{"secret": "rk_sim_0123456789abcdef"}]}]}}),
            "permissions",
        ),
        (json!({"bogus": 1}), "unknown field"),
        (json!({"admin_token": "short"}), "admin_token"),
        (
            json!({"idempotency_key_max_len": 256}),
            "idempotency_key_max_len",
        ),
    ] {
        let mut v = base_json();
        // Replace (not merge) the fixture's account list for the key cases.
        if let Some(accts) = extra.pointer("/fixture/accounts") {
            v["fixture"] = json!({"accounts": accts});
        } else {
            merge(&mut v, extra.clone());
        }
        let p = tmpdir().join("c.json");
        std::fs::write(&p, v.to_string()).unwrap();
        let (code, err) = run(&p, &[]);
        assert_eq!(code, 2, "{extra}");
        assert!(err.contains(why), "{why}: {err}");
    }
    let (code, _) = run(&PathBuf::from("/nonexistent/simpay.json"), &[]);
    assert_eq!(code, 2);
}

#[test]
fn shipped_example_configs_validate() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    for f in ["local-config.json", "container-config.json"] {
        let c = Config::load(&root.join(f)).unwrap_or_else(|e| panic!("{f}: {e}"));
        c.validate().unwrap_or_else(|e| panic!("{f}: {e}"));
    }
}

#[test]
fn fixture_path_resolves_relative_to_config() {
    let d = tmpdir();
    let fx = base_json()["fixture"].clone();
    std::fs::write(d.join("fx.json"), fx.to_string()).unwrap();
    let mut v = base_json();
    v.as_object_mut().unwrap().remove("fixture");
    v["fixture_path"] = json!("fx.json");
    std::fs::write(d.join("cfg.json"), v.to_string()).unwrap();
    let c = Config::load(&d.join("cfg.json")).unwrap();
    assert_eq!(c.fixture.unwrap().charges.len(), 5);
}

#[tokio::test]
async fn snapshot_round_trip() {
    let d = tmpdir();
    let snap = d.join("state.json");
    let extra = json!({"snapshot_path": snap});
    let s = start(extra.clone()).await;
    let first = refund(
        &s,
        SK,
        "k",
        &format!("charge={CH_USD}&amount=123&reference=eff_1"),
    )
    .await;
    assert_eq!(
        admin(&s, "POST", "/admin/snapshot", Value::Null)
            .await
            .status,
        200
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&snap).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let text = std::fs::read_to_string(&snap).unwrap();
    assert!(text.contains("\"simulator\": true"));
    s.shutdown().await;

    // Without --restore, state comes from the fixture.
    let fresh = start(extra.clone()).await;
    assert_eq!(ledger(&fresh, CH_USD).await, (0, 0, 0));
    fresh.shutdown().await;

    let restored = simpay::start(
        config(extra),
        StartOptions {
            restore: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(ledger(&restored, CH_USD).await, (1, 123, 123));
    let replay = refund(
        &restored,
        SK,
        "k",
        &format!("charge={CH_USD}&amount=123&reference=eff_1"),
    )
    .await;
    assert_eq!(
        replay.header("idempotent-replayed").as_deref(),
        Some("true")
    );
    assert_eq!(replay.body, first.body);
    let next = refund(&restored, SK, "k2", &format!("charge={CH_USD}&amount=1")).await;
    assert_ne!(
        next.json()["id"],
        first.json()["id"],
        "id counter persisted"
    );
}

#[tokio::test]
async fn reset_restores_fixture() {
    let s = start(json!({})).await;
    refund(&s, SK, "k", &format!("charge={CH_USD}&amount=1")).await;
    faults(&s, json!([{"fault": {"kind": "rate_limit"}}])).await;
    assert_eq!(
        admin(&s, "POST", "/admin/reset", Value::Null).await.status,
        200
    );
    assert_eq!(ledger(&s, CH_USD).await, (0, 0, 0));
    assert_eq!(
        refund(&s, SK, "k", &format!("charge={CH_USD}&amount=1"))
            .await
            .status,
        200
    );
}

#[cfg(unix)]
#[test]
fn sigterm_writes_snapshot() {
    let d = tmpdir();
    let snap = d.join("on-exit.json");
    let cfg = write_config(json!({"snapshot_path": snap}));
    let (mut child, _) = spawn_until_listening(&cfg, &[]);
    // The shell builtin works even where no `kill` binary is installed (slim images).
    let st = Command::new("sh")
        .arg("-c")
        .arg(format!("kill -TERM {}", child.id()))
        .status()
        .unwrap();
    assert!(st.success());
    let code = child.wait().unwrap();
    assert!(code.success(), "{code:?}");
    assert!(snap.exists());
}
