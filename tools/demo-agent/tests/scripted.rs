// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! The scripted agent end to end: agent → real MCP front (`nodkey-mcp-front`) on `mcp.sock` →
//! a fake broker socket W that plays the §5 outcomes. This checks the agent's call order,
//! arguments and recording, and the front's mapping; the outcomes themselves are the fake's, not
//! Nodkey's (the full Demo A run is the next step).

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use demo_agent::{Client, RunOptions, run, script, select};
use nodkey_mcp_front::config::{FrontConfig, parse_operations};
use nodkey_mcp_front::mcp::{Front, Timing};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const OPS: &str =
    include_str!("../../../crates/nodkey-mcp-front/tests/fixtures/operations-demo-a.json");
const TICKET: &str = include_str!("../fixtures/ticket-T-1.txt");

fn uid() -> u32 {
    let p = std::env::temp_dir().join(format!("da-uid-{}", std::process::id()));
    std::fs::write(&p, b"").unwrap();
    std::fs::metadata(&p).unwrap().uid()
}

fn tmpdir(name: &str) -> PathBuf {
    let d = PathBuf::from("/tmp").join(format!("da-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("agent")).unwrap();
    std::fs::set_permissions(d.join("agent"), std::fs::Permissions::from_mode(0o750)).unwrap();
    d
}

fn pid(n: u64) -> String {
    format!("{:0>21}A", format!("p{n}"))
}

fn st(state: &str, awaiting: Option<&str>, class: Option<&str>) -> Value {
    let outcome = match class {
        Some(c) => json!({"class": c, "receipt_id": pid(900)}),
        None => Value::Null,
    };
    json!({"state": state, "awaiting": awaiting, "outcome": outcome, "expires_at": 1_900_000_000u64})
}

/// The §5 outcomes as the fake broker plays them (scripted principal: approves only S0).
fn plan_for(op: &str, p: &Value, seen: usize) -> Vec<Value> {
    let confirm = || st("PENDING", Some("confirmation"), None);
    let mandate = || st("PENDING", Some("mandate"), None);
    let cs = p["customer_sub"].as_str().unwrap_or("");
    match (op, cs, p["order_id"].as_u64(), p["amount_minor"].as_u64()) {
        ("mandate.support_ticket", "c42", _, _) if seen == 0 => {
            vec![confirm(), st("SUCCEEDED", None, Some("succeeded"))]
        }
        ("mandate.support_ticket", "c42", _, _) => {
            vec![confirm(), st("EXPIRED", None, Some("expired"))]
        }
        ("mandate.support_ticket", _, _, _) => vec![confirm(), st("DENIED", None, Some("denied"))],
        ("payments.support_refund", _, Some(101), Some(2000)) if seen == 0 => {
            vec![mandate(), st("SUCCEEDED", None, Some("succeeded"))]
        }
        ("payments.support_refund", _, Some(101), _) => {
            vec![confirm(), st("FAILED", None, Some("failed"))]
        }
        ("payments.support_refund", _, Some(102), Some(100)) => {
            vec![confirm(), st("EXPIRED", None, Some("expired"))]
        }
        ("payments.support_refund", _, Some(102), _) => {
            vec![mandate(), st("SUCCEEDED", None, Some("succeeded"))]
        }
        ("messages.send", "c42", _, _) => vec![mandate(), st("SUCCEEDED", None, Some("succeeded"))],
        _ => vec![confirm(), st("DENIED", None, Some("denied"))],
    }
}

#[derive(Default)]
struct Fake {
    requests: Vec<Value>,
    records: std::collections::HashMap<String, Vec<Value>>,
    proposals: Vec<Value>,
}

async fn fake_broker(path: &Path) -> Arc<Mutex<Fake>> {
    let l = UnixListener::bind(path).unwrap();
    let state: Arc<Mutex<Fake>> = Arc::default();
    let s2 = state.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let state = s2.clone();
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let req: Value = serde_json::from_str(&line).unwrap();
                    let id = req["id"].clone();
                    let ok =
                        |r: Value| json!({"v":2,"id":id,"correlation_id":"c","ok":true,"result":r});
                    let err = |c: &str| json!({"v":2,"id":id,"correlation_id":"c","ok":false,"error":{"code":c,"message":"m"}});
                    let resp = {
                        let mut g = state.lock().unwrap();
                        g.requests.push(req.clone());
                        let a = &req["args"];
                        match req["op"].as_str().unwrap() {
                            "effect.propose" => {
                                let op = a["op"].as_str().unwrap().to_owned();
                                // Earlier identical proposals (S10 repeats S2, S11 repeats S0).
                                let seen = g
                                    .proposals
                                    .iter()
                                    .filter(|p| {
                                        p["op"] == op.as_str() && p["params"] == a["params"]
                                    })
                                    .count();
                                g.proposals.push(json!({"op": op, "params": a["params"]}));
                                let id = pid(g.proposals.len() as u64);
                                let plan = plan_for(&op, &a["params"], seen);
                                g.records.insert(id.clone(), plan);
                                ok(
                                    json!({"pending_id": id, "confirm_url": "x", "expires_at": 1_900_000_000u64}),
                                )
                            }
                            "effect.status" => {
                                let p = a["pending_id"].as_str().unwrap().to_owned();
                                match g.records.get_mut(&p) {
                                    Some(plan) => {
                                        let mut s = if plan.len() > 1 {
                                            plan.remove(0)
                                        } else {
                                            plan[0].clone()
                                        };
                                        s["pending_id"] = json!(p);
                                        ok(s)
                                    }
                                    None => err("not_found"),
                                }
                            }
                            "payments.support_get_order"
                                if a["order_id"] == 101
                                    && g.requests
                                        .iter()
                                        .filter(|r| r["op"] == "payments.support_get_order")
                                        .count()
                                        == 1 =>
                            {
                                ok(json!({"order_id":101,"customer_sub":"c42","currency":"EUR",
                                          "amount_minor":3500,"refunded_minor":0,"status":"captured"}))
                            }
                            _ => err("grant_denied"),
                        }
                    };
                    if w.write_all(format!("{resp}\n").as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    state
}

async fn start(name: &str) -> (PathBuf, PathBuf, Arc<Mutex<Fake>>) {
    let dir = tmpdir(name);
    let broker_path = dir.join("broker.sock");
    let fake = fake_broker(&broker_path).await;
    let me = uid();
    let cfg = json!({
        "format": "nodkey.mcp-front.v1",
        "listen_socket": dir.join("agent/mcp.sock"), "agent_uid": me,
        "broker_socket": broker_path, "broker_uid": me,
        "operations_path": "/unused",
        "write_ops": ["payments.support_refund", "messages.send", "mandate.support_ticket"],
        "read_ops": ["payments.support_get_order"],
        "approver": {"ten": "shop1", "sub": "op_ana"},
        "auth_origin": "https://auth.shop.test"
    });
    let ops = parse_operations(OPS.as_bytes()).unwrap();
    let j = nodkey_mcp_front::json::parse(cfg.to_string().as_bytes()).unwrap();
    let cfg = FrontConfig::from_parts(&j, &ops).unwrap();
    let sock = cfg.listen_socket.clone();
    let timing = Timing {
        write_poll: Duration::from_millis(5),
        settle: Duration::from_millis(200),
        status_poll: Duration::from_millis(5),
        second: Duration::from_millis(10),
    };
    let front = Arc::new(Front::new(cfg, timing));
    let l = nodkey_mcp_front::server::bind(&sock).unwrap();
    tokio::spawn(nodkey_mcp_front::server::serve(front, l, me));
    (dir, sock, fake)
}

fn final_status(step: &Value) -> Value {
    match step["polls"].as_array().and_then(|p| p.last()) {
        Some(p) => p["result"]["structuredContent"]["status"].clone(),
        None => step["response"]["result"]["structuredContent"]["status"].clone(),
    }
}

#[tokio::test]
async fn full_script_through_the_front() {
    let (_dir, sock, fake) = start("full").await;
    let s = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let (r, w) = s.into_split();
    let mut c = Client::new(BufReader::new(r), w);
    let mut rec = Vec::new();
    let opts = RunOptions {
        steps: script(),
        decision_wait_s: 2,
    };
    run(&mut c, TICKET, &opts, |v| rec.push(v)).await.unwrap();

    assert_eq!(rec[0]["event"], "ticket");
    assert!(
        rec[0]["text"].as_str().unwrap().contains("x@evil.example"),
        "whole ticket read"
    );
    assert_eq!(
        rec[1]["response"]["result"]["supportedVersions"],
        json!(["2026-07-28"])
    );
    assert_eq!(
        rec[2]["names"],
        json!([
            "payments.support_refund",
            "payments.support_get_order",
            "messages.send",
            "mandate.support_ticket",
            "nodkey.effect_status"
        ])
    );
    let steps: Vec<&Value> = rec.iter().filter(|v| v["event"] == "step").collect();
    let by = |id: &str| *steps.iter().find(|s| s["step"] == id).unwrap();
    let ids: Vec<&str> = steps.iter().map(|s| s["step"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        [
            "S0p", "S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9a", "S9b", "S10",
            "S11", "S12a", "S12b"
        ]
    );
    for (id, want) in [
        ("S0p", "rejected"),
        ("S0", "succeeded"),
        ("S2", "succeeded"),
        ("S3", "rejected"),
        ("S7", "rejected"),
        ("S8", "succeeded"),
        ("S9a", "succeeded"),
        ("S9b", "succeeded"),
        ("S10", "failed"),
        ("S11", "expired"),
        ("S12b", "expired"),
    ] {
        assert_eq!(final_status(by(id)), want, "{id}");
    }
    // S0', S3, S7, S10 went through pending_confirmation first.
    for id in ["S0p", "S3", "S7", "S10"] {
        assert_eq!(
            by(id)["response"]["result"]["structuredContent"]["status"],
            "pending_confirmation",
            "{id}"
        );
    }
    assert_eq!(
        by("S1")["response"]["result"]["structuredContent"]["order_id"],
        101
    );
    assert_eq!(
        by("S4")["response"]["result"]["structuredContent"],
        json!({"error": "grant_denied"})
    );
    assert_eq!(
        by("S12a")["response"]["result"]["structuredContent"],
        json!({"error": "grant_denied"})
    );
    // S5: no such tool (-32602). S6: `to` is not an argument (invalid_argument, no record).
    assert_eq!(by("S5")["response"]["error"]["code"], -32602);
    assert_eq!(
        by("S6")["response"]["result"]["structuredContent"],
        json!({"error": "invalid_argument"})
    );
    // S8's body is what the agent had from S1 (order data, no card data).
    let body = by("S8")["arguments"]["body"].as_str().unwrap();
    assert!(body.starts_with("Card details: {"));
    assert!(body.contains("\"order_id\":101"));
    assert!(body.len() <= 256);

    // What reached socket W: proposals in script order, approver always the enrolment, never
    // `to`, never a card operation.
    let g = fake.lock().unwrap();
    let props: Vec<(String, Value)> = g
        .requests
        .iter()
        .filter(|r| r["op"] == "effect.propose")
        .map(|r| {
            assert_eq!(r["args"]["approver"], json!({"ten":"shop1","sub":"op_ana"}));
            (
                r["args"]["op"].as_str().unwrap().to_owned(),
                r["args"]["params"].clone(),
            )
        })
        .collect();
    let ops: Vec<&str> = props.iter().map(|p| p.0.as_str()).collect();
    assert_eq!(
        ops,
        [
            "mandate.support_ticket",
            "mandate.support_ticket",
            "payments.support_refund",
            "payments.support_refund",
            "messages.send",
            "messages.send",
            "payments.support_refund",
            "payments.support_refund",
            "payments.support_refund",
            "mandate.support_ticket",
            "payments.support_refund"
        ]
    );
    assert!(props.iter().all(|p| p.1.get("to").is_none()));
    assert!(
        !g.requests
            .iter()
            .any(|r| r["op"].as_str().unwrap().contains("card"))
    );
}

#[tokio::test]
async fn binary_runs_selected_steps_and_records() {
    let (dir, sock, _fake) = start("bin").await;
    std::fs::write(dir.join("ticket.txt"), TICKET).unwrap();
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_demo-agent"))
        .args(["--ticket"])
        .arg(dir.join("ticket.txt"))
        .arg("--mcp-socket")
        .arg(&sock)
        .args(["--steps", "S1,S5,S6", "--decision-wait-s", "0", "--record"])
        .arg(dir.join("rec.jsonl"))
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec: Vec<Value> = std::fs::read_to_string(dir.join("rec.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let steps: Vec<&str> = rec
        .iter()
        .filter(|v| v["event"] == "step")
        .map(|v| v["step"].as_str().unwrap())
        .collect();
    assert_eq!(steps, ["S1", "S5", "S6"]);
    assert_eq!(rec.last().unwrap()["event"], "done");
    assert!(select("S6").is_ok());
}

#[tokio::test]
async fn binary_fails_closed_on_bad_transport_and_refuses_model_mode() {
    let dir = tmpdir("badtx");
    std::fs::write(dir.join("ticket.txt"), TICKET).unwrap();
    // `cat` echoes the agent's own request: not a response → protocol error, exit 1.
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_demo-agent"))
        .arg("--ticket")
        .arg(dir.join("ticket.txt"))
        .args(["--mcp-command", "/bin/cat", "--steps", "S1"])
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let last = String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap()
        .to_owned();
    assert!(last.contains("\"event\":\"error\""), "{last}");
    // Optional model mode is off and not implemented: explicit refusal.
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_demo-agent"))
        .args(["--model", "http://127.0.0.1:1", "--ticket", "/dev/null"])
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not implemented"));
}
