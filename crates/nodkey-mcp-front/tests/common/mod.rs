// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Test harness: a fake broker socket W and a running front on a real `mcp.sock`.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nodkey_mcp_front::config::{FrontConfig, parse_operations};
use nodkey_mcp_front::json;
use nodkey_mcp_front::mcp::{Front, Timing};
use nodkey_mcp_front::server;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

pub const OPS: &str = include_str!("../fixtures/operations-demo-a.json");
pub const V: &str = "2026-07-28";

static N: AtomicU64 = AtomicU64::new(0);

pub fn my_uid() -> u32 {
    std::fs::metadata("/proc/self").map_or_else(
        |_| {
            let p = std::env::temp_dir().join(format!("gmf-uid-{}", std::process::id()));
            std::fs::write(&p, b"").unwrap();
            std::fs::metadata(&p).unwrap().uid()
        },
        |m| m.uid(),
    )
}

pub fn tmpdir(name: &str) -> PathBuf {
    // Short base path: Unix socket paths are limited to ~104 bytes on macOS.
    let d = PathBuf::from("/tmp").join(format!(
        "gmf-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Deterministic, canonical 22-character pending ids (last character in `AQgw`).
pub fn pid(n: u64) -> String {
    format!("{:0>21}A", format!("p{n}"))
}

/// What the fake broker does.
#[derive(Default)]
pub struct BrokerState {
    /// Every request envelope received.
    pub requests: Vec<Value>,
    /// `effect.propose`: an error code, or `None` to create a record.
    pub propose_error: Option<String>,
    /// Status results returned by `effect.status`, in order; the last one repeats.
    pub plan: VecDeque<Value>,
    /// Per-record status results (pid → plan) once proposed.
    pub records: HashMap<String, VecDeque<Value>>,
    /// Reply to any read method: `Ok(result)` or `Err(code)`.
    pub read: Option<Result<Value, String>>,
    /// Replace the next response line verbatim.
    pub raw_reply: Option<String>,
    pub next_pid: u64,
}

pub type Shared = Arc<Mutex<BrokerState>>;

pub fn status(pid: &str, state: &str, awaiting: Option<&str>, outcome: Value) -> Value {
    json!({"pending_id": pid, "state": state, "expires_at": 1_900_000_000u64,
           "outcome": outcome, "awaiting": awaiting})
}

fn respond(st: &mut BrokerState, req: &Value) -> String {
    let id = req["id"].clone();
    if let Some(raw) = st.raw_reply.take() {
        return raw;
    }
    let ok =
        |r: Value| json!({"v":2,"id":id,"correlation_id":"c1","ok":true,"result":r}).to_string();
    let err = |c: &str| {
        json!({"v":2,"id":id,"correlation_id":"c1","ok":false,
               "error":{"code":c,"message":"BROKER FREE TEXT MUST NOT LEAK"}})
        .to_string()
    };
    match req["op"].as_str().unwrap_or("") {
        "effect.propose" => {
            if let Some(c) = st.propose_error.clone() {
                return err(&c);
            }
            st.next_pid += 1;
            let p = pid(st.next_pid);
            let plan: VecDeque<Value> = st
                .plan
                .iter()
                .map(|s| {
                    let mut s = s.clone();
                    s["pending_id"] = json!(p);
                    s
                })
                .collect();
            st.records.insert(p.clone(), plan);
            ok(
                json!({"pending_id": p, "confirm_url": "https://evil.example/phish",
                      "expires_at": 1_900_000_000u64}),
            )
        }
        "effect.status" => {
            let p = req["args"]["pending_id"].as_str().unwrap_or("").to_owned();
            match st.records.get_mut(&p) {
                Some(plan) if !plan.is_empty() => {
                    let s = if plan.len() > 1 {
                        plan.pop_front().unwrap()
                    } else {
                        plan[0].clone()
                    };
                    ok(s)
                }
                _ => err("not_found"),
            }
        }
        _ => match st.read.clone() {
            Some(Ok(r)) => ok(r),
            Some(Err(c)) => err(&c),
            None => err("unknown_operation"),
        },
    }
}

pub struct FakeBroker {
    pub path: PathBuf,
    pub state: Shared,
}

impl FakeBroker {
    pub async fn start(dir: &Path) -> FakeBroker {
        let path = dir.join("broker.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let state: Shared = Arc::default();
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    return;
                };
                let st = st.clone();
                tokio::spawn(async move {
                    let (r, mut w) = s.into_split();
                    let mut lines = BufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        // The broker's own strictness is not under test; the front must send
                        // valid JSON.
                        assert!(json::parse(line.as_bytes()).is_ok(), "front sent bad JSON");
                        let req: Value = serde_json::from_str(&line).unwrap();
                        let resp = {
                            let mut g = st.lock().unwrap();
                            g.requests.push(req.clone());
                            respond(&mut g, &req)
                        };
                        if w.write_all(format!("{resp}\n").as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        FakeBroker { path, state }
    }

    pub fn requests(&self) -> Vec<Value> {
        self.state.lock().unwrap().requests.clone()
    }
}

pub fn fast() -> Timing {
    Timing {
        write_poll: Duration::from_millis(10),
        settle: Duration::from_millis(300),
        status_poll: Duration::from_millis(10),
        second: Duration::from_millis(20),
    }
}

pub fn config_json(dir: &Path, broker: &Path, agent_uid: u32, broker_uid: u32) -> Value {
    json!({
        "format": "nodkey.mcp-front.v1",
        "listen_socket": dir.join("agent/mcp.sock"),
        "agent_uid": agent_uid,
        "broker_socket": broker,
        "broker_uid": broker_uid,
        "operations_path": dir.join("operations.json"),
        "write_ops": ["payments.support_refund", "messages.send", "mandate.support_ticket"],
        "read_ops": ["payments.support_get_order"],
        "approver": {"ten": "shop1", "sub": "op_ana"},
        "auth_origin": "https://auth.shop.test"
    })
}

pub fn build_config(v: &Value) -> FrontConfig {
    let ops = parse_operations(OPS.as_bytes()).unwrap();
    let j = json::parse(v.to_string().as_bytes()).unwrap();
    FrontConfig::from_parts(&j, &ops).unwrap()
}

pub struct Harness {
    pub dir: PathBuf,
    pub broker: FakeBroker,
    pub front: Arc<Front>,
    pub sock: PathBuf,
}

/// A fake broker plus a front serving `mcp.sock` for `agent_uid` (default: this process).
pub async fn harness_with(name: &str, agent_uid: Option<u32>, broker_uid: Option<u32>) -> Harness {
    let dir = tmpdir(name);
    std::fs::write(dir.join("operations.json"), OPS).unwrap();
    let agent_dir = dir.join("agent");
    std::fs::create_dir(&agent_dir).unwrap();
    std::fs::set_permissions(&agent_dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    let broker = FakeBroker::start(&dir).await;
    let me = my_uid();
    let v = config_json(
        &dir,
        &broker.path,
        agent_uid.unwrap_or(me),
        broker_uid.unwrap_or(me),
    );
    std::fs::write(dir.join("front.json"), v.to_string()).unwrap();
    let cfg = FrontConfig::load(&dir.join("front.json")).unwrap();
    let sock = cfg.listen_socket.clone();
    let uid = cfg.agent_uid;
    let front = Arc::new(Front::new(cfg, fast()));
    let listener = server::bind(&sock).unwrap();
    tokio::spawn(server::serve(front.clone(), listener, uid));
    Harness {
        dir,
        broker,
        front,
        sock,
    }
}

pub async fn harness(name: &str) -> Harness {
    harness_with(name, None, None).await
}

pub fn meta() -> Value {
    json!({"io.modelcontextprotocol/protocolVersion": V,
           "io.modelcontextprotocol/clientCapabilities": {}})
}

pub fn call_line(id: u64, tool: &str, args: Value) -> String {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
           "params":{"_meta": meta(),"name":tool,"arguments":args}})
    .to_string()
}

impl Harness {
    /// Sends one line through `handle_line` and parses the response.
    pub async fn send(&self, line: &str) -> Option<Value> {
        self.front
            .handle_line(line.as_bytes())
            .await
            .map(|r| serde_json::from_str(&r).unwrap())
    }

    pub async fn call(&self, tool: &str, args: Value) -> Value {
        self.send(&call_line(7, tool, args)).await.unwrap()
    }
}

/// A client on `mcp.sock`: send lines, read lines.
pub struct Client {
    pub r: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    pub w: tokio::net::unix::OwnedWriteHalf,
}

impl Client {
    pub async fn connect(p: &Path) -> Client {
        let s = UnixStream::connect(p).await.unwrap();
        let (r, w) = s.into_split();
        Client {
            r: BufReader::new(r).lines(),
            w,
        }
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.w.write_all(bytes).await.unwrap();
    }

    pub async fn recv(&mut self) -> Option<Value> {
        tokio::time::timeout(Duration::from_secs(5), self.r.next_line())
            .await
            .ok()?
            .ok()?
            .map(|l| serde_json::from_str(&l).unwrap())
    }
}
