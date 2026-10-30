// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! Socket I wire format as defined by crates/nodkey-authority (README "Wire formats", AU-1, AU-6).
//! A strict fake authority checks every request member exactly as that README states and answers
//! with the authority's exact response shapes.

use std::time::Duration;

use nodkey_gateway::ipc::{self, IpcError, Peer, Subject};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const PID: &str = "-xEiM0RVZneImaq7zN3u_w";
const DIGEST: &str = "920744baca72aba5050f061410f1b55d0d201e3dad6862dfd40956ee5082dddc";

fn keys(o: &Map<String, Value>) -> Vec<&str> {
    let mut k: Vec<&str> = o.keys().map(String::as_str).collect();
    k.sort_unstable();
    k
}

fn is_request_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn subject_ok(v: &Value) -> bool {
    v.as_object()
        .is_some_and(|o| keys(o) == ["sub", "ten"] && o.values().all(Value::is_string))
}

/// Mirrors the authority's checks of the envelope and of each op's `args`.
fn answer(line: &str, mode: &str) -> Value {
    let o: Map<String, Value> = serde_json::from_str(line).expect("strict JSON object");
    assert_eq!(
        keys(&o),
        ["args", "id", "op", "v"],
        "exact envelope members"
    );
    assert_eq!(o["v"], json!(2));
    let id = o["id"].as_str().unwrap();
    assert!(is_request_id(id), "id grammar");
    let args = o["args"].as_object().unwrap();
    let err = |id: Value, code: &str| {
        json!({"v": 2, "id": id, "correlation_id": "c-9", "ok": false,
               "error": {"code": code, "message": "The request is not available."}})
    };
    match o["op"].as_str().unwrap() {
        "approve" => {
            assert_eq!(keys(args), ["digest_shown", "pending_id", "subject"]);
            assert_eq!(args["pending_id"], PID);
            assert_eq!(args["digest_shown"], DIGEST);
            assert!(subject_ok(&args["subject"]));
            match mode {
                "ok" => {
                    json!({"v": 2, "id": id, "correlation_id": "c-9", "ok": true, "result": {}})
                }
                "null-id" => err(Value::Null, "malformed_request"),
                _ => err(json!(id), "not_available"),
            }
        }
        "read_grant" => {
            assert_eq!(keys(args), ["rop", "subject", "wid"]);
            assert!(subject_ok(&args["subject"]));
            assert!(args["wid"].is_string());
            let rop = args["rop"].as_array().unwrap();
            assert!((1..=16).contains(&rop.len()) && rop.iter().all(Value::is_string));
            match mode {
                "ok" => json!({"v": 2, "id": id, "correlation_id": "c-9", "ok": true,
                               "result": {"grant": "0oRDoQEmoQRCAAFYAA"}}),
                _ => err(json!(id), "not_available"),
            }
        }
        _ => err(json!(id), "unknown_operation"),
    }
}

async fn fake_authority(mode: &'static str, delay: Duration) -> (std::path::PathBuf, Peer) {
    let dir = std::env::temp_dir().join(format!(
        "glgw-au-{}",
        nodkey_gateway::util::hex_lower(&nodkey_gateway::util::random_bytes::<6>().unwrap())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("i.sock");
    let l = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut line = String::new();
                BufReader::new(r).read_line(&mut line).await.unwrap();
                assert!(line.ends_with('\n') && line.len() <= 8 * 1024);
                let resp = answer(line.trim_end_matches('\n'), mode);
                tokio::time::sleep(delay).await;
                let mut b = serde_json::to_vec(&resp).unwrap();
                b.push(b'\n');
                let _ = w.write_all(&b).await;
            });
        }
    });
    let peer = Peer {
        path,
        expected_uid: None,
        timeout: Duration::from_secs(2),
    };
    (dir, peer)
}

const S: Subject<'static> = Subject {
    ten: "acme",
    sub: "user:u-17",
};

#[tokio::test]
async fn approve_and_read_grant_in_authority_format() {
    let (dir, p) = fake_authority("ok", Duration::ZERO).await;
    assert_eq!(ipc::approve(&p, PID, DIGEST, S).await, Ok(()));
    let g = ipc::read_grant(
        &p,
        S,
        "spiffe://nodkey.test/workload/shop",
        &["payments.get_order".into()],
    )
    .await;
    assert_eq!(g, Ok("0oRDoQEmoQRCAAFYAA".to_owned()));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn refusals_in_authority_format() {
    let (dir, p) = fake_authority("refuse", Duration::ZERO).await;
    assert_eq!(
        ipc::approve(&p, PID, DIGEST, S).await,
        Err(IpcError::Refused("not_available".into()))
    );
    assert_eq!(
        ipc::read_grant(&p, S, "w", &["payments.get_order".into()]).await,
        Err(IpcError::Refused("not_available".into()))
    );
    let _ = std::fs::remove_dir_all(dir);
    // An envelope error with `"id": null` does not match our request id: fail closed.
    let (dir, p) = fake_authority("null-id", Duration::ZERO).await;
    assert!(matches!(
        ipc::approve(&p, PID, DIGEST, S).await,
        Err(IpcError::Transport(_))
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn approve_waits_for_the_authority_reply_timeout() {
    // The authority may hold `approve` for up to its `approve_reply_timeout_ms` (AU-6).
    let (dir, p) = fake_authority("ok", Duration::from_millis(1200)).await;
    let short = Peer {
        timeout: Duration::from_millis(500),
        ..p.clone()
    };
    assert_eq!(
        ipc::approve(&short, PID, DIGEST, S).await,
        Err(IpcError::Transport("timeout"))
    );
    assert_eq!(ipc::approve(&p, PID, DIGEST, S).await, Ok(()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn default_approve_timeout_exceeds_authority_maximum() {
    let l = nodkey_gateway::config::Limits::default();
    assert!(
        l.approve_timeout_ms > 30_000,
        "authority approve_reply_timeout_ms is at most 30 000"
    );
}
