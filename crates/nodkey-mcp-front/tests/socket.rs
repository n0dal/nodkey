// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! The front on a real `mcp.sock` and the stdio shim as a subprocess (agent-interface-v1 §2.2):
//! framing, peer-uid refusal (AI-11), oversize lines, concurrency, broker uid check.

mod common;

use std::process::Stdio;

use common::*;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn discover(id: u64) -> String {
    json!({"jsonrpc":"2.0","id":id,"method":"server/discover","params":{"_meta":meta()}})
        .to_string()
}

#[tokio::test]
async fn socket_framing_and_concurrency() {
    let h = harness("sock").await;
    let mode = std::fs::metadata(&h.sock).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(mode.permissions().mode() & 0o777, 0o660);
    let mut c = Client::connect(&h.sock).await;
    // A slow call (mandate path, waits for settle) and a fast one on the same connection: the
    // fast one is answered first; responses are correlated by id.
    h.broker.state.lock().unwrap().plan =
        vec![status("", "PENDING", Some("mandate"), Value::Null)].into();
    let slow = call_line(
        1,
        "messages.send",
        json!({"customer_sub":"c42","body":"hi"}),
    );
    c.send_raw(format!("{slow}\n{}\n", discover(2)).as_bytes())
        .await;
    let first = c.recv().await.unwrap();
    assert_eq!(first["id"], 2);
    let second = c.recv().await.unwrap();
    assert_eq!(second["id"], 1);
    assert_eq!(
        second["result"]["structuredContent"]["status"],
        "in_progress"
    );
    // A notification gets nothing; the next request is still answered.
    c.send_raw(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{}}\n")
        .await;
    c.send_raw(format!("{}\n", discover(3)).as_bytes()).await;
    assert_eq!(c.recv().await.unwrap()["id"], 3);
}

#[tokio::test]
async fn oversize_line_is_refused_and_closes() {
    let h = harness("big").await;
    let mut c = Client::connect(&h.sock).await;
    let big = vec![b'a'; 64 * 1024 + 1];
    c.send_raw(&big).await;
    let r = c.recv().await.unwrap();
    assert_eq!(r["error"]["code"], -32600);
    assert_eq!(r["id"], Value::Null);
    assert!(c.recv().await.is_none(), "connection closed");
    assert!(h.broker.requests().is_empty());
}

/// AI-11 / AT-01 (front part): a peer whose uid is not the agent's gets no response.
#[tokio::test]
async fn foreign_uid_is_refused_without_response() {
    let other = my_uid().wrapping_add(1);
    let h = harness_with("uid", Some(other), None).await;
    let mut c = Client::connect(&h.sock).await;
    let _ = c.w.write_all(format!("{}\n", discover(1)).as_bytes()).await;
    assert!(c.recv().await.is_none());
    assert!(h.broker.requests().is_empty());
}

/// The front checks the broker's uid on socket W: a different listener uid is `unavailable`.
#[tokio::test]
async fn wrong_broker_uid_is_unavailable() {
    let h = harness_with("buid", None, Some(my_uid().wrapping_add(1))).await;
    let r = h
        .call("messages.send", json!({"customer_sub":"c42","body":"hi"}))
        .await;
    assert_eq!(
        r["result"]["structuredContent"],
        json!({"error":"unavailable"})
    );
    assert!(
        h.broker.requests().is_empty(),
        "nothing sent to that listener"
    );
}

/// The shim copies stdin → mcp.sock → stdout byte for byte (§2.2).
#[tokio::test]
async fn stdio_shim_end_to_end() {
    let h = harness("shim").await;
    h.broker.state.lock().unwrap().read = Some(Ok(json!({"order_id":101})));
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_nodkey-mcp-stdio"))
        .arg(&h.sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap()).lines();
    stdin
        .write_all(format!("{}\n", discover(1)).as_bytes())
        .await
        .unwrap();
    let r: Value = serde_json::from_str(&out.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(r["result"]["supportedVersions"], json!([V]));
    stdin
        .write_all(
            format!(
                "{}\n",
                call_line(2, "payments.support_get_order", json!({"order_id":101}))
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let r: Value = serde_json::from_str(&out.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(r["result"]["structuredContent"], json!({"order_id":101}));
    drop(stdin);
    assert!(out.next_line().await.unwrap().is_none());
    let st = child.wait().await.unwrap();
    assert!(st.success());
}

#[tokio::test]
async fn stdio_shim_refuses_oversize_line() {
    let h = harness("shimbig").await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_nodkey-mcp-stdio"))
        .arg(&h.sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(&vec![b'x'; 64 * 1024 + 10]).await;
    let st = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!st.success());
}

#[tokio::test]
async fn bind_refuses_open_directory() {
    let dir = tmpdir("bind");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o757)).unwrap();
    assert!(nodkey_mcp_front::server::bind(&dir.join("mcp.sock")).is_err());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    std::fs::write(dir.join("file"), b"").unwrap();
    assert!(nodkey_mcp_front::server::bind(&dir.join("file")).is_err());
    assert!(nodkey_mcp_front::server::bind(&dir.join("mcp.sock")).is_ok());
}
