// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! T29 / T46: the authority process is killed (SIGKILL) between signing and a delivery result,
//! then restarted on the same issuance store. It must re-deliver the identical stored bytes and
//! never sign a second grant for the same `jti`; past `exp` it must mark the row expired instead.
//!
//! The parent test re-executes this test binary as a child (`child_authority`, ignored unless
//! `GLA_CRASH_DIR` is set) so that the kill is a real process kill, not a dropped runtime.

mod common;

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::*;
use nodkey_authority::digest::PendingId;
use nodkey_authority::server::Clock;
use nodkey_authority::store::{Issuance, Status, Store};

#[test]
#[ignore = "child process for t29_kill_between_sign_and_delivery_then_restart"]
fn child_authority() {
    let Ok(dir) = std::env::var("GLA_CRASH_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let keys = Keys {
            key_path: dir.join("authority.key"),
            registry_json: String::new(),
        };
        let broker_path = dir.join("au-broker").join("broker.sock");
        let _run = start_authority(&dir, &keys, &broker_path, Opts::new()).await;
        std::future::pending::<()>().await;
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t29_kill_between_sign_and_delivery_then_restart() {
    let dir = tmpdir("crash");
    let keys = make_key(&dir);
    let broker = FakeBroker::start(&dir, &keys.registry_json).await;
    broker.set_mode(DeliverMode::Hang);
    let pid = random_pid();
    let rec = refund_record(&pid, "user:u-17", 1250, now() + 600);
    let digest = digest_of(&rec);
    broker.add(rec, "PENDING");

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["child_authority", "--exact", "--ignored", "--nocapture"])
        .env("GLA_CRASH_DIR", &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let gw = dir.join("gw-authority").join("authority.sock");
    for _ in 0..500 {
        if gw.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(gw.exists(), "child authority did not start");

    let (g, p, d) = (gw.clone(), pid.clone(), digest.clone());
    let pending = tokio::spawn(async move { approve(&g, &p, &d, "acme", "user:u-17").await });
    for _ in 0..500 {
        if !broker.deliveries().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        broker.deliveries().len(),
        1,
        "delivery attempt reached the broker"
    );

    // SIGKILL while the delivery is in flight (no response, no status record written).
    child.kill().unwrap();
    child.wait().unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let _ = pending.await;

    // Logs carry no secrets: neither the key nor the grant.
    let secret = std::fs::read_to_string(&keys.key_path).unwrap();
    let delivered = broker.deliveries()[0].1.clone();
    assert!(out.contains("grant_signed"), "child logged: {out}");
    assert!(!out.contains(secret.trim()));
    assert!(!out.contains(&nodkey_grant::encode_transport(&delivered)));

    // The row was durable before delivery.
    {
        let s = Store::open(
            &dir.join("issuance.log"),
            nodkey_authority::own_uid().unwrap(),
        )
        .unwrap();
        let row = s.get(&PendingId::parse(&pid).unwrap()).unwrap();
        assert_eq!(row.status, Status::Signed);
        assert_eq!(row.grant, delivered);
    }

    // Restart in-process on the same store; the broker now answers.
    broker.set_mode(DeliverMode::Accept);
    let run = start_authority(&dir, &keys, &broker.path, Opts::new()).await;
    let results: Vec<_> = futures_join(run.authority.recover().await).await;
    assert_eq!(
        results,
        vec![Some(
            nodkey_authority::broker_client::DeliverResult::Accepted
        )]
    );
    let all = broker.deliveries();
    assert!(all.len() >= 2);
    assert!(
        all.iter().all(|(_, g)| *g == delivered),
        "identical bytes after restart"
    );
    assert_eq!(broker.record_state(&pid), "APPROVED");
    let row = run
        .authority
        .issuance(&PendingId::parse(&pid).unwrap())
        .await
        .unwrap();
    assert_eq!(row.status, Status::Accepted);

    // A gateway retry after restart cannot produce a second grant.
    let n = broker.deliveries().len();
    let r = approve(&run.gateway_path, &pid, &digest, "acme", "user:u-17").await;
    assert_eq!(err_code(&r), Some("not_available"));
    assert_eq!(broker.deliveries().len(), n);
}

async fn futures_join<T>(hs: Vec<tokio::task::JoinHandle<T>>) -> Vec<T> {
    let mut out = vec![];
    for h in hs {
        out.push(h.await.unwrap());
    }
    out
}

#[tokio::test]
async fn t29_restart_after_exp_marks_expired_without_delivery() {
    let dir = tmpdir("crash-exp");
    let keys = make_key(&dir);
    let broker = FakeBroker::start(&dir, &keys.registry_json).await;
    let t = now();
    {
        let mut s = Store::open(
            &dir.join("issuance.log"),
            nodkey_authority::own_uid().unwrap(),
        )
        .unwrap();
        s.insert(Issuance {
            jti: PendingId([3; 16]),
            digest: [3; 32],
            ten: "acme".into(),
            sub: "user:u-17".into(),
            wid: SHOP.into(),
            op: "payments.refund".into(),
            signed_at: t - 100,
            exp: t - 70,
            grant: vec![0xd2, 0x84],
            status: Status::Signed,
        })
        .unwrap();
    }
    let mut o = Opts::new();
    o.skew = 5;
    let clock: Clock = std::sync::Arc::new(now);
    o.clock = clock;
    let run = start_authority(&dir, &keys, &broker.path, o).await;
    let results = futures_join(run.authority.recover().await).await;
    assert_eq!(results, vec![None]);
    assert!(broker.deliveries().is_empty());
    let text = std::fs::read_to_string(dir.join("issuance.log")).unwrap();
    assert!(text.contains(r#""status":"expired""#));
}
