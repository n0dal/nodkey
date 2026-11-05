// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! TLS on the API listener: test-CA generation, handshake policy, malicious certificates,
//! and every fault class over TLS. The admin listener stays plain HTTP.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::*;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde_json::{Value, json};
use simpay::tls::{self, TlsFiles};
use simpay::{Server, StartOptions};

const NAME: &str = "simpay.internal";
static N: AtomicUsize = AtomicUsize::new(0);

fn tmpdir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "simpay-tls-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn certs() -> PathBuf {
    let d = tmpdir().join("certs");
    tls::generate_test_ca(&d, NAME, true).unwrap();
    d
}

async fn start_tls_with(dir: &Path, cert: &str, key: &str, extra: Value) -> Server {
    simpay::start(
        config(extra),
        StartOptions {
            tls: Some(TlsFiles {
                cert: dir.join(cert),
                key: dir.join(key),
            }),
            ..Default::default()
        },
    )
    .await
    .expect("start tls")
}

struct Env {
    s: Server,
    c: TlsClient,
    dir: PathBuf,
}

async fn env(extra: Value) -> Env {
    let dir = certs();
    let s = start_tls_with(&dir, tls::SERVER_CERT, tls::SERVER_KEY, extra).await;
    let c = tls_client(&dir.join(tls::CA_CERT), NAME);
    Env { s, c, dir }
}

fn p(amount: u64, r: &str) -> String {
    format!("charge={CH_USD}&amount={amount}&reference={r}")
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

#[test]
fn gen_test_ca_files_are_labelled_and_keys_private() {
    let d = tmpdir().join("out");
    let files = tls::generate_test_ca(&d, NAME, false).unwrap();
    assert_eq!(files.len(), 5);
    assert!(
        !d.join(tls::WRONG_HOST_CERT).exists(),
        "malicious certs are opt-in"
    );
    for f in &files {
        assert!(
            f.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("TEST-ONLY")
        );
    }
    let ca = CertificateDer::from_pem_file(d.join(tls::CA_CERT)).unwrap();
    assert!(contains(ca.as_ref(), b"TEST-ONLY CA - DO NOT TRUST"));
    let leaf = CertificateDer::from_pem_file(d.join(tls::SERVER_CERT)).unwrap();
    assert!(contains(leaf.as_ref(), NAME.as_bytes()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for k in [tls::CA_KEY, tls::SERVER_KEY] {
            let m = std::fs::metadata(d.join(k)).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600, "{k}");
        }
    }
    // Never overwrites, rejects bad names.
    assert!(tls::generate_test_ca(&d, NAME, false).is_err());
    assert!(tls::generate_test_ca(&tmpdir(), "Bad Name", false).is_err());
}

#[test]
fn gen_test_ca_cli() {
    let d = tmpdir().join("cli");
    let bin = env!("CARGO_BIN_EXE_simpay");
    let out = Command::new(bin)
        .args(["gen-test-ca", "--out"])
        .arg(&d)
        .args(["--dns-name", "pay.test.internal", "--malicious-certs"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("[simpay SIMULATOR] wrote TEST-ONLY"));
    for f in [
        tls::CA_CERT,
        tls::SERVER_KEY,
        tls::WRONG_HOST_CERT,
        tls::EXPIRED_CERT,
        "TEST-ONLY-README.txt",
    ] {
        assert!(d.join(f).exists(), "{f}");
    }
    assert_eq!(
        Command::new(bin)
            .args(["gen-test-ca"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    // --tls-cert without --tls-key, and an unreadable cert, refuse to start.
    let cfg = tmpdir().join("c.json");
    std::fs::write(&cfg, base_json().to_string()).unwrap();
    let o = Command::new(bin)
        .arg("--config")
        .arg(&cfg)
        .arg("--tls-cert")
        .arg(d.join(tls::SERVER_CERT))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let o = Command::new(bin)
        .arg("--config")
        .arg(&cfg)
        .args([
            "--tls-cert",
            "/nonexistent.crt",
            "--tls-key",
            "/nonexistent.key",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("refusing to start"));
}

#[tokio::test]
async fn handshake_policy() {
    let e = env(json!({})).await;
    // Pinned CA, right name, TLS 1.3: works and is still labelled.
    let r = get_tls(&e.s, &e.c, SK, &format!("/v1/charges/{CH_USD}")).await;
    assert_eq!(r.status, 200);
    assert!(r.header("simpay-simulator").unwrap().contains("SIMULATED"));
    let probe = build_request(e.s.api_addr, "GET", "/v1/refunds", &[], b"");
    // Wrong name.
    let other = tls_client(&e.dir.join(tls::CA_CERT), "other.internal");
    let err = raw_tls(e.s.api_addr, &other, &probe, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ClientError::Io(m) if m.starts_with("tls:")),
        "{err:?}"
    );
    // A client that trusts a different CA.
    let foreign = certs();
    let fc = tls_client(&foreign.join(tls::CA_CERT), NAME);
    assert!(matches!(
        raw_tls(e.s.api_addr, &fc, &probe, Duration::from_secs(5)).await,
        Err(ClientError::Io(_))
    ));
    // TLS 1.2-only client: refused (server is TLS 1.3 only).
    let old = tls_client_versions(&e.dir.join(tls::CA_CERT), NAME, &[&rustls::version::TLS12]);
    assert!(matches!(
        raw_tls(e.s.api_addr, &old, &probe, Duration::from_secs(5)).await,
        Err(ClientError::Io(_))
    ));
    // Plain HTTP to the TLS port never gets an HTTP response.
    let r = raw(e.s.api_addr, &probe, Duration::from_secs(5)).await;
    if let Ok(bytes) = r {
        assert!(!bytes.starts_with(b"HTTP/"), "plaintext answer on TLS port");
    }
    // Admin stays plain HTTP: plain works, TLS does not.
    assert_eq!(
        admin(&e.s, "GET", "/admin/health", Value::Null)
            .await
            .status,
        200
    );
    let mut admin_target = e.c.clone();
    admin_target.name = rustls_pki_types::ServerName::try_from(NAME).unwrap();
    // (The admin listener waits for an HTTP head that never comes; a short timeout suffices.)
    assert!(
        raw_tls(
            e.s.admin_addr,
            &admin_target,
            &probe,
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn malicious_certificates_fail_verification() {
    let dir = certs();
    let ca = dir.join(tls::CA_CERT);
    let probe = |s: &Server| build_request(s.api_addr, "GET", "/v1/refunds", &[], b"");
    let s = start_tls_with(&dir, tls::WRONG_HOST_CERT, tls::WRONG_HOST_KEY, json!({})).await;
    let err = raw_tls(
        s.api_addr,
        &tls_client(&ca, NAME),
        &probe(&s),
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, ClientError::Io(m) if m.contains("NotValidForName") || m.contains("name")),
        "{err:?}"
    );
    let s = start_tls_with(&dir, tls::EXPIRED_CERT, tls::EXPIRED_KEY, json!({})).await;
    let err = raw_tls(
        s.api_addr,
        &tls_client(&ca, NAME),
        &probe(&s),
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, ClientError::Io(m) if m.to_lowercase().contains("expired")),
        "{err:?}"
    );
    // Nothing reached the API.
    assert_eq!(ledger(&s, CH_USD).await, (0, 0, 0));
}

#[tokio::test]
async fn api_semantics_over_tls() {
    let e = env(json!({})).await;
    let a = refund_tls(&e.s, &e.c, SK, "k", &p(100, "eff_1")).await;
    assert_eq!(a.status, 200);
    let b = refund_tls(&e.s, &e.c, SK, "k", &p(100, "eff_1")).await;
    assert_eq!(
        (b.header("idempotent-replayed").as_deref(), &b.body),
        (Some("true"), &a.body)
    );
    let c = refund_tls(&e.s, &e.c, SK, "k", &p(101, "eff_1")).await;
    assert_eq!(c.err_code(), "idempotency_params_mismatch");
    assert_eq!(
        refund_tls(&e.s, &e.c, RK_READ, "x", &p(1, "eff_2"))
            .await
            .status,
        403
    );
    assert_eq!(
        refund_tls(&e.s, &e.c, RK_CIDR_BAD, "x", &p(1, "eff_2"))
            .await
            .status,
        401
    );
    let l = get_tls(&e.s, &e.c, SK, "/v1/refunds?reference=eff_1")
        .await
        .json();
    assert_eq!(l["data"].as_array().unwrap().len(), 1);
    assert_eq!(ledger(&e.s, CH_USD).await, (1, 100, 100));
}

#[tokio::test]
async fn commit_faults_over_tls() {
    let e = env(json!({})).await;
    // fail_before_commit: not cached.
    faults(&e.s, json!([{"fault": {"kind": "fail_before_commit"}}])).await;
    assert_eq!(
        refund_tls(&e.s, &e.c, SK, "a", &p(1, "eff_a")).await.status,
        500
    );
    assert_eq!(ledger(&e.s, CH_USD).await, (0, 0, 0));
    assert_eq!(
        refund_tls(&e.s, &e.c, SK, "a", &p(1, "eff_a")).await.status,
        200
    );
    // commit_then_500: cached 500.
    faults(&e.s, json!([{"fault": {"kind": "commit_then_500"}}])).await;
    assert_eq!(
        refund_tls(&e.s, &e.c, SK, "b", &p(1, "eff_b")).await.status,
        500
    );
    let r = refund_tls(&e.s, &e.c, SK, "b", &p(1, "eff_b")).await;
    assert_eq!(
        (r.status, r.header("idempotent-replayed").as_deref()),
        (500, Some("true"))
    );
    // commit_then_drop: abrupt close (no close_notify), committed, same-key replay resolves.
    faults(&e.s, json!([{"fault": {"kind": "commit_then_drop"}}])).await;
    let r = refund_tls_t(&e.s, &e.c, SK, "c", &p(1, "eff_c"), Duration::from_secs(5)).await;
    assert_eq!(r.unwrap_err(), ClientError::Closed);
    assert_eq!(ledger(&e.s, CH_USD).await, (3, 3, 3));
    let r = refund_tls(&e.s, &e.c, SK, "c", &p(1, "eff_c")).await;
    assert_eq!(
        (r.status, r.header("idempotent-replayed").as_deref()),
        (200, Some("true"))
    );
    // drop_before_commit.
    faults(&e.s, json!([{"fault": {"kind": "drop_before_commit"}}])).await;
    let r = refund_tls_t(&e.s, &e.c, SK, "d", &p(1, "eff_d"), Duration::from_secs(5)).await;
    assert_eq!(r.unwrap_err(), ClientError::Closed);
    assert_eq!(ledger(&e.s, CH_USD).await, (3, 3, 3));
    // rate_limit.
    faults(&e.s, json!([{"fault": {"kind": "rate_limit"}}])).await;
    assert_eq!(
        refund_tls(&e.s, &e.c, SK, "e", &p(1, "eff_e")).await.status,
        429
    );
    assert_eq!(ledger(&e.s, CH_USD).await, (3, 3, 3));
}

#[tokio::test]
async fn timing_faults_over_tls() {
    let e = env(json!({})).await;
    // commit_after_delay: client times out, 409 while in progress, commit lands.
    faults(
        &e.s,
        json!([{"fault": {"kind": "commit_after_delay", "ms": 500}}]),
    )
    .await;
    let r = refund_tls_t(
        &e.s,
        &e.c,
        SK,
        "k",
        &p(7, "eff_k"),
        Duration::from_millis(100),
    )
    .await;
    assert_eq!(r.unwrap_err(), ClientError::Timeout);
    let r = refund_tls(&e.s, &e.c, SK, "k", &p(7, "eff_k")).await;
    assert_eq!(r.status, 409);
    let shared = e.s.shared().clone();
    assert!(wait_until(|| shared.lock().refunds.len() == 1, Duration::from_secs(3)).await);
    // slow_response: committed before the client gives up.
    faults(
        &e.s,
        json!([{"fault": {"kind": "slow_response", "ms": 400}}]),
    )
    .await;
    let r = refund_tls_t(
        &e.s,
        &e.c,
        SK,
        "s",
        &p(7, "eff_s"),
        Duration::from_millis(100),
    )
    .await;
    assert_eq!(r.unwrap_err(), ClientError::Timeout);
    assert_eq!(ledger(&e.s, CH_USD).await.0, 2);
    // inflight_409.
    faults(
        &e.s,
        json!([{"fault": {"kind": "inflight_409", "hold_ms": 400}}]),
    )
    .await;
    let body = p(7, "eff_i");
    let first = refund_tls(&e.s, &e.c, SK, "i", &body);
    let second = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        refund_tls(&e.s, &e.c, SK, "i", &body).await
    };
    let (a, b) = tokio::join!(first, second);
    assert_eq!((a.status, b.status), (200, 409));
    assert_eq!(ledger(&e.s, CH_USD).await, (3, 21, 21));
}

#[tokio::test]
async fn webhook_and_settlement_faults_with_tls_api() {
    let e = env(json!({})).await;
    let hook = hook_server(0).await;
    set_endpoint(&e.s, &hook.url()).await;
    faults(
        &e.s,
        json!([
            {"fault": {"kind": "webhook_duplicate", "n": 2}},
            {"fault": {"kind": "late_refund_failed", "after_s": 10}}
        ]),
    )
    .await;
    let r = refund_tls(&e.s, &e.c, SK, "w", &p(50, "eff_w"))
        .await
        .json();
    assert!(wait_until(|| hook.count() == 2, Duration::from_secs(5)).await);
    let now = now(&e.s).await;
    for h in hook.all() {
        assert!(verify(WHSEC, &h.signature, &h.body, now, 300).is_ok());
    }
    advance(&e.s, 10).await;
    let g = get_tls(
        &e.s,
        &e.c,
        SK,
        &format!("/v1/refunds/{}", r["id"].as_str().unwrap()),
    )
    .await;
    assert_eq!(g.json()["status"], "failed");
}

#[tokio::test]
async fn malicious_faults_over_tls() {
    let e = env(json!({"malicious_mode": true})).await;
    let one = |f: Value| json!([{ "fault": f }]);

    faults(&e.s, one(json!({"kind": "lie_amount", "amount": 4242}))).await;
    assert_eq!(
        refund_tls(&e.s, &e.c, SK, "l", &p(1, "eff_l")).await.json()["amount"],
        4242
    );
    assert_eq!(ledger(&e.s, CH_USD).await, (1, 1, 1));

    faults(&e.s, one(json!({"kind": "phantom_success"}))).await;
    assert_eq!(
        refund_tls(&e.s, &e.c, SK, "ph", &p(1, "eff_p"))
            .await
            .status,
        200
    );
    assert_eq!(ledger(&e.s, CH_USD).await, (1, 1, 1));

    faults(&e.s, one(json!({"kind": "deny_but_commit"}))).await;
    assert_eq!(
        refund_tls(&e.s, &e.c, SK, "db", &p(1, "eff_db"))
            .await
            .status,
        400
    );
    assert_eq!(ledger(&e.s, CH_USD).await, (2, 2, 2));

    faults(
        &e.s,
        one(json!({"kind": "redirect", "location": "https://attacker.invalid/"})),
    )
    .await;
    let r = refund_tls(&e.s, &e.c, SK, "rd", &p(1, "eff_rd")).await;
    assert_eq!(
        (r.status, r.header("location").as_deref()),
        (307, Some("https://attacker.invalid/"))
    );

    faults(
        &e.s,
        one(json!({"kind": "oversized_body", "bytes": 3_000_000})),
    )
    .await;
    assert!(
        refund_tls(&e.s, &e.c, SK, "ob", &p(1, "eff_ob"))
            .await
            .body
            .len()
            >= 2_999_000
    );

    faults(
        &e.s,
        one(json!({"kind": "header_injection", "variant": "bare_cr"})),
    )
    .await;
    assert!(contains(
        &refund_tls(&e.s, &e.c, SK, "hi", &p(1, "eff_hi")).await.raw,
        b"a\rb"
    ));

    faults(
        &e.s,
        one(json!({"kind": "malformed_json", "variant": "truncated"})),
    )
    .await;
    let r = refund_tls(&e.s, &e.c, SK, "mj", &p(1, "eff_mj")).await;
    assert!(serde_json::from_slice::<Value>(&r.body).is_err());

    faults(&e.s, one(json!({"kind": "hostile_error_text"}))).await;
    let r = refund_tls(&e.s, &e.c, SK, "ht", &p(1, "eff_ht")).await;
    assert!(
        r.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("<script>")
    );

    faults(
        &e.s,
        one(json!({"kind": "slow_drip", "chunk": 32, "interval_ms": 10})),
    )
    .await;
    let t = Instant::now();
    let r = refund_tls(&e.s, &e.c, SK, "sd", &p(1, "eff_sd")).await;
    assert_eq!(r.status, 200);
    assert!(t.elapsed() >= Duration::from_millis(10) * ((r.raw.len() / 32) as u32 - 1));
}
