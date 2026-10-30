// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0

//! The orders view over a real PostgreSQL 17 (Docker), through the adapter's production
//! connector (`PgUnixView`: connect the Unix socket, check the server's `SO_PEERCRED` uid, then
//! `connect_raw` with SCRAM). On macOS a container's Unix socket cannot be mounted into the
//! host, so the test listens on a local Unix socket and relays it to the container's loopback TCP
//! port; the relay is this process, so `db_uid` is the test user's uid. The `pg-adapter` volume,
//! `pg_hba` and uid separation themselves are deployment properties (PT-31) and are not covered.
//!
//! Ignored by default (needs Docker): `cargo test --test postgres -- --ignored`.

mod common;

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use nodkey_payments_adapter::grant::RefundGrant;
use nodkey_payments_adapter::orders::{OrderCheck, PG_SOCKET_NAME, PgUnixView, check_order};
use zeroize::Zeroizing;

const IMAGE: &str =
    "postgres:17-alpine@sha256:eee6c6e1b0894fa4fe0075eb054af9fd1cf39a35321c2d4110626cfe506411fb";
const ADAPTER_PW: &str = "adapter-test-password";

const INIT: &str = r#"
REVOKE CREATE, TEMPORARY ON DATABASE ledger FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA nodkey AUTHORIZATION postgres;
CREATE TABLE nodkey.orders (
  order_id bigint PRIMARY KEY CHECK (order_id BETWEEN 1 AND 9007199254740991),
  ten text NOT NULL, owner_sub text NOT NULL,
  charge_id text NOT NULL UNIQUE CHECK (charge_id ~ '^ch_[A-Za-z0-9]{8,61}$'),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  captured_minor bigint NOT NULL CHECK (captured_minor >= 1),
  external_refunded_minor bigint NOT NULL DEFAULT 0,
  status text NOT NULL);
CREATE ROLE nodkey_payments_adapter LOGIN PASSWORD 'adapter-test-password';
ALTER ROLE nodkey_payments_adapter SET search_path = '';
GRANT USAGE ON SCHEMA nodkey TO nodkey_payments_adapter;
GRANT SELECT (order_id, ten, owner_sub, charge_id, currency) ON nodkey.orders TO nodkey_payments_adapter;
INSERT INTO nodkey.orders VALUES
  (4711, 'acme', 'user:u-17', 'ch_demoorder0001', 'USD', 5000, 0, 'captured'),
  (4712, 'acme', 'user:u-18', 'ch_demoorder0002', 'JPY', 1000, 0, 'captured');
"#;

struct Pg {
    name: String,
    port: u16,
}

impl Drop for Pg {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker").args(args).output().expect("docker")
}

fn start_pg() -> Pg {
    let name = format!("nodkey-pa-test-{}-{}", std::process::id(), uniq());
    let out = docker(&[
        "run",
        "-d",
        "--rm",
        "--name",
        &name,
        "-e",
        "POSTGRES_PASSWORD=postgres-test",
        "-e",
        "POSTGRES_DB=ledger",
        "-p",
        "127.0.0.1::5432",
        IMAGE,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut pg = Pg { name, port: 0 };
    let port_out = docker(&["port", &pg.name, "5432/tcp"]);
    let s = String::from_utf8_lossy(&port_out.stdout);
    let port: u16 = s
        .lines()
        .next()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    pg.port = port;
    // Ready = the init script ran (the entrypoint restarts the server once).
    for _ in 0..120 {
        let r = docker(&[
            "exec",
            &pg.name,
            "psql",
            "-U",
            "postgres",
            "-d",
            "ledger",
            "-h",
            "127.0.0.1",
            "-c",
            "select 1",
        ]);
        if r.status.success() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let mut c = Command::new("docker")
        .args([
            "exec",
            "-i",
            &pg.name,
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            "ledger",
            "-h",
            "127.0.0.1",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    use std::io::Write;
    c.stdin.take().unwrap().write_all(INIT.as_bytes()).unwrap();
    assert!(c.wait().unwrap().success(), "init SQL failed");
    pg
}

/// Unix socket `dir/.s.PGSQL.5432` relayed to `127.0.0.1:port`.
async fn relay(port: u16) -> std::path::PathBuf {
    let dir = sockdir();
    let l = tokio::net::UnixListener::bind(dir.join(PG_SOCKET_NAME)).unwrap();
    tokio::spawn(async move {
        while let Ok((mut u, _)) = l.accept().await {
            tokio::spawn(async move {
                if let Ok(mut t) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                    let _ = tokio::io::copy_bidirectional(&mut u, &mut t).await;
                }
            });
        }
    });
    dir
}

fn view(dir: &std::path::Path, pw: &str) -> PgUnixView {
    PgUnixView {
        socket_dir: dir.to_path_buf(),
        db_uid: my_uid(),
        dbname: "ledger".into(),
        user: "nodkey_payments_adapter".into(),
        password: Zeroizing::new(pw.as_bytes().to_vec()),
        timeout: Duration::from_secs(5),
    }
}

fn rg(order_id: u64, sub: &str, charge: &str, cur: &str) -> RefundGrant {
    RefundGrant {
        iss: ISS.into(),
        jti: [1; 16],
        op: "payments.refund".into(),
        opv: 1,
        iat: 0,
        ten: "acme".into(),
        sub: sub.into(),
        order_id,
        amount_minor: 5,
        currency: cur.into(),
        charge_id: charge.into(),
        customer_sub: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Docker and the pinned postgres:17-alpine image"]
async fn orders_view_over_real_postgres() {
    let pg = start_pg();
    let dir = relay(pg.port).await;
    let v = view(&dir, ADAPTER_PW);
    assert_eq!(
        check_order(&v, &rg(4711, "user:u-17", CH_USD, "USD")).await,
        Ok(())
    );
    for g in [
        rg(4711, "user:u-18", CH_USD, "USD"),
        rg(4711, "user:u-17", CH_JPY, "USD"),
        rg(4711, "user:u-17", CH_USD, "EUR"),
        rg(4712, "user:u-17", CH_JPY, "JPY"),
        rg(9999, "user:u-17", CH_USD, "USD"),
    ] {
        assert_eq!(
            check_order(&v, &g).await,
            Err(OrderCheck::Mismatch),
            "{g:?}"
        );
    }
    // Wrong password → unavailable (never a refusal that could be mistaken for a decision).
    let bad = view(&dir, "wrong");
    assert!(matches!(
        check_order(&bad, &rg(4711, "user:u-17", CH_USD, "USD")).await,
        Err(OrderCheck::Unavailable(_))
    ));
    // Role privileges: other columns, writes, locks and object creation are denied.
    let mut cfg = tokio_postgres::Config::new();
    cfg.user("nodkey_payments_adapter")
        .dbname("ledger")
        .password(ADAPTER_PW);
    let s = tokio::net::UnixStream::connect(dir.join(PG_SOCKET_NAME))
        .await
        .unwrap();
    let (c, conn) = cfg.connect_raw(s, tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(conn);
    for sql in [
        "SELECT captured_minor FROM nodkey.orders",
        "UPDATE nodkey.orders SET owner_sub = 'x' WHERE order_id = 4711",
        "SELECT order_id FROM nodkey.orders WHERE order_id = 4711 FOR UPDATE",
        "INSERT INTO nodkey.orders VALUES (1,'a','b','ch_AAAAAAAA','USD',1,0,'captured')",
        "CREATE TABLE public.orders (x int)",
        "CREATE TEMP TABLE t (x int)",
        "SELECT order_id FROM orders",
    ] {
        assert!(c.simple_query(sql).await.is_err(), "allowed: {sql}");
    }

    // PC-A-06: with the role's search_path setting removed, the connector's own start-up
    // parameters still give the session an empty search_path.
    let r = docker(&[
        "exec",
        &pg.name,
        "psql",
        "-U",
        "postgres",
        "-d",
        "ledger",
        "-h",
        "127.0.0.1",
        "-c",
        "ALTER ROLE nodkey_payments_adapter RESET search_path",
    ]);
    assert!(r.status.success());
    let s = tokio::net::UnixStream::connect(dir.join(PG_SOCKET_NAME))
        .await
        .unwrap();
    let (c2, conn) = v
        .startup_config()
        .connect_raw(s, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(conn);
    let sp = c2.simple_query("SHOW search_path").await.unwrap();
    let sp = sp
        .iter()
        .find_map(|m| match m {
            tokio_postgres::SimpleQueryMessage::Row(r) => r.get(0).map(str::to_owned),
            _ => None,
        })
        .unwrap();
    assert!(sp.is_empty() || sp == "\"\"", "search_path = {sp:?}");
    assert_eq!(
        check_order(&v, &rg(4711, "user:u-17", CH_USD, "USD")).await,
        Ok(())
    );

    // End to end: socket P → order view in PostgreSQL → simpay over TLS.
    let s = Simpay::start(Tls::Good);
    let mut o = Opts::new(s.api);
    o.orders = Arc::new(view(&dir, ADAPTER_PW));
    let p = start_p(o).await;
    let ok = p
        .create(&sign(&refund_grant(500, "USD", CH_USD, now()), SEED))
        .await;
    assert_eq!(result_class(&ok).0, "created");
    let foreign =
        refund_grant(500, "JPY", CH_JPY, now()).resource(0, nodkey_grant::ParamValue::Uint(4712));
    assert_eq!(
        err_code(&p.create(&sign(&foreign, SEED)).await),
        "grant_refused"
    );
    assert_eq!(s.ledger(CH_USD), (1, 500));
    assert_eq!(s.ledger(CH_JPY), (0, 0));
    drop(pg);
    // DB gone → unavailable, nothing sent.
    let v = p
        .create(&sign(&refund_grant(5, "USD", CH_USD, now()), SEED))
        .await;
    assert_eq!(err_code(&v), "unavailable");
    assert_eq!(s.ledger(CH_USD), (1, 500));
}
