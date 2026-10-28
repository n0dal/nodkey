//! `mailsink [--admin <addr>] [--poll-ms <n>] [--container-bind]`
//!
//! Database connection: the tokio-postgres connection string in the environment variable
//! `MAILSINK_DATABASE` (a read-only role with `SELECT` on `public.outbox` only).

use std::net::SocketAddr;
use std::time::Duration;

use mailsink::{Sink, check_bind, log, poll_outbox, serve_admin};

const USAGE: &str = "usage: mailsink [--admin <addr>] [--poll-ms <n>] [--container-bind]
  SIMULATED mail sink: reads the broker's outbox; delivers no mail.
  --admin <addr>      admin listener (default 127.0.0.1:12121): GET /messages, GET /healthz
  --poll-ms <n>       outbox poll interval in ms (50..60000, default 500)
  --container-bind    allow 0.0.0.0 / :: (only inside an isolated container network)
  env MAILSINK_DATABASE  tokio-postgres connection string (required)";

fn fail(m: &str) -> ! {
    eprintln!("mailsink: {m}\n{USAGE}");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let mut admin: SocketAddr = "127.0.0.1:12121"
        .parse()
        .unwrap_or_else(|_| fail("default"));
    let mut poll_ms: u64 = 500;
    let mut container_bind = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--admin" => {
                admin = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| fail("--admin needs an address"))
            }
            "--poll-ms" => {
                poll_ms = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|n| (50..=60_000).contains(n))
                    .unwrap_or_else(|| fail("--poll-ms needs 50..60000"))
            }
            "--container-bind" => container_bind = true,
            _ => fail(&format!("unknown argument {a}")),
        }
    }
    if let Err(e) = check_bind(admin, container_bind) {
        fail(&e);
    }
    let Ok(db) = std::env::var("MAILSINK_DATABASE") else {
        fail("MAILSINK_DATABASE is not set");
    };
    let listener = tokio::net::TcpListener::bind(admin)
        .await
        .unwrap_or_else(|e| fail(&format!("cannot bind {admin}: {e}")));
    log(&format!("admin listening on {admin} (local test use only)"));
    let sink = Sink::new();
    tokio::spawn(serve_admin(listener, sink.clone()));
    let every = Duration::from_millis(poll_ms);
    let poller = async {
        loop {
            match tokio_postgres::connect(&db, tokio_postgres::NoTls).await {
                Ok((client, conn)) => {
                    tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    if let Err(e) = client
                        .batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
                        .await
                    {
                        sink.poll_failed(&e.to_string());
                    } else {
                        let e = poll_outbox(&client, &sink, every).await;
                        sink.poll_failed(&e);
                        log(&format!("outbox poll failed: {e}; reconnecting"));
                    }
                }
                Err(e) => {
                    sink.poll_failed(&e.to_string());
                    log(&format!("database connection failed: {e}"));
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    tokio::select! {
        _ = poller => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
