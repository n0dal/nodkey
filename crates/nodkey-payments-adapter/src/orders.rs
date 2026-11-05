// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! The adapter's own read-only view of `nodkey.orders` (payments-adapter-v1 §2, §3.2).
//!
//! Channel (PA-16): the adapter connects the PostgreSQL Unix socket in the `pg-adapter` volume
//! itself, requires the server's `SO_PEERCRED` uid to equal the configured `db_uid`, and only then
//! runs the PostgreSQL protocol over that stream (`tokio-postgres` `connect_raw`). The statement
//! is schema-qualified and is the only one the adapter ever sends.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::grant::RefundGrant;

/// The only statement (§2, "Orders view: privileges").
pub const ORDER_SQL: &str =
    "SELECT order_id, ten, owner_sub, charge_id, currency FROM nodkey.orders WHERE order_id = $1";

/// Socket file name inside `socket_dir` (PostgreSQL's default port 5432).
pub const PG_SOCKET_NAME: &str = ".s.PGSQL.5432";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderRow {
    pub order_id: u64,
    pub ten: String,
    pub owner_sub: String,
    pub charge_id: String,
    pub currency: String,
}

/// Why the order check did not pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderCheck {
    /// No row, or a row that differs from the grant → `grant_refused`.
    Mismatch,
    /// The view could not be read → `unavailable`.
    Unavailable(&'static str),
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Source of order rows. Production: [`PgUnixView`].
pub trait OrderView: Send + Sync {
    fn fetch(&self, order_id: u64) -> BoxFut<'_, Result<Option<OrderRow>, &'static str>>;
}

/// §3.2: a row with `ten` = grant `ten`, `owner_sub` = grant `sub`, `charge_id` = con2 and
/// `currency` = con1. For `payments.support_refund` (§16.3), `owner_sub` = grant con3 instead.
pub async fn check_order(view: &dyn OrderView, g: &RefundGrant) -> Result<(), OrderCheck> {
    let owner = if g.op == crate::grant::SUPPORT_OP {
        match g.customer_sub.as_deref() {
            Some(c) => c,
            None => return Err(OrderCheck::Mismatch),
        }
    } else {
        g.sub.as_str()
    };
    let row = view
        .fetch(g.order_id)
        .await
        .map_err(OrderCheck::Unavailable)?;
    match row {
        Some(r)
            if r.order_id == g.order_id
                && r.ten == g.ten
                && r.owner_sub == owner
                && r.charge_id == g.charge_id
                && r.currency == g.currency =>
        {
            Ok(())
        }
        _ => Err(OrderCheck::Mismatch),
    }
}

/// `db` section of the configuration (§9) plus the password read from `password_file`.
pub struct PgUnixView {
    pub socket_dir: PathBuf,
    pub db_uid: u32,
    pub dbname: String,
    pub user: String,
    pub password: Zeroizing<Vec<u8>>,
    pub timeout: Duration,
}

impl std::fmt::Debug for PgUnixView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgUnixView")
            .field("socket_dir", &self.socket_dir)
            .field("db_uid", &self.db_uid)
            .field("dbname", &self.dbname)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl PgUnixView {
    /// Start-up parameters. The session's `search_path` is pinned to empty here as well as by
    /// the role setting (PC-A-06), so a role-level misconfiguration cannot reopen PA-17.
    pub fn startup_config(&self) -> tokio_postgres::Config {
        let mut cfg = tokio_postgres::Config::new();
        cfg.user(&self.user)
            .dbname(&self.dbname)
            .password(&self.password[..])
            .application_name("nodkey-payments-adapter")
            .options("-c search_path=");
        cfg
    }

    async fn connect(&self) -> Result<tokio_postgres::Client, &'static str> {
        let path = self.socket_dir.join(PG_SOCKET_NAME);
        let stream = match timeout(self.timeout, UnixStream::connect(&path)).await {
            Ok(Ok(s)) => s,
            _ => return Err("db_connect"),
        };
        // The server peer must be the configured PostgreSQL uid (PA-16).
        match stream.peer_cred() {
            Ok(c) if c.uid() == self.db_uid => {}
            Ok(c) => {
                crate::log::event(
                    "alarm",
                    serde_json::json!({"alarm": "db_peer_uid_mismatch", "peer_uid": c.uid(),
                                       "expected_uid": self.db_uid}),
                );
                return Err("db_peer_uid");
            }
            Err(_) => return Err("db_peer_cred"),
        }
        let cfg = self.startup_config();
        let (client, conn) =
            match timeout(self.timeout, cfg.connect_raw(stream, tokio_postgres::NoTls)).await {
                Ok(Ok(v)) => v,
                _ => return Err("db_auth"),
            };
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(client)
    }
}

impl OrderView for PgUnixView {
    fn fetch(&self, order_id: u64) -> BoxFut<'_, Result<Option<OrderRow>, &'static str>> {
        Box::pin(async move {
            let Ok(id) = i64::try_from(order_id) else {
                return Ok(None);
            };
            let client = self.connect().await?;
            let row = match timeout(self.timeout, client.query_opt(ORDER_SQL, &[&id])).await {
                Ok(Ok(r)) => r,
                _ => return Err("db_query"),
            };
            let Some(row) = row else { return Ok(None) };
            let get = |i: usize| row.try_get::<_, String>(i).map_err(|_| "db_row_type");
            let rid: i64 = row.try_get(0).map_err(|_| "db_row_type")?;
            Ok(Some(OrderRow {
                order_id: u64::try_from(rid).map_err(|_| "db_row_type")?,
                ten: get(1)?,
                owner_sub: get(2)?,
                charge_id: get(3)?,
                currency: get(4)?,
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake(HashMap<u64, OrderRow>, bool);
    impl OrderView for Fake {
        fn fetch(&self, id: u64) -> BoxFut<'_, Result<Option<OrderRow>, &'static str>> {
            let r = if self.1 {
                Err("down")
            } else {
                Ok(self.0.get(&id).cloned())
            };
            Box::pin(async move { r })
        }
    }

    fn grant() -> RefundGrant {
        RefundGrant {
            iss: "i".into(),
            jti: [0; 16],
            op: "payments.refund".into(),
            opv: 1,
            iat: 0,
            ten: "acme".into(),
            sub: "user:u-17".into(),
            order_id: 7,
            amount_minor: 1,
            currency: "USD".into(),
            charge_id: "ch_demoorder0001".into(),
            customer_sub: None,
        }
    }

    fn row() -> OrderRow {
        OrderRow {
            order_id: 7,
            ten: "acme".into(),
            owner_sub: "user:u-17".into(),
            charge_id: "ch_demoorder0001".into(),
            currency: "USD".into(),
        }
    }

    #[tokio::test]
    async fn order_check_requires_every_field() {
        let ok = Fake(HashMap::from([(7, row())]), false);
        assert_eq!(check_order(&ok, &grant()).await, Ok(()));
        let mut muts: Vec<OrderRow> = Vec::new();
        for f in 0..4 {
            let mut r = row();
            match f {
                0 => r.ten = "other".into(),
                1 => r.owner_sub = "user:u-18".into(),
                2 => r.charge_id = "ch_demoorder0002".into(),
                _ => r.currency = "EUR".into(),
            }
            muts.push(r);
        }
        for r in muts {
            let v = Fake(HashMap::from([(7, r)]), false);
            assert_eq!(check_order(&v, &grant()).await, Err(OrderCheck::Mismatch));
        }
        let none = Fake(HashMap::new(), false);
        assert_eq!(
            check_order(&none, &grant()).await,
            Err(OrderCheck::Mismatch)
        );
        let down = Fake(HashMap::new(), true);
        assert_eq!(
            check_order(&down, &grant()).await,
            Err(OrderCheck::Unavailable("down"))
        );
    }

    /// The server peer uid is checked before any PostgreSQL byte is sent.
    #[tokio::test]
    async fn refuses_db_socket_with_wrong_peer_uid() {
        let dir = std::env::temp_dir().join(format!("gpa-db-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let l = tokio::net::UnixListener::bind(dir.join(PG_SOCKET_NAME)).unwrap();
        let got = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let g2 = got.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 64];
                let n = tokio::time::timeout(Duration::from_millis(300), s.read(&mut b))
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or(0);
                g2.fetch_add(n, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let me = tokio::net::UnixStream::pair()
            .unwrap()
            .0
            .peer_cred()
            .unwrap()
            .uid();
        let v = PgUnixView {
            socket_dir: dir.clone(),
            db_uid: me.wrapping_add(1),
            dbname: "ledger".into(),
            user: "nodkey_payments_adapter".into(),
            password: Zeroizing::new(b"pw".to_vec()),
            timeout: Duration::from_secs(1),
        };
        assert_eq!(v.fetch(1).await, Err("db_peer_uid"));
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            got.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no protocol byte sent"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
