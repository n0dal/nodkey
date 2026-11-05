// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0

//! A small bounded PostgreSQL connection pool: a fixed number of connections, a semaphore
//! bounding concurrent users, and bounded waits. A connection that saw an error is discarded so
//! the server rolls back whatever it had open.

use std::time::Duration;

use tokio::sync::{Mutex, MutexGuard, Semaphore, SemaphorePermit};
use tokio_postgres::{Client, NoTls};

use crate::config::DbConfig;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);
/// Server-side limits applied to every session (deadlines; spec §4.4 "lock timeout").
pub const SESSION_OPTIONS: &str =
    "-c statement_timeout=5000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=15000";

#[derive(Debug)]
pub struct DbError(pub String);

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<tokio_postgres::Error> for DbError {
    fn from(e: tokio_postgres::Error) -> Self {
        DbError(e.to_string())
    }
}

pub struct Pool {
    pg: tokio_postgres::Config,
    slots: Vec<Mutex<Option<Client>>>,
    sem: Semaphore,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("size", &self.slots.len())
            .finish()
    }
}

pub struct Conn<'a> {
    _permit: SemaphorePermit<'a>,
    guard: MutexGuard<'a, Option<Client>>,
}

impl Conn<'_> {
    pub fn client(&mut self) -> &mut Client {
        self.guard
            .as_mut()
            .expect("Conn always holds a connected client")
    }
    /// Drops the connection (the server rolls back any open transaction).
    pub fn discard(mut self) {
        *self.guard = None;
    }
}

impl Pool {
    pub fn new(db: &DbConfig, password: String, size: usize) -> Pool {
        let mut pg = tokio_postgres::Config::new();
        pg.host(&db.host)
            .port(db.port)
            .dbname(&db.dbname)
            .user(&db.user)
            .password(password);
        Pool::from_config(pg, size)
    }

    pub fn from_config(mut pg: tokio_postgres::Config, size: usize) -> Pool {
        pg.application_name("nodkey-broker-v2")
            .connect_timeout(CONNECT_TIMEOUT)
            .options(SESSION_OPTIONS);
        let size = size.clamp(1, 32);
        Pool {
            pg,
            slots: (0..size).map(|_| Mutex::new(None)).collect(),
            sem: Semaphore::new(size),
        }
    }

    pub async fn get(&self) -> Result<Conn<'_>, DbError> {
        let permit = tokio::time::timeout(ACQUIRE_TIMEOUT, self.sem.acquire())
            .await
            .map_err(|_| DbError("pool: acquire timeout".into()))?
            .map_err(|_| DbError("pool: closed".into()))?;
        // A permit guarantees that at least one slot is unlocked.
        let mut guard = None;
        for s in &self.slots {
            if let Ok(g) = s.try_lock() {
                guard = Some(g);
                break;
            }
        }
        let mut guard = guard.ok_or_else(|| DbError("pool: no free slot".into()))?;
        if guard.as_ref().is_none_or(|c| c.is_closed()) {
            let (client, conn) = tokio::time::timeout(CONNECT_TIMEOUT, self.pg.connect(NoTls))
                .await
                .map_err(|_| DbError("connect timeout".into()))??;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            *guard = Some(client);
        }
        Ok(Conn {
            _permit: permit,
            guard,
        })
    }
}
