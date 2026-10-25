//! Simulated ledger backed by PostgreSQL. All statements are fixed and parameterised; the
//! workload never supplies SQL text, table names, or credentials (SI-16).
//!
//! A single connection is guarded by a mutex: operations are serialised. That is a deliberate
//! simplicity choice for the prototype; correctness under concurrency does not depend on it,
//! because transfers lock the affected rows with `SELECT ... FOR UPDATE` inside the transaction,
//! the schema enforces `balance_cents >= 0`, and the unique constraint on
//! `(workload, idempotency_key)` arbitrates duplicate submissions (SI-09).
//!
//! Failure classification (SI-15): a failure is reported as [`LedgerError::Unavailable`] only when
//! no data-modifying statement and no COMMIT has been sent on the connection for this operation.
//! Once the first write has been issued, every failure (statement error, connection loss, the
//! outer operation timeout, a failed COMMIT) is [`LedgerError::OutcomeUnknown`]. That is
//! conservative: before COMMIT the server should roll back when the connection is dropped, but
//! the broker does not claim it as a known outcome. The idempotency key makes a retry safe.

use crate::config::DbConfig;
use crate::protocol::{AccountId, Transfer};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, NoTls};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on waiting for the shared connection. Nothing has been sent when this fires.
const LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(3);
const OP_TIMEOUT: Duration = Duration::from_secs(10);

/// Name of the unique constraint in `01-ledger.sh`. Only a violation of this constraint is
/// treated as "another submission with this key committed first".
pub const IDEMPOTENCY_CONSTRAINT: &str = "transfers_workload_idempotency_key_uniq";

#[derive(Debug)]
pub enum LedgerError {
    UnknownAccount,
    InsufficientFunds,
    /// Credit would overflow the destination balance.
    Overflow,
    /// The key was already used by this workload for a transfer with different arguments.
    IdempotencyConflict,
    /// Nothing was executed: the failure happened before any write was sent to the database.
    Unavailable(String),
    /// A write or COMMIT was sent and its result is unknown.
    OutcomeUnknown(String),
}

/// Records whether a write (data-modifying statement or COMMIT) has been issued for the current
/// operation. It lives outside the operation's future so the outer timeout can read it after
/// that future has been dropped.
#[derive(Debug, Default)]
pub struct WriteTracker(AtomicBool);

impl WriteTracker {
    /// Must be called *before* the write's future is first polled (tokio-postgres sends the
    /// statement on first poll).
    pub fn mark(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn sent(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
    /// Classifies a failure according to whether a write had been issued.
    pub fn failure(&self, what: &str, e: impl std::fmt::Display) -> LedgerError {
        classify_failure(self.sent(), format!("{what}: {e}"))
    }
}

pub fn classify_failure(write_sent: bool, detail: String) -> LedgerError {
    if write_sent {
        LedgerError::OutcomeUnknown(format!("after-write: {detail}"))
    } else {
        LedgerError::Unavailable(format!("before-write: {detail}"))
    }
}

/// True only for a unique violation of the idempotency constraint.
pub fn is_idempotency_violation(code: Option<&SqlState>, constraint: Option<&str>) -> bool {
    code == Some(&SqlState::UNIQUE_VIOLATION) && constraint == Some(IDEMPOTENCY_CONSTRAINT)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOutcome {
    pub transfer_id: i64,
    pub from_balance_cents: i64,
    /// True when this result is the stored result of an earlier submission with the same key.
    pub replayed: bool,
}

/// A transfer previously committed under an idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTransfer {
    pub transfer_id: i64,
    pub from: String,
    pub to: String,
    pub amount_cents: i64,
    pub from_balance_after_cents: i64,
}

/// Decides what a repeat submission gets: the original result when the arguments are identical,
/// otherwise a conflict. Never produces a second effect.
pub fn replay_or_conflict(
    stored: &StoredTransfer,
    t: &Transfer,
) -> Result<TransferOutcome, LedgerError> {
    if stored.from == t.from.as_str()
        && stored.to == t.to.as_str()
        && stored.amount_cents == t.amount_cents
    {
        Ok(TransferOutcome {
            transfer_id: stored.transfer_id,
            from_balance_cents: stored.from_balance_after_cents,
            replayed: true,
        })
    } else {
        Err(LedgerError::IdempotencyConflict)
    }
}

const LOOKUP_SQL: &str = "SELECT id, from_account, to_account, amount_cents, from_balance_after_cents \
     FROM transfers WHERE workload = $1 AND idempotency_key = $2";

async fn lookup(
    c: &(impl tokio_postgres::GenericClient + Sync),
    workload: &str,
    key: &str,
) -> Result<Option<StoredTransfer>, tokio_postgres::Error> {
    let rows = c.query(LOOKUP_SQL, &[&workload, &key]).await?;
    let Some(r) = rows.first() else {
        return Ok(None);
    };
    Ok(Some(StoredTransfer {
        transfer_id: r.try_get(0)?,
        from: r.try_get(1)?,
        to: r.try_get(2)?,
        amount_cents: r.try_get(3)?,
        from_balance_after_cents: r.try_get(4)?,
    }))
}

pub struct Ledger {
    pg: tokio_postgres::Config,
    client: Mutex<Option<Client>>,
}

impl Ledger {
    pub fn new(db: &DbConfig, password: String) -> Ledger {
        let mut pg = tokio_postgres::Config::new();
        pg.host(&db.host)
            .port(db.port)
            .dbname(&db.dbname)
            .user(&db.user)
            .password(password)
            .application_name("nodkey-broker")
            .connect_timeout(CONNECT_TIMEOUT)
            .options("-c statement_timeout=5000 -c lock_timeout=3000");
        Ledger {
            pg,
            client: Mutex::new(None),
        }
    }

    async fn connect(&self) -> Result<Client, LedgerError> {
        let (client, conn) = self
            .pg
            .connect(NoTls)
            .await
            .map_err(|e| LedgerError::Unavailable(format!("before-write: connect: {e}")))?;
        tokio::spawn(async move {
            // Ends when the connection closes; errors surface on the next query.
            let _ = conn.await;
        });
        Ok(client)
    }

    /// Runs `f` with a live client. Any `Unavailable`/`OutcomeUnknown` error or timeout drops the
    /// connection, so a half-done transaction is rolled back by the server and the next call
    /// reconnects. The outer timeout is classified by the [`WriteTracker`].
    async fn with_client<T, F>(&self, f: F) -> Result<T, LedgerError>
    where
        F: for<'c> FnOnce(
            &'c mut Client,
            &'c WriteTracker,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, LedgerError>> + Send + 'c>,
        >,
    {
        let mut guard = tokio::time::timeout(LOCK_WAIT_TIMEOUT, self.client.lock())
            .await
            .map_err(|_| LedgerError::Unavailable("before-write: connection busy".into()))?;
        if guard.as_ref().is_none_or(|c| c.is_closed()) {
            *guard = Some(self.connect().await?);
        }
        let client = guard
            .as_mut()
            .ok_or_else(|| LedgerError::Unavailable("before-write: no client".into()))?;
        let tracker = WriteTracker::default();
        let res = match tokio::time::timeout(OP_TIMEOUT, f(client, &tracker)).await {
            Ok(r) => r,
            Err(_) => Err(classify_failure(tracker.sent(), "operation timeout".into())),
        };
        if matches!(
            res,
            Err(LedgerError::Unavailable(_) | LedgerError::OutcomeUnknown(_))
        ) {
            *guard = None;
        }
        res
    }

    /// Claims the database for protocol v1 (effect protocol v2 §2.1, EP-10): a v1 and a v2
    /// broker must never share one database. Returns `Ok(false)` if the database has no
    /// `broker_claim` table (a Demo 1 database without the v2 schema, which no v2 broker can
    /// use either). Any other failure, or a claim by another protocol, is an error.
    pub async fn claim_protocol_v1(&self) -> Result<bool, String> {
        let r = self
            .with_client(move |c, w| {
                Box::pin(async move {
                    let ins = c
                        .execute(
                            "INSERT INTO broker_claim (singleton, protocol, broker_id) \
                             VALUES (true, 1, 'demo1') ON CONFLICT (singleton) DO NOTHING",
                            &[],
                        )
                        .await;
                    if let Err(e) = &ins {
                        if e.code() == Some(&SqlState::UNDEFINED_TABLE) {
                            return Ok(None);
                        }
                    }
                    ins.map_err(|e| w.failure("claim", e))?;
                    let row = c
                        .query_one("SELECT protocol FROM broker_claim", &[])
                        .await
                        .map_err(|e| w.failure("claim read", e))?;
                    let p: i32 = row.try_get(0).map_err(|e| w.failure("decode", e))?;
                    Ok(Some(p))
                })
            })
            .await;
        match r {
            Ok(None) => Ok(false),
            Ok(Some(1)) => Ok(true),
            Ok(Some(p)) => Err(format!(
                "database already claimed by a protocol {p} broker (refusing to start)"
            )),
            Err(LedgerError::Unavailable(d) | LedgerError::OutcomeUnknown(d)) => Err(d),
            Err(e) => Err(format!("{e:?}")),
        }
    }

    pub async fn get_balance(&self, account: &AccountId) -> Result<i64, LedgerError> {
        let account = account.as_str().to_owned();
        self.with_client(move |c, w| {
            Box::pin(async move {
                let rows = c
                    .query(
                        "SELECT balance_cents FROM accounts WHERE id = $1",
                        &[&account],
                    )
                    .await
                    .map_err(|e| w.failure("select", e))?;
                match rows.first() {
                    Some(r) => r.try_get::<_, i64>(0).map_err(|e| w.failure("decode", e)),
                    None => Err(LedgerError::UnknownAccount),
                }
            })
        })
        .await
    }

    pub async fn transfer(
        &self,
        t: &Transfer,
        workload: &str,
        correlation_id: &str,
    ) -> Result<TransferOutcome, LedgerError> {
        let t = t.clone();
        let workload = workload.to_owned();
        let correlation_id = correlation_id.to_owned();
        self.with_client(move |c, w| {
            Box::pin(async move {
                let from = t.from.as_str();
                let to = t.to.as_str();
                let amount = t.amount_cents;
                let key = t.idempotency_key.as_str();

                let tx = c.transaction().await.map_err(|e| w.failure("begin", e))?;

                // Repeat of a committed submission: answer from the stored row, no new effect.
                if let Some(stored) = lookup(&tx, &workload, key).await.map_err(|e| w.failure("lookup", e))? {
                    let _ = tx.rollback().await;
                    return replay_or_conflict(&stored, &t);
                }

                // Lock both rows in a deterministic order (ORDER BY id) to avoid deadlocks between
                // opposite-direction transfers. The funds check below reads the locked row, so it
                // cannot be invalidated before COMMIT (SI-11).
                let rows = tx
                    .query(
                        "SELECT id, balance_cents FROM accounts WHERE id = $1 OR id = $2 ORDER BY id FOR UPDATE",
                        &[&from, &to],
                    )
                    .await
                    .map_err(|e| w.failure("lock", e))?;

                // Re-check after acquiring the locks: a same-key transaction that was committing
                // while we waited on them is now visible (READ COMMITTED takes a fresh snapshot per
                // statement). Without this, the retry would see the post-debit balance and could be
                // denied for insufficient funds although its effect already happened (review ID-02).
                if let Some(stored) = lookup(&tx, &workload, key).await.map_err(|e| w.failure("lookup", e))? {
                    let _ = tx.rollback().await;
                    return replay_or_conflict(&stored, &t);
                }

                let mut from_bal: Option<i64> = None;
                let mut to_bal: Option<i64> = None;
                for r in &rows {
                    let id: String = r.try_get(0).map_err(|e| w.failure("decode", e))?;
                    let bal: i64 = r.try_get(1).map_err(|e| w.failure("decode", e))?;
                    if id == from {
                        from_bal = Some(bal);
                    } else if id == to {
                        to_bal = Some(bal);
                    }
                }
                let (Some(from_bal), Some(to_bal)) = (from_bal, to_bal) else {
                    let _ = tx.rollback().await;
                    return Err(LedgerError::UnknownAccount);
                };
                if from_bal < amount {
                    let _ = tx.rollback().await;
                    return Err(LedgerError::InsufficientFunds);
                }
                if to_bal.checked_add(amount).is_none() {
                    let _ = tx.rollback().await;
                    return Err(LedgerError::Overflow);
                }
                let from_after = from_bal - amount;

                // First write: the journal row carrying the key. A concurrent submission with the
                // same key either blocks here on the unique index until the other transaction
                // ends, or fails with a unique violation if the other one committed.
                w.mark();
                let inserted = tx
                    .query_one(
                        "INSERT INTO transfers (from_account, to_account, amount_cents, workload, correlation_id, \
                         idempotency_key, from_balance_after_cents) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
                        &[&from, &to, &amount, &workload, &correlation_id, &key, &from_after],
                    )
                    .await;
                let transfer_id: i64 = match inserted {
                    Ok(row) => row.try_get(0).map_err(|e| w.failure("decode", e))?,
                    Err(e) => {
                        let db = e.as_db_error();
                        if !is_idempotency_violation(e.code(), db.and_then(|d| d.constraint())) {
                            return Err(w.failure("journal", e));
                        }
                        // The server rejected our INSERT, so this transaction cannot commit and
                        // nothing of ours took effect. Another submission with this key committed
                        // first; answer from its row.
                        let _ = tx.rollback().await;
                        return match lookup(&*c, &workload, key).await {
                            Ok(Some(stored)) => replay_or_conflict(&stored, &t),
                            Ok(None) => Err(LedgerError::OutcomeUnknown(
                                "after-write: key conflict but no stored row".into(),
                            )),
                            Err(e) => Err(LedgerError::OutcomeUnknown(format!(
                                "after-write: lookup after key conflict: {e}"
                            ))),
                        };
                    }
                };
                let n1 = tx
                    .execute("UPDATE accounts SET balance_cents = balance_cents - $2 WHERE id = $1", &[&from, &amount])
                    .await
                    .map_err(|e| w.failure("debit", e))?;
                let n2 = tx
                    .execute("UPDATE accounts SET balance_cents = balance_cents + $2 WHERE id = $1", &[&to, &amount])
                    .await
                    .map_err(|e| w.failure("credit", e))?;
                if n1 != 1 || n2 != 1 {
                    // Not committed (the transaction is dropped and the connection discarded), but
                    // classified conservatively like every failure after the first write.
                    return Err(w.failure("row count", format!("{n1}/{n2}")));
                }
                tx.commit().await.map_err(|e| w.failure("commit", e))?;
                Ok(TransferOutcome { transfer_id, from_balance_cents: from_after, replayed: false })
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AccountId, IdempotencyKey};

    fn transfer(from: &str, to: &str, amount: i64) -> Transfer {
        Transfer {
            from: AccountId::parse(from).unwrap(),
            to: AccountId::parse(to).unwrap(),
            amount_cents: amount,
            idempotency_key: IdempotencyKey::parse("aaaaaaaaaaaaaaaa").unwrap(),
        }
    }

    fn stored() -> StoredTransfer {
        StoredTransfer {
            transfer_id: 42,
            from: "alice".into(),
            to: "bob".into(),
            amount_cents: 100,
            from_balance_after_cents: 99_900,
        }
    }

    #[test]
    fn failure_before_write_is_unavailable() {
        let w = WriteTracker::default();
        assert!(matches!(
            w.failure("lock", "timeout"),
            LedgerError::Unavailable(_)
        ));
        assert!(matches!(
            classify_failure(false, "operation timeout".into()),
            LedgerError::Unavailable(_)
        ));
    }

    #[test]
    fn failure_after_write_is_outcome_unknown() {
        let w = WriteTracker::default();
        w.mark();
        for what in ["journal", "debit", "credit", "commit", "row count"] {
            assert!(
                matches!(
                    w.failure(what, "connection closed"),
                    LedgerError::OutcomeUnknown(_)
                ),
                "{what}"
            );
        }
        // The outer timeout that wraps COMMIT (D1-01 second path).
        assert!(matches!(
            classify_failure(w.sent(), "operation timeout".into()),
            LedgerError::OutcomeUnknown(_)
        ));
    }

    #[test]
    fn tracker_is_monotonic() {
        let w = WriteTracker::default();
        assert!(!w.sent());
        w.mark();
        w.mark();
        assert!(w.sent());
    }

    #[test]
    fn replay_with_identical_args_returns_original_result() {
        let o = replay_or_conflict(&stored(), &transfer("alice", "bob", 100)).unwrap();
        assert_eq!(
            o,
            TransferOutcome {
                transfer_id: 42,
                from_balance_cents: 99_900,
                replayed: true
            }
        );
    }

    #[test]
    fn replay_with_different_args_is_conflict() {
        for t in [
            transfer("alice", "bob", 101),
            transfer("alice", "carol", 100),
            transfer("carol", "bob", 100),
            transfer("bob", "alice", 100),
        ] {
            assert!(matches!(
                replay_or_conflict(&stored(), &t),
                Err(LedgerError::IdempotencyConflict)
            ));
        }
    }

    #[test]
    fn only_the_idempotency_constraint_counts_as_replay() {
        assert!(is_idempotency_violation(
            Some(&SqlState::UNIQUE_VIOLATION),
            Some(IDEMPOTENCY_CONSTRAINT)
        ));
        assert!(!is_idempotency_violation(
            Some(&SqlState::UNIQUE_VIOLATION),
            Some("transfers_pkey")
        ));
        assert!(!is_idempotency_violation(
            Some(&SqlState::UNIQUE_VIOLATION),
            None
        ));
        assert!(!is_idempotency_violation(
            Some(&SqlState::CHECK_VIOLATION),
            Some(IDEMPOTENCY_CONSTRAINT)
        ));
        assert!(!is_idempotency_violation(None, None));
    }
}
