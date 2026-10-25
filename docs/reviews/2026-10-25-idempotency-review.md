# Adversarial review: D1-01 fix (ambiguous outcomes, idempotent transfers)

- **Date:** 2026-10-25
- **Scope (narrow):** the D1-01 fix only. Files reviewed: `broker/src/ledger.rs`, `broker/src/server.rs`,
  `broker/src/protocol.rs` (transfer arguments), `examples/php-ledger/docker/postgres/initdb/01-ledger.sh`,
  `examples/php-ledger/app/lib/BrokerClient.php`, `examples/php-ledger/app/public/index.php`,
  `tests/integration/idempotency.sh`.
- **Invariants:** SI-09, SI-15 (`docs/SECURITY_INVARIANTS.md`), ADR-0006 rev. 2.
- **Reviewer stance:** independent. I did not write this code.

## Verdict

The broker core holds up. I found no path that produces two debits for one `(workload, idempotency_key)`, and
no path that reports success without a commit. Both of those conclusions also hold with a connection pool.

The fix is not complete for the user-facing half of D1-01. Two reproduced paths still tell the user that a
transfer was not executed, or was denied, when the transfer for that key committed:

- **ID-01 (High).** A double-submit while the DB is stalled renders `TRANSFER NOT EXECUTED … Nothing was
  charged` for a transfer that commits about 0.1 s later. A browser shows the user the second response.
- **ID-02 (Medium).** If a same-key transaction commits while a retry waits for row locks, the retry is answered
  `insufficient_funds`, shown as `TRANSFER DENIED`, even though the key's transfer committed. In the shipped
  single-connection broker this needs a narrow timing window. With a connection pool it is a routine race.

| ID | Severity | Title | Blocks commit |
|---|---|---|---|
| ID-01 | High | `unavailable` on a resubmit is rendered "Nothing was charged" while the same key's transfer is in flight and commits | **Yes** |
| ID-02 | Medium | Business denial (`insufficient_funds`) returned for a key whose transfer committed concurrently; the key is not re-checked after the lock wait | No for the single-connection prototype; **Yes** before any connection pool |
| ID-03 | Low | Client maps post-send protocol anomalies on an effectful call to `bad_response`, which the UI renders as DENIED | No |
| ID-04 | Low | `INSERT` on `transfers` is not column-scoped; no `DELETE` means ADR-0006 §8 retention cannot be done by the broker role | No |
| ID-05 | Low | Unbounded `transfers` growth by 1-cent ping-pong from a compromised workload (keys do not amplify it) | No |
| ID-06 | Low | Replay of a committed key after a policy change is answered DENIED (`limit_exceeded` / `operation_not_permitted`) | No |
| ID-07 | Info | Key namespace is the workload *name*: a rename orphans keys, and reusing a name inherits them | No |

## Evidence: tests run

Run on 2026-10-25 against the working tree (Colima Docker).

```
$ cd broker && cargo test
test result: ok. 40 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ tests/integration/idempotency.sh
A    PASS rows=1 delta=100 id=1 second.replayed=true
B    PASS code=idempotency_conflict rows=1 delta=0
C    PASS responses=20 fresh=1 replayed=19 other=0 rows=1 delta=7
D    PASS first=outcome_unknown retry.replayed=true rows=1 delta=100
E    PASS http=200,200 rows=1 delta=100
F    PASS http=502 'OUTCOME UNKNOWN', resubmit http=200 rows=1 delta=100
idempotency: all cases PASS
```

The suite does what it claims. It does not cover ID-01 or ID-02. Note that case C runs through one broker DB
connection, so it never reaches the unique-violation branch (see Q2).

My reproduction script was a throwaway in the reviewer scratch area and is not committed. It brings up the
protected stack the same way `idempotency.sh` does. The output is quoted under ID-01 and ID-02.

---

## Findings

### ID-01 (High): resubmit during an in-flight transfer is told "Nothing was charged"

- **Files:**
  - `examples/php-ledger/app/public/index.php:92-98`: the `unavailable` text.
  - `broker/src/ledger.rs:188-190`: `LOCK_WAIT_TIMEOUT` of 3 s returns `Unavailable("connection busy")`.
  - `broker/src/protocol.rs:81`: the message "service unavailable; nothing was executed".
- **Reproduced:**
  1. GET `/` to obtain the form key K.
  2. `docker compose pause db`.
  3. POST the transfer with K (first request). 0.5 s later, POST the same form again with K: a double-click,
     or a reload after a slow response.
  4. Unpause the DB about 4 s later.

  ```
  second http=503 at +4s
  <p id="result">TRANSFER NOT EXECUTED: service unavailable (service unavailable; nothing was executed). Nothing was charged; resubmitting this same form is safe.
  first http=200 at +4s
  <p id="result">TRANSFER OK id=2: 100 cents alice &rarr; bob. New alice balance: 99899 cents.
  delta=100 rows=1
  broker: {"code":"unavailable","detail":"before-write: connection busy","effect":"none","idempotency_key":"afa4fe4c…",…}
  broker: {"decision":"allow","effect":"committed","idempotency_key":"afa4fe4c…","duration_us":3619211,…}
  ```

  A browser abandons the first request on a resubmit, so the user sees only the second page: "Nothing was
  charged". The money moved.
- **Reasoning:** `unavailable` is true *for that request*. The UI turns it into a claim about the *transfer*,
  and the transfer is identified by the key, not by the request. The same thing happens whenever a prior
  submission of K is still unresolved on the broker:
  - the client times out at 5 s;
  - the broker can hold the operation for up to 3 s (lock wait) + 5 s (connect) + 10 s (`OP_TIMEOUT`);
  - the retry then hits `connection busy` or a `connect` failure.

  This is the D1-01 failure mode under different wording. A user told "Nothing was charged" who goes back to
  `/` gets a fresh key (`no-store`) and is debited twice. The SI-15 clause "never retried as if they had
  failed" is falsified through the user.
- **Fix:**
  - For a transfer, render `unavailable` as: "This attempt was not processed. If this form was submitted
    before, that submission may still complete. Resubmit this same form to learn the outcome." Never say
    "Nothing was charged" for a key-bearing request.
  - Optionally, give the broker's `Unavailable` message for effectful operations the same per-attempt
    wording.
  - Add an `idempotency.sh` case: double-submit with the DB paused; assert the second page does not contain
    `NOT EXECUTED` / `Nothing was charged`; assert rows=1 and delta=amount.
- **Blocks commit:** yes. D1-01's acceptance condition was that the UI never states non-execution for an
  effect that may have committed.

### ID-02 (Medium): committed key answered with a business denial after the lock wait

- **File:** `broker/src/ledger.rs:249-287`. The key lookup (`:250`) runs *before* `SELECT … FOR UPDATE`
  (`:258-264`). The denials at `:276-287` (`UnknownAccount`, `InsufficientFunds`, `Overflow`) return without
  re-checking the key.
- **Mechanism (READ COMMITTED):**
  1. Transaction A, holding K, has locked the rows and is committing.
  2. Retry B, with the same K and the same arguments, runs its lookup and sees nothing, because A is
     uncommitted.
  3. B blocks on `FOR UPDATE`.
  4. A commits. B's `FOR UPDATE` returns the *post-A* balance.
  5. If that balance is below the amount, B returns `insufficient_funds` and never reaches the INSERT, which
     would have hit the unique violation and replayed.
- **Reproduced:** I simulated A with a superuser `psql` session on a second connection: the same statements
  the broker issues, key K, workload `app1`, and `pg_sleep(1.5)` before COMMIT. I set alice to 150 first.

  ```
  http=403
  <p id="result">TRANSFER DENIED: insufficient_funds (insufficient funds), correlation id …-00000007
  rows for key=1 alice=50
  resubmit http=200
  <p id="result">TRANSFER OK id=3 (already completed earlier; not charged again): …
  broker: {"code":"insufficient_funds","effect":"none","idempotency_key":"70c8e223…",…}
  ```

  The audit log also records `effect:"none"` for a key whose effect exists.
- **Reachability:**
  - *Shipped single-connection broker:* `with_client` drops the connection on `OP_TIMEOUT`. A COMMIT that the
    server has already received still completes after the drop, for example while it waits on WAL flush. A
    retry in that window takes a new connection and follows the path above. This is narrow and needs the
    funds condition.
  - *With a pool:* any two concurrent same-key submissions where the first one drains the account.
  - There are no double debits in either case (see Q2). The harm is a false DENIED for a committed transfer,
    which invites a new-key retry.
- **Fix:** re-run `lookup` after `FOR UPDATE` and before any business denial. The simplest form is to move the
  lookup after the lock statement. READ COMMITTED takes a fresh snapshot per statement, so after the lock
  wait it sees any same-argument transaction that held those rows. A same-key, different-argument
  transaction does not share locks, but the unique index still arbitrates it at the INSERT. Add a test that
  holds a same-key transaction open on a second connection, as above.
- **Blocks commit:** no for the single-connection prototype, if it is listed as a known residual. Yes before a
  connection pool or any claim of SI-15 under concurrent DB connections.

### ID-03 (Low): post-send anomalies on an effectful call become `bad_response` (rendered DENIED)

- **Files:**
  - `examples/php-ledger/app/lib/BrokerClient.php:78-79`: `v`/`id` mismatch.
  - `examples/php-ledger/app/lib/BrokerClient.php:81-89`: `ok:true` without an array `result`, or a missing
    `error.code`.
  - `examples/php-ledger/app/public/index.php:99-102`: both of these render as `TRANSFER DENIED`.
- **Reasoning:** the current broker never produces any of these after executing:
  - it echoes `id` on every response from `handle_line`;
  - the responses with `id:null` (unauthenticated, connection limit, incomplete or too-large frame) are all
    non-executing.

  So the case is not reachable today. It is still the same classification error D1-01 fixed for transport
  failures: a request was sent and the reply cannot be trusted, so for `effectful` it should be
  `outcome_unknown`. The connection-limit refusal (`code:"unavailable"`, `id:null`) also shows as
  `DENIED: bad_response`. That case is non-executing, so it is a wording issue (overlaps D1-12).
- **Fix:** when `$effectful` is true, map any non-conforming response after a complete send to
  `outcome_unknown`.
- **Blocks commit:** no.

### ID-04 (Low): DB grants are close to minimal; two gaps

- **File:** `examples/php-ledger/docker/postgres/initdb/01-ledger.sh:35-43`.
- **Checked and correct:**
  - `SELECT` on `accounts`; `UPDATE (balance_cents)` only.
  - `SELECT` on `transfers` limited to the columns the lookup reads and filters on. `correlation_id` and
    `created_at` are not readable.
  - `USAGE` on the sequence, needed for `nextval`.
  - No `DELETE`, `TRUNCATE`, `REFERENCES` or DDL. `PUBLIC` is revoked on the schema and the database.
  - FK and unique checks need no extra grant.
- **Gaps:**
  - (a) `GRANT INSERT ON transfers` covers all columns, so the broker role can set `id` (desynchronising
    the sequence) and `created_at`. Least privilege is
    `INSERT (from_account, to_account, amount_cents, workload, correlation_id, idempotency_key, from_balance_after_cents)`.
  - (b) With no `DELETE`, the broker cannot apply ADR-0006 §8 retention. That is a reasonable choice, but
    retention then has to be an operator job, and that should be stated.
- **Blocks commit:** no.

### ID-05 (Low): unbounded `transfers` growth from a compromised workload

- **Reasoning:** an attacker in the app can loop 1-cent transfers alice→bob→alice with fresh keys. Each one
  commits a row, and there is no rate or count limit. The DB is shared, so disk exhaustion affects every
  workload.
- **What keys do not change:** they add no amplification, because a row exists only for a committed
  effect. Replays, conflicts and every failed attempt write nothing (`ledger.rs:250-253`, `:303-321`,
  `:276-287`). The lookup is served by the unique index, so it is not a slow-query vector.
- Overlaps D1-06 and D1-07.
- **Fix:** a per-workload rate or count budget (ADR-0006 §2), plus a documented retention job.
- **Blocks commit:** no.

### ID-06 (Low): replay after a policy change is answered DENIED

- **File:** `broker/src/server.rs:172-175`. `wl.authorize` (op permission, `max_transfer_cents`) runs before
  the ledger's replay lookup.
- **Reasoning:** suppose a transfer committed but its response was lost, and the operator then lowers the
  limit or removes the op and restarts. The retry with the same key gets `limit_exceeded` /
  `operation_not_permitted`, shown as `TRANSFER DENIED`, for a committed transfer. Denying is defensible as
  policy. Presenting it as "not executed" is not.
- **Fix:** for transfers, render an authorization denial on a key-bearing retry neutrally. Alternatively,
  answer a replay of an already-committed key from the stored row; that creates no new effect.
- **Blocks commit:** no.

### ID-07 (Info): key namespace is the workload name

- **Files:** `ledger.rs:121`, `server.rs:183`.
- **Reasoning:** `config.rs:84` rejects duplicate names. However:
  - renaming a workload in config makes earlier keys unknown, so a retry after the rename executes anew;
  - giving a retired name to a different application lets it replay the old one's results, though only
    with an identical 16-64-character key.
- **Fix:** document that a workload name must never be renamed or reused while its keys are retained.

---

## Answers to the questions

### Q1. Commit reported as anything but success or outcome_unknown? Success without a commit?

No success without a commit. `Ok` is returned only after `tx.commit()` returns `Ok` (`ledger.rs:336-337`), or
from a stored committed row (`:250-253`, `:312-313`). COMMIT on an aborted transaction returns `ROLLBACK`
without an error. That path is not reachable here, because every statement error returns early through `?`,
or through the unique-violation branch, before `commit()`.

Every branch after `w.mark()` (`:293`) maps to `OutcomeUnknown`: INSERT error, decode, debit, credit, row
count, commit. The branches before it map to `Unavailable` or a business denial, and nothing was written on
those. I checked the edges:

- **Outer timeout:** `tokio::time::timeout` polls the inner future first, so a completed commit is never
  reported as a timeout. A timeout while COMMIT is pending reads the tracker and gives `OutcomeUnknown`
  (`:198-201`).
- **Drop on timeout:** dropping the `Transaction` queues ROLLBACK, and the connection is then discarded
  (`:202-207`).
- **Mutex wait and connect failures:** `Unavailable`. This is true for the request, but see ID-01.
- **Response write failure:** the handler is not cancelled when the peer disconnects, so the effect completes
  either way. The failure is logged as `response_not_delivered` (`server.rs:324-331`). The client sees EOF or
  a timeout and reports `outcome_unknown` (`BrokerClient.php:109-113`).

Paths that do report a committed key wrongly:

- `unavailable`, which the UI renders as "Nothing was charged" (ID-01, reproduced);
- `insufficient_funds` and the other business denials (ID-02, reproduced);
- `bad_response` (ID-03, not reachable today);
- authorization denial after a policy change (ID-06).

### Q2. Two debits for one key? Cross-workload? Conflict leaks?

**No double debit.** I found no interleaving that commits two rows for one `(workload, key)`. The unique
constraint `transfers_workload_idempotency_key_uniq` arbitrates.

The unique-violation branch (`ledger.rs:303-321`) is correct under a pool:

- A concurrent same-key INSERT blocks on the index until the other transaction ends. It then fails with
  23505 if the other committed, or proceeds if it rolled back.
- After the violation, the aborted transaction is rolled back. The lookup then runs on the bare client, with
  a fresh snapshot that sees the winner, and returns a replay or a conflict.
- `Ok(None)` and lookup errors become `OutcomeUnknown`. This is conservative.
- Only the named constraint counts as a replay (`:78-80`). Any other 23505, or a 55P03 lock timeout or 40P01
  deadlock after the mark, becomes `OutcomeUnknown`. A deadlock or lock timeout at `FOR UPDATE`, before the
  mark, becomes `Unavailable`, and in that case nothing was written.
- The one pool-sensitive defect is the misreport in ID-02. It is not a double debit.

**Cross-workload: no collision and no read.** `workload` comes from the socket (`server.rs:183`), never from
the request. Both the constraint and the lookup are scoped by it (`ledger.rs:120-121`).

**Conflict leaks:** `IdempotencyConflict` carries a static message and no stored fields (`protocol.rs:82-84`).
A replay requires identical arguments, so it returns only `transfer_id` and `from_balance_after_cents`. Those
come from a transfer the same workload already made with arguments it already supplied.

### Q3. Abuse of idempotency keys by an attacker in the app

- **Growth:** bounded by committed effects (ID-05). Keys add no amplification.
- **Probing:** only within the attacker's own workload. A miss *executes* a transfer, so probing is not free.
  PHP keys have 128 random bits (`BrokerClient.php:60-63`). An attacker with code execution in the app
  already holds all of that workload's authority and sees its keys in the page HTML. Keys give no extra
  reach.
- **Timing:** replay versus fresh execution is already explicit in the response (`replayed`), so timing adds
  nothing.

### Q4. PHP client classification and UI wording

- **Partial or failed write:** `unavailable`. This is correct. The broker executes only a full line with a
  newline (`server.rs:104-110`; `Incomplete` gives `malformed_request`). A short `fwrite` cannot have sent
  the final `\n`.
- **EOF, partial line, timeout or non-JSON after send:** `outcome_unknown` for effectful calls. Correct.
- **Gaps:** the post-send `bad_response` cases in ID-03.
- **UI:**
  - `OUTCOME UNKNOWN` is rendered correctly (case F).
  - `NOT EXECUTED … Nothing was charged` *is* shown for a transfer that committed (ID-01).
  - `DENIED` *is* shown for a committed key under ID-02 and ID-06.

### Q5. Are the grants minimal?

Nearly. See ID-04: column-scope the `INSERT`.

## Not tested

- I did not run a live connection-pool broker. The pool analysis is reasoning only, plus the second-connection
  simulation in ID-02.
- I did not reproduce the ID-02 single-connection window, where `OP_TIMEOUT` fires with COMMIT in flight and
  the server later commits. It is analytical.
- I did not test ID-06 (policy change plus restart) or ID-07.

## Resolution (orchestrator, 2026-10-25)

| Finding | Disposition | Evidence |
|---|---|---|
| ID-01 High | Fixed. `unavailable` on a key-bearing transfer now reads "NOT EXECUTED BY THIS REQUEST … an earlier submission may still complete; resubmitting is safe" — never "nothing was charged". `bad_response` on a transfer renders as outcome unknown. | Integration case G (double-submit with stalled DB): second page 503 without "nothing was charged", exactly one debit. The pre-fix wording fails this check. |
| ID-02 Medium | Fixed. Idempotency lookup is repeated after acquiring the row locks. | Reasoning plus the reviewer's manual two-session reproduction. **No automated test** yet (requires a second concurrent DB session); tracked for when a connection pool is introduced. |
| Lows | Tracked for the hardening phase (column-scoped INSERT, key retention/pruning, table growth from tiny transfers, replay after policy change, workload-name key scope). | — |
