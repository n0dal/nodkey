# ADR-0006: Replay prevention, budgets, and effect state (rev. 2)

- **Status:** Accepted — review conditions AR-05, AR-10, AR-11 decided below; AR-18 is a condition on
  *claiming* SI-09 across restore/clock rollback, which SI-09 v0.2 now scopes explicitly.
- **Date:** 2026-10-24
- **Invariants:** SI-09, SI-11, SI-15

## Problem

At-most-once effects per grant under concurrency, retries, restarts, and ambiguous external
outcomes; concurrency-safe budgets.

## Evaluation criteria

Atomicity; durability; one decision per grant; no blind retry; budgets that concurrent callers cannot
exceed; bounded storage.

## Alternatives considered

In-memory cache (lost on restart) and separate replay store (not atomic) — rejected. For budgets:
SERIALIZABLE with retry vs locked counter rows (AR-05) — counters chosen: deterministic, no retry
loop, no dependence on aggregate reads.

## Decision

1. **Transaction mode:** READ COMMITTED with explicit locks, fixed lock order: budget counter rows
   (sorted by key) → workflow row → resource row. Deadlock or lock timeout ⇒ Deny, no automatic retry.
2. **Budgets:** counter rows `budget(scope, window_start) → spent, limit` for scopes `(ten, sub)`,
   `(ten)`, `(ten, wid)` as configured; **fixed windows** (e.g. UTC day). Each effect locks its rows
   `FOR UPDATE` and advances them with `UPDATE … WHERE spent + $amt <= limit` (rows = 1). Fixed windows
   allow at most **2× limit** across one boundary; published as such.
3. **Consumption:** `INSERT consumed_grant(iss, jti, exp, request_hash, outcome)` in the effect
   transaction; unique key arbitrates concurrency; store unavailable ⇒ deny; synchronous commit.
4. **One decision per grant (AR-11):** if a *verified* grant is denied (policy, state, budget, lock
   failure), the broker rolls back the effect transaction and records `outcome = DENIED` in a separate
   short transaction; if that write fails, the response is still Deny. Later submissions of that `jti`
   return the stored outcome. Unverified grants consume nothing.
5. **Idempotent retry:** same `jti` and request hash ⇒ stored outcome; different hash ⇒ deny + log.
6. **Revocation:** `revoked_before` per `(ten)`, `(ten, wid)`, `(ten, sub)` checked in-transaction;
   written by the gateway's revoke socket on logout/session revocation, or by the operator (ADR-0004).
7. **External effects:** `RESERVED → DISPATCHED → SUCCEEDED | FAILED | UNKNOWN`; upstream key
   `HMAC(broker_key, "nodkey.idem.v1" ‖ iss ‖ jti)`; `UNKNOWN` never retried or moved to `FAILED` without
   documented upstream deduplication; reconciliation or operator resolves. **(AR-10)** Any effect on
   a resource with a pending `UNKNOWN` of a conflicting operation type is denied as an in-transaction
   precondition, so a fresh grant cannot cause a duplicate.
8. **Retention and clock (AR-18):** prune rows no earlier than `exp + skew + margin`. Persist a clock
   high-water mark; refuse to serve while `now` < mark − skew.
9. **Restore runbook (AR-18):** after any DB restore, set `revoked_before = now` for every tenant (or
   rotate the grant key) before serving. Until mark and runbook are implemented and tested, SI-09 is
   not claimed across restore or clock rollback.

## Evidence

Research 02 §5; PostgreSQL isolation and explicit locking [F\*]; Stripe / IETF idempotency keys
(research 01); review AR-05, AR-10, AR-11, AR-18.

## Consequences
- **Advantages:** at-most-once and budgets reduce to unique constraints and guarded writes.
- **Drawbacks:** per-DB consumption tables; hot budget rows serialize a subject's effects; fixed
  windows double the worst case at boundaries.
- **Security:** `UNKNOWN` blocks progress on a resource (liveness cost for SI-15).
- **Performance:** extra indexed insert plus counter-row locks per effect [H].
- **Compatibility:** Postgres in v0.

## Open

Business-intent upstream idempotency keys (AR-10 second half): deferred to the first external
adapter; depends on upstream semantics.

## Reversal / migration

Broker-internal; no wire change. SERIALIZABLE can be added on top of counters without loss.
