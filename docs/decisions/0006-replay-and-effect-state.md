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

## Amendment 1 (2026-10-25): atomic recording of denials

Source: grant spec review GS-02 ([`docs/reviews/2026-10-25-grant-v1-spec-review.md`](../reviews/2026-10-25-grant-v1-spec-review.md)),
implemented in [`docs/specs/grant-v1.md`](../specs/grant-v1.md) Draft 2 §7.3. Status of this ADR unchanged
(Accepted).

**Problem.** Decision 4 recorded `outcome = DENIED` "in a separate short transaction; if that write fails,
the response is still Deny". This allows two ways for a verified grant that was answered with a denial to
produce an effect later, which falsifies SI-09. (a) The DENIED write fails; no row exists, and a later
submission of the same grant can be accepted. (b) The effect transaction rolls back, removing the
consumption row; before the separate DENIED insert, a concurrent submission inserts its own row and
commits.

**Decision 4 is replaced by:**

4. **One decision per write grant, recorded atomically.** The consumption insert
   `consumed_grant(iss, jti, exp, request_hash, outcome = PENDING)` is the first statement of the effect
   transaction, before the operation, constraint, revocation, policy, state and budget checks. A
   `SAVEPOINT` follows it. On any denial, the broker rolls back to the savepoint (undoing partial effect
   work but keeping the consumption row), sets `outcome = DENIED`, and commits the same transaction. If
   the savepoint rollback, the update or the commit fails, or the commit outcome is unknown, the response
   is `unavailable` ("nothing was executed"), never a denial. A grant has then received no decision and
   may be decided by a later submission. Every denial returned for a verified write grant is therefore
   backed by a committed DENIED row. Later submissions of that `jti` return the stored outcome (same
   request hash) or are denied as replays (different hash). Unverified grants consume nothing. Read
   grants are never consumed.

Decision 3 is unchanged except that "in the effect transaction" now means "as its first statement".
Verification needs an integration test that injects a failure into the DENIED update and the commit, and
asserts that no ACCEPT ever follows a returned denial for the same grant.

## Amendment 2 (2026-10-25): reconciler resend of an external effect (resolves OQ-10)

Source: [ADR-0012](0012-payments-adapter.md) rev. 1 and review PA-02/PA-05
([`docs/reviews/2026-10-25-payments-adapter-review.md`](../reviews/2026-10-25-payments-adapter-review.md));
specified in [`docs/specs/payments-adapter-v1.md`](../specs/payments-adapter-v1.md) Draft 3 §3, §7.3 (clause 7b amended for Draft 3, PA-18).
Status of this ADR unchanged (Accepted).

Decision 7 is extended:

> **7a. Reconciler resend.** For an external effect in `UNKNOWN` whose grant was consumed with outcome
> `ACCEPT`, the broker MAY have the adapter resend the request decided in that grant's effect transaction
> if and only if: (1) the provider profile documents deduplication by idempotency key; (2) a lookup of
> the effect at the provider has been made first in that round and found nothing; (3) every request
> field, the key and the destination derive from the stored grant (and the frozen effect row), so the
> fingerprint is identical; (4) the broker clock is before `iat + R_max − 60 s`; (5) fewer than
> `max_resends` resends have been made; (6) where the provider exposes key state, it does not report the
> key unknown after the first round.
>
> **7b. Adapter-side window.** Independently of the broker, the adapter verifies the grant's signature
> and claims on every operation, and refuses any **create (dispatch or resend)** when `now − iat > R_max`
> on its own clock, where `R_max <` the provider's documented retention − margin (start-up check).
> Resends after the provider may have pruned the key are therefore refused even if the broker clock or
> configuration is wrong. Lookups (which cannot cause an effect) verify signature and bindings but are
> not age-bounded, so late resolution and settlement tracking remain possible (review PA-18).
>
> A resend is a retransmission of an already-decided effect: it creates no effect row, consumes no
> grant and takes no value from the workload. Its authority is the consumed grant recorded on a
> broker-owned row and re-verified by the adapter, so it is **not a grantless effect under SI-19**.
> After the window the broker only looks the effect up; "not found" is never proof of no effect.
> `UNKNOWN → FAILED` requires the positive evidence defined by the adapter specification.

SI-19 needs no text change if "effect" is read as "one decided effect row"; a clarifying note is proposed
for SECURITY_INVARIANTS v0.5 (not made here).
