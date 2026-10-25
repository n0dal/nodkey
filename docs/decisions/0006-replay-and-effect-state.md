# ADR-0006: Replay prevention and effect state

- **Status:** Proposed
- **Date:** 2026-10-24
- **Invariants:** SI-09, SI-11, SI-15

## Problem

Guarantee at-most-once effects per single-use grant under concurrency, retries, restarts, and
ambiguous external outcomes.

## Evaluation criteria

Atomicity of consumption and effect; durability across restart; correct handling of legitimate
retries; no blind retry of ambiguous external effects; bounded storage.

## Alternatives considered

- In-memory replay cache — lost on restart, reopens the window: rejected.
- Separate replay store (e.g. Redis) — not atomic with the effect; crash between the two yields
  either a lost grant or a duplicate effect: rejected for internal effects.
- Per-`jti` denylist — unnecessary when consumption is recorded.
- Consumption row in the **same transaction** as the effect: chosen.

## Decision

1. **Internal effects:** in one serializable (or row-locked) DB transaction: `INSERT
   consumed_grant(iss, jti, exp, request_hash, outcome)` (unique key = arbiter under concurrency),
   re-check state preconditions, write the effect, commit. Crash ⇒ both or neither. Store
   unavailable ⇒ deny. Synchronous commit on.
2. **Idempotent retry:** same `(iss, jti)` with the same canonical request hash returns the stored
   outcome without a second effect; a different hash is denied and logged.
3. **External effects:** durable state machine `RESERVED → DISPATCHED → SUCCEEDED | FAILED |
   UNKNOWN`. `RESERVED` (which consumes `jti`) commits before any network call; the upstream
   idempotency key is `HMAC(broker_key, "pbe.idem.v1" ‖ iss ‖ jti)`. Timeout, reset, or 5xx after
   dispatch ⇒ `UNKNOWN`. **`UNKNOWN` is never retried or moved to `FAILED`** unless the upstream
   documents idempotency-key deduplication over a window longer than the retry horizon; otherwise it
   is resolved by reconciliation or an operator. Crash in `RESERVED` ⇒ safe to fail; crash in
   `DISPATCHED` ⇒ `UNKNOWN`.
4. **Retention:** consumption rows are pruned no earlier than `exp + skew + margin`.
5. Revocation (epoch) is checked inside the consuming transaction.

## Evidence

Research 02 §5; PostgreSQL transaction isolation and explicit locking (cited in 04 §4); Stripe
idempotent requests and IETF Idempotency-Key draft (01 §4).

## Consequences
- **Advantages:** at-most-once follows from a unique constraint and a single commit, both standard.
- **Drawbacks:** the consumption table must live in the same database as each internal effect; a
  deployment with several protected databases needs a consumption table per DB or the
  RESERVED pattern for all but one.
- **Security:** an `UNKNOWN` effect blocks automatic progress, which is a liveness cost accepted for
  SI-15.
- **Performance:** one extra indexed insert per effect.
- **Compatibility:** requires a transactional store; Postgres in v0.

## Open risks (listed, not resolved)

- **Clock:** pruning and `exp` checks trust the broker clock. A backward jump larger than the margin
  could readmit a pruned `jti`. Proposed mitigation: persist a clock high-water mark and refuse to
  serve if `now` is below it. Behaviour must be specified then tested (02 §8 vector 26).
- **Replay-store restore:** restoring the DB from a backup older than live grants' `exp` reopens
  their replay window. Proposed mitigation: restore procedure must bump all epochs or rotate the
  grant key before the broker serves. Until then SI-09 cannot be claimed across restore (vector 22).
- **Re-issue after `UNKNOWN`:** the authority should refuse new grants for a resource with a pending
  `UNKNOWN` operation; not yet designed.

## Reversal / migration

The state machine is broker-internal; changes do not affect the wire protocol.
