# ADR-0007: Receipts are evidence; workflow state is broker-owned

- **Status:** Proposed
- **Date:** 2026-10-24
- **Invariants:** SI-11, SI-12, SI-15
- **Open questions:** OQ-06 (addressed for v0)

## Problem

Demo 3 (order → reserve → authorize → capture → confirm) requires that steps cannot be skipped,
repeated, or reordered, including under concurrency and retries. Decide whether workload-held
receipts or broker-owned state enforce this.

## Evaluation criteria

No authority from possession; resistance to replay, cross-tenant reuse, and laundering; current-state
checks (SI-11); minimal new mechanism.

## Alternatives considered

- **Receipt chain as authority:** step N's signed receipt authorizes step N+1. Adds replay,
  cross-tenant reuse, and laundering surface; stale by construction.
- **External orchestrator (Temporal, sagas) as authority:** provides durability and compensation,
  but the workflow code is trusted, which the workload is not.
- **Broker-owned state machine:** privsep-monitor pattern; the broker re-reads its own state.
- Cross-broker receipts (in-toto / Txn-Token style): only needed when brokers share no database.

## Decision

1. **Workflow state is owned by the broker** in its DB: per-workflow row with tenant, resource, and
   current state, plus a declared transition table per workflow type (`from_state`, operation,
   `to_state`, guard).
2. Each transition is a typed operation. In the effect transaction the broker locks the workflow
   row, checks that `(current_state, op)` is a declared transition and that its guard holds against
   current trusted state, applies the effect, and advances the state with a guarded write
   (`WHERE state = from_state`, rows = 1). Any failure ⇒ rollback ⇒ deny.
3. **Receipts are evidence only (SI-12):** returned to the app and logged; signed with a
   receipt-purpose key and `typ` distinct from grants. The broker **never** accepts a receipt as an
   input to authorization.
4. External orchestrators, if used, sit outside the TCB and only *request* transitions.
5. Cross-broker receipt chains are deferred until a concrete multi-broker deployment needs them.

## Evidence

Research 01 §4: OpenSSH privsep monitor state machine; Bertino et al. 1999 workflow authorization
constraints; in-toto receipts as evidence to a verifier; Zanzibar zookies on staleness.

## Consequences
- **Advantages:** skipping or repeating a step reduces to a failed guarded update; concurrency is
  handled by the same row lock as SI-11.
- **Drawbacks:** each workflow type needs a declared transition table in broker config (TCB data).
- **Security:** a compromised app can still request any declared transition whose guard holds for a
  user it has a grant for; the state machine bounds order, not intent.
- **Performance:** one row lock per transition.
- **Compatibility:** receipts in a documented format let adopters audit without trusting the app.

## Architect notes

- Privacy: receipts should carry opaque identifiers only (research 05, privacy considerations).
- Tests: skip a step, repeat a step, two concurrent transitions from the same state, replay a
  receipt, present a receipt from another tenant — all must deny.

## Reversal / migration

Adding cross-broker receipts later is additive and must re-check the receiving broker's own state.
