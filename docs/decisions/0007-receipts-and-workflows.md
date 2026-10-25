# ADR-0007: Outcomes are evidence; workflow state is broker-owned (rev. 2)

- **Status:** Proposed — AR-19 applied; AR-06 is addressed in ADR-0009, which is new and unreviewed.
  Accept together with ADR-0009.
- **Date:** 2026-10-24
- **Invariants:** SI-11, SI-12, SI-15, SI-19
- **Open questions:** OQ-06 (addressed for v0)

## Problem

Demo 3 (order → reserve → authorize → capture → confirm) requires that steps cannot be skipped,
repeated, or reordered, including under concurrency and retries.

## Evaluation criteria

No authority from possession; resistance to replay, cross-tenant reuse, laundering; current-state
checks; minimal new mechanism.

## Alternatives considered

Receipt chain as authority (replay/laundering surface, stale by construction); external orchestrator
as authority (workflow code trusted); **broker-owned state machine** (privsep monitor pattern);
cross-broker receipts (only when brokers share no DB).

## Decision

1. **Workflow state is broker-owned:** per-workflow row (tenant, subject, resource, state) and a
   declared transition table per workflow type (`from_state`, operation, `to_state`, guard, required
   authority per ADR-0009).
2. Each transition is a typed operation: lock the workflow row (lock order per ADR-0006), check
   `(state, op)` is declared and its guard holds on current trusted state, apply the effect, advance
   with `WHERE state = from_state` (rows = 1). Any failure ⇒ rollback ⇒ deny.
3. **Transitions without a user request** (e.g. capture after authorize) are `derived`
   transitions whose authority is the consumed user grant recorded on the workflow row (ADR-0009 rev. 2,
   Phase 5).
4. **v0 returns an unsigned outcome plus an audit row id (AR-19).** No receipt signing key, no second
   COSE type. Signed receipts are added only with a named external verifier. Nothing returned to the
   app is ever accepted as an authorization input (SI-12).
5. **Evidence is the broker DB audit table** (or an append-only log only the broker writes), never
   aggregated container logs, which the app can forge.
6. External orchestrators sit outside the TCB and only request transitions.

## Evidence

Research 01 §4 (privsep monitor; Bertino et al. 1999; in-toto as evidence); review AR-06, AR-19, AR-20.

## Consequences
- **Advantages:** skipping or repeating a step is a failed guarded update; concurrency handled by the
  same locks as SI-11.
- **Drawbacks:** transition tables are TCB configuration.
- **Security:** a compromised app can still request any declared transition its grants and guards
  allow; the state machine bounds order, not intent.
- **Performance:** one row lock per transition.
- **Compatibility:** audit rows are the export format for auditors.

## Required tests

Skip a step; repeat a step; two concurrent transitions from one state; replay an outcome; cross-tenant
workflow id; `derived` transition from another workload, after `derived_until`, or not declared as a follow-on
(ADR-0009).

## Reversal / migration

Signed receipts and cross-broker chains are additive and must re-check the receiving broker's state.
