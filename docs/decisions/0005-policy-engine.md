# ADR-0005: Policy evaluation — Cedar embedded in the broker (rev. 2)

- **Status:** Accepted — review conditions AR-04 (CI binding check) and AR-05 (budget facts from
  locked counters) addressed below and in ADR-0006.
- **Date:** 2026-10-24
- **Invariants:** SI-08, SI-10, SI-11, SI-13, SI-15

## Problem

Decide whether a typed, grant-bound request is permitted given trusted facts.

## Evaluation criteria

Embeddable in Rust; deterministic, no I/O; default deny; formal analysis; schema validation;
Apache-2.0-compatible; maturity (research 04 §3.1).

## Alternatives considered

OPA/Rego (I/O builtins, no analysis); OpenFGA/SpiceDB (separate store; later as fact source only);
Casbin; hand-written Rust; **Cedar** (`cedar-policy` 4.14.0, Apache-2.0, CNCF Sandbox, `symcc`).

## Decision

Three layers, each failing closed:

1. **Typed Rust (before):** typed request; Cedar `principal`/`action`/`resource`/`context` built
   only from trusted facts: grant-sourced `sub`/`ten`, socket `wid`, rows read in the transaction.
2. **Cedar:** schema-validated, default deny, `forbid` overrides `permit`. Guardrail forbids:
   cross-tenant, amount above refundable, budget exceeded.
3. **Transaction (after):** state preconditions, guarded writes, consumption (ADR-0006).

**Budget facts (AR-05).** `context.window_spent_*` comes **only** from budget counter rows locked
`SELECT … FOR UPDATE` in the effect transaction (ADR-0006 §2), never from an unlocked aggregate.
The counter is advanced with a guarded write, so the SQL guard and the Cedar forbid both enforce it.

**Fail-closed adapter.** Allow iff decision = Allow **and** zero diagnostic errors; any evaluation,
validation, or entity-construction error ⇒ Deny. Policy sets failing strict validation are refused at
startup. CI: `symcc` never-errors on every guardrail `forbid`; implication checks for published
guardrails; and a **binding check** that every request attribute used in policy is either grant-bound
(`exact`/`bounded`) or a declared `free` parameter (AR-04); also flags route-map ceilings tighter than
policy.

## Evidence

Cedar authorization semantics (error-skip); Cutler et al., OOPSLA 2024; `cedar-policy-symcc`;
PostgreSQL isolation docs on write skew [F\*] — research 04; review AR-05, AR-20.

## Consequences
- **Advantages:** analyzable policy; facts and policy separated.
- **Drawbacks:** another language for adopters; `cvc5` needed at CI time only.
- **Security:** proofs cover policy given the schema, not fact truth (R-11); Cedar is a pinned TCB
  dependency.
- **Performance:** in-process [H, unmeasured].
- **Compatibility:** language-neutral policy.

## Required deny tests

Forged context, cross-tenant IDs, wrong owner, over-refund, budget exceeded including N = 64
concurrent requests on **different** resources, Cedar evaluation error, invalid policy at startup.

## Reversal / migration

Cedar sits behind `decide(facts) -> Allow | Deny`; engine replacement does not change the protocol.
