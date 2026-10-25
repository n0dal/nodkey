# ADR-0005: Policy evaluation — Cedar embedded in the broker

- **Status:** Proposed
- **Date:** 2026-10-24
- **Invariants:** SI-08, SI-10, SI-11, SI-13, SI-15

## Problem

Choose how the broker decides whether a typed, grant-bound request is permitted given trusted facts.

## Evaluation criteria

Embeddable in Rust with no network hop; deterministic, no I/O; default deny; formal analysis;
schema validation; Apache-2.0-compatible; maturity (research 04 §3.1).

## Alternatives considered

**OPA/Rego** (Go sidecar or `regorus`; builtins with I/O must be disabled; no formal analysis).
**OpenFGA/SpiceDB** (server with own store; cross-store staleness) — later as a fact source only.
**Casbin** (nothing over Cedar). **Hand-written Rust** (no analysis, policy mixed into code).
**Cedar** (`cedar-policy` 4.14.0, Apache-2.0, CNCF Sandbox; Lean-modeled semantics; `symcc` SMT
analysis).

## Decision

Three layers, each failing closed:

1. **Typed Rust validation (before):** parse the declared operation into a typed request; reject
   unknown fields; build Cedar `principal`, `action`, `resource`, `context` **only from trusted
   facts** (grant-verified subject/tenant, transport workload id, DB rows read in the transaction).
2. **Cedar (decision):** embedded, schema-validated policy set; default deny; `forbid` overrides
   `permit`. Guardrail forbids include cross-tenant, amount above refundable, and budget exceeded.
3. **DB transaction (after):** state preconditions, guarded writes (`rows = 1`), consumption (ADR-0006).

**Fail-closed adapter:** Allow only if the decision is Allow **and** diagnostics contain zero errors.
Any evaluation error, request-validation error, or entity-construction error ⇒ Deny. Cedar *skips*
an erroring policy and reports it in diagnostics; an erroring `forbid` would otherwise let a
`permit` through. The broker refuses to start with a policy set that fails strict validation. CI runs
`symcc` never-errors checks on every guardrail `forbid` and implication checks for published
guardrails.

## Evidence

Cedar authorization semantics (error-skip, default deny); Cutler et al., OOPSLA 2024;
`cedar-policy-symcc` docs; OPA capabilities docs; Zanzibar §2.2 — cited in research 04.

## Consequences
- **Advantages:** policies are analyzable before deployment; pure evaluation keeps facts and policy
  separate.
- **Drawbacks:** Cedar plus schema is another language for adopters; `symcc` requires an external
  `cvc5` binary at analysis time (not runtime, not TCB at runtime).
- **Security:** proofs cover *policy given the schema*, not the truth of the facts fed in; the fact
  layer needs its own tests (R-11; 04 §9 item 6). Cedar crate is a TCB dependency (attacker H): pin
  and review.
- **Performance:** in-process evaluation [H, small relative to the transaction; not measured].
- **Compatibility:** policy is language-neutral; adopters on Rego would need translation.

## Architect notes

- Policy and the authority's route-map ceilings are two sources of truth. A ceiling looser than
  policy is harmless (policy narrows); a ceiling tighter than policy silently denies legitimate
  requests. A CI check comparing them is recommended.
- Required deny tests: forged context, cross-tenant IDs, wrong owner, over-refund, budget exceeded,
  Cedar evaluation error, invalid policy set at startup.

## Reversal / migration

The typed layer isolates Cedar behind a `decide(facts) -> Allow|Deny` interface; replacing the
engine does not change the wire protocol.
