# ADR-0009: Workload-authority and background operations

- **Status:** Proposed — new in response to review AR-06; not yet reviewed.
- **Date:** 2026-10-24
- **Invariants:** SI-05, SI-10, SI-12, SI-19

## Problem

Some effects have no user HTTP request behind them: background workflow steps (capture after
authorize, confirm), scheduled jobs, maintenance. Rev. 1 described them as "a separate, budgeted class",
which is a grantless path with no trusted tenant (review AR-06): in a multi-tenant workload every
tenant's workflows would be in reach.

## Evaluation criteria

No undeclared grantless path; trusted tenant and subject for every effect; a background step's
authority derived from a prior user-granted effect, not from the app; fixed, published ceilings.

## Alternatives considered

- **Grantless operations limited by budgets** (rev. 1) — budgets alone bound value, not *whose*
  resource; rejected.
- **Long-lived workload tokens** — standing credential in the workload (SI-02); rejected.
- **Broker executes background steps itself** — strongest, but only for steps needing no app
  computation.
- **Trusted scheduler issues grants** derived from broker state — chosen for steps that need app
  computation.

## Decision

Every operation declares its required authority: `user_grant` (default), `scheduler_grant`, or
`workload`. The broker refuses to start if a non-default class is not listed in its config (SI-19).

1. **`scheduler_grant` (background steps).** A trusted **scheduler** (TCB; own container, no app
   traffic, own signing key with its own `iss`/`kid`, read-only DB role) issues a Nodkey-Grant v1 for a
   declared transition only when broker state shows the precondition was created by a prior
   **user-granted** effect on the same `(ten, sub, resource)` — e.g. `capture` on order 9821 only if
   `authorize` committed under a grant for `(acme, u-17, 9821)`. `ten`, `sub`, `res`, and exact
   parameters are copied from that broker record, never from the app. The scheduler places
   `{job, grant}` in a broker-owned queue; the worker obtains it through a typed `job.claim` operation.
   The broker re-checks the transition guard in-transaction (ADR-0007).
2. **Broker-internal steps.** Steps that need no app computation run inside the broker on the same
   trigger, with no grant handed to the workload.
3. **`workload` (grantless) operations** are permitted only in a **single-tenant** workload whose
   registration fixes `ten`; each must declare a fixed per-call ceiling and a locked-counter budget
   (ADR-0006), and may not have destination-like or `free` parameters. In a multi-tenant workload a
   `workload` operation is a startup error: **no grantless path**.
4. The published residual table lists every `scheduler_grant` and `workload` operation with its
   ceilings.

## Evidence

Review AR-06; Hardy, "The Confused Deputy" (research 04 §5.1); research 02 §2 value 2 (decision time ≠
effect time).

## Consequences
- **Advantages:** every effect has a trusted tenant and subject; background steps cannot exceed what a
  user already authorized.
- **Drawbacks:** adds a trusted scheduler (TCB growth) and a second grant issuer.
- **Security:** scheduler compromise = attacker J for background transitions; its authority is
  limited to transitions whose precondition already exists in broker state. A compromised worker can
  delay or drop jobs.
- **Performance:** one signature per background step.
- **Compatibility:** apps must declare background steps as workflow transitions.

## Reversal / migration

Moving a step from `scheduler_grant` to broker-internal removes the workload from the path; no wire
change.
