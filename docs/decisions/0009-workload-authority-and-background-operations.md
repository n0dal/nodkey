# ADR-0009: Workload-authority and background operations (rev. 2)

- **Status:** Proposed. **Phase 5 scope.** Rev. 2 responds to review 2026-10-25 (R3-12, R3-13, R3-14;
  verdict on rev. 1: reject and resubmit). Accept together with ADR-0007.
- **Date:** 2026-10-25
- **Invariants:** SI-05, SI-10, SI-12, SI-19

## Problem

Some effects have no user HTTP request behind them, such as follow-on workflow steps (capture after
authorize, confirm) and maintenance jobs. They need a trusted tenant, subject, and resource without a
standing credential in the workload and without a grantless path.

## Evaluation criteria

- No undeclared grantless path.
- Tenant and subject come from trusted state.
- Follow-on steps cannot exceed what a user authorized.
- No component whose checks duplicate the broker guard.
- No grantless operations in multi-tenant workloads.

## Alternatives considered

- **Trusted scheduler that signs grants** (rev. 1): rejected (R3-12). It signs facts the broker
  already holds, adds a TCB container, a key, a queue, and a TTL problem. Its `job.claim` was itself
  an undeclared grantless operation in multi-tenant workloads (R3-13).
- **Grantless operations limited by budgets:** rejected. Budgets bound value, not whose resource.
- **Long-lived workload tokens:** rejected (SI-02).
- **Broker-derived authority from broker-owned workflow rows:** chosen.

## Decision

**Phase 3 permits no grantless effects at all.** Every Phase 3 effect requires a user write grant or
read grant (ADR-0003 §7). The Demo 1 operations `ledger.transfer` (`from`/`to`) and
`ledger.get_balance` (`account`) must migrate before Phase 3: transfer becomes a `user_grant` write with
`from` bound to the subject's account and `to` exact (`confirm` above threshold); balance becomes a
`read` operation filtered by owner = `sub`.

For Phase 5, every operation declares one authority class. The broker refuses to start if any
non-default class is not listed in its configuration (SI-19).

1. **`user_grant`** (default) / **`read`**: ADR-0003.
2. **`derived`** (follow-on workflow transitions). Not grantless: the authority is a **consumed user
   grant recorded on a broker-owned workflow row**.
   - When a `user_grant` effect creates a workflow row, the row stores `ten`, `sub`, `wid`, `res`, the
     exact parameters, the consuming `jti`, the workflow definition, and `derived_until` (default 7
     days).
   - The workload calls `workflow.advance(workflow_id, transition)`, a typed `derived` operation. The
     broker locks the row and requires:
     - caller `wid` = row `wid`;
     - the transition is declared as a follow-on of the originating operation;
     - its guard holds on current state, and `now ≥ not_before` if declared;
     - `now < derived_until`;
     - each follow-on is applied at most once per row (state machine).
   - All parameters come from the row or from broker recomputation over trusted state. **App-computed
     parameters are not allowed**; a step that needs them requires a new user grant.
   - Budgets are charged to the row's `(ten, sub)` and `(ten)` counters.
   - The tenant comes from the row, never from the app, so `derived` is permitted in multi-tenant
     workloads.
   - No grant, no TTL, and no scheduler signing. Time-based triggers are a not-before guard checked
     when the workload calls. The broker runs no timer.
3. **`workload`** (maintenance, no user). **Grantless; forbidden in multi-tenant workloads.** Tenancy is
   enforced by configuration, not by assertion:
   - The workload registration fixes `ten`.
   - The broker denies any grant for that `wid` whose `ten` differs.
   - The gateway refuses to route other tenants' users to that `wid`.
   - The principal is `sub = wid`.
   - Each operation declares a **resource scope** limited to rows created by this workload or rows
     not owned by any user. User-owned rows are out of scope.
   - Each operation has a fixed per-call ceiling and a locked **count** budget (plus a value budget
     where monetary). Destination-like and `free` parameters are forbidden.
4. A published residual table lists every `derived` transition and `workload` operation.

## Residual

- **`derived`:** a compromised workload chooses **which** and **when** declared follow-on transitions
  run. This applies to any workflow row it originated, across all its tenants, within guards and
  `derived_until`. Where the workflow offers alternatives (capture vs. void), C picks among those whose
  guards hold. Security-relevant business decisions must therefore be guards, not app logic.
- **`workload`:** C applies the operation to any in-scope, non-user-owned row of the fixed tenant, up
  to the ceilings and count budget.

## Evidence

Review 2026-10-25 R3-12..14; OpenSSH privsep monitor state machine (research 01 §4); Hardy, "The
Confused Deputy".

## Consequences

- **Advantages:** no new TCB component or key. Tenant and subject come from broker state. Multi-tenant
  safe for `derived`.
- **Drawbacks:**
  - Workflow definitions must declare follow-on transitions.
  - Steps that need app computation need a user grant.
  - `derived_until` bounds long-running flows.
- **Security:** ordering and choice among declared transitions remain with the workload (residual
  above).
- **Performance:** one row lock per transition; no signing.
- **Compatibility:** external job runners may call `workflow.advance`; they remain untrusted.

## Reversal / migration

A scheduler can be reintroduced later only if it provides a property the broker guard cannot provide;
that property must be named.
